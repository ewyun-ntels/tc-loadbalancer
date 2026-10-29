// SPDX-License-Identifier: GPL-2.0
//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"syscall"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
	"github.com/ewyun-ntels/tc-loadbalancer/internal/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type LinuxProber struct{ Config Config }

func OpenPlatform(c Config) (Plane, Prober, error) {
	p, err := dataplane.Open(c.Interface, c.Object, c.PinPath, c.LockFile)
	if err != nil {
		return nil, nil, err
	}
	return p, &LinuxProber{c}, nil
}

func (p *LinuxProber) Probe(ctx context.Context, b control.Backend, family uint8, previous control.Endpoint) ProbeResult {
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, p.Config.Timeout)
	defer cancel()
	r := ProbeResult{}
	host, network := b.IPv4, "tcp4"
	if family == 6 {
		host, network = b.IPv6, "tcp6"
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		ips, lookupErr := net.DefaultResolver.LookupNetIP(ctx, map[uint8]string{4: "ip4", 6: "ip6"}[family], host)
		var candidates []netip.Addr
		for _, a := range ips {
			if a.Is4In6() {
				a = a.Unmap()
			}
			if a.Is4() == (family == 4) && p.Config.Allows(a) {
				candidates = append(candidates, a)
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Less(candidates[j]) })
		if lookupErr != nil || len(candidates) == 0 {
			// A control-plane/DNS outage must not erase last-known endpoints.
			if !previous.IP.IsValid() {
				r.Detail = fmt.Sprintf("DNS %s: %v (no usable address)", host, lookupErr)
				return r
			}
			address = previous.IP
			r.Detail = fmt.Sprintf("DNS unavailable; probing cached %s", address)
			// Use a fresh budget after a DNS timeout; this still fits the
			// outer bounded reconcile context.
			cancel()
			ctx, cancel = context.WithTimeout(parent, p.Config.Timeout)
			defer cancel()
		} else {
			address = candidates[0]
		}
	}
	if !p.Config.Allows(address) {
		r.Invalidate = true
		r.Detail = "backend address outside allocation ranges"
		return r
	}
	r.Endpoint.IP = address
	iface, err := netlink.LinkByName(p.Config.Interface)
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	all, err := net.Interfaces()
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	localMACs := make(map[[6]uint8]bool)
	localIPs := make(map[netip.Addr]bool)
	var source netip.Addr
	direct := false
	for _, i := range all {
		if len(i.HardwareAddr) == 6 {
			var m [6]uint8
			copy(m[:], i.HardwareAddr)
			localMACs[m] = true
		}
		addrs, err := i.Addrs()
		if err != nil {
			r.Detail = err.Error()
			return r
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			localIPs[ip] = true
			if i.Index == iface.Attrs().Index && ip.Is4() == (family == 4) && !ip.IsLinkLocalUnicast() && prefix.Contains(address) {
				direct = true
				if !source.IsValid() || ip.Less(source) {
					source = ip
				}
				if address.Is4() && prefix.Bits() < 31 {
					n := prefix.Masked().Addr().As4()
					a := address.As4()
					last := uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3])
					last |= uint32((uint64(1) << (32 - prefix.Bits())) - 1)
					v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
					if address == prefix.Masked().Addr() || v == last {
						r.Invalidate = true
						r.Detail = "backend is subnet network/broadcast address"
						return r
					}
				}
			}
		}
	}
	if localIPs[address] || !direct || !source.IsValid() {
		r.Invalidate = true
		r.Detail = "backend is local or not on the attached interface's L2 subnet"
		return r
	}
	ip := net.IP(address.AsSlice())
	src := net.IP(source.AsSlice())
	routes, err := netlink.RouteGetWithOptions(ip, &netlink.RouteGetOptions{OifIndex: iface.Attrs().Index, SrcAddr: src})
	if err != nil || len(routes) == 0 {
		r.Detail = fmt.Sprintf("route lookup: %v", err)
		return r
	}
	for _, route := range routes {
		if route.LinkIndex != iface.Attrs().Index || len(route.Gw) != 0 || len(route.MultiPath) != 0 || route.Type != unix.RTN_UNICAST {
			r.Invalidate = true
			r.Detail = "backend route must be direct on the TC interface, without a gateway"
			return r
		}
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: src}, Control: func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, p.Config.Interface)
		}); err != nil {
			return err
		}
		return bindErr
	}}
	conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), fmt.Sprint(b.HealthPort)))
	if conn != nil {
		conn.Close()
	}
	neighbors, err := netlink.NeighList(iface.Attrs().Index, netlink.FAMILY_ALL)
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	found := false
	for _, n := range neighbors {
		if !n.IP.Equal(ip) || n.State&(netlink.NUD_INCOMPLETE|netlink.NUD_FAILED) != 0 || n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_DELAY|netlink.NUD_PROBE|netlink.NUD_PERMANENT) == 0 || len(n.HardwareAddr) != 6 {
			continue
		}
		copy(r.Endpoint.MAC[:], n.HardwareAddr)
		if !ValidMAC(r.Endpoint.MAC) || localMACs[r.Endpoint.MAC] {
			r.Invalidate = true
			r.Endpoint.MAC = [6]uint8{}
			r.Detail = "unsafe/self backend MAC"
			return r
		}
		found = true
		break
	}
	if !found {
		r.Detail = "no usable ARP/ND neighbor on TC interface"
		return r
	}
	if dialErr != nil {
		r.Detail = errors.Join(errors.New(r.Detail), dialErr).Error()
		return r
	}
	r.OK = true
	return r
}
