// SPDX-License-Identifier: GPL-2.0
package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

type Config struct {
	Interface         string         `json:"interface"`
	Object            string         `json:"object"`
	PinPath           string         `json:"pin_path"`
	LockFile          string         `json:"lock_file"`
	Listen            string         `json:"listen"`
	BackendPrefixes   []string       `json:"backend_prefixes"`
	ForbiddenPrefixes []string       `json:"forbidden_prefixes,omitempty"`
	Health            HealthConfig   `json:"health"`
	Bird              BirdConfig     `json:"bird"`
	Interval          time.Duration  `json:"-"`
	Timeout           time.Duration  `json:"-"`
	Drain             time.Duration  `json:"-"`
	Allowed           []netip.Prefix `json:"-"`
	Forbidden         []netip.Prefix `json:"-"`
}

type HealthConfig struct {
	Interval string `json:"interval"`
	Timeout  string `json:"timeout"`
	Rise     int    `json:"rise"`
	Fall     int    `json:"fall"`
}

type BirdConfig struct {
	Socket        string   `json:"socket,omitempty"`
	Protocols     []string `json:"protocols,omitempty"`
	IPv4Protocols []string `json:"ipv4_protocols,omitempty"`
	IPv6Protocols []string `json:"ipv6_protocols,omitempty"`
	Drain         string   `json:"drain"`
	ConfigFile    string   `json:"config_file,omitempty"`
	Executable    string   `json:"executable,omitempty"`
	PIDFile       string   `json:"pid_file,omitempty"`
}

func LoadConfig(file string) (Config, error) {
	c := Config{Object: "bpf/lb_kern.o", Listen: "127.0.0.1:9090", Health: HealthConfig{"2s", "500ms", 1, 3}, Bird: BirdConfig{Drain: "2s", Executable: "bird"}}
	if err := control.DecodeFile(file, &c); err != nil {
		return c, err
	}
	if c.Interface == "" || len(c.Interface) > 15 || strings.ContainsAny(c.Interface, "/\x00 \t\n") {
		return c, errors.New("invalid interface")
	}
	if c.PinPath == "" {
		c.PinPath = "/sys/fs/bpf/tc-lb-" + c.Interface
	}
	if c.LockFile == "" {
		c.LockFile = "/run/tc-lb-" + c.Interface + ".lock"
	}
	if !strings.HasPrefix(c.PinPath, "/sys/fs/bpf/") || path.Clean(c.PinPath) != c.PinPath || strings.Contains(c.PinPath, "..") {
		return c, errors.New("pin_path must be a dedicated directory below /sys/fs/bpf")
	}
	if !path.IsAbs(c.LockFile) || strings.HasPrefix(c.LockFile, "/sys/fs/bpf/") {
		return c, errors.New("lock_file must be absolute and outside bpffs")
	}
	if c.Object == "" {
		return c, errors.New("object is required")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return c, fmt.Errorf("listen: %w", err)
	}
	var err error
	c.Interval, err = time.ParseDuration(c.Health.Interval)
	if err != nil {
		return c, err
	}
	c.Timeout, err = time.ParseDuration(c.Health.Timeout)
	if err != nil {
		return c, err
	}
	c.Drain, err = time.ParseDuration(c.Bird.Drain)
	if err != nil {
		return c, err
	}
	if c.Interval < 10*time.Millisecond || c.Interval > time.Minute || c.Timeout <= 0 || c.Timeout > c.Interval || c.Drain < 0 || c.Drain > time.Minute || c.Health.Rise < 1 || c.Health.Rise > 100 || c.Health.Fall < 1 || c.Health.Fall > 100 {
		return c, errors.New("invalid health interval/timeout/rise/fall or drain")
	}
	if len(c.BackendPrefixes) == 0 {
		return c, errors.New("backend_prefixes must restrict Multus backend addresses")
	}
	for _, item := range []struct {
		raw []string
		out *[]netip.Prefix
	}{{c.BackendPrefixes, &c.Allowed}, {c.ForbiddenPrefixes, &c.Forbidden}} {
		for _, raw := range item.raw {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p.Addr().Is4In6() || p.Bits() == 0 {
				return c, fmt.Errorf("invalid network prefix %q", raw)
			}
			*item.out = append(*item.out, p.Masked())
		}
	}
	allProtocols := append(append(append([]string(nil), c.Bird.Protocols...), c.Bird.IPv4Protocols...), c.Bird.IPv6Protocols...)
	if (c.Bird.Socket == "") != (len(allProtocols) == 0) {
		return c, errors.New("bird socket and protocols must be configured together")
	}
	if c.Bird.Socket != "" && !path.IsAbs(c.Bird.Socket) {
		return c, errors.New("bird socket must be absolute")
	}
	if c.Bird.Socket != "" {
		if !path.IsAbs(c.Bird.ConfigFile) {
			return c, errors.New("bird config_file must be an absolute path")
		}
		if c.Bird.Executable == "" {
			return c, errors.New("bird executable must not be empty")
		}
		if c.Bird.PIDFile == "" {
			c.Bird.PIDFile = path.Join(path.Dir(c.Bird.Socket), "bird.pid")
		}
		if !path.IsAbs(c.Bird.PIDFile) {
			return c, errors.New("bird pid_file must be an absolute path")
		}
	}
	name := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	seen := make(map[string]bool)
	if len(c.Bird.Protocols) > 0 && (len(c.Bird.IPv4Protocols) > 0 || len(c.Bird.IPv6Protocols) > 0) {
		return c, errors.New("use either legacy protocols or family-specific BIRD protocols")
	}
	for _, p := range allProtocols {
		if !name.MatchString(p) || seen[p] {
			return c, errors.New("BIRD protocol names must be unique simple identifiers")
		}
		seen[p] = true
	}
	return c, nil
}

func (c Config) Allows(ip netip.Addr) bool {
	for _, p := range c.Forbidden {
		if p.Contains(ip) {
			return false
		}
	}
	for _, p := range c.Allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateTable rejects VIPs inside the backend pool: without this separation a
// name accidentally resolving to a VIP could health-check through the LB.
func (c Config) ValidateTable(t control.Table) error {
	if err := t.Validate(); err != nil {
		return err
	}
	for _, a := range t.Assignments {
		if c.Bird.Socket != "" {
			v4 := mustIP(a.Source).Is4()
			if len(c.Bird.Protocols) > 0 && tableHasBothFamilies(t) {
				return errors.New("dual-stack BIRD requires ipv4_protocols and ipv6_protocols for independent withdrawal")
			}
			if len(c.Bird.Protocols) == 0 && ((v4 && len(c.Bird.IPv4Protocols) == 0) || (!v4 && len(c.Bird.IPv6Protocols) == 0)) {
				return errors.New("missing BIRD protocol binding for an assigned address family")
			}
		}
		for _, raw := range []string{a.PrimaryVIP, a.SecondaryVIP} {
			ip := netip.MustParseAddr(raw)
			for _, p := range c.Allowed {
				if p.Contains(ip) {
					return fmt.Errorf("VIP %s overlaps backend_prefixes; restrict prefixes to IPAM allocation ranges", ip)
				}
			}
		}
	}
	for _, b := range t.Backends {
		for _, raw := range []string{b.IPv4, b.IPv6} {
			if ip, err := netip.ParseAddr(raw); err == nil && !c.Allows(ip) {
				return fmt.Errorf("backend %s address %s outside permitted allocation ranges", b.ID, ip)
			}
		}
	}
	return nil
}

func tableHasBothFamilies(t control.Table) bool {
	v4, v6 := false, false
	for _, a := range t.Assignments {
		if mustIP(a.Source).Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4 && v6
}
