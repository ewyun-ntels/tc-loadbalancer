// SPDX-License-Identifier: GPL-2.0
//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const filterName = "tc_lb_agent"
const filterPriority = 49152
const filterHandle = 1

type Plane struct {
	assign, stats *ebpf.Map
	program       *ebpf.Program
	iface         netlink.Link
	lock          *os.File
}

// Open never deletes a qdisc or a pin. Dedicated pins are reused only when
// their ABI and program's referenced map IDs agree with the requested ELF.
func Open(iface, object, pins, lockFile string) (p *Plane, err error) {
	p = &Plane{}
	opened := p
	defer func() {
		if err != nil {
			opened.release()
		}
	}()
	p.iface, err = netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	if len(p.iface.Attrs().HardwareAddr) != 6 {
		return nil, fmt.Errorf("interface %s must be Ethernet", iface)
	}
	p.lock, err = os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(p.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("another agent owns %s: %w", iface, err)
	}
	if err = os.MkdirAll(pins, 0750); err != nil {
		return nil, err
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(pins, &fs); err != nil {
		return nil, err
	}
	if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return nil, errors.New("pin_path must be on a mounted bpffs")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, err
	}
	if err = ValidateSpec(spec); err != nil {
		return nil, err
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	programPath := filepath.Join(pins, "lb_ingress")
	if _, statErr := os.Stat(programPath); statErr == nil {
		p.assign, err = ebpf.LoadPinnedMap(filepath.Join(pins, "lb_assign"), nil)
		if err != nil {
			return nil, err
		}
		p.stats, err = ebpf.LoadPinnedMap(filepath.Join(pins, "lb_stats"), nil)
		if err != nil {
			return nil, err
		}
		if err = spec.Maps["lb_assign"].Compatible(p.assign); err != nil {
			return nil, err
		}
		if err = spec.Maps["lb_stats"].Compatible(p.stats); err != nil {
			return nil, err
		}
		p.program, err = ebpf.LoadPinnedProgram(programPath, nil)
		if err != nil {
			return nil, err
		}
		info, infoErr := p.program.Info()
		if infoErr != nil {
			return nil, infoErr
		}
		// ELF instructions still contain relocations/fixups. Compare against
		// an unattached candidate loaded by the same library/kernel, rather
		// than hashing the unrelocated ELF instruction stream directly.
		candidate, loadErr := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"lb_assign": p.assign, "lb_stats": p.stats}})
		if loadErr != nil {
			return nil, loadErr
		}
		defer candidate.Close()
		expected, infoErr := candidate.Programs["lb_ingress"].Info()
		if infoErr != nil {
			return nil, infoErr
		}
		if info.Type != ebpf.SchedCLS || info.Tag != expected.Tag {
			return nil, errors.New("pinned program differs from ELF; withdraw VIPs and perform an explicit pin/program upgrade")
		}
		ids, ok := info.MapIDs()
		if !ok || len(ids) != 2 {
			return nil, errors.New("cannot verify pinned program map IDs")
		}
		for _, m := range []*ebpf.Map{p.assign, p.stats} {
			mi, err := m.Info()
			if err != nil {
				return nil, err
			}
			id, ok := mi.ID()
			if !ok || (ids[0] != id && ids[1] != id) {
				return nil, errors.New("pinned program refers to different maps")
			}
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		collection, loadErr := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pins}})
		if loadErr != nil {
			return nil, loadErr
		}
		defer collection.Close()
		p.assign = collection.DetachMap("lb_assign")
		p.stats = collection.DetachMap("lb_stats")
		p.program = collection.DetachProgram("lb_ingress")
		if err = p.program.Pin(programPath); err != nil {
			return nil, err
		}
	} else {
		return nil, statErr
	}
	return p, nil
}

func (p *Plane) Entries() (map[control.Key]control.Dest, error) {
	entries := make(map[control.Key]control.Dest)
	iter := p.assign.Iterate()
	var k control.Key
	var d control.Dest
	for iter.Next(&k, &d) {
		entries[k] = d
	}
	return entries, iter.Err()
}

func (p *Plane) Put(k control.Key, d control.Dest) error {
	return p.assign.Update(k, d, ebpf.UpdateAny)
}

func (p *Plane) filter() *netlink.BpfFilter {
	return &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: p.iface.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Handle: filterHandle, Priority: filterPriority, Protocol: unix.ETH_P_ALL}, Fd: p.program.FD(), Name: filterName, DirectAction: true}
}

func (p *Plane) owned(f netlink.Filter) bool {
	b, ok := f.(*netlink.BpfFilter)
	if !ok {
		return false
	}
	info, err := p.program.Info()
	if err != nil {
		return false
	}
	id, ok := info.ID()
	return ok && b.Name == filterName && b.LinkIndex == p.iface.Attrs().Index && b.Parent == netlink.HANDLE_MIN_INGRESS && b.Handle == filterHandle && b.Priority == filterPriority && b.Protocol == unix.ETH_P_ALL && b.Id == int(id) && b.DirectAction && (b.Chain == nil || *b.Chain == 0)
}

// currentInterface refuses to adopt a different device that happens to reuse
// the configured name. The loader/prober must be restarted for a new ifindex.
// MAC changes alone are allowed, e.g. a bond failover policy may change MAC.
func (p *Plane) currentInterface() (netlink.Link, error) {
	current, err := netlink.LinkByName(p.iface.Attrs().Name)
	if err != nil {
		return nil, fmt.Errorf("TC interface lookup: %w", err)
	}
	if current.Attrs().Index != p.iface.Attrs().Index || current.Type() != p.iface.Type() {
		return nil, fmt.Errorf("TC interface %s changed identity (ifindex %d -> %d); restart agent", p.iface.Attrs().Name, p.iface.Attrs().Index, current.Attrs().Index)
	}
	return current, nil
}

func (p *Plane) checkFilters(iface netlink.Link) (bool, error) {
	filters, err := netlink.FilterList(iface, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, err
	}
	found := false
	for _, f := range filters {
		if !p.owned(f) {
			return false, fmt.Errorf("refusing to replace/share existing ingress filter: %s", f.Attrs())
		}
		found = true
	}
	return found, nil
}

// Attach ensures the actual owned filter exists. It never trusts a cached
// attachment flag, replaces a foreign filter, or deletes a shared qdisc.
func (p *Plane) Attach() error {
	iface, err := p.currentInterface()
	if err != nil {
		return err
	}
	q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: iface.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
	if err := netlink.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	found, err := p.checkFilters(iface)
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	if err := netlink.FilterAdd(p.filter()); err != nil {
		return err
	}
	// Confirm the installed program ID/protocol before allowing advertisement.
	found, err = p.checkFilters(iface)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("owned TC filter missing after attachment")
	}
	return nil
}

func (p *Plane) Stats() (map[string]uint64, error) {
	out := make(map[string]uint64, len(StatNames))
	for i, name := range StatNames {
		key := uint32(i)
		var values []uint64
		if err := p.stats.Lookup(key, &values); err != nil {
			return nil, err
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		out[name] = sum
	}
	return out, nil
}

func (p *Plane) Close() error {
	defer p.release()
	// The device may already be gone. Find the original ifindex and only
	// remove a filter whose full ownership still matches this program.
	iface, err := netlink.LinkByIndex(p.iface.Attrs().Index)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	}
	filters, err := netlink.FilterList(iface, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}
	for _, f := range filters {
		if p.owned(f) {
			if err := netlink.FilterDel(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Plane) release() {
	if p.assign != nil {
		p.assign.Close()
	}
	if p.stats != nil {
		p.stats.Close()
	}
	if p.program != nil {
		p.program.Close()
	}
	if p.lock != nil {
		p.lock.Close()
	}
	// clsact, lock file, and only our pinned maps/program survive for restart.
}
