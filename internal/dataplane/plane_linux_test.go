// SPDX-License-Identifier: GPL-2.0
//go:build linux

package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Run only in an explicitly isolated network namespace and a private bpffs:
//
//	unshare --mount --propagation private sh -c \
//	  'mount -t bpf bpf /sys/fs/bpf; unshare --net env LB_TEST_PRIVILEGED=1 ...'
//
// This test does not touch a host NIC, shared qdisc, or existing pinned maps.
func kernelPlane(t *testing.T) (*Plane, netlink.Link) {
	t.Helper()
	if os.Getenv("LB_TEST_PRIVILEGED") != "1" {
		t.Skip("requires opt-in, root, isolated network namespace and bpffs")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged tests require root")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == init {
		t.Fatal("refusing to test in the init network namespace; use unshare --net")
	}
	name := fmt.Sprintf("tcg%d", os.Getpid())
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	actual, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(actual) })
	object := os.Getenv("LB_TEST_OBJECT")
	if object == "" {
		object = "../../bpf/lb_kern.o"
	}
	pins := filepath.Join("/sys/fs/bpf", fmt.Sprintf("tc-lb-filter-test-%d", os.Getpid()))
	if _, err := os.Stat(pins); !os.IsNotExist(err) {
		t.Fatal("test pin directory already exists or is inaccessible")
	}
	p, err := Open(name, object, pins, filepath.Join(t.TempDir(), "agent.lock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
		for _, name := range []string{"lb_ingress", "lb_assign", "lb_stats"} {
			if err := os.Remove(filepath.Join(pins, name)); err != nil {
				t.Errorf("remove test pin: %v", err)
			}
		}
		if err := os.Remove(pins); err != nil {
			t.Errorf("remove test directory: %v", err)
		}
	})
	return p, actual
}

func requireOwned(t *testing.T, p *Plane) netlink.Filter {
	t.Helper()
	filters, err := netlink.FilterList(p.iface, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 || !p.owned(filters[0]) {
		t.Fatalf("expected exactly our filter, got %+v", filters)
	}
	return filters[0]
}

func TestKernelTCFilterRevalidation(t *testing.T) {
	p, iface := kernelPlane(t)
	if err := p.Attach(); err != nil {
		t.Fatal(err)
	}
	initial := requireOwned(t, p).(*netlink.BpfFilter).Id
	if err := p.Attach(); err != nil {
		t.Fatal(err)
	}
	if requireOwned(t, p).(*netlink.BpfFilter).Id != initial {
		t.Fatal("revalidation replaced a healthy program")
	}

	t.Run("removed-filter", func(t *testing.T) {
		if err := netlink.FilterDel(requireOwned(t, p)); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err != nil {
			t.Fatal(err)
		}
		requireOwned(t, p)
	})
	t.Run("removed-qdisc", func(t *testing.T) {
		q := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: iface.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}}
		if err := netlink.QdiscDel(q); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err != nil {
			t.Fatal(err)
		}
		requireOwned(t, p)
	})
	t.Run("foreign-filter", func(t *testing.T) {
		if err := netlink.FilterDel(requireOwned(t, p)); err != nil {
			t.Fatal(err)
		}
		foreign := p.filter()
		foreign.Name = "foreign_test"
		foreign.Handle = 2
		foreign.Priority = 1
		if err := netlink.FilterAdd(foreign); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("foreign filter not rejected: %v", err)
		}
		filters, err := netlink.FilterList(iface, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			t.Fatal(err)
		}
		if len(filters) != 1 || filters[0].(*netlink.BpfFilter).Name != foreign.Name {
			t.Fatal("foreign filter was changed")
		}
		if err := netlink.FilterDel(filters[0]); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err != nil {
			t.Fatal(err)
		}
		requireOwned(t, p)
	})
	t.Run("wrong-protocol", func(t *testing.T) {
		if err := netlink.FilterDel(requireOwned(t, p)); err != nil {
			t.Fatal(err)
		}
		foreign := p.filter()
		foreign.Protocol = unix.ETH_P_IP
		if err := netlink.FilterAdd(foreign); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err == nil {
			t.Fatal("IPv4-only filter accepted as dual-stack attachment")
		}
		if err := netlink.FilterDel(foreign); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err != nil {
			t.Fatal(err)
		}
		requireOwned(t, p)
	})
	t.Run("wrong-program-ID", func(t *testing.T) {
		other, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "foreign_tc", Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		if err := netlink.FilterDel(requireOwned(t, p)); err != nil {
			t.Fatal(err)
		}
		foreign := p.filter()
		foreign.Fd = other.FD()
		if err := netlink.FilterAdd(foreign); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err == nil {
			t.Fatal("foreign program ID accepted as owned")
		}
		if err := netlink.FilterDel(foreign); err != nil {
			t.Fatal(err)
		}
		if err := p.Attach(); err != nil {
			t.Fatal(err)
		}
		requireOwned(t, p)
	})
	t.Run("recreated-interface", func(t *testing.T) {
		if err := netlink.LinkSetName(iface, "old-"+iface.Attrs().Name); err != nil {
			t.Fatal(err)
		}
		replacement := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: p.iface.Attrs().Name}}
		if err := netlink.LinkAdd(replacement); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(replacement)
		if err := p.Attach(); err == nil || !strings.Contains(err.Error(), "changed identity") {
			t.Fatalf("new device silently adopted: %v", err)
		}
		filters, err := netlink.FilterList(replacement, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			t.Fatal(err)
		}
		if len(filters) != 0 {
			t.Fatal("unexpected filter installed on replacement interface")
		}
	})
}

func TestKernelTCMissingInterface(t *testing.T) {
	p, iface := kernelPlane(t)
	if err := p.Attach(); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(iface); err != nil {
		t.Fatal(err)
	}
	if err := p.Attach(); err == nil {
		t.Fatal("missing interface accepted")
	}
}
