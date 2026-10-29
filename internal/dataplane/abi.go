// SPDX-License-Identifier: GPL-2.0
package dataplane

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

var StatNames = []string{"rx", "redirect", "miss", "not_ip", "proto_other", "inactive", "malformed", "store_fail", "vlan", "exthdr", "exthdr_deep", "frag_later", "nd"}

// ValidateSpec checks both sizes and member offsets against the actual ELF
// BTF, so a same-sized C layout change cannot silently corrupt Go map keys.
func ValidateSpec(s *ebpf.CollectionSpec) error {
	assign, stats := s.Maps["lb_assign"], s.Maps["lb_stats"]
	if assign == nil || assign.Type != ebpf.Hash || assign.KeySize != uint32(unsafe.Sizeof(control.Key{})) || assign.ValueSize != uint32(unsafe.Sizeof(control.Dest{})) || assign.MaxEntries != control.MaxAssignments {
		return fmt.Errorf("incompatible lb_assign ABI")
	}
	if stats == nil || stats.Type != ebpf.PerCPUArray || stats.KeySize != 4 || stats.ValueSize != 8 || stats.MaxEntries != uint32(len(StatNames)) {
		return fmt.Errorf("incompatible lb_stats ABI")
	}
	for _, layout := range []struct {
		typ     btf.Type
		name    string
		members []string
		offsets []uint32
	}{{assign.Key, "lb_key", []string{"family", "pad", "saddr", "daddr"}, []uint32{0, 8, 32, 160}}, {assign.Value, "lb_dest", []string{"mac", "flags", "pad"}, []uint32{0, 48, 56}}} {
		st, ok := btf.UnderlyingType(layout.typ).(*btf.Struct)
		if !ok || st.Name != layout.name || len(st.Members) != len(layout.members) {
			return fmt.Errorf("missing BTF layout for %s", layout.name)
		}
		for i, m := range st.Members {
			if m.Name != layout.members[i] || uint32(m.Offset) != layout.offsets[i] {
				return fmt.Errorf("incompatible %s.%s offset", layout.name, m.Name)
			}
		}
	}
	p := s.Programs["lb_ingress"]
	if p == nil || p.Type != ebpf.SchedCLS {
		return fmt.Errorf("missing SchedCLS lb_ingress")
	}
	return nil
}
