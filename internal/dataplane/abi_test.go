// SPDX-License-Identifier: GPL-2.0
package dataplane

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestActualELFABI(t *testing.T) {
	object := "../../bpf/lb_kern.o"
	if override := os.Getenv("LB_TEST_OBJECT"); override != "" {
		object = override
	}
	if _, err := os.Stat(object); os.IsNotExist(err) {
		t.Skip("build existing C object with make first")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSpec(spec); err != nil {
		t.Fatal(err)
	}
	// Offset-only changes must fail even when sizeof(lb_key) is unchanged.
	s := spec.Copy()
	st := btf.UnderlyingType(s.Maps["lb_assign"].Key).(*btf.Struct)
	st.Members[2].Offset += 8
	if ValidateSpec(s) == nil {
		t.Fatal("same-size C ABI mismatch was not detected")
	}
	s = spec.Copy()
	s.Maps["lb_stats"].MaxEntries--
	if ValidateSpec(s) == nil {
		t.Fatal("stat index mismatch accepted")
	}
}
