// SPDX-License-Identifier: GPL-2.0
package control

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"sort"
	"testing"
)

func testPlan(n int) Plan {
	p := Plan{Version: 1, Generation: 1, Backends: []Backend{{"be-0", "192.0.2.130", "2001:db8:1::82", 8080}, {"be-1", "192.0.2.131", "2001:db8:1::83", 8080}, {"be-2", "192.0.2.132", "2001:db8:1::84", 8080}}, VIPs: []Pair{{"192.0.2.10", "192.0.2.11"}, {"2001:db8:1::a", "2001:db8:1::b"}}}
	for i := 0; i < n; i++ {
		p.Clients = append(p.Clients, Client{fmt.Sprintf("client-%02d", i), []string{fmt.Sprintf("198.51.100.%d", i+1), fmt.Sprintf("2001:db8:2::%x", i+1)}})
	}
	return p
}

func testTable(t *testing.T) Table {
	t.Helper()
	table, err := Generate(testPlan(20))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func TestMapEncoding(t *testing.T) {
	k, err := MakeKey(netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := binary.Append(nil, binary.NativeEndian, k)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 36 || !reflect.DeepEqual(b[:8], []byte{4, 0, 0, 0, 198, 51, 100, 7}) || !reflect.DeepEqual(b[20:24], []byte{192, 0, 2, 10}) {
		t.Fatalf("wrong C key bytes: %x", b)
	}
	for _, i := range append(append([]int{}, rangeInts(8, 20)...), rangeInts(24, 36)...) {
		if b[i] != 0 {
			t.Fatalf("nonzero padding at %d", i)
		}
	}
	d, _ := binary.Append(nil, binary.NativeEndian, Dest{MAC: [6]uint8{2, 1, 2, 3, 4, 5}, Flags: Active})
	if !reflect.DeepEqual(d, []byte{2, 1, 2, 3, 4, 5, 1, 0}) {
		t.Fatalf("wrong value: %x", d)
	}
	v6, _ := MakeKey(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"))
	if v6.Family != 6 || v6.Source != netip.MustParseAddr("2001:db8::1").As16() {
		t.Fatal("IPv6 layout")
	}
}
func rangeInts(a, b int) []int {
	var out []int
	for i := a; i < b; i++ {
		out = append(out, i)
	}
	return out
}

func TestMaglevSlotBalanceAndOrderIndependence(t *testing.T) {
	for n := 1; n <= 20; n++ {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("be-%d", i)
		}
		a, err := Maglev(ids)
		if err != nil {
			t.Fatal(err)
		}
		counts := make(map[string]int)
		for _, id := range a {
			counts[id]++
		}
		for _, id := range ids {
			if counts[id] != MaglevSize/n && counts[id] != MaglevSize/n+1 {
				t.Fatalf("n=%d counts=%v", n, counts)
			}
		}
		rand.New(rand.NewSource(int64(n))).Shuffle(n, func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
		b, _ := Maglev(ids)
		if !reflect.DeepEqual(a, b) {
			t.Fatal("input order affects Maglev")
		}
	}
}

func TestGenerateBalancesFiniteClientsAndSeparatesPairs(t *testing.T) {
	for n := 1; n <= 25; n++ {
		p := testPlan(n)
		table, err := Generate(p)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		groups := map[string]map[string]int{}
		bySource := map[string]Assignment{}
		for _, a := range table.Assignments {
			if a.PrimaryBackend == a.SecondaryBackend {
				t.Fatal("pair overlap")
			}
			if !netip.MustParseAddr(a.Source).Is4() {
				continue
			}
			counts[a.PrimaryBackend]++
			if groups[a.PrimaryBackend] == nil {
				groups[a.PrimaryBackend] = map[string]int{}
			}
			groups[a.PrimaryBackend][a.SecondaryBackend]++
			bySource[a.Source] = a
		}
		for _, b := range p.Backends {
			if counts[b.ID] != n/3 && counts[b.ID] != n/3+1 {
				t.Fatalf("n=%d primary counts=%v", n, counts)
			}
		}
		for primary, g := range groups {
			values := []int{}
			for _, b := range p.Backends {
				if b.ID != primary {
					values = append(values, g[b.ID])
				}
			}
			sort.Ints(values)
			if values[len(values)-1]-values[0] > 1 {
				t.Fatalf("secondary group imbalance: %v", groups)
			}
		}
		// Matching v4/v6 clients must use the same IDs, despite DNS/IP changes.
		for _, c := range p.Clients {
			var pair []Assignment
			for _, a := range table.Assignments {
				if a.Source == c.Addresses[0] || a.Source == c.Addresses[1] {
					pair = append(pair, a)
				}
			}
			if len(pair) != 2 || pair[0].PrimaryBackend != pair[1].PrimaryBackend || pair[0].SecondaryBackend != pair[1].SecondaryBackend {
				t.Fatal("dual-stack assignment drift")
			}
		}
		rand.New(rand.NewSource(int64(n))).Shuffle(len(p.Backends), func(i, j int) { p.Backends[i], p.Backends[j] = p.Backends[j], p.Backends[i] })
		p.Clients[0].Addresses[0], p.Clients[0].Addresses[1] = p.Clients[0].Addresses[1], p.Clients[0].Addresses[0]
		p.Clients[0], p.Clients[len(p.Clients)-1] = p.Clients[len(p.Clients)-1], p.Clients[0]
		p.VIPs[0], p.VIPs[1] = p.VIPs[1], p.VIPs[0]
		other, err := Generate(p)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(table)
		b, _ := json.Marshal(other)
		if string(a) != string(b) {
			t.Fatal("generation depends on input order")
		}
	}
}

func allEndpoints(table Table) map[EndpointKey]Endpoint {
	out := map[EndpointKey]Endpoint{}
	for i, b := range table.Backends {
		out[EndpointKey{b.ID, 4}] = Endpoint{netip.MustParseAddr(b.IPv4), [6]uint8{2, 0, 0, 0, 0, uint8(i + 1)}, true}
		out[EndpointKey{b.ID, 6}] = Endpoint{netip.MustParseAddr(b.IPv6), [6]uint8{2, 0, 0, 0, 0, uint8(i + 1)}, true}
	}
	return out
}

func TestFallbackKeepsUnaffectedAssignments(t *testing.T) {
	table := testTable(t)
	endpoints := allEndpoints(table)
	baseline, baseDecisions := Desired(table, endpoints)
	for _, failure := range table.Backends {
		failed := allEndpoints(table)
		for _, family := range []uint8{4, 6} {
			k := EndpointKey{failure.ID, family}
			e := failed[k]
			e.Healthy = false
			failed[k] = e
		}
		got, decisions := Desired(table, failed)
		for i, d := range decisions {
			if !d.Active || d.Backend == failure.ID {
				t.Fatal("failed backend selected")
			}
			if baseDecisions[i].Backend != failure.ID && d.Backend != baseDecisions[i].Backend {
				t.Fatalf("healthy baseline moved: %+v -> %+v", baseDecisions[i], d)
			}
			if i%2 == 1 && d.Backend == decisions[i-1].Backend {
				t.Fatal("fallback primary/secondary overlap")
			}
		}
		reversed := table
		reversed.Backends = append([]Backend(nil), table.Backends...)
		sort.Slice(reversed.Backends, func(i, j int) bool { return reversed.Backends[i].ID > reversed.Backends[j].ID })
		other, _ := Desired(reversed, failed)
		if !reflect.DeepEqual(got, other) {
			t.Fatal("fallback order dependence")
		}
	}
	recovered, _ := Desired(table, endpoints)
	if !reflect.DeepEqual(baseline, recovered) {
		t.Fatal("recovery did not restore baseline")
	}
}

func TestOnlyOneOrNoSurvivingBackend(t *testing.T) {
	table := testTable(t)
	ep := allEndpoints(table)
	for k, e := range ep {
		e.Healthy = k.Backend == "be-1"
		ep[k] = e
	}
	_, ds := Desired(table, ep)
	for i := 0; i < len(ds); i += 2 {
		if ds[i].Active == ds[i+1].Active {
			t.Fatal("with one live backend exactly one side must be inactive")
		}
		if ds[i].Active && ds[i].Backend != "be-1" || ds[i+1].Active && ds[i+1].Backend != "be-1" {
			t.Fatal("wrong survivor")
		}
	}
	for k, e := range ep {
		e.Healthy = false
		ep[k] = e
	}
	m, _ := Desired(table, ep)
	for _, d := range m {
		if d != (Dest{}) {
			t.Fatal("all failed must drop")
		}
	}
}

func TestHysteresis(t *testing.T) {
	h := Health{}
	for _, ok := range []bool{true, false, true} {
		h.Observe(ok, 2, 3)
		if h.Healthy {
			t.Fatal("premature rise")
		}
	}
	h.Observe(true, 2, 3)
	if !h.Healthy {
		t.Fatal("did not rise")
	}
	for range 2 {
		h.Observe(false, 2, 3)
		if !h.Healthy {
			t.Fatal("premature fall")
		}
	}
	h.Observe(true, 2, 3)
	h.Observe(false, 2, 3)
	h.Observe(false, 2, 3)
	if !h.Healthy {
		t.Fatal("success did not reset failures")
	}
	h.Observe(false, 2, 3)
	if h.Healthy {
		t.Fatal("did not fall")
	}
}

type fakeMap struct {
	entries map[Key]Dest
	puts    int
	fail    bool
}

func (f *fakeMap) Entries() (map[Key]Dest, error) {
	out := map[Key]Dest{}
	for k, v := range f.entries {
		out[k] = v
	}
	return out, nil
}
func (f *fakeMap) Put(k Key, v Dest) error {
	f.puts++
	if f.fail {
		return errors.New("injected update failure")
	}
	f.entries[k] = v
	return nil
}

func TestMapSyncTombstonesAndCapacity(t *testing.T) {
	table := testTable(t)
	want, _ := Desired(table, allEndpoints(table))
	f := &fakeMap{entries: map[Key]Dest{}}
	if err := Sync(f, want); err != nil {
		t.Fatal(err)
	}
	f.puts = 0
	if err := Sync(f, want); err != nil || f.puts != 0 {
		t.Fatal("unchanged map should not be written")
	}
	var removed Key
	for k := range want {
		removed = k
		delete(want, k)
		break
	}
	if err := Sync(f, want); err != nil {
		t.Fatal(err)
	}
	if d, ok := f.entries[removed]; !ok || d != (Dest{}) {
		t.Fatal("removed assignment must be an inactive tombstone")
	}
	f.fail = true
	want[removed] = Dest{Flags: Active}
	if err := Sync(f, want); err == nil {
		t.Fatal("lost update failure")
	}
	f = &fakeMap{entries: map[Key]Dest{}}
	for i := 0; i < MaxAssignments; i++ {
		var k Key
		binary.BigEndian.PutUint32(k.Source[:4], uint32(i))
		f.entries[k] = Dest{Flags: Active}
	}
	if err := Sync(f, map[Key]Dest{{Family: 6}: {Flags: Active}}); err == nil || f.puts != 0 {
		t.Fatal("capacity failure must be detected before mutations")
	}
}

func TestRejectMalformedTables(t *testing.T) {
	mutations := map[string]func(*Table){
		"zero generation":   func(x *Table) { x.Generation = 0 },
		"unknown version":   func(x *Table) { x.Version = 2 },
		"pair overlap":      func(x *Table) { x.Assignments[0].SecondaryBackend = x.Assignments[0].PrimaryBackend },
		"unknown backend":   func(x *Table) { x.Assignments[0].PrimaryBackend = "absent" },
		"duplicate key":     func(x *Table) { x.Assignments = append(x.Assignments, x.Assignments[0]) },
		"family mismatch":   func(x *Table) { x.Assignments[0].PrimaryVIP = "2001:db8::1" },
		"mapped IPv4":       func(x *Table) { x.Assignments[0].Source = "::ffff:198.51.100.7" },
		"multicast":         func(x *Table) { x.Assignments[0].Source = "ff02::1" },
		"duplicate backend": func(x *Table) { x.Backends[1] = x.Backends[0] },
		"bad DNS":           func(x *Table) { x.Backends[0].IPv4 = "bad/name" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := testTable(t)
			mutate(&x)
			if x.Validate() == nil {
				t.Fatal("accepted invalid table")
			}
		})
	}
}
