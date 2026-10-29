// SPDX-License-Identifier: GPL-2.0
package agent

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

type observationProber struct {
	mode, backend string
	family        uint8
	live          map[control.EndpointKey]bool
}

func (p *observationProber) Probe(ctx context.Context, b control.Backend, f uint8, prev control.Endpoint) ProbeResult {
	r := (&fakeProber{}).Probe(ctx, b, f, prev)
	if p.live != nil {
		r.OK = p.live[control.EndpointKey{Backend: b.ID, Family: f}]
	}
	if b.ID != p.backend || f != p.family {
		return r
	}
	switch p.mode {
	case "missing-mac":
		r.Endpoint.MAC = [6]uint8{}
		r.OK = false
	case "missing-ip":
		r.Endpoint = control.Endpoint{}
		r.OK = false
	case "unsafe":
		r.Endpoint.MAC = [6]uint8{}
		r.OK = false
		r.Invalidate = true
	case "new-ip-missing-mac":
		r.Endpoint.IP = netip.MustParseAddr("192.0.2.190")
		r.Endpoint.MAC = [6]uint8{}
		r.OK = false
	}
	return r
}

func backendHealthy(e *Engine, id string, f uint8) bool {
	for _, b := range e.Snapshot().Backends {
		if b.Backend == id && b.Family == f {
			return b.Healthy
		}
	}
	return false
}

func TestTransientEndpointReadsHonorFallAndRecovery(t *testing.T) {
	for _, mode := range []string{"missing-mac", "missing-ip"} {
		t.Run(mode, func(t *testing.T) {
			c, table := fixture(t)
			trace := []string{}
			plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
			bird := &recordingBird{trace: &trace}
			probe := &observationProber{backend: "be-0", family: 4}
			e := &Engine{Config: c, Plane: plane, Prober: probe, Bird: bird}
			cycle := func() {
				t.Helper()
				if err := e.Reconcile(context.Background(), table); err != nil {
					t.Fatal(err)
				}
			}
			cycle()
			cycle()
			baseline, _ := plane.Entries()
			probe.mode = mode
			for range 2 {
				cycle()
				if !backendHealthy(e, "be-0", 4) {
					t.Fatal("transient read bypassed fall")
				}
				if !reflect.DeepEqual(baseline, plane.values) {
					t.Fatal("transient read changed flow assignment")
				}
			}
			cycle()
			if backendHealthy(e, "be-0", 4) {
				t.Fatal("did not fall after threshold")
			}
			if reflect.DeepEqual(baseline, plane.values) {
				t.Fatal("did not reassign after fall")
			}
			probe.mode = ""
			cycle()
			if backendHealthy(e, "be-0", 4) {
				t.Fatal("recovered before rise")
			}
			cycle()
			if !backendHealthy(e, "be-0", 4) || !reflect.DeepEqual(baseline, plane.values) {
				t.Fatal("recovery did not restore baseline")
			}
		})
	}
}

func TestUnsafeOrReplacedEndpointCannotReuseHealthyCache(t *testing.T) {
	for _, mode := range []string{"unsafe", "new-ip-missing-mac"} {
		t.Run(mode, func(t *testing.T) {
			c, table := fixture(t)
			trace := []string{}
			plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
			probe := &observationProber{backend: "be-0", family: 4}
			e := &Engine{Config: c, Plane: plane, Prober: probe, Bird: &recordingBird{trace: &trace}}
			for range 2 {
				if err := e.Reconcile(context.Background(), table); err != nil {
					t.Fatal(err)
				}
			}
			probe.mode = mode
			if err := e.Reconcile(context.Background(), table); err != nil {
				t.Fatal(err)
			}
			if backendHealthy(e, "be-0", 4) {
				t.Fatal("unsafe/replaced endpoint inherited cached healthy state")
			}
		})
	}
}

func TestSingleSurvivorKeepsServiceAndSeparation(t *testing.T) {
	c, table := fixture(t)
	c.Health.Rise = 1
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	bird := &recordingBird{trace: &trace}
	survivor := table.Assignments[0].SecondaryBackend
	probe := &observationProber{live: map[control.EndpointKey]bool{{Backend: survivor, Family: 4}: true, {Backend: survivor, Family: 6}: true}}
	e := &Engine{Config: c, Plane: plane, Prober: probe, Bird: bird}
	if err := e.Reconcile(context.Background(), table); err != nil {
		t.Fatal(err)
	}
	s := e.Snapshot()
	if !s.Ready || !s.Degraded || !bird.on || !bird.families[4] || !bird.families[6] {
		t.Fatal("single survivor must keep family advertisements and report degraded")
	}
	for i := 0; i < len(s.Decisions); i += 2 {
		p, q := s.Decisions[i], s.Decisions[i+1]
		if p.Active == q.Active {
			t.Fatal("exactly one paired path should remain active")
		}
		if p.Active && p.Backend != survivor || q.Active && q.Backend != survivor {
			t.Fatal("dead backend selected")
		}
	}
	if s.Decisions[0].Active || !s.Decisions[1].Active {
		t.Fatal("healthy baseline secondary moved")
	}
	probe.live = map[control.EndpointKey]bool{}
	for range c.Health.Fall {
		if err := e.Reconcile(context.Background(), table); err != nil {
			t.Fatal(err)
		}
	}
	if e.Snapshot().Ready || bird.on {
		t.Fatal("zero survivors must withdraw")
	}
}

func TestAddressFamilyAvailabilityIsIndependent(t *testing.T) {
	c, table := fixture(t)
	c.Health.Rise = 1
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	bird := &recordingBird{trace: &trace}
	probe := &observationProber{live: map[control.EndpointKey]bool{{Backend: "be-0", Family: 6}: true}}
	e := &Engine{Config: c, Plane: plane, Prober: probe, Bird: bird}
	if err := e.Reconcile(context.Background(), table); err != nil {
		t.Fatal(err)
	}
	if !e.Snapshot().Ready || bird.families[4] || !bird.families[6] {
		t.Fatal("IPv4 failure must not withdraw usable IPv6 or advertise IPv4")
	}
	c.Bird = BirdConfig{Socket: "/run/bird.ctl", Protocols: []string{"legacy"}}
	if c.ValidateTable(table) == nil {
		t.Fatal("ambiguous dual-stack BIRD bindings accepted")
	}
	c.Bird = BirdConfig{Socket: "/run/bird.ctl", IPv4Protocols: []string{"v4"}, IPv6Protocols: []string{"v6"}}
	if err := c.ValidateTable(table); err != nil {
		t.Fatal(err)
	}
}
