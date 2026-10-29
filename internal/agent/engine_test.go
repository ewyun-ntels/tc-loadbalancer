// SPDX-License-Identifier: GPL-2.0
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

func fixture(t *testing.T) (Config, control.Table) {
	t.Helper()
	c, err := LoadConfig("../../configs/agent.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var plan control.Plan
	if err := control.DecodeFile("../../configs/plan.example.json", &plan); err != nil {
		t.Fatal(err)
	}
	table, err := control.Generate(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Explicitly exercise configurable multi-success hysteresis, independent of the default.
	c.Health.Rise = 2
	return c, table
}

type memoryPlane struct {
	values    map[control.Key]control.Dest
	attached  bool
	fail      bool
	attachErr error
	trace     *[]string
}

func (m *memoryPlane) Entries() (map[control.Key]control.Dest, error) {
	out := map[control.Key]control.Dest{}
	for k, v := range m.values {
		out[k] = v
	}
	return out, nil
}
func (m *memoryPlane) Put(k control.Key, d control.Dest) error {
	if m.fail {
		return errors.New("map failure")
	}
	m.values[k] = d
	return nil
}
func (m *memoryPlane) Attach() error {
	*m.trace = append(*m.trace, "attach")
	if m.attachErr != nil {
		return m.attachErr
	}
	if len(m.values) == 0 {
		return errors.New("attached before populated")
	}
	m.attached = true
	return nil
}
func (m *memoryPlane) Close() error { return nil }
func (m *memoryPlane) Stats() (map[string]uint64, error) {
	return map[string]uint64{"rx": 13, "redirect": 11}, nil
}

type recordingBird struct {
	on        bool
	trace     *[]string
	beforeSet func(bool)
	families  map[uint8]bool
}

func (b *recordingBird) Set(_ context.Context, on bool) error {
	if b.beforeSet != nil {
		b.beforeSet(on)
	}
	b.on = on
	if on {
		*b.trace = append(*b.trace, "advertise")
	} else {
		*b.trace = append(*b.trace, "withdraw")
	}
	return nil
}

func (b *recordingBird) SetFamilies(ctx context.Context, families map[uint8]bool) error {
	b.families = families
	on := false
	for _, covered := range families {
		on = on || covered
	}
	return b.Set(ctx, on)
}

func TestTCFilterRevalidatedAndRepairedEveryCycle(t *testing.T) {
	c, table := fixture(t)
	c.Health.Rise = 1
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	bird := &recordingBird{trace: &trace}
	e := &Engine{Config: c, Plane: plane, Prober: &fakeProber{}, Bird: bird}
	for cycle := 0; cycle < 3; cycle++ {
		// Model deletion of the actual filter after each successful cycle.
		plane.attached = false
		trace = nil
		if err := e.Reconcile(context.Background(), table); err != nil {
			t.Fatal(err)
		}
		if !plane.attached || !e.Snapshot().Ready || !bird.on {
			t.Fatal("filter was not restored before readiness/advertisement")
		}
		if !reflect.DeepEqual(trace, []string{"attach", "advertise"}) {
			t.Fatalf("cycle %d order: %v", cycle, trace)
		}
	}
}

func TestTCValidationFailureWithdrawsAndRecovers(t *testing.T) {
	c, table := fixture(t)
	c.Health.Rise = 1
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	bird := &recordingBird{trace: &trace}
	e := &Engine{Config: c, Plane: plane, Prober: &fakeProber{}, Bird: bird}
	if err := e.Reconcile(context.Background(), table); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"foreign ingress filter", "interface changed identity", "filter add permission denied"} {
		trace = nil
		plane.attached = false
		plane.attachErr = errors.New(failure)
		bird.beforeSet = func(on bool) {
			if on {
				t.Fatal("advertised after TC validation failure")
			}
			if e.Snapshot().Ready {
				t.Fatal("readiness remained green during withdrawal")
			}
		}
		if err := e.Reconcile(context.Background(), table); err == nil || !strings.Contains(err.Error(), failure) {
			t.Fatalf("lost TC validation error: %v", err)
		}
		if e.Snapshot().Ready || bird.on {
			t.Fatal("TC failure must withdraw and fail readiness")
		}
		if !reflect.DeepEqual(trace, []string{"attach", "withdraw"}) {
			t.Fatalf("failure order: %v", trace)
		}
		w := httptest.NewRecorder()
		e.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		if w.Code != 503 {
			t.Fatal("TC failure hidden by readiness")
		}
		bird.beforeSet = nil
		plane.attachErr = nil
		if err := e.Reconcile(context.Background(), table); err != nil {
			t.Fatal(err)
		}
		if !plane.attached || !e.Snapshot().Ready || !bird.on {
			t.Fatal("did not recover after successful TC validation")
		}
	}
}

type fakeProber struct {
	fail        bool
	replacement bool
	duplicate   bool
}

func (p *fakeProber) Probe(_ context.Context, b control.Backend, family uint8, _ control.Endpoint) ProbeResult {
	last := b.ID[len(b.ID)-1] - '0' + 1
	host := b.IPv4
	if family == 6 {
		host = b.IPv6
	}
	if p.duplicate {
		last = 1
		host = "192.0.2.130"
		if family == 6 {
			host = "2001:db8:1::82"
		}
	}
	mac := [6]uint8{2, 0, 0, 0, 0, last}
	if p.replacement {
		mac[4] = 1
	}
	return ProbeResult{Endpoint: control.Endpoint{IP: netip.MustParseAddr(host), MAC: mac}, OK: !p.fail}
}

func TestEngineLifecycleMapFailureAndReplacement(t *testing.T) {
	c, table := fixture(t)
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	bird := &recordingBird{trace: &trace}
	probe := &fakeProber{}
	e := &Engine{Config: c, Plane: plane, Prober: probe, Bird: bird}
	ctx := context.Background()
	if err := e.Reconcile(ctx, table); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Ready || bird.on || !plane.attached {
		t.Fatal("startup should attach populated inactive map before rise threshold")
	}
	if err := e.Reconcile(ctx, table); err != nil {
		t.Fatal(err)
	}
	if !e.Snapshot().Ready || !bird.on {
		t.Fatal("not ready after two successes")
	}
	if strings.Index(strings.Join(trace, ","), "attach") > strings.Index(strings.Join(trace, ","), "advertise") {
		t.Fatal("advertised before attaching")
	}
	probe.fail = true
	for range 2 {
		if err := e.Reconcile(ctx, table); err != nil {
			t.Fatal(err)
		}
		if !e.Snapshot().Ready {
			t.Fatal("fell before three failures")
		}
	}
	if err := e.Reconcile(ctx, table); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Ready || bird.on {
		t.Fatal("did not withdraw on complete backend failure")
	}
	for _, d := range plane.values {
		if d.Flags != 0 {
			t.Fatal("failed destinations left active")
		}
	}
	probe.fail = false
	for range 2 {
		if err := e.Reconcile(ctx, table); err != nil {
			t.Fatal(err)
		}
	}
	probe.replacement = true
	if err := e.Reconcile(ctx, table); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Ready {
		t.Fatal("replacement MAC inherited healthy state")
	}
	if err := e.Reconcile(ctx, table); err != nil {
		t.Fatal(err)
	}
	probe.fail = true
	for range 2 {
		if err := e.Reconcile(ctx, table); err != nil {
			t.Fatal(err)
		}
	}
	plane.fail = true
	if err := e.Reconcile(ctx, table); err == nil {
		t.Fatal("map error ignored")
	}
	if bird.on || e.Snapshot().Ready {
		t.Fatal("map failure must withdraw and fail readiness")
	}
	request := httptest.NewRequest("GET", "/readyz", nil)
	response := httptest.NewRecorder()
	e.Handler().ServeHTTP(response, request)
	if response.Code != 503 {
		t.Fatal("readiness hid error")
	}
}

func TestDuplicatePhysicalBackendRejected(t *testing.T) {
	c, table := fixture(t)
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	bird := &recordingBird{trace: &trace}
	probe := &fakeProber{duplicate: true}
	c.Health.Rise = 1
	e := &Engine{Config: c, Plane: plane, Prober: probe, Bird: bird}
	if err := e.Reconcile(context.Background(), table); err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("duplicate endpoints accepted: %v", err)
	}
	if bird.on || len(plane.values) != 0 {
		t.Fatal("invalid endpoints were applied")
	}
}

func TestReloadRetainsKnownGoodOnInvalidMissingAndRollback(t *testing.T) {
	c, table := fixture(t)
	path := filepath.Join(t.TempDir(), "table.json")
	write := func(v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(table)
	file := TableFile{}
	if err := file.Reload(path, c); err != nil {
		t.Fatal(err)
	}
	original := file.Table
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if file.Reload(path, c) == nil || !reflect.DeepEqual(file.Table, original) {
		t.Fatal("missing configuration erased table")
	}
	table.Assignments = nil
	write(table)
	if file.Reload(path, c) == nil || !reflect.DeepEqual(file.Table, original) {
		t.Fatal("invalid configuration erased table")
	}
	table = original
	table.Generation = 2
	write(table)
	if err := file.Reload(path, c); err != nil {
		t.Fatal(err)
	}
	table.Generation = 1
	write(table)
	if file.Reload(path, c) == nil || file.Table.Generation != 2 {
		t.Fatal("rollback accepted")
	}
	table.Generation = 2
	table.Backends[0].HealthPort++
	write(table)
	if file.Reload(path, c) == nil {
		t.Fatal("same generation mutation accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if file.Reload(path, c) == nil {
		t.Fatal("unknown fields accepted")
	}
}

func TestConfigGuardsAndReadOnlyMetrics(t *testing.T) {
	c, table := fixture(t)
	if err := c.ValidateTable(table); err != nil {
		t.Fatal(err)
	}
	if c.Allows(netip.MustParseAddr("192.0.2.194")) || c.Allows(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("unsafe backend address permitted")
	}
	table.Backends[0].IPv4 = "192.0.2.10"
	if c.ValidateTable(table) == nil {
		t.Fatal("VIP used as backend")
	}
	trace := []string{}
	e := Engine{Config: c, Plane: &memoryPlane{trace: &trace}, snapshot: Snapshot{Ready: true, Generation: 3, LastSuccess: time.Now(), Backends: []BackendStatus{{Backend: "be-0", Family: 4, Healthy: true}}}}
	w := httptest.NewRecorder()
	e.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `tc_lb_backend_healthy{backend="be-0",family="4"} 1`) || !strings.Contains(w.Body.String(), `tc_lb_packets_total{reason="rx"} 13`) {
		t.Fatal(w.Body.String())
	}
	e.snapshot.LastSuccess = time.Now().Add(-time.Minute)
	w = httptest.NewRecorder()
	e.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatal("stale reconcile was ready")
	}
}

func TestBirdReplies(t *testing.T) {
	if err := checkBirdReply("0001 BIRD 2 ready.\n0000 vip_routes: enabled\n"); err != nil {
		t.Fatal(err)
	}
	for _, reply := range []string{"0001 BIRD 2.14 ready.\n0008-tc_vips4: already disabled\n", "0001 BIRD 2.14 ready.\n0009-tc_vips4: disabled\n", "0001 BIRD 2.14 ready.\n0010-tc_vips4: already enabled\n", "0001 BIRD 2.14 ready.\n0011-tc_vips4: enabled\n"} {
		if err := checkBirdReply(reply); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"0001 BIRD ready\n8003 No such protocol\n", "0001 BIRD ready\n", "garbage"} {
		if checkBirdReply(s) == nil {
			t.Fatalf("accepted BIRD failure: %q", s)
		}
	}
}

func TestBirdExitDuringReconcileCannotPublishReady(t *testing.T) {
	c, table := fixture(t)
	c.Health.Rise = 1
	trace := []string{}
	bird := &recordingBird{trace: &trace}
	e := &Engine{Config: c, Plane: &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}, Prober: &fakeProber{}, Bird: bird}
	e.birdEvent(123, 1, nil)
	bird.beforeSet = func(on bool) {
		if on {
			e.birdEvent(0, 1, errors.New("BIRD died after enable"))
		}
	}
	if err := e.Reconcile(context.Background(), table); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Ready || e.Snapshot().BirdPID != 0 {
		t.Fatal("stale reconcile overwrote BIRD exit readiness")
	}
}

type failingAdvertiser struct{ err error }

func (b failingAdvertiser) Set(context.Context, bool) error                   { return b.err }
func (b failingAdvertiser) SetFamilies(context.Context, map[uint8]bool) error { return b.err }

func TestWithdrawalFailureSignalsBirdTermination(t *testing.T) {
	c, table := fixture(t)
	c.Health.Rise = 1
	trace := []string{}
	controlError := errors.New("control socket unavailable")
	e := &Engine{Config: c, Plane: &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}, Prober: &fakeProber{}, Bird: failingAdvertiser{controlError}}
	err := e.Reconcile(context.Background(), table)
	if !errors.Is(err, errWithdrawalFailed) || !errors.Is(err, controlError) || e.Snapshot().Ready {
		t.Fatalf("withdrawal failure was not propagated: %v", err)
	}
}

func TestOwnedBirdConfiguration(t *testing.T) {
	c, err := LoadConfig("../../configs/agent.bird.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.Bird.Executable != "bird" || c.Bird.PIDFile != "/run/bird/bird.pid" {
		t.Fatal("wrong BIRD process defaults")
	}
	for _, field := range []string{"config_file", "pid_file"} {
		t.Run(field, func(t *testing.T) {
			bad := c
			if field == "config_file" {
				bad.Bird.ConfigFile = "relative.conf"
			} else {
				bad.Bird.PIDFile = "relative.pid"
			}
			file := filepath.Join(t.TempDir(), "agent.json")
			data, _ := json.Marshal(bad)
			if err := os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(file); err == nil {
				t.Fatal("accepted relative BIRD path")
			}
		})
	}
}
