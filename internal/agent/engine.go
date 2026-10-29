// SPDX-License-Identifier: GPL-2.0
package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

type ProbeResult struct {
	Endpoint control.Endpoint
	OK       bool
	Detail   string
	// Invalidate means a confirmed unsafe endpoint, not a transient read
	// failure. Never continue forwarding to the cached endpoint in this case.
	Invalidate bool
}
type Prober interface {
	Probe(context.Context, control.Backend, uint8, control.Endpoint) ProbeResult
}
type Plane interface {
	control.Map
	Attach() error
	Stats() (map[string]uint64, error)
	Close() error
}
type Advertiser interface {
	Set(context.Context, bool) error
	SetFamilies(context.Context, map[uint8]bool) error
}

// If withdrawal cannot be confirmed, Run must terminate its owned BIRD child.
var errWithdrawalFailed = errors.New("VIP withdrawal failed")

type BackendStatus struct {
	Backend   string   `json:"backend"`
	Family    uint8    `json:"family"`
	IP        string   `json:"ip"`
	MAC       [6]uint8 `json:"mac"`
	Healthy   bool     `json:"healthy"`
	Successes int      `json:"successes"`
	Failures  int      `json:"failures"`
	Detail    string   `json:"detail,omitempty"`
}

type Snapshot struct {
	Generation   uint64             `json:"generation"`
	Ready        bool               `json:"ready"`
	Degraded     bool               `json:"degraded"`
	Families     map[uint8]bool     `json:"families"`
	LastSuccess  time.Time          `json:"last_success"`
	Error        string             `json:"error,omitempty"`
	ConfigError  string             `json:"config_error,omitempty"`
	Backends     []BackendStatus    `json:"backends"`
	Decisions    []control.Decision `json:"decisions"`
	BirdPID      int                `json:"bird_pid"`
	BirdRestarts uint64             `json:"bird_restarts"`
}

type backendState struct {
	backend  control.Backend
	endpoint control.Endpoint
	health   control.Health
}

type Engine struct {
	Config     Config
	Plane      Plane
	Prober     Prober
	Bird       Advertiser
	states     map[control.EndpointKey]*backendState
	mu         sync.RWMutex
	snapshot   Snapshot
	birdPID    int
	birdStarts uint64
	birdEpoch  uint64
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.snapshot
	s.BirdPID = e.birdPID
	if e.birdStarts > 0 {
		s.BirdRestarts = e.birdStarts - 1
	}
	return s
}

func (e *Engine) birdEvent(pid int, starts uint64, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.birdPID = pid
	e.birdStarts = starts
	e.birdEpoch++
	e.snapshot.Ready = false
	if err != nil {
		e.snapshot.Error = err.Error()
	} else {
		e.snapshot.Error = "BIRD started; waiting for dataplane reconciliation"
	}
}
func (e *Engine) ConfigError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snapshot.ConfigError = ""
	if err != nil {
		e.snapshot.ConfigError = err.Error()
	}
}

func (e *Engine) withdraw() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return e.Bird.Set(ctx, false)
}

// Reconcile is serialized by the run loop. Only the short HTTP snapshot is
// shared with other goroutines; health and assignment decisions remain local.
func (e *Engine) Reconcile(ctx context.Context, t control.Table) (err error) {
	e.mu.RLock()
	epoch := e.birdEpoch
	e.mu.RUnlock()
	snap := Snapshot{Generation: t.Generation}
	defer func() {
		if err != nil {
			snap.Error = err.Error()
			if withdrawErr := e.withdraw(); withdrawErr != nil {
				err = errors.Join(err, fmt.Errorf("%w: %w", errWithdrawalFailed, withdrawErr))
			}
			snap.Error = err.Error()
		}
		e.mu.Lock()
		if e.birdEpoch != epoch {
			snap.Ready = false
			if snap.Error == "" {
				snap.Error = e.snapshot.Error
			}
		}
		snap.ConfigError = e.snapshot.ConfigError
		if err == nil {
			snap.LastSuccess = time.Now()
		} else {
			snap.LastSuccess = e.snapshot.LastSuccess
		}
		e.snapshot = snap
		e.mu.Unlock()
	}()
	if err = e.Config.ValidateTable(t); err != nil {
		return err
	}
	if e.states == nil {
		e.states = make(map[control.EndpointKey]*backendState)
	}
	type job struct {
		k      control.EndpointKey
		b      control.Backend
		state  *backendState
		result ProbeResult
	}
	var jobs []*job
	needed := make(map[uint8]bool)
	for _, a := range t.Assignments {
		k, _ := control.MakeKey(mustIP(a.Source), mustIP(a.PrimaryVIP))
		needed[k.Family] = true
	}
	for _, b := range t.Backends {
		for _, family := range []uint8{4, 6} {
			if !needed[family] || (family == 4 && b.IPv4 == "") || (family == 6 && b.IPv6 == "") {
				continue
			}
			k := control.EndpointKey{Backend: b.ID, Family: family}
			state := e.states[k]
			if state == nil || state.backend != b {
				state = &backendState{backend: b}
			}
			jobs = append(jobs, &job{k: k, b: b, state: state})
		}
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				j.result.Detail = ctx.Err().Error()
				return
			}
			j.result = e.Prober.Probe(ctx, j.b, j.k.Family, j.state.endpoint)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	endpoints := make(map[control.EndpointKey]control.Endpoint)
	next := make(map[control.EndpointKey]*backendState)
	for _, j := range jobs {
		r := j.result
		s := j.state
		usable := r.Endpoint.IP.IsValid() && ValidMAC(r.Endpoint.MAC)
		changedIP := r.Endpoint.IP.IsValid() && s.endpoint.IP != r.Endpoint.IP
		changedMAC := usable && s.endpoint.MAC != r.Endpoint.MAC
		// Reset only on a confirmed identity change or unsafe observation.
		// Missing IP/MAC from a failed query is not evidence of replacement.
		if r.Invalidate || changedIP || changedMAC {
			s.health = control.Health{}
			s.endpoint = r.Endpoint
		} else if usable {
			s.endpoint = r.Endpoint
		}
		if r.Invalidate {
			s.endpoint = control.Endpoint{}
		}
		s.health.Observe(r.OK && usable && !r.Invalidate, e.Config.Health.Rise, e.Config.Health.Fall)
		// A transient failure retains the last verified endpoint only until
		// fall is reached. A replacement must independently earn rise.
		s.endpoint.Healthy = s.health.Healthy && s.endpoint.IP.IsValid() && ValidMAC(s.endpoint.MAC)
		endpoints[j.k] = s.endpoint
		next[j.k] = s
		snap.Backends = append(snap.Backends, BackendStatus{j.b.ID, j.k.Family, s.endpoint.IP.String(), s.endpoint.MAC, s.endpoint.Healthy, s.health.Successes, s.health.Failures, r.Detail})
	}
	e.states = next
	desired, decisions := control.Desired(t, endpoints)
	snap.Decisions = decisions
	// Duplicate IDs resolving to the same physical endpoint would violate
	// primary/secondary independence even if their configured IDs differ.
	seen := make(map[string]string)
	for k, v := range endpoints {
		if !v.Healthy {
			continue
		}
		for _, identity := range []string{fmt.Sprintf("%d/ip/%s", k.Family, v.IP), fmt.Sprintf("%d/mac/%x", k.Family, v.MAC)} {
			if old := seen[identity]; old != "" && old != k.Backend {
				return fmt.Errorf("backends %s and %s share %s", old, k.Backend, identity)
			}
			seen[identity] = k.Backend
		}
	}
	// A family remains serviceable when EACH client has at least one of its
	// two VIP paths. With one survivor the other side stays INACTIVE, while
	// healthy baseline assignments and primary/secondary separation remain.
	families := make(map[uint8]bool)
	for family := range needed {
		families[family] = true
	}
	for _, a := range t.Assignments {
		primary, _ := control.MakeKey(mustIP(a.Source), mustIP(a.PrimaryVIP))
		secondary, _ := control.MakeKey(mustIP(a.Source), mustIP(a.SecondaryVIP))
		if desired[primary].Flags&control.Active == 0 && desired[secondary].Flags&control.Active == 0 {
			families[primary.Family] = false
		}
	}
	ready := false
	for _, covered := range families {
		ready = ready || covered
	}
	snap.Families = families
	for _, v := range desired {
		if v.Flags&control.Active == 0 {
			snap.Degraded = true
		}
	}
	if !ready {
		if err = e.Bird.Set(ctx, false); err != nil {
			return err
		}
	}
	if err = control.Sync(e.Plane, desired); err != nil {
		return fmt.Errorf("map sync: %w", err)
	}
	// Revalidate the real TC attachment on EVERY cycle. A successful attach
	// in the past says nothing about a later qdisc deletion or replacement.
	if err = e.Plane.Attach(); err != nil {
		// Publish failure before the potentially slow BIRD withdrawal below.
		e.mu.Lock()
		e.snapshot.Ready = false
		e.mu.Unlock()
		return fmt.Errorf("TC ingress validation: %w", err)
	}
	if err = e.Bird.SetFamilies(ctx, families); err != nil {
		return fmt.Errorf("BIRD gate: %w", err)
	}
	snap.Ready = ready
	return nil
}

func ValidMAC(m [6]uint8) bool { return m != ([6]uint8{}) && m[0]&1 == 0 }
