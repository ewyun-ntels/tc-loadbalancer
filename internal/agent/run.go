// SPDX-License-Identifier: GPL-2.0
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
)

func mustIP(s string) netip.Addr { return netip.MustParseAddr(s) }

type TableFile struct {
	Table  control.Table
	digest [32]byte
}

func (f *TableFile) Reload(file string, c Config) error {
	var next control.Table
	if err := control.DecodeFile(file, &next); err != nil {
		return err
	}
	if err := c.ValidateTable(next); err != nil {
		return err
	}
	data, _ := json.Marshal(next)
	digest := sha256.Sum256(data)
	if f.Table.Generation != 0 {
		if next.Generation < f.Table.Generation {
			return errors.New("refusing older table generation")
		}
		if next.Generation == f.Table.Generation && digest != f.digest {
			return errors.New("changed table requires a higher generation")
		}
	}
	f.Table = next
	f.digest = digest
	return nil
}

func Run(ctx context.Context, c Config, tablePath string) error {
	file := &TableFile{}
	if err := file.Reload(tablePath, c); err != nil {
		return err
	}
	bird := Bird{Config: c.Bird}
	engine := &Engine{Config: c, Bird: bird}
	process, err := newBirdProcess(c.Bird, engine.birdEvent)
	if err != nil {
		return err
	}
	// This runs after the dataplane cleanup below: withdraw, drain,
	// detach our TC filter, then terminate/reap the owned BIRD child.
	defer process.Close()
	plane, prober, err := OpenPlatform(c)
	if err != nil {
		return err
	}
	engine.Plane = plane
	engine.Prober = prober
	defer func() {
		// Withdraw before detaching. On withdrawal failure keep the pinned
		// data path rather than turning an advertised VIP into kernel PASS.
		if err := engine.withdraw(); err != nil {
			slog.Error("withdrawal failed; keeping TC attached", "error", err)
			return
		}
		if c.Bird.Socket != "" {
			timer := time.NewTimer(c.Drain)
			<-timer.C
		}
		if err := plane.Close(); err != nil {
			slog.Error("detach", "error", err)
		}
	}()
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: engine.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("agent started", "interface", c.Interface, "generation", file.Table.Generation, "listen", c.Listen)
	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case err := <-serverErr:
			return err
		default:
		}
		if err := file.Reload(tablePath, c); err != nil {
			engine.ConfigError(err)
			slog.Warn("table reload rejected; retaining accepted table", "error", err)
		} else {
			engine.ConfigError(nil)
		}
		if err := process.EnsureStarted(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			engine.mu.Lock()
			engine.snapshot.Ready = false
			engine.snapshot.Error = err.Error()
			engine.mu.Unlock()
			slog.Error("BIRD unavailable; retrying launch", "error", err)
			continue
		}
		cycle, cancel := context.WithTimeout(ctx, 30*time.Second)
		stopExitCancel := context.AfterFunc(process.Context(), cancel)
		err := engine.Reconcile(cycle, file.Table)
		stopExitCancel()
		cancel()
		if errors.Is(err, errWithdrawalFailed) {
			slog.Error("withdrawal unconfirmed; terminating BIRD before retry", "error", err)
			process.Stop()
		}
		if err != nil && ctx.Err() == nil {
			slog.Error("reconcile; advertisements withdrawn", "error", err)
		}
		timer := time.NewTimer(c.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case err := <-serverErr:
			timer.Stop()
			return err
		case <-process.Done():
			timer.Stop()
			// Preserve BPF/maps and restart only BIRD on the next iteration.
		case <-timer.C:
		}
	}
}

func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		s := e.Snapshot()
		if !s.Ready || time.Since(s.LastSuccess) > 35*time.Second+e.Config.Interval {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e.Snapshot())
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s := e.Snapshot()
		ready := 0
		if s.Ready && time.Since(s.LastSuccess) <= 35*time.Second+e.Config.Interval {
			ready = 1
		}
		fmt.Fprintf(w, "# TYPE tc_lb_ready gauge\ntc_lb_ready %d\n# TYPE tc_lb_table_generation gauge\ntc_lb_table_generation %d\n", ready, s.Generation)
		fmt.Fprintf(w, "# TYPE tc_lb_bird_pid gauge\ntc_lb_bird_pid %d\n# TYPE tc_lb_bird_restarts_total counter\ntc_lb_bird_restarts_total %d\n", s.BirdPID, s.BirdRestarts)
		degraded := 0
		if s.Degraded {
			degraded = 1
		}
		fmt.Fprintf(w, "# TYPE tc_lb_degraded gauge\ntc_lb_degraded %d\n", degraded)
		fmt.Fprintln(w, "# TYPE tc_lb_family_serviceable gauge")
		for _, family := range []uint8{4, 6} {
			if covered, ok := s.Families[family]; ok {
				v := 0
				if covered {
					v = 1
				}
				fmt.Fprintf(w, "tc_lb_family_serviceable{family=\"%d\"} %d\n", family, v)
			}
		}
		configOK := 1
		if s.ConfigError != "" {
			configOK = 0
		}
		fmt.Fprintf(w, "# TYPE tc_lb_config_valid gauge\ntc_lb_config_valid %d\n", configOK)
		fmt.Fprintln(w, "# TYPE tc_lb_backend_healthy gauge")
		for _, b := range s.Backends {
			value := 0
			if b.Healthy {
				value = 1
			}
			fmt.Fprintf(w, "tc_lb_backend_healthy{backend=%s,family=%s} %d\n", strconv.Quote(b.Backend), strconv.Quote(strconv.Itoa(int(b.Family))), value)
		}
		stats, err := e.Plane.Stats()
		if err != nil {
			fmt.Fprintln(w, "tc_lb_stats_read_error 1")
			return
		}
		fmt.Fprintln(w, "tc_lb_stats_read_error 0\n# TYPE tc_lb_packets_total counter")
		for name, value := range stats {
			fmt.Fprintf(w, "tc_lb_packets_total{reason=%s} %d\n", strconv.Quote(name), value)
		}
	})
	return mux
}
