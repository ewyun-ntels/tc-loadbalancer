// SPDX-License-Identifier: GPL-2.0
//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/ewyun-ntels/tc-loadbalancer/internal/control"
	"github.com/vishvananda/netlink"
)

type birdFixture struct {
	dir    string
	config Config
	table  control.Table
	birdc  string
}

func newBirdFixture(t *testing.T) *birdFixture {
	t.Helper()
	if os.Getenv("LB_TEST_PRIVILEGED") != "1" || os.Getenv("LB_TEST_BIRD") == "" || os.Getenv("LB_TEST_BIRDC") == "" {
		t.Skip("requires isolated network namespace and BIRD test paths")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
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
		t.Fatal("refusing init network namespace")
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	c, table := fixture(t)
	c.Health.Rise = 1
	f := &birdFixture{dir: t.TempDir(), config: c, table: table, birdc: os.Getenv("LB_TEST_BIRDC")}
	f.config.Bird = BirdConfig{Socket: filepath.Join(f.dir, "bird.ctl"), IPv4Protocols: []string{"tc_vips4"}, IPv6Protocols: []string{"tc_vips6"}, Drain: "0s", ConfigFile: filepath.Join(f.dir, "bird.conf"), Executable: os.Getenv("LB_TEST_BIRD"), PIDFile: filepath.Join(f.dir, "bird.pid")}
	config := `log stderr all;
router id 192.0.2.1;
protocol device { }
protocol static tc_vips4 { disabled; ipv4; route 192.0.2.10/32 blackhole; route 192.0.2.11/32 blackhole; }
protocol static tc_vips6 { disabled; ipv6; route 2001:db8:1::a/128 blackhole; route 2001:db8:1::b/128 blackhole; }
`
	if err := os.WriteFile(f.config.Bird.ConfigFile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func await(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func (f *birdFixture) routes(t *testing.T, v4, v6 bool) {
	t.Helper()
	await(t, "BIRD route state", func() bool {
		for _, row := range []struct {
			protocol, prefix string
			want             bool
		}{{"tc_vips4", "192.0.2.10/32", v4}, {"tc_vips6", "2001:db8:1::a/128", v6}} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			out, err := exec.CommandContext(ctx, f.birdc, "-v", "-s", f.config.Bird.Socket, "show", "route", "protocol", row.protocol).CombinedOutput()
			cancel()
			if err != nil || strings.Contains(string(out), "800") || strings.Contains(string(out), row.prefix) != row.want {
				return false
			}
		}
		return true
	})
}

func TestRealBirdRestartAndAdvertiseGate(t *testing.T) {
	f := newBirdFixture(t)
	trace := []string{}
	plane := &memoryPlane{values: map[control.Key]control.Dest{}, trace: &trace}
	e := &Engine{Config: f.config, Plane: plane, Prober: &fakeProber{}, Bird: Bird{Config: f.config.Bird}}
	p, err := newBirdProcess(f.config.Bird, e.birdEvent)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.routes(t, false, false)
	if err := e.Reconcile(context.Background(), f.table); err != nil {
		t.Fatal(err)
	}
	f.routes(t, true, true)
	before, _ := plane.Entries()
	pid := e.Snapshot().BirdPID
	exited := p.Done()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("BIRD exit not detected")
	}
	if e.Snapshot().Ready {
		t.Fatal("dead BIRD left readiness green")
	}
	if err := p.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().BirdPID == pid || e.Snapshot().BirdRestarts != 1 {
		t.Fatal("BIRD was not replaced")
	}
	if !reflect.DeepEqual(before, plane.values) {
		t.Fatal("BIRD restart changed assignment maps")
	}
	f.routes(t, false, false)
	if e.Snapshot().Ready {
		t.Fatal("BIRD restart advertised readiness before dataplane check")
	}
	if err := e.Reconcile(context.Background(), f.table); err != nil {
		t.Fatal(err)
	}
	f.routes(t, true, true)
	if !e.Snapshot().Ready {
		t.Fatal("did not recover")
	}
}

func TestRealBirdBadConfigCanRecover(t *testing.T) {
	f := newBirdFixture(t)
	good, err := os.ReadFile(f.config.Bird.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config.Bird.ConfigFile, []byte("invalid BIRD config"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := newBirdProcess(f.config.Bird, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.EnsureStarted(context.Background()); err == nil {
		t.Fatal("invalid config unexpectedly started")
	}
	if err := os.WriteFile(f.config.Bird.ConfigFile, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureStarted(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.routes(t, false, false)
}

// Read only descendants of our own unshare child. PID files written inside a
// child PID namespace contain namespace-local IDs and MUST NOT be signalled
// from this ancestor namespace without mapping them first.
func descendants(root int) []int {
	seen := map[int]bool{}
	queue := []int{root}
	var out []int
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		files, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
		for _, file := range files {
			data, _ := os.ReadFile(file)
			for _, raw := range strings.Fields(string(data)) {
				child, err := strconv.Atoi(raw)
				if err == nil && !seen[child] {
					seen[child] = true
					out = append(out, child)
					queue = append(queue, child)
				}
			}
		}
	}
	return out
}

func childExecutable(root int, name string) int {
	for _, pid := range descendants(root) {
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if filepath.Base(exe) == name {
			return pid
		}
	}
	return 0
}

func TestRealAgentPID1AndBirdRestart(t *testing.T) {
	if os.Getenv("LB_TEST_AGENT") == "" || os.Getenv("LB_TEST_OBJECT") == "" {
		t.Skip("requires built agent and BPF object")
	}
	f := newBirdFixture(t)
	name := fmt.Sprintf("agt%d", os.Getpid())
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	iface, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(iface)
	address, _ := netlink.ParseAddr("192.0.2.1/24")
	if err := netlink.AddrAdd(iface, address); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(iface); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := listener.Addr().String()
	listener.Close()
	pins := fmt.Sprintf("/sys/fs/bpf/tc-lb-process-test-%d", os.Getpid())
	if _, err := os.Stat(pins); !os.IsNotExist(err) {
		t.Fatal("test pin directory already exists")
	}
	defer func() {
		for _, file := range []string{"lb_assign", "lb_stats", "lb_ingress"} {
			_ = os.Remove(filepath.Join(pins, file))
		}
		_ = os.Remove(pins)
	}()
	config := map[string]any{"interface": name, "object": os.Getenv("LB_TEST_OBJECT"), "pin_path": pins, "lock_file": filepath.Join(f.dir, "agent.lock"), "listen": listen, "backend_prefixes": []string{"192.0.2.128/26", "2001:db8:1::80/122"}, "health": map[string]any{"interval": "100ms", "timeout": "30ms", "fall": 3}, "bird": f.config.Bird}
	var table control.Table
	table = f.table
	table.Assignments = nil
	for _, a := range f.table.Assignments {
		if !strings.Contains(a.Source, ":") {
			table.Assignments = append(table.Assignments, a)
		}
	}
	configPath := filepath.Join(f.dir, "agent.json")
	tablePath := filepath.Join(f.dir, "table.json")
	for file, value := range map[string]any{configPath: config, tablePath: table} {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	log, err := os.Create(filepath.Join(f.dir, "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command("unshare", "--mount", "--propagation", "private", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc", os.Getenv("LB_TEST_AGENT"), "-config", configPath, "-table", tablePath)
	command.Stdout = log
	command.Stderr = log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	defer func() {
		_ = command.Process.Kill()
		<-done
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(f.dir, "agent.log"))
			t.Log(string(data))
		}
	}()
	var agentPID, birdPID, filterID int
	await(t, "PID 1 agent with BIRD and TC", func() bool {
		agentPID = childExecutable(command.Process.Pid, "lb-agent")
		birdPID = childExecutable(command.Process.Pid, "bird")
		filters, err := netlink.FilterList(iface, netlink.HANDLE_MIN_INGRESS)
		if agentPID == 0 || birdPID == 0 || err != nil || len(filters) != 1 {
			return false
		}
		filterID = filters[0].(*netlink.BpfFilter).Id
		return true
	})
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", agentPID))
	if err != nil {
		t.Fatal(err)
	}
	foundPID1 := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			foundPID1 = fields[len(fields)-1] == "1"
		}
	}
	if !foundPID1 {
		t.Fatal("agent was not PID 1")
	}
	mapIDs := func() map[string]ebpf.MapID {
		out := map[string]ebpf.MapID{}
		for _, name := range []string{"lb_assign", "lb_stats"} {
			m, err := ebpf.LoadPinnedMap(filepath.Join(pins, name), nil)
			if err != nil {
				t.Fatal(err)
			}
			info, err := m.Info()
			m.Close()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			out[name] = id
		}
		return out
	}
	before := mapIDs()
	oldBird := birdPID
	if err := syscall.Kill(oldBird, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	await(t, "BIRD restart under same agent", func() bool {
		birdPID = childExecutable(command.Process.Pid, "bird")
		return birdPID != 0 && birdPID != oldBird
	})
	if childExecutable(command.Process.Pid, "lb-agent") != agentPID {
		t.Fatal("agent restarted with BIRD")
	}
	if !reflect.DeepEqual(before, mapIDs()) {
		t.Fatal("BIRD restart reloaded BPF maps")
	}
	filters, err := netlink.FilterList(iface, netlink.HANDLE_MIN_INGRESS)
	if err != nil || len(filters) != 1 || filters[0].(*netlink.BpfFilter).Id != filterID {
		t.Fatal("BIRD restart replaced TC program")
	}
	// A live daemon whose control socket is lost must not keep advertising
	// indefinitely. The agent stops it when withdrawal cannot be confirmed.
	awaitReconciled := func(restarts uint64) {
		client := &http.Client{Timeout: time.Second}
		await(t, "BIRD startup and reconciliation", func() bool {
			response, err := client.Get("http://" + listen + "/status")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			var status Snapshot
			return json.NewDecoder(response.Body).Decode(&status) == nil && status.BirdRestarts == restarts && status.Error == "" && !status.LastSuccess.IsZero()
		})
	}
	awaitReconciled(1)
	if err := os.Remove(f.config.Bird.Socket); err != nil {
		t.Fatal(err)
	}
	previousBird := birdPID
	await(t, "BIRD replacement after control loss", func() bool {
		birdPID = childExecutable(command.Process.Pid, "bird")
		return birdPID != 0 && birdPID != previousBird
	})
	awaitReconciled(2)
	if childExecutable(command.Process.Pid, "lb-agent") != agentPID || !reflect.DeepEqual(before, mapIDs()) {
		t.Fatal("control failure replaced agent or maps")
	}
	if err := syscall.Kill(agentPID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("PID 1 death did not end container process tree")
	}
	await(t, "BIRD dies with PID 1", func() bool {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", birdPID))
		if os.IsNotExist(err) {
			return true
		}
		return err == nil && strings.Contains(string(data), ") Z ")
	})
	conn, err := net.DialTimeout("unix", f.config.Bird.Socket, 100*time.Millisecond)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("BIRD control socket survived PID 1 death")
	}
	// The test owns this NIC outside the child PID namespace; real Pod
	// network teardown removes it separately. The deferred cleanup does so.
}
