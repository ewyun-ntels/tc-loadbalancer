#!/usr/bin/env python3
"""Root-only integration test; all links/sysctls live in disposable namespaces.

Uses the built bin/lb-agent and bin/lbctl, and the existing bpf/lb_kern.o.
No BIRD session is started and no host networking/sysctl is changed.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SELF = str(Path(__file__).resolve())


def backend(identity, ipv4, ipv6):
    def serve(host, family, port):
        with socket.socket(family, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.bind((host, port))
            server.listen(128)
            while True:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(1)
                    try:
                        if conn.recv(32):
                            conn.sendall(identity.encode())
                    except (TimeoutError, ConnectionError):
                        pass

    threads = []
    for host, family, port in [
        (ipv4, socket.AF_INET, 8080), (ipv6, socket.AF_INET6, 8080),
        ("10.203.0.10", socket.AF_INET, 9000),
        ("10.203.0.11", socket.AF_INET, 9000),
        ("fd42:203::a", socket.AF_INET6, 9000),
        ("fd42:203::b", socket.AF_INET6, 9000),
    ]:
        thread = threading.Thread(target=serve, args=(host, family, port), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


def client(vip, source):
    family = socket.AF_INET6 if ":" in vip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.bind((source, 0))
        conn.connect((vip, 9000))
        conn.sendall(b"identity")
        return conn.recv(32).decode()


def main():
    if os.geteuid() != 0:
        raise SystemExit("run with sudo python3 test/agent_smoke.py")
    work = Path(tempfile.mkdtemp(prefix="tc-lb-agent-smoke-"))
    tag = f"tcgo-{os.getpid()}"
    names = {key: f"{tag}-{key}" for key in ["hub", "lb", "cl", "be-0", "be-1", "be-2"]}
    pins = Path(f"/sys/fs/bpf/tc-lb-agent-smoke-{os.getpid()}")
    created, processes, logs = [], [], []
    agent = None

    def run(*args, **kwargs):
        return subprocess.run(list(args), check=True, text=True, **kwargs)

    def inside(ns, *args):
        # Switch only the network namespace. ip netns exec also remounts sysfs
        # and can hide the private bpffs mount used by this test's parent.
        return ["nsenter", f"--net=/run/netns/{names[ns]}", "--", *args]

    def spawn(ns, *args, logfile):
        stream = open(work / logfile, "w")
        logs.append(stream)
        proc = subprocess.Popen(inside(ns, *args), stdout=stream, stderr=subprocess.STDOUT, cwd=ROOT)
        processes.append(proc)
        return proc

    def status():
        raw = subprocess.check_output(inside("lb", "python3", SELF, "--status"), text=True, stderr=subprocess.DEVNULL)
        return json.loads(raw)

    def wait_for(predicate, description, timeout=20):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            if agent is not None and agent.poll() is not None:
                raise AssertionError(f"agent exited {agent.returncode}; logs: {work}")
            try:
                last = status()
                if predicate(last):
                    return last
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                pass
            time.sleep(0.05)
        raise AssertionError(f"timeout: {description}: {last}; logs: {work}")

    def call(vip, source):
        return subprocess.check_output(inside("cl", "python3", SELF, "--client", vip, source), text=True).strip()

    def assert_traffic(snapshot):
        decisions = {(d["source"], d["vip"]): d for d in snapshot["decisions"]}
        for source in ["10.203.0.2", "fd42:203::2"]:
            vips = ["10.203.0.10", "10.203.0.11"] if ":" not in source else ["fd42:203::a", "fd42:203::b"]
            replies = [call(vip, source) for vip in vips]
            assert replies[0] != replies[1], replies
            for vip, reply in zip(vips, replies):
                assert decisions[source, vip]["active"]
                assert decisions[source, vip]["backend"] == reply, (vip, reply)

    try:
        for ns in names.values():
            run("ip", "netns", "add", ns)
            created.append(ns)
            run("ip", "-n", ns, "link", "set", "lo", "up")
        run("ip", "-n", names["hub"], "link", "add", "br0", "type", "bridge")
        run("ip", "-n", names["hub"], "link", "set", "br0", "up")
        addresses = {"cl": 2, "lb": 3, "be-0": 130, "be-1": 131, "be-2": 132}
        for i, (key, number) in enumerate(addresses.items()):
            port = f"p{i}"
            run("ip", "-n", names["hub"], "link", "add", port, "type", "veth", "peer", "name", "peer")
            run("ip", "-n", names["hub"], "link", "set", "peer", "netns", names[key])
            run("ip", "-n", names["hub"], "link", "set", port, "master", "br0")
            run("ip", "-n", names["hub"], "link", "set", port, "up")
            run("ip", "-n", names[key], "link", "set", "peer", "name", "net1")
            run("ip", "-n", names[key], "addr", "add", f"10.203.0.{number}/24", "dev", "net1")
            run("ip", "-n", names[key], "-6", "addr", "add", f"fd42:203::{number:x}/64", "dev", "net1", "nodad")
            run("ip", "-n", names[key], "link", "set", "net1", "up")
            if key.startswith("be-"):
                run(*inside(key, "sysctl", "-qw", "net.ipv4.conf.all.arp_ignore=1", "net.ipv4.conf.all.arp_announce=2", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.net1.rp_filter=2"))
                for vip in ["10.203.0.10/32", "10.203.0.11/32"]:
                    run("ip", "-n", names[key], "addr", "add", vip, "dev", "lo")
                for vip in ["fd42:203::a/128", "fd42:203::b/128"]:
                    run("ip", "-n", names[key], "-6", "addr", "add", vip, "dev", "lo", "nodad")
        run("ip", "-n", names["cl"], "addr", "add", "10.203.0.4/24", "dev", "net1")
        run("ip", "-n", names["cl"], "-6", "addr", "add", "fd42:203::4/64", "dev", "net1", "nodad")
        for vip in ["10.203.0.10/32", "10.203.0.11/32"]:
            run("ip", "-n", names["cl"], "route", "add", vip, "via", "10.203.0.3")
        for vip in ["fd42:203::a/128", "fd42:203::b/128"]:
            run("ip", "-n", names["cl"], "-6", "route", "add", vip, "via", "fd42:203::3")
        backends = [{"id": f"be-{i}", "ipv4": f"10.203.0.{130+i}", "ipv6": f"fd42:203::{130+i:x}", "health_port": 8080} for i in range(3)]
        plan = {"version": 1, "generation": 1, "backends": backends, "vip_pairs": [{"primary": "10.203.0.10", "secondary": "10.203.0.11"}, {"primary": "fd42:203::a", "secondary": "fd42:203::b"}], "clients": [{"id": "system-a", "addresses": ["10.203.0.2", "fd42:203::2"]}, {"id": "system-b", "addresses": ["10.203.0.4", "fd42:203::4"]}]}
        config = {"interface": "net1", "object": str(ROOT / "bpf/lb_kern.o"), "pin_path": str(pins), "lock_file": str(work / "agent.lock"), "listen": "127.0.0.1:9090", "backend_prefixes": ["10.203.0.128/26", "fd42:203::80/122"], "health": {"interval": "100ms", "timeout": "100ms", "rise": 2, "fall": 3}, "bird": {"drain": "0s"}}
        config_path, plan_path, table_path = work / "agent.json", work / "plan.json", work / "table.json"
        config_path.write_text(json.dumps(config))

        def generate():
            plan_path.write_text(json.dumps(plan))
            run(str(ROOT / "bin/lbctl"), "generate", "-plan", str(plan_path), "-out", str(table_path))

        generate()
        backend_procs = {b["id"]: spawn(b["id"], "python3", SELF, "--backend", b["id"], b["ipv4"], b["ipv6"], logfile=f"{b['id']}.log") for b in backends}

        def start_agent(suffix):
            return spawn("lb", str(ROOT / "bin/lb-agent"), "-config", str(config_path), "-table", str(table_path), logfile=f"agent-{suffix}.log")

        agent = start_agent("first")
        baseline = wait_for(lambda s: s["ready"], "initial dual-stack health")
        assert_traffic(baseline)
        print("PASS: dual-stack primary/secondary TCP + DSR + actual BPF verifier", flush=True)
        # Simulate a process crash: the filter and pinned maps survive. The
        # replacement must prove ownership and reuse the same maps/program.
        agent.kill()
        agent.wait(timeout=5)
        agent = start_agent("restart")
        baseline = wait_for(lambda s: s["ready"], "restart with pinned program")
        assert_traffic(baseline)
        print("PASS: crash/restart reuses owned TC filter and pinned maps", flush=True)
        old = {(d["source"], d["vip"]): d["backend"] for d in baseline["decisions"]}
        victim = old["10.203.0.2", "10.203.0.10"]
        backend_procs[victim].terminate()
        backend_procs[victim].wait(timeout=5)
        failed = wait_for(lambda s: s["ready"] and all(not b["healthy"] for b in s["backends"] if b["backend"] == victim), "primary failure")
        assert_traffic(failed)
        for d in failed["decisions"]:
            if old[d["source"], d["vip"]] != victim:
                assert old[d["source"], d["vip"]] == d["backend"], "healthy baseline changed"
        print("PASS: failed primary reassigned; healthy assignments unchanged", flush=True)
        b = next(b for b in backends if b["id"] == victim)
        backend_procs[victim] = spawn(victim, "python3", SELF, "--backend", victim, b["ipv4"], b["ipv6"], logfile=f"{victim}-recovered.log")
        restored = wait_for(lambda s: s["ready"] and all(b["healthy"] for b in s["backends"]), "backend recovery")
        assert_traffic(restored)
        assert old == {(d["source"], d["vip"]): d["backend"] for d in restored["decisions"]}
        print("PASS: recovery restores baseline after rise threshold", flush=True)
        table_path.write_text('{"version":1,"generation":2,"unknown":true}')
        retained = wait_for(lambda s: s.get("config_error") and s["ready"], "invalid reload retention")
        assert_traffic(retained)
        print("PASS: invalid reload retains accepted table and traffic", flush=True)
        plan["generation"] = 2
        plan["clients"] = plan["clients"][:1]
        generate()
        reduced = wait_for(lambda s: s["generation"] == 2 and s["ready"], "valid generation 2")
        assert_traffic(reduced)
        for vip, source in [("10.203.0.10", "10.203.0.4"), ("fd42:203::a", "fd42:203::4")]:
            result = subprocess.run(inside("cl", "python3", SELF, "--client", vip, source), capture_output=True, text=True)
            assert result.returncode != 0, "removed client still forwarded"
        print("PASS: removed assignments become inactive tombstones", flush=True)
        agent.terminate()
        agent.wait(timeout=5)
        assert agent.returncode == 0, f"shutdown failed: {work}"
        filters = subprocess.check_output(inside("lb", "tc", "filter", "show", "dev", "net1", "ingress"), text=True)
        assert not filters.strip(), filters
        print("PASS: graceful shutdown detaches owned filter", flush=True)
        print(f"All agent integration checks passed. Logs: {work}")
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        for ns in reversed(created):
            subprocess.run(["ip", "netns", "delete", ns], check=False)
        for name in ["lb_ingress", "lb_assign", "lb_stats"]:
            (pins / name).unlink(missing_ok=True)
        if pins.exists():
            pins.rmdir()
        for stream in logs:
            stream.close()
        if sys.exc_info()[0] is not None:
            for logfile in sorted(work.glob("*.log")):
                print(f"--- {logfile.name} ---", flush=True)
                print(logfile.read_text()[-12000:], flush=True)
        print(f"Integration artifacts: {work}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--backend":
        backend(*sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "--client":
        print(client(*sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] == "--status":
        with urllib.request.urlopen("http://127.0.0.1:9090/status", timeout=2) as response:
            print(response.read().decode())
    else:
        main()
