"""Production-shaped fault-injection benchmark (A/B).

usage: python scripts/benchmark/faults.py <server.py>

Injected conditions inside the proxy process only:
  * resolver: 90 ms for a name's first lookup, 2 ms afterwards (upstream
    resolver cache), matching the 88-92 ms / ~2 ms seen on the Zeabur host;
  * multi.test resolves to 8 IPv4 addresses (like google.com);
  * blackhole.test resolves to [192.0.2.1 (silently drops SYN), 127.0.0.1];
  * deadN.test hangs 5 s then fails (resolver timeout).
"""
from __future__ import annotations

import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench  # noqa: E402

RUNNER = r"""
import asyncio, importlib.util, ipaddress, json, signal, socket, sys, threading, time
ipaddress.IPv4Address.is_global = property(lambda self: not str(self).startswith("10."))
ipaddress.IPv6Address.is_global = property(lambda self: True)
stats_path = sys.argv[2]
lock = threading.Lock()
counters = {"getaddrinfo": 0, "tcp_attempts": 0}
seen_at = {}
real_gai = socket.getaddrinfo
def fake_gai(host, port, *args, **kwargs):
    name = host.decode() if isinstance(host, bytes) else host
    with lock:
        counters["getaddrinfo"] += 1
        now = time.monotonic()
        ready = seen_at.setdefault(name, now + 0.09)
    if name.startswith("dead"):
        time.sleep(5)
        raise socket.gaierror(socket.EAI_AGAIN, "resolver timeout")
    time.sleep(max(ready - now, 0.002))
    if name == "multi.test":
        ips = [f"127.0.0.{i}" for i in range(1, 9)]
    elif name == "blackhole.test":
        ips = ["192.0.2.1", "127.0.0.1"]
    else:
        return real_gai(host, port, *args, **kwargs)
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0)) for ip in ips]
socket.getaddrinfo = fake_gai
real_open = asyncio.open_connection
async def counted_open(host=None, port=None, **kwargs):
    with lock:
        counters["tcp_attempts"] += 1
    if host.startswith("127."):
        host = "127.0.0.1"  # 8 "different" healthy addresses, one local origin
    return await real_open(host=host, port=port, **kwargs)
asyncio.open_connection = counted_open
def dump(*_):
    with open(stats_path, "w") as f:
        json.dump(counters, f)
signal.signal(signal.SIGUSR1, dump)
spec = importlib.util.spec_from_file_location("srv", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules["srv"] = mod
spec.loader.exec_module(mod)
asyncio.run(mod.main())
"""


def start(server_path: str, stats_path: str):
    port, tls_port = bench.free_port(), bench.free_port()
    env = dict(os.environ)
    env.update(
        PORT=str(port), PROXY_TLS_PORT=str(tls_port), PROXY_USERNAME="bench",
        PROXY_PASSWORD="bench-secret", PROXY_MAX_CONNECTIONS="4096", LOG_LEVEL="ERROR",
        PROXY_CONNECT_TIMEOUT_SECONDS="10",
    )
    proc = subprocess.Popen([sys.executable, "-c", RUNNER, server_path, stats_path], env=env)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return proc, port


def counters(proc, path):
    os.kill(proc.pid, signal.SIGUSR1)
    time.sleep(0.2)
    return json.loads(Path(path).read_text())


def timed_echo(port, target):
    try:
        return bench.echo(port, target, False)
    except Exception:
        return None


def summarize(lats):
    ok = sorted(x for x in lats if x is not None)
    out = {"ok": len(ok), "failed": len(lats) - len(ok)}
    if ok:
        out.update(
            p50_ms=round(statistics.median(ok) * 1000, 1),
            p95_ms=round(ok[max(0, int(len(ok) * 0.95) - 1)] * 1000, 1),
            max_ms=round(ok[-1] * 1000, 1),
        )
    return out


def run(server_path: str) -> dict:
    origin = bench.start_origin()
    stats = tempfile.mktemp()
    proc, port = start(server_path, stats)
    res: dict[str, object] = {}
    try:
        # A. Browser-style burst: 40 simultaneous tunnels to a new 8-address host.
        before = counters(proc, stats)
        with ThreadPoolExecutor(40) as pool:
            lats = list(pool.map(lambda _: timed_echo(port, f"multi.test:{origin}"), range(40)))
        after = counters(proc, stats)
        res["A_burst40_new_host"] = summarize(lats) | {
            "dns_lookups": after["getaddrinfo"] - before["getaddrinfo"],
            "tcp_attempts_per_tunnel": round((after["tcp_attempts"] - before["tcp_attempts"]) / 40, 2),
        }

        # B. Steady state: 300 sequential tunnels to the same host.
        before = counters(proc, stats)
        lats = [timed_echo(port, f"multi.test:{origin}") for _ in range(300)]
        after = counters(proc, stats)
        res["B_sequential300_warm_host"] = summarize(lats) | {
            "dns_lookups": after["getaddrinfo"] - before["getaddrinfo"],
            "tcp_attempts_per_tunnel": round((after["tcp_attempts"] - before["tcp_attempts"]) / 300, 2),
        }

        # C. Resolver stall: 24 tunnels to hosts whose DNS hangs 5 s, while a
        #    user keeps opening tunnels to an already-used host.
        stop = threading.Event()
        dead_pool = ThreadPoolExecutor(24)
        for i in range(24):
            dead_pool.submit(timed_echo, port, f"dead{i}.test:{origin}")
        time.sleep(0.1)
        lats = []
        t_end = time.time() + 3
        while time.time() < t_end:
            lats.append(timed_echo(port, f"multi.test:{origin}"))
        res["C_healthy_during_resolver_stall"] = summarize(lats)
        dead_pool.shutdown(wait=True)

        # D. One black-holed address listed first.
        lats = [timed_echo(port, f"blackhole.test:{origin}") for _ in range(30)]
        res["D_blackholed_first_address"] = summarize(lats) | {
            "first_ms": round(lats[0] * 1000, 1) if lats[0] else None,
        }
    finally:
        proc.terminate()
        proc.wait(5)
    return res


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1])))
