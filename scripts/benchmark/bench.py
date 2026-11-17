"""Local A/B benchmark for the selective proxy.

usage: python scripts/benchmark/bench.py <path-to-server.py> [--uvloop]

Starts a threaded origin, the proxy (in its own process), and blocking
socket clients in threads so the proxy event loop is the bottleneck. Compare
two revisions by running it against each server.py. Requires openssl for a
throwaway localhost certificate; loopback targets are allowed only inside the
benchmark's proxy process.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CERT_DIR = Path(tempfile.mkdtemp(prefix="proxy-bench-"))
subprocess.run(
    [
        "openssl", "req", "-x509", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", str(CERT_DIR / "key.pem"), "-out", str(CERT_DIR / "cert.pem"),
        "-days", "1", "-subj", "/CN=minbot-egress.local",
        "-addext", "subjectAltName=DNS:minbot-egress.local",
    ],
    check=True,
    capture_output=True,
)
CHUNK = b"\0" * (1 << 20)


# ---------------------------------------------------------------- origin
def origin_conn(conn: socket.socket) -> None:
    try:
        head = b""
        while len(head) < 9:
            part = conn.recv(9 - len(head))
            if not part:
                return
            head += part
        mode, size = head[:1], int.from_bytes(head[1:], "big")
        if mode == b"D":
            view = memoryview(CHUNK)
            left = size
            while left:
                n = min(left, len(CHUNK))
                conn.sendall(view[:n])
                left -= n
        elif mode == b"U":
            buf = bytearray(1 << 20)
            left = size
            while left:
                n = conn.recv_into(buf)
                if not n:
                    return
                left -= n
            conn.sendall(b"OK")
        elif mode == b"E":
            data = conn.recv(size)
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def start_origin() -> int:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1024)

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=origin_conn, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


# ---------------------------------------------------------------- proxy
PROXY_RUNNER = r"""
import asyncio, importlib.util, ipaddress, sys
ipaddress.IPv4Address.is_global = property(lambda self: True)
ipaddress.IPv6Address.is_global = property(lambda self: True)
spec = importlib.util.spec_from_file_location("srv", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules["srv"] = mod
spec.loader.exec_module(mod)
if "--uvloop" in sys.argv:
    import uvloop
    uvloop.run(mod.main())
else:
    asyncio.run(mod.main())
"""


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_proxy(server_path: str, extra: list[str]) -> tuple[subprocess.Popen, int, int]:
    port, tls_port = free_port(), free_port()
    env = dict(os.environ)
    env.update(
        PORT=str(port),
        PROXY_TLS_PORT=str(tls_port),
        PROXY_USERNAME="bench",
        PROXY_PASSWORD="bench-secret",
        PROXY_TLS_CERT_PEM=(CERT_DIR / "cert.pem").read_text(),
        PROXY_TLS_KEY_PEM=(CERT_DIR / "key.pem").read_text(),
        PROXY_MAX_CONNECTIONS="4096",
        LOG_LEVEL="WARNING",
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", PROXY_RUNNER, server_path, *extra], env=env
    )
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            socket.create_connection(("127.0.0.1", tls_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return proc, port, tls_port


def cpu_seconds(pid: int) -> float:
    out = subprocess.check_output(["ps", "-o", "time=", "-p", str(pid)]).decode().strip()
    # [[dd-]hh:]mm:ss.ss
    parts = out.replace("-", ":").split(":")
    total = 0.0
    for part in parts:
        total = total * 60 + float(part)
    return total


# ---------------------------------------------------------------- client
AUTH = "YmVuY2g6YmVuY2gtc2VjcmV0"  # bench:bench-secret
CTX = ssl.create_default_context(cafile=str(CERT_DIR / "cert.pem"))


def tunnel(port: int, target: str, tls: bool) -> socket.socket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=30)
    sock = CTX.wrap_socket(raw, server_hostname="minbot-egress.local") if tls else raw
    sock.sendall(
        f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        f"Proxy-Authorization: Basic {AUTH}\r\n\r\n".encode()
    )
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        part = sock.recv(1)
        if not part:
            raise ConnectionError("proxy closed during CONNECT")
        head += part
    if not head.startswith(b"HTTP/1.1 200"):
        raise ConnectionError(head.decode(errors="replace"))
    return sock


def download(port, target, tls, size) -> int:
    s = tunnel(port, target, tls)
    s.sendall(b"D" + size.to_bytes(8, "big"))
    buf = bytearray(1 << 20)
    got = 0
    while got < size:
        n = s.recv_into(buf)
        if not n:
            break
        got += n
    s.close()
    return got


def upload(port, target, tls, size) -> int:
    s = tunnel(port, target, tls)
    s.sendall(b"U" + size.to_bytes(8, "big"))
    view = memoryview(CHUNK)
    left = size
    while left:
        n = min(left, len(CHUNK))
        s.sendall(view[:n])
        left -= n
    ok = s.recv(2)
    s.close()
    return size if ok == b"OK" else 0


def echo(port, target, tls) -> float:
    t0 = time.perf_counter()
    s = tunnel(port, target, tls)
    s.sendall(b"E" + (64).to_bytes(8, "big") + b"x" * 64)
    got = b""
    while len(got) < 64:
        part = s.recv(64)
        if not part:
            break
        got += part
    s.close()
    if len(got) != 64:
        raise ConnectionError("short echo")
    return time.perf_counter() - t0


def run(server_path: str, extra: list[str]) -> dict:
    origin = start_origin()
    proc, port, tls_port = start_proxy(server_path, extra)
    target_ip = f"127.0.0.1:{origin}"
    target_dns = f"localhost:{origin}"
    results: dict[str, object] = {}
    try:
        def measure(name, fn, total_bytes):
            c0 = cpu_seconds(proc.pid)
            t0 = time.perf_counter()
            moved = fn()
            dt = time.perf_counter() - t0
            c1 = cpu_seconds(proc.pid)
            assert moved == total_bytes, (name, moved, total_bytes)
            results[name] = {
                "MiB_s": round(total_bytes / dt / 2**20, 1),
                "proxy_cpu_s_per_GiB": round((c1 - c0) / (total_bytes / 2**30), 3),
            }

        size = 1 << 30
        measure("download_1x1GiB_plain", lambda: download(port, target_ip, False, size), size)
        measure("download_1x1GiB_tls", lambda: download(tls_port, target_ip, True, size), size)
        measure("upload_1x512MiB_tls", lambda: upload(tls_port, target_ip, True, size // 2), size // 2)

        def parallel(n, each, tls):
            with ThreadPoolExecutor(n) as pool:
                return sum(pool.map(lambda _: download(tls_port if tls else port, target_ip, tls, each), range(n)))

        measure("download_16x128MiB_plain", lambda: parallel(16, 128 << 20, False), 16 * (128 << 20))
        measure("download_16x64MiB_tls", lambda: parallel(16, 64 << 20, True), 16 * (64 << 20))

        # connection churn through DNS path (localhost resolves to ::1 and 127.0.0.1;
        # origin only listens on IPv4 so ::1 attempts are refused).
        for label, tls, p in (("plain", False, port), ("tls", True, tls_port)):
            count, conc = 1500, 48
            c0 = cpu_seconds(proc.pid)
            t0 = time.perf_counter()
            errors = 0
            lats: list[float] = []
            with ThreadPoolExecutor(conc) as pool:
                for fut in [pool.submit(echo, p, target_dns, tls) for _ in range(count)]:
                    try:
                        lats.append(fut.result())
                    except Exception:
                        errors += 1
            dt = time.perf_counter() - t0
            c1 = cpu_seconds(proc.pid)
            lats.sort()
            results[f"churn_{count}_c{conc}_{label}"] = {
                "conn_per_s": round(count / dt, 1),
                "p50_ms": round(statistics.median(lats) * 1000, 2),
                "p99_ms": round(lats[int(len(lats) * 0.99) - 1] * 1000, 2),
                "errors": errors,
                "proxy_cpu_ms_per_conn": round((c1 - c0) / count * 1000, 3),
            }
    finally:
        proc.terminate()
        proc.wait(5)
    return results


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], sys.argv[2:]), indent=1))
