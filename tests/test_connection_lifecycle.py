from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import socket

import pytest

import minbot_selective_proxy.server as server


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False
        self.aborted = False
        self.transport = self

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def abort(self):
        self.aborted = True


def config(**kwargs):
    return server.ProxyConfig(username="test", password="test-only", domains=("example.com",), **kwargs)


def public_rows(*addresses):
    rows = []
    for ip in addresses:
        if ":" in ip:
            rows.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443, 0, 0)))
        else:
            rows.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)))
    return rows


async def stream_pair():
    """Loopback connection: (proxy_reader, proxy_writer, peer_reader, peer_writer)."""
    accepted = asyncio.get_running_loop().create_future()

    async def on_accept(reader, writer):
        accepted.set_result((reader, writer))

    listener = await asyncio.start_server(on_accept, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    peer_reader, peer_writer = await asyncio.open_connection("127.0.0.1", port)
    proxy_reader, proxy_writer = await accepted
    listener.close()
    return proxy_reader, proxy_writer, peer_reader, peer_writer


class Tunnel:
    """client <-> [proxy client side | relay | proxy upstream side] <-> origin."""

    async def __aenter__(self):
        (self.proxy_client_r, self.proxy_client_w, self.client_r, self.client_w) = await stream_pair()
        (self.proxy_up_r, self.proxy_up_w, self.origin_r, self.origin_w) = await stream_pair()
        await asyncio.sleep(0)
        return self

    def relay(self, idle_timeout=10.0):
        return asyncio.create_task(
            server._relay_bidirectionally(
                self.proxy_client_r,
                self.proxy_client_w,
                self.proxy_up_r,
                self.proxy_up_w,
                idle_timeout=idle_timeout,
            )
        )

    async def __aexit__(self, *exc):
        for writer in (self.proxy_client_w, self.proxy_up_w, self.client_w, self.origin_w):
            writer.transport.abort()
        await asyncio.sleep(0)


# ----------------------------------------------------------------- relay


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["download", "upload"])
async def test_active_one_way_traffic_outlives_idle_timeout(direction):
    async with Tunnel() as t:
        sender, receiver = (t.origin_w, t.client_r) if direction == "download" else (t.client_w, t.origin_r)
        relay = t.relay(idle_timeout=0.08)
        for _ in range(12):
            sender.write(b"streaming-data")
            await sender.drain()
            await asyncio.sleep(0.02)
            assert not relay.done(), "Active one-way traffic must keep the tunnel alive"
        received = await asyncio.wait_for(receiver.readexactly(14 * 12), 0.5)
        assert received == b"streaming-data" * 12
        relay.cancel()
        await asyncio.gather(relay, return_exceptions=True)


@pytest.mark.asyncio
async def test_truly_idle_tunnel_expires_and_reaps_children():
    async with Tunnel() as t:
        before = asyncio.all_tasks()
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(t.relay(idle_timeout=0.05), 0.5)
        assert asyncio.get_running_loop().time() - started >= 0.05
        assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_cancelling_relay_reaps_children():
    async with Tunnel() as t:
        before = asyncio.all_tasks()
        relay = t.relay()
        await asyncio.sleep(0.01)
        relay.cancel()
        with pytest.raises(asyncio.CancelledError):
            await relay
        assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_peer_reset_ends_relay_without_unretrieved_errors():
    loop = asyncio.get_running_loop()
    errors = []
    loop.set_exception_handler(lambda _loop, context: errors.append(context))
    try:
        async with Tunnel() as t:
            before = asyncio.all_tasks()
            relay = t.relay()
            t.client_w.write(b"data")
            t.origin_w.write(b"data")
            await asyncio.sleep(0.01)
            sock = t.origin_w.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            t.origin_w.transport.abort()
            await asyncio.wait_for(relay, 0.5)
            assert asyncio.all_tasks() == before
    finally:
        loop.set_exception_handler(None)
    assert errors == []


@pytest.mark.asyncio
async def test_large_bidirectional_transfer_is_intact():
    payload_down = os.urandom(8 * 1024 * 1024)
    payload_up = os.urandom(3 * 1024 * 1024)
    async with Tunnel() as t:
        relay = t.relay()

        async def send(writer, payload):
            for offset in range(0, len(payload), 100_000):
                writer.write(payload[offset : offset + 100_000])
                await writer.drain()
            writer.write_eof()

        async def receive(reader):
            return await reader.read()

        results = await asyncio.wait_for(
            asyncio.gather(
                send(t.origin_w, payload_down),
                send(t.client_w, payload_up),
                receive(t.client_r),
                receive(t.origin_r),
            ),
            10,
        )
        assert hashlib.sha256(results[2]).digest() == hashlib.sha256(payload_down).digest()
        assert hashlib.sha256(results[3]).digest() == hashlib.sha256(payload_up).digest()
        await asyncio.wait_for(relay, 1)


@pytest.mark.asyncio
async def test_client_half_close_still_receives_response():
    """A client that sends its request then shutdown(SHUT_WR) gets the reply."""
    async with Tunnel() as t:
        relay = t.relay()
        t.client_w.write(b"request")
        t.client_w.write_eof()
        assert await asyncio.wait_for(t.origin_r.read(), 0.5) == b"request"
        await asyncio.sleep(0.05)
        assert not relay.done(), "half-close must not tear down the response direction"
        t.origin_w.write(b"late response")
        t.origin_w.write_eof()
        assert await asyncio.wait_for(t.client_r.read(), 0.5) == b"late response"
        await asyncio.wait_for(relay, 0.5)


@pytest.mark.asyncio
async def test_upstream_half_close_lets_client_finish_uploading():
    async with Tunnel() as t:
        relay = t.relay()
        t.origin_w.write(b"ready")
        t.origin_w.write_eof()
        assert await asyncio.wait_for(t.client_r.read(), 0.5) == b"ready"
        assert not relay.done()
        t.client_w.write(b"trailing upload")
        t.client_w.write_eof()
        assert await asyncio.wait_for(t.origin_r.read(), 0.5) == b"trailing upload"
        await asyncio.wait_for(relay, 0.5)


@pytest.mark.asyncio
async def test_data_buffered_before_relay_is_forwarded():
    """Bytes pipelined right after the CONNECT head must not be lost."""
    async with Tunnel() as t:
        t.client_w.write(b"pipelined-client-hello")
        t.origin_w.write(b"early-server-bytes")
        await asyncio.sleep(0.02)
        # Let the StreamReaders buffer the data before the relay takes over.
        assert await t.proxy_client_r.readexactly(4) == b"pipe"
        relay = t.relay()
        assert await asyncio.wait_for(t.origin_r.readexactly(18), 0.5) == b"lined-client-hello"
        assert await asyncio.wait_for(t.client_r.readexactly(18), 0.5) == b"early-server-bytes"
        relay.cancel()
        await asyncio.gather(relay, return_exceptions=True)


@pytest.mark.asyncio
async def test_slow_reader_applies_backpressure_to_sender():
    async with Tunnel() as t:
        t.client_w.transport.pause_reading()
        relay = t.relay()
        sent = 0
        chunk = b"x" * 65536
        # The origin can only push until kernel buffers and the bounded relay
        # buffer are full; then its own drain() must block.
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.5):
                while True:
                    t.origin_w.write(chunk)
                    sent += len(chunk)
                    await t.origin_w.drain()
        buffered = t.proxy_client_w.transport.get_write_buffer_size()
        assert buffered <= server._RELAY_WRITE_HIGH_WATER + 256 * 1024
        t.client_w.transport.resume_reading()
        received = 0
        while received < sent:
            received += len(await asyncio.wait_for(t.client_r.read(1 << 20), 1))
        assert received == sent
        relay.cancel()
        await asyncio.gather(relay, return_exceptions=True)


# ------------------------------------------------------------ connecting


@pytest.mark.asyncio
async def test_dns_is_inside_connect_timeout(monkeypatch):
    cancelled = asyncio.Event()

    async def blocked_dns(*args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(server, "_resolve_public_addresses", blocked_dns)
    async with asyncio.timeout(0.5):
        with pytest.raises(ConnectionError, match="dns.*TimeoutError"):
            await server._open_public_connection("example.com", 443, config(connect_timeout_seconds=0.03))
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_dns_and_tcp_share_one_deadline(monkeypatch):
    cancelled = asyncio.Event()

    async def delayed_dns(*args):
        await asyncio.sleep(0.05)
        return public_rows("8.8.8.8")

    async def slow_connect(**kwargs):
        try:
            await asyncio.sleep(0.05)
            return asyncio.StreamReader(), MemoryWriter()
        finally:
            cancelled.set()

    monkeypatch.setattr(server, "_resolve_public_addresses", delayed_dns)
    monkeypatch.setattr(asyncio, "open_connection", slow_connect)
    with pytest.raises(ConnectionError, match="tcp.*TimeoutError"):
        await server._open_public_connection("example.com", 443, config(connect_timeout_seconds=0.08))
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_healthy_first_address_uses_a_single_handshake(monkeypatch):
    attempts = []

    async def resolve(*args):
        return public_rows(*(f"8.8.8.{i}" for i in range(1, 9)))

    async def connect(**kwargs):
        attempts.append(kwargs["host"])
        return asyncio.StreamReader(), MemoryWriter()

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    await server._open_public_connection("example.com", 443, config())
    assert attempts == ["8.8.8.1"]


@pytest.mark.asyncio
async def test_successful_losing_connections_are_closed(monkeypatch):
    monkeypatch.setattr(server, "_HAPPY_EYEBALLS_DELAY", 0.01)
    writers = {}
    release = asyncio.Event()

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        writer = MemoryWriter()
        writers[kwargs["host"]] = writer
        # Both attempts complete in the same loop iteration.
        await release.wait()
        return asyncio.StreamReader(), writer

    async def open_both():
        while len(writers) < 2:
            await asyncio.sleep(0.005)
        release.set()

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    opener = asyncio.create_task(open_both())
    _, winner = await server._open_public_connection("example.com", 443, config())
    await opener
    assert len(writers) == 2
    assert not winner.closed
    assert all(w.closed for w in writers.values() if w is not winner)


@pytest.mark.asyncio
async def test_failed_attempt_starts_next_address_without_delay(monkeypatch):
    monkeypatch.setattr(server, "_HAPPY_EYEBALLS_DELAY", 5)

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        if kwargs["host"] == "8.8.8.8":
            raise ConnectionRefusedError("refused")
        return asyncio.StreamReader(), MemoryWriter()

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    await asyncio.wait_for(server._open_public_connection("example.com", 443, config()), 0.5)


@pytest.mark.asyncio
async def test_all_addresses_are_tried_not_only_the_first_eight(monkeypatch):
    attempts = []

    async def resolve(*args):
        return public_rows(*(f"8.8.8.{i}" for i in range(1, 12)))

    async def connect(**kwargs):
        attempts.append(kwargs["host"])
        if kwargs["host"] != "8.8.8.11":
            raise ConnectionRefusedError("refused")
        return asyncio.StreamReader(), MemoryWriter()

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    await server._open_public_connection("example.com", 443, config())
    assert len(attempts) == 11


@pytest.mark.asyncio
async def test_all_failed_addresses_raise_connection_error(monkeypatch):
    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    with pytest.raises(ConnectionError, match="tcp.*ConnectionRefusedError"):
        await server._open_public_connection("example.com", 443, config())


@pytest.mark.asyncio
async def test_blackholed_address_is_demoted_for_later_connections(monkeypatch):
    monkeypatch.setattr(server, "_HAPPY_EYEBALLS_DELAY", 0.05)
    attempts = []

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        attempts.append(kwargs["host"])
        if kwargs["host"] == "8.8.8.8":
            await asyncio.Event().wait()
        return asyncio.StreamReader(), MemoryWriter()

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    await server._open_public_connection("example.com", 443, config())
    assert attempts == ["8.8.8.8", "1.1.1.1"]
    attempts.clear()
    loop = asyncio.get_running_loop()
    started = loop.time()
    await server._open_public_connection("example.com", 443, config())
    assert attempts == ["1.1.1.1"]
    assert loop.time() - started < 0.05


def test_address_order_interleaves_families_and_dedupes():
    rows = public_rows("2001:4860::1", "2001:4860::2", "8.8.8.8", "8.8.4.4", "8.8.8.8")

    async def order():
        return [row[4][0] for row in server._order_addresses(rows)]

    assert asyncio.run(order()) == ["2001:4860::1", "8.8.8.8", "2001:4860::2", "8.8.4.4"]


@pytest.mark.asyncio
async def test_cancelled_connect_cancels_all_attempts(monkeypatch):
    monkeypatch.setattr(server, "_HAPPY_EYEBALLS_DELAY", 0.005)
    started, stopped = [], []

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        started.append(kwargs["host"])
        try:
            await asyncio.Event().wait()
        finally:
            stopped.append(kwargs["host"])

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    task = asyncio.create_task(server._open_public_connection("example.com", 443, config()))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(started) == 2
    assert sorted(started) == sorted(stopped)


@pytest.mark.asyncio
async def test_cancellation_during_race_cleanup_closes_unreturned_winner(monkeypatch):
    monkeypatch.setattr(server, "_HAPPY_EYEBALLS_DELAY", 0.005)
    winner = MemoryWriter()
    cleanup_started = asyncio.Event()

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        if kwargs["host"] == "1.1.1.1":
            return asyncio.StreamReader(), winner
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_started.set()
            await asyncio.sleep(0.1)

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    task = asyncio.create_task(server._open_public_connection("example.com", 443, config()))
    await asyncio.wait_for(cleanup_started.wait(), 0.5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert winner.closed


# --------------------------------------------------------------- closing


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["timeout", "cancel", "error"])
async def test_writer_cleanup_aborts_unfinished_shutdown(monkeypatch, mode):
    class StuckWriter(MemoryWriter):
        async def wait_closed(self):
            if mode == "error":
                raise OSError("TLS shutdown failed")
            await asyncio.Event().wait()

    monkeypatch.setattr(server, "_STREAM_CLOSE_TIMEOUT", 0.03)
    writer = StuckWriter()
    if mode == "cancel":
        task = asyncio.create_task(server._close_writer(writer))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await asyncio.wait_for(server._close_writer(writer), 0.5)
    assert writer.closed and writer.aborted


@pytest.mark.asyncio
async def test_close_keeps_flushing_to_a_slow_but_live_reader(monkeypatch):
    """The end of a response must reach a slow client instead of being cut."""
    monkeypatch.setattr(server, "_STREAM_CLOSE_TIMEOUT", 0.1)
    proxy_r, proxy_w, peer_r, peer_w = await stream_pair()
    try:
        peer_w.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        # A large kernel send buffer that only reports writability once much
        # of it is free (Linux's default behaviour) keeps the user-space
        # buffer unchanged for long stretches while the kernel still drains.
        proxy_sock = proxy_w.get_extra_info("socket")
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        with contextlib.suppress(OSError):
            proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDLOWAT, 2 * 1024 * 1024)
        payload = os.urandom(6 * 1024 * 1024)
        proxy_w.write(payload)
        closer = asyncio.create_task(server._close_writer(proxy_w))
        received = bytearray()
        while True:
            chunk = await asyncio.wait_for(peer_r.read(512 * 1024), 2)
            if not chunk:
                break
            received.extend(chunk)
            await asyncio.sleep(0.03)
        await asyncio.wait_for(closer, 2)
        assert len(received) == len(payload)
        assert bytes(received) == payload
    finally:
        peer_w.transport.abort()


@pytest.mark.asyncio
@pytest.mark.parametrize("lifetime", [0, 0.04])
async def test_tunnel_lifetime_is_optional_and_cleanup_is_complete(monkeypatch, lifetime):
    async with Tunnel() as t:
        async def open_upstream(*args):
            return t.proxy_up_r, t.proxy_up_w

        monkeypatch.setattr(server, "_open_public_connection", open_upstream)
        proxy = server.SelectiveProxyServer(config(tunnel_max_seconds=lifetime, idle_timeout_seconds=0.1))
        before = asyncio.all_tasks()
        tunnel = asyncio.create_task(proxy._handle_connect("example.com:443", t.proxy_client_w, t.proxy_client_r))
        try:
            for _ in range(8):
                t.origin_w.write(b"active")
                await asyncio.sleep(0.02)
            if lifetime:
                assert tunnel.done()
            else:
                assert not tunnel.done()
                t.origin_w.write_eof()
                t.client_w.write_eof()
            await asyncio.wait_for(tunnel, 0.5)
            assert t.proxy_up_w.is_closing()
            await asyncio.sleep(0)
            assert asyncio.all_tasks() == before
        finally:
            tunnel.cancel()
            await asyncio.gather(tunnel, return_exceptions=True)


@pytest.mark.asyncio
async def test_connect_reply_failure_still_closes_upstream(monkeypatch):
    class BrokenWriter(MemoryWriter):
        async def drain(self):
            raise ConnectionResetError("client disconnected before CONNECT reply")

    upstream_writer = MemoryWriter()

    async def open_upstream(*args):
        return asyncio.StreamReader(), upstream_writer

    monkeypatch.setattr(server, "_open_public_connection", open_upstream)
    with pytest.raises(ConnectionResetError):
        await server.SelectiveProxyServer(config())._handle_connect("example.com:443", BrokenWriter(), asyncio.StreamReader())
    assert upstream_writer.closed


def test_tunnel_lifetime_config_defaults_to_disabled_and_keeps_explicit_limit(monkeypatch):
    monkeypatch.setenv("PROXY_PASSWORD", "test-only")
    monkeypatch.delenv("PROXY_TUNNEL_MAX_SECONDS", raising=False)
    assert server.load_config().tunnel_max_seconds == 0
    monkeypatch.setenv("PROXY_TUNNEL_MAX_SECONDS", "1800")
    assert server.load_config().tunnel_max_seconds == 1800


def test_performance_settings_have_safe_defaults_and_overrides(monkeypatch):
    monkeypatch.setenv("PROXY_PASSWORD", "test-only")
    for name in ("PROXY_DNS_CACHE_SECONDS", "PROXY_DNS_WORKERS", "PROXY_LISTEN_BACKLOG"):
        monkeypatch.delenv(name, raising=False)
    defaults = server.load_config()
    assert (defaults.dns_cache_seconds, defaults.dns_workers, defaults.listen_backlog) == (30, 32, 1024)
    monkeypatch.setenv("PROXY_DNS_CACHE_SECONDS", "0")
    monkeypatch.setenv("PROXY_DNS_WORKERS", "64")
    monkeypatch.setenv("PROXY_LISTEN_BACKLOG", "4096")
    tuned = server.load_config()
    assert (tuned.dns_cache_seconds, tuned.dns_workers, tuned.listen_backlog) == (0, 64, 4096)
