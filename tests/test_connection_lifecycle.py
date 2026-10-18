from __future__ import annotations

import asyncio
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
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in addresses]


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", [0, 1])
async def test_active_one_way_traffic_outlives_idle_timeout(direction):
    readers = [asyncio.StreamReader(), asyncio.StreamReader()]
    writers = [MemoryWriter(), MemoryWriter()]
    relay = asyncio.create_task(server._relay_bidirectionally(readers[0], writers[0], readers[1], writers[1], idle_timeout=0.08))
    try:
        for _ in range(12):
            readers[direction].feed_data(b"streaming-data")
            await asyncio.sleep(0.02)
            assert not relay.done(), "Active one-way traffic must keep the tunnel alive"
        readers[direction].feed_eof()
        await asyncio.wait_for(relay, 0.5)
        assert bytes(writers[1-direction].data) == b"streaming-data" * 12
    finally:
        relay.cancel()
        await asyncio.gather(relay, return_exceptions=True)


@pytest.mark.asyncio
async def test_truly_idle_tunnel_expires_and_reaps_children():
    before = asyncio.all_tasks()
    async with asyncio.timeout(0.5):
        await server._relay_bidirectionally(asyncio.StreamReader(), MemoryWriter(), asyncio.StreamReader(), MemoryWriter(), idle_timeout=0.03)
    assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_cancelling_relay_reaps_both_pumps_and_idle_watch():
    before = asyncio.all_tasks()
    relay = asyncio.create_task(server._relay_bidirectionally(asyncio.StreamReader(), MemoryWriter(), asyncio.StreamReader(), MemoryWriter(), idle_timeout=10))
    await asyncio.sleep(0.01)
    relay.cancel()
    with pytest.raises(asyncio.CancelledError):
        await relay
    assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_concurrent_transport_errors_are_all_retrieved():
    class BrokenWriter(MemoryWriter):
        async def drain(self):
            raise OSError("simulated TLS transport failure")

    readers = [asyncio.StreamReader(), asyncio.StreamReader()]
    for reader in readers:
        reader.feed_data(b"data")
    before = asyncio.all_tasks()
    await server._relay_bidirectionally(readers[0], BrokenWriter(), readers[1], BrokenWriter(), idle_timeout=1)
    assert asyncio.all_tasks() == before


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
async def test_successful_losing_connections_are_closed(monkeypatch):
    writers = []

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        writer = MemoryWriter()
        writers.append(writer)
        return asyncio.StreamReader(), writer

    monkeypatch.setattr(server, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    _, winner = await server._open_public_connection("example.com", 443, config())
    assert len(writers) == 2
    assert not winner.closed
    assert all(w.closed for w in writers if w is not winner)


@pytest.mark.asyncio
async def test_cancelled_connect_cancels_all_attempts(monkeypatch):
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
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(started) == 2
    assert sorted(started) == sorted(stopped)


@pytest.mark.asyncio
async def test_cancellation_during_race_cleanup_closes_unreturned_winner(monkeypatch):
    winner = MemoryWriter()
    cleanup_started = asyncio.Event()

    async def resolve(*args):
        return public_rows("8.8.8.8", "1.1.1.1")

    async def connect(**kwargs):
        if kwargs["host"] == "8.8.8.8":
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
@pytest.mark.parametrize("lifetime", [0, 0.04])
async def test_tunnel_lifetime_is_optional_and_cleanup_is_complete(monkeypatch, lifetime):
    upstream_reader, upstream_writer = asyncio.StreamReader(), MemoryWriter()
    client_reader, client_writer = asyncio.StreamReader(), MemoryWriter()

    async def open_upstream(*args):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(server, "_open_public_connection", open_upstream)
    proxy = server.SelectiveProxyServer(config(tunnel_max_seconds=lifetime, idle_timeout_seconds=0.1))
    before = asyncio.all_tasks()
    tunnel = asyncio.create_task(proxy._handle_connect("example.com:443", client_writer, client_reader))
    try:
        for _ in range(8):
            upstream_reader.feed_data(b"active")
            await asyncio.sleep(0.02)
        if lifetime:
            assert tunnel.done()
        else:
            assert not tunnel.done()
            upstream_reader.feed_eof()
        await asyncio.wait_for(tunnel, 0.5)
        assert upstream_writer.closed
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
