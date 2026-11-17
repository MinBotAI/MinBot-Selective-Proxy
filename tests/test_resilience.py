from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import socket

import pytest

import minbot_selective_proxy.server as server


def rows(*addresses):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0)) for ip in addresses]


class FakeResolver:
    def __init__(self, monkeypatch, answer=("93.184.216.34",), delay=0.0):
        self.calls = []
        self.answer = answer
        self.delay = delay
        self.error: OSError | None = None
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", self)

    async def __call__(self, host, *args, **kwargs):
        self.calls.append(host)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return rows(*self.answer)


# ------------------------------------------------------------------- DNS


@pytest.mark.asyncio
async def test_concurrent_lookups_for_one_host_share_a_single_resolution(monkeypatch):
    resolver = FakeResolver(monkeypatch, delay=0.05)
    results = await asyncio.gather(
        *(server._resolve_public_addresses("cdn.example.com", 443) for _ in range(50))
    )
    assert resolver.calls == ["cdn.example.com"]
    assert all(result[0][4][0] == "93.184.216.34" for result in results)


@pytest.mark.asyncio
async def test_answers_are_cached_until_ttl_then_refreshed(monkeypatch):
    server._DNS_CACHE.ttl = 0.05
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("example.com", 443)
    await server._resolve_public_addresses("EXAMPLE.com", 8443)
    assert len(resolver.calls) == 1
    await asyncio.sleep(0.06)
    resolver.answer = ("93.184.216.35",)
    refreshed = await server._resolve_public_addresses("example.com", 443)
    assert refreshed[0][4][0] == "93.184.216.35"
    assert len(resolver.calls) == 2


@pytest.mark.asyncio
async def test_popular_entries_are_refreshed_before_expiry(monkeypatch):
    server._DNS_CACHE.ttl = 0.1
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("example.com", 443)
    await asyncio.sleep(0.085)
    await server._resolve_public_addresses("example.com", 443)  # served from cache
    await asyncio.sleep(0.01)
    assert len(resolver.calls) == 2, "a background refresh should have run"
    await asyncio.sleep(0.03)
    await server._resolve_public_addresses("example.com", 443)
    assert len(resolver.calls) == 2, "the refreshed answer should still be fresh"


@pytest.mark.asyncio
async def test_stale_answer_is_used_when_resolver_fails(monkeypatch):
    server._DNS_CACHE.ttl = 0.02
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("example.com", 443)
    await asyncio.sleep(0.03)
    resolver.error = socket.gaierror(socket.EAI_AGAIN, "temporary failure")
    stale = await server._resolve_public_addresses("example.com", 443)
    assert stale[0][4][0] == "93.184.216.34"


@pytest.mark.asyncio
async def test_name_error_replaces_stale_answer_immediately(monkeypatch):
    server._DNS_CACHE.ttl = 0.02
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("deleted.example", 443)
    await asyncio.sleep(0.03)
    resolver.error = socket.gaierror(socket.EAI_NONAME, "not known")
    for _ in range(2):
        with pytest.raises(socket.gaierror):
            await server._resolve_public_addresses("deleted.example", 443)
    assert resolver.calls == ["deleted.example", "deleted.example"]


@pytest.mark.asyncio
async def test_stale_answer_expiring_during_refresh_is_not_used(monkeypatch):
    server._DNS_CACHE.ttl = 0.02
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("expired.example", 443)
    entry = server._DNS_CACHE._entries["expired.example"]
    entry.expires = asyncio.get_running_loop().time() - 1
    entry.stale_until = asyncio.get_running_loop().time() + 0.01
    resolver.delay = 0.03
    resolver.error = socket.gaierror(socket.EAI_AGAIN, "temporary failure")
    with pytest.raises(socket.gaierror):
        await server._resolve_public_addresses("expired.example", 443)


@pytest.mark.asyncio
async def test_stale_answer_is_used_when_resolver_is_slow(monkeypatch):
    server._DNS_CACHE.ttl = 0.02
    monkeypatch.setattr(server, "_DNS_STALE_WAIT", 0.02)
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("example.com", 443)
    await asyncio.sleep(0.03)
    resolver.delay = 1.0
    loop = asyncio.get_running_loop()
    started = loop.time()
    stale = await server._resolve_public_addresses("example.com", 443)
    assert loop.time() - started < 0.5
    assert stale[0][4][0] == "93.184.216.34"


@pytest.mark.asyncio
async def test_name_errors_are_cached_briefly(monkeypatch):
    resolver = FakeResolver(monkeypatch)
    resolver.error = socket.gaierror(socket.EAI_NONAME, "not known")
    for _ in range(3):
        with pytest.raises(ConnectionError, match="dns.*gaierror"):
            await server._open_public_connection(
                "missing.example", 443,
                server.ProxyConfig(username="u", password="p", domains=("example.com",)),
            )
    assert resolver.calls == ["missing.example"]


@pytest.mark.asyncio
async def test_temporary_failures_are_not_cached(monkeypatch):
    resolver = FakeResolver(monkeypatch)
    resolver.error = socket.gaierror(socket.EAI_AGAIN, "temporary failure")
    with pytest.raises(socket.gaierror):
        await server._resolve_public_addresses("flaky.example", 443)
    resolver.error = None
    assert await server._resolve_public_addresses("flaky.example", 443)
    assert len(resolver.calls) == 2


@pytest.mark.asyncio
async def test_caller_timeout_does_not_cancel_the_shared_lookup(monkeypatch):
    resolver = FakeResolver(monkeypatch, delay=0.05)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await server._resolve_public_addresses("example.com", 443)
    await asyncio.sleep(0.06)
    await server._resolve_public_addresses("example.com", 443)
    assert len(resolver.calls) == 1


@pytest.mark.asyncio
async def test_cached_private_answers_are_still_rejected(monkeypatch):
    resolver = FakeResolver(monkeypatch, answer=("10.0.0.5",))
    for _ in range(2):
        with pytest.raises(PermissionError, match="public address"):
            await server._resolve_public_addresses("internal.example", 443)
    assert len(resolver.calls) == 1


@pytest.mark.asyncio
async def test_ip_literals_skip_the_resolver(monkeypatch):
    resolver = FakeResolver(monkeypatch)
    v4 = await server._resolve_public_addresses("93.184.216.34", 8443)
    v6 = await server._resolve_public_addresses("[2606:4700::1111]", 443)
    assert resolver.calls == []
    assert v4[0][0] == socket.AF_INET and v4[0][4][0] == "93.184.216.34"
    assert v6[0][0] == socket.AF_INET6 and v6[0][4][0] == "2606:4700::1111"
    with pytest.raises(PermissionError):
        await server._resolve_public_addresses("127.0.0.1", 443)


@pytest.mark.asyncio
async def test_zero_ttl_disables_the_cache(monkeypatch):
    server._DNS_CACHE.ttl = 0
    resolver = FakeResolver(monkeypatch)
    await server._resolve_public_addresses("example.com", 443)
    await server._resolve_public_addresses("example.com", 443)
    assert len(resolver.calls) == 2


# ------------------------------------------------------- request handling


async def _proxy_request(
    proxy: server.SelectiveProxyServer, payload: bytes, *, half_close: bool = False
) -> bytes:
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        if half_close:
            writer.write_eof()
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 2)
        writer.close()
        await writer.wait_closed()
        return response
    finally:
        listener.close()
        await listener.wait_closed()


def _proxy() -> server.SelectiveProxyServer:
    return server.SelectiveProxyServer(
        server.ProxyConfig(username="proxy", password="secret", domains=("example.com",))
    )


_AUTH = "Proxy-Authorization: Basic " + base64.b64encode(b"proxy:secret").decode()


@pytest.mark.asyncio
async def test_malformed_connect_authority_is_rejected_cleanly(caplog):
    with caplog.at_level(logging.ERROR):
        response = await _proxy_request(
            _proxy(), f"CONNECT [::1:443 HTTP/1.1\r\n{_AUTH}\r\n\r\n".encode()
        )
    assert response.startswith(b"HTTP/1.1 403 Forbidden")
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.asyncio
async def test_unexpected_handler_error_is_contained(monkeypatch, caplog):
    proxy = _proxy()

    async def explode(*args):
        raise RuntimeError("bug")

    monkeypatch.setattr(proxy, "_handle_connect", explode)
    loop = asyncio.get_running_loop()
    unhandled = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    try:
        with caplog.at_level(logging.ERROR):
            response = await _proxy_request(
                proxy, f"CONNECT example.com:443 HTTP/1.1\r\n{_AUTH}\r\n\r\n".encode()
            )
    finally:
        loop.set_exception_handler(None)
    assert response == b""
    assert unhandled == []
    assert any("unexpected proxy connection error" in r.getMessage() for r in caplog.records)
    assert not proxy._slots.locked()


@pytest.mark.asyncio
async def test_end_to_end_connect_relays_pipelined_data_and_half_close(monkeypatch):
    """CONNECT through the real handler to a local origin, as curl -N would."""

    async def origin(reader, writer):
        request = await reader.read()  # until the client half-closes
        writer.write(b"echo:" + request)
        await writer.drain()
        writer.close()

    upstream = await asyncio.start_server(origin, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]

    async def open_local(host, port, _config):
        return await asyncio.open_connection("127.0.0.1", upstream_port)

    monkeypatch.setattr(server, "_open_public_connection", open_local)
    try:
        response = await _proxy_request(
            _proxy(),
            f"CONNECT example.com:443 HTTP/1.1\r\n{_AUTH}\r\n\r\n".encode()
            + b"pipelined-request",
            half_close=True,
        )
    finally:
        upstream.close()
        await upstream.wait_closed()
    head, _, body = response.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 Connection Established")
    assert body == b"echo:pipelined-request"


@pytest.mark.asyncio
async def test_tls_listener_relays_large_payload_and_closes_cleanly(monkeypatch, tmp_path):
    """Production clients reach the proxy over TLS; exercise that transport."""
    import hashlib
    import os
    import shutil
    import ssl
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl is required to create a throwaway certificate")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(tmp_path / "key.pem"), "-out", str(tmp_path / "cert.pem"),
            "-days", "1", "-subj", "/CN=proxy.test",
            "-addext", "subjectAltName=DNS:proxy.test",
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setenv("PROXY_TLS_CERT_PEM", (tmp_path / "cert.pem").read_text())
    monkeypatch.setenv("PROXY_TLS_KEY_PEM", (tmp_path / "key.pem").read_text())
    server_context = server.load_tls_context()
    client_context = ssl.create_default_context(cafile=str(tmp_path / "cert.pem"))
    payload = os.urandom(4 * 1024 * 1024)

    async def origin(reader, writer):
        request = await reader.readexactly(7)
        writer.write(request + payload)
        await writer.drain()
        writer.close()

    upstream = await asyncio.start_server(origin, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]

    async def open_local(host, port, _config):
        return await asyncio.open_connection("127.0.0.1", upstream_port)

    monkeypatch.setattr(server, "_open_public_connection", open_local)
    proxy = _proxy()
    listener = await asyncio.start_server(
        proxy.handle_client, "127.0.0.1", 0, ssl=server_context
    )
    port = listener.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context, server_hostname="proxy.test"
        )
        writer.write(
            f"CONNECT example.com:443 HTTP/1.1\r\n{_AUTH}\r\n\r\n".encode() + b"request"
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        body = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
            await writer.wait_closed()
    finally:
        listener.close()
        upstream.close()
        await upstream.wait_closed()
    assert head.startswith(b"HTTP/1.1 200 Connection Established")
    assert body[:7] == b"request"
    assert hashlib.sha256(body[7:]).digest() == hashlib.sha256(payload).digest()
    await asyncio.sleep(0.05)
    assert not proxy._slots.locked()
