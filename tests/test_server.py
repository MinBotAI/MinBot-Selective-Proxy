from __future__ import annotations

import asyncio
import base64
import json
import socket
import subprocess
from pathlib import Path

import pytest

from minbot_selective_proxy.server import (
    DEFAULT_PROXY_DOMAINS,
    ProxyConfig,
    SelectiveProxyServer,
    _admin_authorized,
    _authorized,
    _load_additional_users,
    _resolve_public_addresses,
    build_pac,
    domain_is_allowed,
    normalize_domains,
    normalize_proxy_authority,
)


def _config() -> ProxyConfig:
    return ProxyConfig(
        username="proxy",
        password="correct horse battery staple",
        domains=("example.com", "youtube.com"),
    )


def test_macos_tun_template_preserves_allowlisted_domains_for_http_proxy() -> None:
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["bash", str(repository / "install-macos.sh"), "_print-template"],
        check=True,
        capture_output=True,
        text=True,
    )
    config = json.loads(result.stdout)

    dns = config["dns"]
    assert {server["tag"]: server["type"] for server in dns["servers"]} == {
        "local": "local",
        "minbot-fakeip": "fakeip",
    }
    assert dns["rules"] == [
        {
            "rule_set": "minbot-domains",
            "action": "route",
            "server": "minbot-fakeip",
        }
    ]
    assert dns["final"] == "local"

    assert config["route"]["default_domain_resolver"] == "local"
    route_rules = config["route"]["rules"]
    dns_hijack_index = route_rules.index(
        {"protocol": "dns", "action": "hijack-dns"}
    )
    udp_direct_index = route_rules.index(
        {"network": "udp", "action": "route", "outbound": "direct"}
    )
    assert dns_hijack_index < udp_direct_index


def test_domain_allowlist_covers_subdomains_but_rejects_lookalikes_and_ips() -> None:
    domains = normalize_domains(["*.YouTube.com", "example.com", "example.com"])

    assert domains == ("example.com", "youtube.com")
    assert domain_is_allowed("www.youtube.com", domains)
    assert domain_is_allowed("EXAMPLE.COM.", domains)
    assert not domain_is_allowed("youtube.com.example.org", domains)
    assert not domain_is_allowed("127.0.0.1", domains)


def test_default_allowlist_covers_heygen_app_api_and_first_party_assets() -> None:
    assert domain_is_allowed("www.heygen.com", DEFAULT_PROXY_DOMAINS)
    assert domain_is_allowed("app.heygen.com", DEFAULT_PROXY_DOMAINS)
    assert domain_is_allowed("api.heygen.com", DEFAULT_PROXY_DOMAINS)
    assert domain_is_allowed("static.heygen.ai", DEFAULT_PROXY_DOMAINS)
    assert domain_is_allowed("files2.heygen.ai", DEFAULT_PROXY_DOMAINS)
    assert not domain_is_allowed("heygen.com.example.org", DEFAULT_PROXY_DOMAINS)


def test_pac_defaults_to_direct_and_routes_only_allowlisted_domains() -> None:
    pac = build_pac("proxy.example:3128", ("youtube.com", "x.com"))

    assert 'var proxy = "PROXY proxy.example:3128"' in pac
    assert '"youtube.com"' in pac
    assert '"x.com"' in pac
    assert 'return "DIRECT"' in pac
    assert "dnsDomainIs(host, \".\" + domains[i])" in pac


def test_pac_proxy_authority_rejects_script_injection() -> None:
    assert normalize_proxy_authority("Proxy.Example.:3128") == "proxy.example:3128"

    with pytest.raises(ValueError, match="invalid proxy authority"):
        build_pac('proxy.example;alert(1):3128', ("youtube.com",))


def test_proxy_basic_auth_uses_proxy_authorization_header() -> None:
    config = _config()
    encoded = base64.b64encode(
        f"{config.username}:{config.password}".encode()
    ).decode()

    assert _authorized({"proxy-authorization": f"Basic {encoded}"}, config)
    assert not _authorized({"authorization": f"Basic {encoded}"}, config)
    assert not _authorized({"proxy-authorization": "Basic invalid"}, config)


def test_additional_proxy_users_can_use_proxy_and_admin_auth() -> None:
    config = ProxyConfig(
        username="primary",
        password="primary-secret",
        domains=("example.com",),
        additional_users=(("second", "second-secret"),),
    )
    encoded = base64.b64encode(b"second:second-secret").decode()

    assert _authorized({"proxy-authorization": f"Basic {encoded}"}, config)
    assert _admin_authorized({"authorization": f"Basic {encoded}"}, config)
    assert not _admin_authorized({"proxy-authorization": f"Basic {encoded}"}, config)


def test_additional_proxy_users_load_from_secret_json() -> None:
    assert _load_additional_users('{"second":"second-secret"}') == (
        ("second", "second-secret"),
    )

    with pytest.raises(RuntimeError, match="JSON object"):
        _load_additional_users("[]")


@pytest.mark.asyncio
async def test_direct_pac_endpoint_is_public_but_proxy_requests_require_auth() -> None:
    proxy = SelectiveProxyServer(_config())
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]

    async def request(payload: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        return response

    try:
        pac_response = await request(
            b"GET /proxy.pac HTTP/1.1\r\nHost: proxy.example:3128\r\n\r\n"
        )
        proxy_response = await request(
            b"CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n"
        )
    finally:
        listener.close()
        await listener.wait_closed()

    assert pac_response.startswith(b"HTTP/1.1 200 OK")
    assert b"application/x-ns-proxy-autoconfig" in pac_response
    assert b"PROXY proxy.example:3128" in pac_response
    assert proxy_response.startswith(b"HTTP/1.1 407 Proxy Authentication Required")
    assert b"Proxy-Authenticate: Basic" in proxy_response


@pytest.mark.asyncio
async def test_authenticated_proxy_still_rejects_nonallowlisted_destination() -> None:
    config = _config()
    proxy = SelectiveProxyServer(config)
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(
        f"{config.username}:{config.password}".encode()
    ).decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        (
            "CONNECT example.org:443 HTTP/1.1\r\n"
            "Host: example.org:443\r\n"
            f"Proxy-Authorization: Basic {encoded}\r\n\r\n"
        ).encode()
    )
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    listener.close()
    await listener.wait_closed()

    assert response.startswith(b"HTTP/1.1 403 Forbidden")
    assert b"outside the proxy allowlist" in response


@pytest.mark.asyncio
async def test_allowlist_api_requires_auth_and_updates_pac(tmp_path) -> None:
    config = ProxyConfig(
        username="proxy",
        password="secret",
        domains=("youtube.com",),
        domains_state_path=str(tmp_path / "domains.json"),
    )
    proxy = SelectiveProxyServer(config)
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(b"proxy:secret").decode()

    async def request(payload: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        return response

    body = json.dumps({"domain": "Example.COM"}).encode()
    try:
        unauthorized = await request(
            b"GET /api/domains HTTP/1.1\r\nHost: proxy.example\r\n\r\n"
        )
        added = await request(
            (
                "POST /api/domains HTTP/1.1\r\n"
                "Host: proxy.example\r\n"
                f"Authorization: Basic {encoded}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode()
            + body
        )
        pac = await request(
            b"GET /proxy.pac HTTP/1.1\r\nHost: proxy.example:3128\r\n\r\n"
        )
        domain_set = await request(
            b"GET /domains.list HTTP/1.1\r\nHost: proxy.example:3128\r\n\r\n"
        )
        sing_box_rule_set = await request(
            b"GET /domains.sing-box.json HTTP/1.1\r\n"
            b"Host: proxy.example:3128\r\n\r\n"
        )
        removed = await request(
            (
                "DELETE /api/domains/example.com HTTP/1.1\r\n"
                "Host: proxy.example\r\n"
                f"Authorization: Basic {encoded}\r\n\r\n"
            ).encode()
        )
    finally:
        listener.close()
        await listener.wait_closed()

    assert unauthorized.startswith(b"HTTP/1.1 401 Unauthorized")
    assert added.startswith(b"HTTP/1.1 200 OK")
    assert b'"example.com"' in added
    assert b'"example.com"' in pac
    assert domain_set.startswith(b"HTTP/1.1 200 OK")
    assert b".example.com\n" in domain_set
    assert b".youtube.com\n" in domain_set
    assert sing_box_rule_set.startswith(b"HTTP/1.1 200 OK")
    assert b"Content-Type: application/json" in sing_box_rule_set
    sing_box_payload = json.loads(sing_box_rule_set.split(b"\r\n\r\n", 1)[1])
    assert sing_box_payload == {
        "version": 3,
        "rules": [{"domain_suffix": ["example.com", "youtube.com"]}],
    }
    assert removed.startswith(b"HTTP/1.1 200 OK")
    assert b'"example.com"' not in removed
    assert json.loads((tmp_path / "domains.json").read_text()) == {
        "version": 1,
        "domains": ["youtube.com"],
    }


@pytest.mark.asyncio
async def test_allowlist_state_survives_server_restart(tmp_path) -> None:
    state_path = tmp_path / "domains.json"
    config = ProxyConfig(
        username="proxy",
        password="secret",
        domains=("youtube.com",),
        domains_state_path=str(state_path),
    )
    first = SelectiveProxyServer(config)

    await first.allowlist.add("example.com")
    restored = SelectiveProxyServer(config)

    assert restored.allowlist.domains == ("example.com", "youtube.com")


@pytest.mark.asyncio
async def test_dns_validation_keeps_only_public_addresses(monkeypatch) -> None:
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.4", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    rows = await _resolve_public_addresses("example.com", 443)

    assert [row[4][0] for row in rows] == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_dns_validation_rejects_private_only_resolution(monkeypatch) -> None:
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.8", 443)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(PermissionError, match="public address"):
        await _resolve_public_addresses("example.com", 443)
