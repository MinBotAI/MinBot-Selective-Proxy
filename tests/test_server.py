from __future__ import annotations

import asyncio
import base64
import json
import os
import plistlib
import socket
import subprocess
from pathlib import Path

import pytest
import minbot_selective_proxy.server as server_module

from minbot_selective_proxy.server import (
    DEFAULT_PROXY_DOMAIN_GROUPS,
    DEFAULT_PROXY_DOMAINS,
    DEFAULT_PROXY_IP_CIDRS,
    ProxyConfig,
    SelectiveProxyServer,
    _admin_authorized,
    _authorized,
    _load_additional_users,
    _open_public_connection,
    _parse_tls_client_hello_sni,
    _read_tls_client_hello_sni,
    _resolve_public_addresses,
    build_pac,
    domain_is_allowed,
    load_tls_context,
    normalize_domains,
    normalize_proxy_authority,
)


def _config() -> ProxyConfig:
    return ProxyConfig(
        username="proxy",
        password="correct horse battery staple",
        domains=("example.com", "youtube.com"),
    )


def _tls_client_hello(server_name: str) -> bytes:
    encoded_name = server_name.encode("ascii")
    server_name_entry = b"\x00" + len(encoded_name).to_bytes(2, "big") + encoded_name
    server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    server_name_extension = (
        b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    )
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(server_name_extension).to_bytes(2, "big")
        + server_name_extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_tls_client_hello_parser_extracts_normalized_sni() -> None:
    record = _tls_client_hello("WWW.Dropbox.COM")

    assert _parse_tls_client_hello_sni(record[5:]) == "www.dropbox.com"


@pytest.mark.asyncio
async def test_tls_client_hello_reader_accepts_fragmented_records() -> None:
    record = _tls_client_hello("x.com")
    handshake = record[5:]
    split_at = 19
    fragmented = (
        b"\x16\x03\x01"
        + split_at.to_bytes(2, "big")
        + handshake[:split_at]
        + b"\x16\x03\x01"
        + (len(handshake) - split_at).to_bytes(2, "big")
        + handshake[split_at:]
    )
    reader = asyncio.StreamReader()
    reader.feed_data(fragmented)
    reader.feed_eof()

    server_name, buffered = await _read_tls_client_hello_sni(reader, timeout=0.1)

    assert server_name == "x.com"
    assert buffered == fragmented


def test_macos_tun_template_preserves_allowlisted_domains_for_http_proxy() -> None:
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["bash", str(repository / "install-macos.sh"), "_print-template"],
        check=True,
        capture_output=True,
        text=True,
    )
    config = json.loads(result.stdout)

    assert config["log"] == {"level": "warn", "timestamp": True}

    dns = config["dns"]
    assert {server["tag"]: server["type"] for server in dns["servers"]} == {
        "alidns-doh": "https",
        "minbot-fakeip": "fakeip",
    }
    alidns = next(server for server in dns["servers"] if server["tag"] == "alidns-doh")
    assert alidns == {
        "type": "https",
        "tag": "alidns-doh",
        "server": "223.5.5.5",
        "server_port": 443,
        "path": "/dns-query",
        "tls": {"enabled": True, "server_name": "dns.alidns.com"},
    }
    assert dns["rules"] == [
        {
            "query_type": ["HTTPS", "SVCB"],
            "action": "predefined",
            "rcode": "NOERROR",
        },
        {
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "minbot-fakeip",
        }
    ]
    assert dns["final"] == "alidns-doh"
    assert dns["independent_cache"] is True

    assert config["route"]["default_domain_resolver"] == "alidns-doh"
    route_rules = config["route"]["rules"]
    tls_sniff_index = route_rules.index(
        {
            "network": "tcp",
            "port": 443,
            "action": "sniff",
            "sniffer": ["tls"],
            "timeout": "300ms",
        }
    )
    dns_hijack_index = route_rules.index(
        {"protocol": "dns", "action": "hijack-dns"}
    )
    udp_direct_index = route_rules.index(
        {"network": "udp", "action": "route", "outbound": "direct"}
    )
    allowlist_udp_reject_index = route_rules.index(
        {"network": "udp", "rule_set": "minbot-domains", "action": "reject"}
    )
    global_quic_reject_index = route_rules.index(
        {"network": "udp", "port": 443, "action": "reject"}
    )
    allowlist_proxy_index = route_rules.index(
        {
            "rule_set": "minbot-domains",
            "action": "route",
            "outbound": "minbot-egress",
        }
    )
    codex_proxy_index = route_rules.index(
        {
            "network": "tcp",
            "process_path_regex": ["/(ChatGPT|Codex)\\.app/Contents/"],
            "action": "route",
            "outbound": "minbot-egress",
        }
    )
    mainland_direct_index = route_rules.index(
        {
            "network": "tcp",
            "domain_suffix": ["feishu.cn", "feishucdn.com"],
            "action": "route",
            "outbound": "direct",
        }
    )
    app_attest_direct_index = route_rules.index(
        {
            "network": "tcp",
            "domain": ["register.appattest.apple.com"],
            "action": "route",
            "outbound": "direct",
        }
    )
    assert tls_sniff_index < dns_hijack_index < global_quic_reject_index
    assert global_quic_reject_index < allowlist_udp_reject_index < udp_direct_index
    assert udp_direct_index < mainland_direct_index < app_attest_direct_index
    assert app_attest_direct_index < codex_proxy_index
    assert codex_proxy_index < allowlist_proxy_index

    outbound = next(
        item for item in config["outbounds"] if item["tag"] == "minbot-egress"
    )
    assert outbound["server_port"] == 31528
    assert outbound["tls"] == {
        "enabled": True,
        "server_name": "minbot-egress.local",
        "certificate_public_key_sha256": [
            "GVMj+hTQYmgLDC+XzCL7Sy3MTneSXdqHwUoEcQ9qrXs="
        ],
    }
    assert config["route"]["rule_set"][0]["url"] == (
        "http://43.156.119.18:31456/domains.sing-box.json"
    )
    assert "experimental" not in config


def test_macos_installer_supports_launchd_background_service() -> None:
    repository = Path(__file__).resolve().parents[1]
    installer = (repository / "install-macos.sh").read_text()
    result = subprocess.run(
        ["bash", str(repository / "install-macos.sh"), "_print-launchd-template"],
        check=True,
        capture_output=True,
    )
    plist = plistlib.loads(result.stdout)

    assert 'readonly LAUNCHD_LABEL="ai.minbot.selective-proxy"' in installer
    assert plist["Label"] == "ai.minbot.selective-proxy"
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is True
    assert plist["WorkingDirectory"] == (
        "/Library/Application Support/MinBot Selective Proxy"
    )
    assert plist["ProgramArguments"] == [
        "/opt/homebrew/bin/sing-box",
        "run",
        "-c",
        "/Library/Application Support/MinBot Selective Proxy/config.json",
    ]
    bootstrap_index = installer.index(
        'sudo launchctl bootstrap system "${DAEMON_PLIST}"'
    )
    enable_index = installer.index(
        'sudo launchctl enable "system/${LAUNCHD_LABEL}"'
    )
    assert enable_index < bootstrap_index
    assert 'sudo launchctl kickstart -k "system/${LAUNCHD_LABEL}"' in installer
    assert 'sudo install -d -m 0700 "${DAEMON_DIR}"' in installer
    assert '"${DAEMON_DIR}/cache.db-wal"' in installer
    assert 'sudo install -m 0600 -o root -g wheel /dev/null "${DAEMON_LOG}"' in installer
    assert 'sudo install -m 0600 -o root -g wheel' in installer


def test_macos_installer_reports_its_version() -> None:
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["bash", str(repository / "install-macos.sh"), "version"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "minbot-proxy 1.4.0"


def test_tls_certificate_and_key_must_be_configured_together(monkeypatch) -> None:
    monkeypatch.setenv("PROXY_TLS_CERT_PEM", "certificate only")
    monkeypatch.delenv("PROXY_TLS_KEY_PEM", raising=False)

    with pytest.raises(RuntimeError, match="must be configured together"):
        load_tls_context()


def test_tls_listener_is_optional(monkeypatch) -> None:
    monkeypatch.delenv("PROXY_TLS_CERT_PEM", raising=False)
    monkeypatch.delenv("PROXY_TLS_KEY_PEM", raising=False)

    assert load_tls_context() is None


def test_macos_installer_uses_current_script_without_git_clone(tmp_path) -> None:
    repository = Path(__file__).resolve().parents[1]
    script = tmp_path / "install-macos.sh"
    script.write_bytes((repository / "install-macos.sh").read_bytes())
    script.chmod(0o755)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    brew_prefix = tmp_path / "homebrew"
    fake_brew = fake_bin / "brew"
    fake_brew.write_text(
        f'#!/bin/bash\nif [[ "$1" == "--prefix" ]]; then echo "{brew_prefix}"; exit 0; fi\nexit 99\n'
    )
    fake_brew.chmod(0o755)
    fake_git = fake_bin / "git"
    fake_git.write_text("#!/bin/bash\nexit 99\n")
    fake_git.chmod(0o755)

    result = subprocess.run(
        ["bash", str(script), "_install-cli-current"],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    installed = brew_prefix / "bin" / "minbot-proxy"
    assert installed.read_bytes() == script.read_bytes()
    assert "from the current script" in result.stdout


def test_domain_allowlist_covers_subdomains_but_rejects_lookalikes_and_ips() -> None:
    domains = normalize_domains(["*.YouTube.com", "example.com", "example.com"])

    assert domains == ("example.com", "youtube.com")
    assert domain_is_allowed("www.youtube.com", domains)
    assert domain_is_allowed("EXAMPLE.COM.", domains)
    assert not domain_is_allowed("youtube.com.example.org", domains)
    assert not domain_is_allowed("127.0.0.1", domains)


def test_default_allowlist_covers_blocked_heygen_app_and_api() -> None:
    assert domain_is_allowed("www.heygen.com", DEFAULT_PROXY_DOMAINS)
    assert domain_is_allowed("app.heygen.com", DEFAULT_PROXY_DOMAINS)
    assert domain_is_allowed("api.heygen.com", DEFAULT_PROXY_DOMAINS)
    assert not domain_is_allowed("static.heygen.ai", DEFAULT_PROXY_DOMAINS)
    assert not domain_is_allowed("files2.heygen.ai", DEFAULT_PROXY_DOMAINS)
    assert not domain_is_allowed("heygen.com.example.org", DEFAULT_PROXY_DOMAINS)


@pytest.mark.parametrize(
    ("group", "domain"),
    [
        ("ai", "claude.ai"),
        ("google", "youtube.com"),
        ("social_and_messaging", "telegram.org"),
        ("media", "netflix.com"),
        ("developer_and_productivity", "github.com"),
        ("news_and_reference", "wikipedia.org"),
        ("shared_infrastructure", "cloudfront.net"),
    ],
)
def test_default_allowlist_covers_common_blocked_service_groups(
    group: str, domain: str
) -> None:
    assert domain in DEFAULT_PROXY_DOMAIN_GROUPS[group]
    assert domain_is_allowed(f"www.{domain}", DEFAULT_PROXY_DOMAINS)


def test_default_allowlist_is_normalized_unique_and_broad() -> None:
    grouped_domains = tuple(
        domain
        for domains in DEFAULT_PROXY_DOMAIN_GROUPS.values()
        for domain in domains
    )

    assert len(DEFAULT_PROXY_DOMAINS) == 249
    assert DEFAULT_PROXY_DOMAINS == normalize_domains(grouped_domains)


@pytest.mark.parametrize(
    "domain",
    [
        "amplitude.com",
        "anthropicusercontent.com",
        "bloomberg.net",
        "box.com",
        "boxcdn.net",
        "braze.com",
        "characterai.io",
        "contentfulassets.com",
        "ct.sendgrid.net",
        "datadoghq.com",
        "figma.net",
        "heygen.ai",
        "hubspot.com",
        "hubspotusercontent.com",
        "huggingfaceusercontent.com",
        "launchdarkly.com",
        "midjourneycdn.com",
        "onesignal.com",
        "openaimerge.com",
        "optimizely.com",
        "pusher.com",
        "railway.app",
        "register.appattest.apple.com",
        "render.com",
        "replicate.com",
        "replicate.delivery",
        "segment.com",
        "segment.io",
        "sendgrid.net",
        "statsig.com",
        "statsigapi.net",
        "workos.com",
        "workoscdn.com",
        "zeabur.app",
    ],
)
def test_default_allowlist_excludes_direct_or_unverified_domains(domain: str) -> None:
    assert not domain_is_allowed(domain, DEFAULT_PROXY_DOMAINS)


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
async def test_authenticated_proxy_allows_nonallowlisted_public_destination(
    monkeypatch,
) -> None:
    config = _config()
    attempted: list[tuple[str, int]] = []

    async def fail_after_policy_validation(host, port, _config):
        attempted.append((host, port))
        raise OSError("upstream dial intentionally stopped")

    monkeypatch.setattr(
        server_module, "_open_public_connection", fail_after_policy_validation
    )
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

    assert response.startswith(b"HTTP/1.1 502 Bad Gateway")
    assert attempted == [("example.org", 443)]


@pytest.mark.asyncio
async def test_ip_connect_rejects_private_addresses_before_opening_tunnel() -> None:
    config = _config()
    proxy = SelectiveProxyServer(config)
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    proxy_port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(
        f"{config.username}:{config.password}".encode()
    ).decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(
        (
            "CONNECT 10.0.0.1:443 HTTP/1.1\r\n"
            "Host: 10.0.0.1:443\r\n"
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
    assert b"destination did not resolve to a public address" in response


@pytest.mark.asyncio
async def test_authenticated_ip_connect_allows_any_port(monkeypatch) -> None:
    config = _config()
    attempted: list[tuple[str, int]] = []

    async def fail_after_policy_validation(host, port, _config):
        attempted.append((host, port))
        raise OSError("upstream dial intentionally stopped")

    monkeypatch.setattr(
        server_module, "_open_public_connection", fail_after_policy_validation
    )
    proxy = SelectiveProxyServer(config)
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    proxy_port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(
        f"{config.username}:{config.password}".encode()
    ).decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(
        (
            "CONNECT 157.240.7.20:80 HTTP/1.1\r\n"
            "Host: 157.240.7.20:80\r\n"
            f"Proxy-Authorization: Basic {encoded}\r\n\r\n"
        ).encode()
    )
    await writer.drain()

    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    listener.close()
    await listener.wait_closed()

    assert response.startswith(b"HTTP/1.1 502 Bad Gateway")
    assert attempted == [("157.240.7.20", 80)]


@pytest.mark.asyncio
async def test_ip_tls_connect_recovers_nonallowlisted_sni_and_forwards_hello(
    monkeypatch,
) -> None:
    config = _config()
    hello = _tls_client_hello("www.dropbox.com")
    received_hello: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def handle_upstream(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        received_hello.set_result(await reader.readexactly(len(hello)))
        writer.write(b"upstream-ok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]
    attempted: list[tuple[str, int]] = []

    async def open_recovered_domain(host, port, _config):
        attempted.append((host, port))
        return await asyncio.open_connection("127.0.0.1", upstream_port)

    monkeypatch.setattr(server_module, "_open_public_connection", open_recovered_domain)
    proxy = SelectiveProxyServer(config)
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    proxy_port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(
        f"{config.username}:{config.password}".encode()
    ).decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(
        (
            "CONNECT 108.160.163.108:443 HTTP/1.1\r\n"
            "Host: 108.160.163.108:443\r\n"
            f"Proxy-Authorization: Basic {encoded}\r\n\r\n"
        ).encode()
    )
    await writer.drain()
    response_head = await reader.readuntil(b"\r\n\r\n")
    writer.write(hello)
    await writer.drain()
    response_body = await reader.read()
    writer.close()
    await writer.wait_closed()
    listener.close()
    await listener.wait_closed()
    upstream.close()
    await upstream.wait_closed()

    assert response_head.startswith(b"HTTP/1.1 200 Connection Established")
    assert response_body == b"upstream-ok"
    assert await received_hello == hello
    assert attempted == [("www.dropbox.com", 443)]


@pytest.mark.asyncio
async def test_authenticated_domains_accept_all_connect_ports(
    monkeypatch,
) -> None:
    config = ProxyConfig(
        username="proxy",
        password="secret",
        domains=("example.com",),
    )

    async def fail_after_policy_validation(*args, **kwargs):
        raise OSError("upstream dial intentionally stopped")

    monkeypatch.setattr(
        server_module, "_open_public_connection", fail_after_policy_validation
    )
    proxy = SelectiveProxyServer(config)
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(b"proxy:secret").decode()

    async def request(host: str, destination_port: int) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                f"CONNECT {host}:{destination_port} HTTP/1.1\r\n"
                f"Host: {host}:{destination_port}\r\n"
                f"Proxy-Authorization: Basic {encoded}\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        return response

    try:
        http_allowed = await request("not-allowlisted.invalid", 80)
        push_allowed = await request("mtalk.google.com", 5228)
        custom_allowed = await request("mtalk.google.com", 8443)
    finally:
        listener.close()
        await listener.wait_closed()

    assert http_allowed.startswith(b"HTTP/1.1 502 Bad Gateway")
    assert push_allowed.startswith(b"HTTP/1.1 502 Bad Gateway")
    assert custom_allowed.startswith(b"HTTP/1.1 502 Bad Gateway")


@pytest.mark.asyncio
async def test_saturated_proxy_returns_service_unavailable_without_queueing() -> None:
    config = ProxyConfig(
        username="proxy",
        password="secret",
        domains=("example.com",),
        max_connections=1,
    )
    proxy = SelectiveProxyServer(config)
    await proxy._slots.acquire()
    listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    encoded = base64.b64encode(b"proxy:secret").decode()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        (
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            f"Proxy-Authorization: Basic {encoded}\r\n\r\n"
        ).encode()
    )
    await writer.drain()

    response = await asyncio.wait_for(reader.read(), timeout=0.5)
    writer.close()
    await writer.wait_closed()
    listener.close()
    await listener.wait_closed()
    proxy._slots.release()

    assert response.startswith(b"HTTP/1.1 503 Service Unavailable")
    assert b"Retry-After: 1" in response


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
        "rules": [
            {"domain_suffix": ["example.com", "youtube.com"]},
            {"ip_cidr": list(DEFAULT_PROXY_IP_CIDRS)},
        ],
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


@pytest.mark.asyncio
async def test_public_connection_does_not_wait_for_unreachable_first_address(
    monkeypatch,
) -> None:
    async def fake_resolve(_host, port):
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2606:4700::1111", port, 0, 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", port),
            ),
        ]

    expected = (object(), object())

    async def fake_open_connection(*, host, **_kwargs):
        if host == "2606:4700::1111":
            await asyncio.Event().wait()
        return expected

    monkeypatch.setattr(server_module, "_resolve_public_addresses", fake_resolve)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    connection = await asyncio.wait_for(
        _open_public_connection(
            "example.com",
            443,
            ProxyConfig(
                username="proxy",
                password="secret",
                domains=("example.com",),
                connect_timeout_seconds=1,
            ),
        ),
        timeout=0.2,
    )

    assert connection is expected
