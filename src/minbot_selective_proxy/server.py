"""Authenticated domain-scoped forward proxy with PAC and allowlist management.

The service intentionally supports only destinations from ``PROXY_DOMAINS``.
The PAC file is a client convenience, not the security boundary; the server
repeats the allowlist and public-IP checks for every connection.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_PROXY_DOMAINS = (
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "google.com",
    "google.com.hk",
    "google.com.sg",
    "googleapis.com",
    "googleusercontent.com",
    "ggpht.com",
    "gstatic.com",
    "googlevideo.com",
    "gvt1.com",
    "recaptcha.net",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "x.com",
    "twitter.com",
    "t.co",
    "twimg.com",
    "facebook.com",
    "fbcdn.net",
    "fbsbx.com",
    "instagram.com",
    "cdninstagram.com",
    "messenger.com",
    "threads.net",
    "whatsapp.com",
    "whatsapp.net",
    "telegram.org",
    "telegram-cdn.org",
    "telegram.me",
    "t.me",
    "reddit.com",
    "redd.it",
    "redditstatic.com",
    "redditmedia.com",
    "wikipedia.org",
    "wikimedia.org",
    "mediawiki.org",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discordcdn.com",
    "discord.media",
    "dropbox.com",
    "dropboxapi.com",
    "dropboxstatic.com",
    "medium.com",
    "signal.org",
    "twitch.tv",
    "ttvnw.net",
    "vimeo.com",
    "vimeocdn.com",
    "heygen.com",
    "heygen.ai",
)

_HEADER_LIMIT = 65_536
_ADMIN_BODY_LIMIT = 16_384
_PROXY_HOST_PATTERN = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)
_ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    username: str
    password: str
    domains: tuple[str, ...]
    domains_state_path: str = ""
    additional_users: tuple[tuple[str, str], ...] = ()
    max_connections: int = 64
    connect_timeout_seconds: float = 10.0
    idle_timeout_seconds: float = 120.0
    tunnel_max_seconds: float = 1_800.0


def load_config() -> ProxyConfig:
    username = os.getenv("PROXY_USERNAME", "proxy").strip()
    password = os.getenv("PROXY_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("PROXY_USERNAME and PROXY_PASSWORD must be configured")
    additional_users = _load_additional_users(
        os.getenv("PROXY_ADDITIONAL_USERS_JSON", "")
    )
    raw_domains = os.getenv("PROXY_DOMAINS", "")
    domains = normalize_domains(raw_domains.split(",") if raw_domains else DEFAULT_PROXY_DOMAINS)
    if not domains:
        raise RuntimeError("PROXY_DOMAINS must contain at least one valid domain")
    return ProxyConfig(
        username=username,
        password=password,
        domains=domains,
        domains_state_path=os.getenv("PROXY_DOMAINS_STATE_PATH", "").strip(),
        additional_users=additional_users,
        max_connections=max(1, int(os.getenv("PROXY_MAX_CONNECTIONS", "64"))),
        connect_timeout_seconds=max(
            1.0, float(os.getenv("PROXY_CONNECT_TIMEOUT_SECONDS", "10"))
        ),
        idle_timeout_seconds=max(
            10.0, float(os.getenv("PROXY_IDLE_TIMEOUT_SECONDS", "120"))
        ),
        tunnel_max_seconds=max(
            60.0, float(os.getenv("PROXY_TUNNEL_MAX_SECONDS", "1800"))
        ),
    )


def _load_additional_users(raw_value: str) -> tuple[tuple[str, str], ...]:
    if not raw_value.strip():
        return ()
    try:
        payload = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PROXY_ADDITIONAL_USERS_JSON must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("PROXY_ADDITIONAL_USERS_JSON must be a JSON object")
    users: list[tuple[str, str]] = []
    for raw_username, raw_password in payload.items():
        if not isinstance(raw_username, str) or not isinstance(raw_password, str):
            raise RuntimeError("proxy usernames and passwords must be strings")
        additional_username = raw_username.strip()
        if not additional_username or not raw_password:
            raise RuntimeError("proxy usernames and passwords cannot be empty")
        users.append((additional_username, raw_password))
    return tuple(users)


def normalize_domains(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    cleaned: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        domain = value.strip().casefold().rstrip(".")
        domain = domain.removeprefix("*.")
        if domain and all(part and part.replace("-", "a").isalnum() for part in domain.split(".")):
            cleaned.add(domain)
    return tuple(sorted(cleaned))


def domain_is_allowed(host: str, domains: tuple[str, ...]) -> bool:
    normalized = host.strip().casefold().rstrip(".")
    if not normalized or _is_ip_literal(normalized):
        return False
    return any(normalized == domain or normalized.endswith(f".{domain}") for domain in domains)


class DomainAllowlist:
    """Runtime-editable domain rules with an optional local state snapshot."""

    def __init__(self, defaults: tuple[str, ...], state_path: str = "") -> None:
        self.defaults = defaults
        self._domains = defaults
        self._state_path = Path(state_path) if state_path else None
        self._write_lock = asyncio.Lock()
        self._load_state()

    @property
    def domains(self) -> tuple[str, ...]:
        return self._domains

    async def add(self, domain: str) -> tuple[str, ...]:
        normalized = normalize_domains([domain])
        if len(normalized) != 1:
            raise ValueError("invalid domain")
        async with self._write_lock:
            next_domains = tuple(sorted({*self._domains, normalized[0]}))
            self._save_state(next_domains)
            self._domains = next_domains
            return self._domains

    async def remove(self, domain: str) -> tuple[str, ...]:
        normalized = normalize_domains([domain])
        if len(normalized) != 1:
            raise ValueError("invalid domain")
        async with self._write_lock:
            next_domains = tuple(
                item for item in self._domains if item != normalized[0]
            )
            if not next_domains:
                raise ValueError("at least one domain must remain")
            self._save_state(next_domains)
            self._domains = next_domains
            return self._domains

    def _load_state(self) -> None:
        if self._state_path is None or not self._state_path.is_file():
            return
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
            domains = normalize_domains(payload.get("domains"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return
        if domains:
            self._domains = domains

    def _save_state(self, domains: tuple[str, ...]) -> None:
        if self._state_path is None:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self._state_path.with_suffix(
            f"{self._state_path.suffix}.tmp"
        )
        temporary_path.write_text(
            json.dumps(
                {"version": 1, "domains": domains},
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.replace(temporary_path, self._state_path)


def build_pac(proxy_authority: str, domains: tuple[str, ...]) -> str:
    safe_authority = normalize_proxy_authority(proxy_authority)
    domain_rows = ",\n    ".join(f'"{domain}"' for domain in domains)
    return f'''function FindProxyForURL(url, host) {{
  var proxy = "PROXY {safe_authority}";
  var domains = [
    {domain_rows}
  ];

  host = host.toLowerCase();
  if (isPlainHostName(host) ||
      shExpMatch(host, "localhost") ||
      shExpMatch(host, "127.*") ||
      shExpMatch(host, "10.*") ||
      shExpMatch(host, "192.168.*") ||
      shExpMatch(host, "172.16.*") ||
      shExpMatch(host, "172.17.*") ||
      shExpMatch(host, "172.18.*") ||
      shExpMatch(host, "172.19.*") ||
      shExpMatch(host, "172.2?.*") ||
      shExpMatch(host, "172.30.*") ||
      shExpMatch(host, "172.31.*")) {{
    return "DIRECT";
  }}

  for (var i = 0; i < domains.length; i++) {{
    if (host === domains[i] || dnsDomainIs(host, "." + domains[i])) {{
      return proxy;
    }}
  }}
  return "DIRECT";
}}
'''


def normalize_proxy_authority(authority: str) -> str:
    try:
        parsed = urlsplit(f"//{authority}")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid proxy authority") from exc
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        not host
        or not _PROXY_HOST_PATTERN.fullmatch(host)
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid proxy authority")
    return f"{host}:{port}" if port is not None else host


class SelectiveProxyServer:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.allowlist = DomainAllowlist(config.domains, config.domains_state_path)
        self._slots = asyncio.Semaphore(config.max_connections)

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            header_block = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self.config.connect_timeout_seconds,
            )
            if len(header_block) > _HEADER_LIMIT:
                await _send_error(writer, 431, "Request Header Fields Too Large")
                return
            request_line, headers = _parse_headers(header_block)
            method, target, version = _parse_request_line(request_line)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ValueError):
            await _send_error(writer, 400, "Bad Request")
            return

        try:
            if target.startswith("/"):
                await self._serve_direct(
                    method,
                    target,
                    headers,
                    reader,
                    writer,
                )
                return
            if not _authorized(headers, self.config):
                await _send_proxy_auth_required(writer)
                return
            async with self._slots:
                if method == "CONNECT":
                    await self._handle_connect(target, writer, reader)
                    return
                await self._handle_http(method, target, version, headers, writer, reader)
        except PermissionError as exc:
            await _send_error(writer, 403, "Forbidden", str(exc))
        except (ConnectionError, OSError, TimeoutError):
            await _send_error(writer, 502, "Bad Gateway")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_direct(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        path = urlsplit(target).path
        if method == "GET" and path == "/healthz":
            await _send_response(writer, 200, "OK", b'{"status":"ok"}\n', "application/json")
            return
        if method == "GET" and path in {"/proxy.pac", "/wpad.dat"}:
            authority = headers.get("host", "").strip()
            try:
                pac = build_pac(authority, self.allowlist.domains).encode("utf-8")
            except ValueError:
                await _send_error(writer, 400, "Bad Request")
                return
            await _send_response(
                writer,
                200,
                "OK",
                pac,
                "application/x-ns-proxy-autoconfig",
                extra_headers={"Cache-Control": "public, max-age=300"},
            )
            return
        if method == "GET" and path == "/domains.list":
            domain_set = "".join(
                f".{domain}\n" for domain in self.allowlist.domains
            ).encode("utf-8")
            await _send_response(
                writer,
                200,
                "OK",
                domain_set,
                "text/plain",
                extra_headers={"Cache-Control": "public, max-age=60"},
            )
            return
        if method == "GET" and path == "/domains.sing-box.json":
            rule_set = json.dumps(
                {
                    "version": 3,
                    "rules": [
                        {"domain_suffix": list(self.allowlist.domains)},
                    ],
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            await _send_response(
                writer,
                200,
                "OK",
                rule_set,
                "application/json",
                extra_headers={"Cache-Control": "public, max-age=60"},
            )
            return
        if method == "GET" and path == "/robots.txt":
            await _send_response(writer, 200, "OK", b"User-agent: *\nDisallow: /\n", "text/plain")
            return
        if path == "/api/domains" or path.startswith("/api/domains/"):
            await self._serve_domain_api(method, path, headers, reader, writer)
            return
        await _send_error(writer, 404, "Not Found")

    async def _serve_domain_api(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization, Content-Type",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Cache-Control": "no-store",
        }
        if method == "OPTIONS":
            await _send_response(
                writer,
                204,
                "No Content",
                b"",
                "text/plain",
                extra_headers=cors_headers,
            )
            return
        if not _admin_authorized(headers, self.config):
            await _send_response(
                writer,
                401,
                "Unauthorized",
                b'{"error":"authentication_required"}\n',
                "application/json",
                extra_headers=cors_headers,
            )
            return
        try:
            if method == "GET" and path == "/api/domains":
                await self._send_domains(writer, cors_headers)
                return
            if method == "POST" and path == "/api/domains":
                payload = await _read_json_body(reader, headers)
                await self.allowlist.add(str(payload.get("domain", "")))
                await self._send_domains(writer, cors_headers)
                return
            if method == "DELETE" and path.startswith("/api/domains/"):
                domain = unquote(path.removeprefix("/api/domains/"))
                await self.allowlist.remove(domain)
                await self._send_domains(writer, cors_headers)
                return
        except ValueError as exc:
            await _send_response(
                writer,
                400,
                "Bad Request",
                json.dumps({"error": str(exc)}).encode("utf-8") + b"\n",
                "application/json",
                extra_headers=cors_headers,
            )
            return
        except OSError:
            await _send_response(
                writer,
                503,
                "Service Unavailable",
                b'{"error":"allowlist_storage_unavailable"}\n',
                "application/json",
                extra_headers=cors_headers,
            )
            return
        await _send_response(
            writer,
            405,
            "Method Not Allowed",
            b'{"error":"method_not_allowed"}\n',
            "application/json",
            extra_headers=cors_headers,
        )

    async def _send_domains(
        self,
        writer: asyncio.StreamWriter,
        extra_headers: dict[str, str],
    ) -> None:
        body = json.dumps(
            {"domains": self.allowlist.domains},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        await _send_response(
            writer,
            200,
            "OK",
            body,
            "application/json",
            extra_headers=extra_headers,
        )

    async def _handle_connect(
        self,
        target: str,
        client_writer: asyncio.StreamWriter,
        client_reader: asyncio.StreamReader,
    ) -> None:
        host, port = _split_authority(target, default_port=443)
        if port != 443:
            raise PermissionError("only HTTPS port 443 is allowed")
        upstream_reader, upstream_writer = await _open_public_connection(
            host,
            port,
            self.config,
            self.allowlist.domains,
        )
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        try:
            with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                async with asyncio.timeout(self.config.tunnel_max_seconds):
                    await _relay_bidirectionally(
                        client_reader,
                        client_writer,
                        upstream_reader,
                        upstream_writer,
                        idle_timeout=self.config.idle_timeout_seconds,
                    )
        finally:
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()

    async def _handle_http(
        self,
        method: str,
        target: str,
        version: str,
        headers: dict[str, str],
        client_writer: asyncio.StreamWriter,
        client_reader: asyncio.StreamReader,
    ) -> None:
        if method not in _ALLOWED_HTTP_METHODS:
            raise PermissionError("HTTP method is not allowed")
        try:
            parsed = urlsplit(target)
            port = parsed.port or 80
        except ValueError as exc:
            raise PermissionError("invalid destination") from exc
        if parsed.scheme.casefold() != "http" or not parsed.hostname:
            raise PermissionError("only absolute HTTP URLs are allowed")
        if parsed.username or parsed.password or parsed.fragment:
            raise PermissionError("URL credentials are not allowed")
        if port != 80:
            raise PermissionError("only HTTP port 80 is allowed")
        if headers.get("transfer-encoding"):
            raise PermissionError("chunked HTTP requests are not supported")
        upstream_reader, upstream_writer = await _open_public_connection(
            parsed.hostname,
            port,
            self.config,
            self.allowlist.domains,
        )
        origin_target = parsed.path or "/"
        if parsed.query:
            origin_target = f"{origin_target}?{parsed.query}"
        filtered_headers = {
            key: value
            for key, value in headers.items()
            if key not in _HOP_BY_HOP_HEADERS
        }
        filtered_headers["host"] = parsed.netloc
        filtered_headers["connection"] = "close"
        request_head = [f"{method} {origin_target} {version}"]
        request_head.extend(f"{key}: {value}" for key, value in filtered_headers.items())
        upstream_writer.write(("\r\n".join(request_head) + "\r\n\r\n").encode("latin-1"))
        await upstream_writer.drain()
        try:
            with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                async with asyncio.timeout(self.config.tunnel_max_seconds):
                    await _relay_bidirectionally(
                        client_reader,
                        client_writer,
                        upstream_reader,
                        upstream_writer,
                        idle_timeout=self.config.idle_timeout_seconds,
                    )
        finally:
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()


def _parse_headers(block: bytes) -> tuple[str, dict[str, str]]:
    text = block.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("missing request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        key, separator, value = line.partition(":")
        if not separator or not key.strip():
            raise ValueError("invalid header")
        normalized_key = key.strip().casefold()
        if normalized_key in headers:
            headers[normalized_key] = f"{headers[normalized_key]}, {value.strip()}"
        else:
            headers[normalized_key] = value.strip()
    return lines[0], headers


def _parse_request_line(line: str) -> tuple[str, str, str]:
    parts = line.split(" ")
    if len(parts) != 3:
        raise ValueError("invalid request line")
    method, target, version = parts
    method = method.upper()
    if not method or len(target) > 8_192 or version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("unsupported request")
    return method, target, version


def _authorized(headers: dict[str, str], config: ProxyConfig) -> bool:
    return _basic_authorized(headers.get("proxy-authorization", ""), config)


def _admin_authorized(headers: dict[str, str], config: ProxyConfig) -> bool:
    return _basic_authorized(headers.get("authorization", ""), config)


def _basic_authorized(value: str, config: ProxyConfig) -> bool:
    scheme, separator, encoded = value.partition(" ")
    if not separator or scheme.casefold() != "basic":
        return False
    try:
        supplied = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    credentials = ((config.username, config.password), *config.additional_users)
    authorized = False
    for username, password in credentials:
        expected = f"{username}:{password}"
        authorized = hmac.compare_digest(supplied, expected) or authorized
    return authorized


async def _read_json_body(
    reader: asyncio.StreamReader,
    headers: dict[str, str],
) -> dict[str, object]:
    if headers.get("transfer-encoding"):
        raise ValueError("chunked request bodies are not supported")
    try:
        content_length = int(headers.get("content-length", "0"))
    except ValueError as exc:
        raise ValueError("invalid content length") from exc
    if content_length <= 0 or content_length > _ADMIN_BODY_LIMIT:
        raise ValueError("invalid request body size")
    try:
        payload = json.loads((await reader.readexactly(content_length)).decode("utf-8"))
    except (asyncio.IncompleteReadError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON body") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")
    return payload


def _split_authority(authority: str, *, default_port: int) -> tuple[str, int]:
    parsed = urlsplit(f"//{authority}")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PermissionError("invalid destination")
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise PermissionError("invalid destination port") from exc
    return parsed.hostname, port


async def _open_public_connection(
    host: str,
    port: int,
    config: ProxyConfig,
    domains: tuple[str, ...] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if not domain_is_allowed(host, domains if domains is not None else config.domains):
        raise PermissionError("destination is outside the proxy allowlist")
    addresses = await _resolve_public_addresses(host, port)
    last_error: OSError | None = None
    for family, _socktype, protocol, _canonname, sockaddr in addresses:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    host=str(sockaddr[0]),
                    port=port,
                    family=family,
                    proto=protocol,
                ),
                timeout=config.connect_timeout_seconds,
            )
        except OSError as exc:
            last_error = exc
    raise ConnectionError("upstream connection failed") from last_error


async def _resolve_public_addresses(
    host: str,
    port: int,
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    loop = asyncio.get_running_loop()
    rows = await loop.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    public_rows: list[tuple[int, int, int, str, tuple[object, ...]]] = []
    for row in rows:
        address = str(row[4][0])
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_global:
            public_rows.append(row)
    if not public_rows:
        raise PermissionError("destination did not resolve to a public address")
    return public_rows


def _is_ip_literal(host: str) -> bool:
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


async def _relay_bidirectionally(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    *,
    idle_timeout: float,
) -> None:
    tasks = {
        asyncio.create_task(_pump(client_reader, upstream_writer, idle_timeout)),
        asyncio.create_task(_pump(upstream_reader, client_writer, idle_timeout)),
    }
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in done:
        with contextlib.suppress(ConnectionError, OSError, TimeoutError):
            await task
    for task in pending:
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def _pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    idle_timeout: float,
) -> None:
    while True:
        chunk = await asyncio.wait_for(reader.read(64 * 1024), timeout=idle_timeout)
        if not chunk:
            return
        writer.write(chunk)
        await writer.drain()


async def _send_proxy_auth_required(writer: asyncio.StreamWriter) -> None:
    await _send_response(
        writer,
        407,
        "Proxy Authentication Required",
        b"Proxy authentication required\n",
        "text/plain",
        extra_headers={"Proxy-Authenticate": 'Basic realm="Selective Proxy"'},
    )


async def _send_error(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    detail: str = "",
) -> None:
    body = f"{reason}{f': {detail}' if detail else ''}\n".encode()
    await _send_response(writer, status, reason, body, "text/plain")


async def _send_response(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    body: bytes,
    content_type: str,
    *,
    extra_headers: dict[str, str] | None = None,
) -> None:
    headers = {
        "Content-Type": f"{content_type}; charset=utf-8",
        "Content-Length": str(len(body)),
        "Connection": "close",
        "X-Content-Type-Options": "nosniff",
    }
    headers.update(extra_headers or {})
    head = [f"HTTP/1.1 {status} {reason}"]
    head.extend(f"{key}: {value}" for key, value in headers.items())
    writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)
    await writer.drain()


async def main() -> None:
    config = load_config()
    port = int(os.getenv("PORT", "8080"))
    server = SelectiveProxyServer(config)
    listener = await asyncio.start_server(
        server.handle_client,
        host="0.0.0.0",
        port=port,
        limit=_HEADER_LIMIT,
        start_serving=True,
    )
    async with listener:
        await listener.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
