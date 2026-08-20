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
import logging
import os
import re
import socket
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_PROXY_DOMAIN_GROUPS = {
    "ai": (
        "anthropic.com",
        "anthropicusercontent.com",
        "character.ai",
        "characterai.io",
        "chatgpt.com",
        "challenges.cloudflare.com",
        "claude.ai",
        "claude.com",
        "claudeusercontent.com",
        "codeium.com",
        "cursor.com",
        "cursor.sh",
        "cursorapi.com",
        "ct.sendgrid.net",
        "gamma.app",
        "grok.com",
        "heygen.ai",
        "heygen.com",
        "hf.co",
        "hf.space",
        "huggingface.co",
        "huggingfaceusercontent.com",
        "midjourney.com",
        "midjourneycdn.com",
        "oaistatic.com",
        "oaistatsig.com",
        "oaiusercontent.com",
        "openai.com",
        "openaimerge.com",
        "perplexity.ai",
        "poe.com",
        "pplx.ai",
        "replicate.com",
        "replicate.delivery",
        "register.appattest.apple.com",
        "sora.com",
        "windsurf.com",
        "x.ai",
    ),
    "google": (
        "appspot.com",
        "blogger.com",
        "blogspot.com",
        "doubleclick.net",
        "firebaseapp.com",
        "firebaseio.com",
        "ggpht.com",
        "gmail.com",
        "google-analytics.com",
        "google.com",
        "google.com.hk",
        "google.com.sg",
        "googleadservices.com",
        "googleapis.com",
        "googleblog.com",
        "googledrive.com",
        "googlemail.com",
        "googlesyndication.com",
        "googletagmanager.com",
        "googleusercontent.com",
        "googlevideo.com",
        "gstatic.com",
        "gvt1.com",
        "gvt2.com",
        "recaptcha.net",
        "withgoogle.com",
        "youtu.be",
        "youtube-nocookie.com",
        "youtube.com",
        "ytimg.com",
    ),
    "social_and_messaging": (
        "cdninstagram.com",
        "clubhouse.com",
        "discord.com",
        "discord.gg",
        "discord.media",
        "discordapp.com",
        "discordapp.net",
        "discordcdn.com",
        "facebook.com",
        "facebook.net",
        "fb.com",
        "fb.me",
        "fbcdn.net",
        "fbsbx.com",
        "flickr.com",
        "instagram.com",
        "imgur.com",
        "imgur.io",
        "kakao.com",
        "kakaocdn.net",
        "licdn.com",
        "line.me",
        "line-scdn.net",
        "linkedin.com",
        "messenger.com",
        "oculus.com",
        "pinimg.com",
        "pinterest.com",
        "quora.com",
        "redd.it",
        "reddit.com",
        "redditmedia.com",
        "redditstatic.com",
        "sc-cdn.net",
        "signal.org",
        "snapchat.com",
        "staticflickr.com",
        "t.co",
        "t.me",
        "tdesktop.com",
        "telegram-cdn.org",
        "telegram.dog",
        "telegram.me",
        "telegram.org",
        "threads.net",
        "tumblr.com",
        "twimg.com",
        "twitter.com",
        "whatsapp.com",
        "whatsapp.net",
        "x.com",
    ),
    "media": (
        "dailymotion.com",
        "dmcdn.net",
        "hulu.com",
        "netflix.com",
        "nflxext.com",
        "nflximg.com",
        "nflximg.net",
        "nflxso.net",
        "nflxvideo.net",
        "scdn.co",
        "sndcdn.com",
        "soundcloud.com",
        "spotify.com",
        "spotifycdn.com",
        "tiktok.com",
        "tiktokcdn.com",
        "tiktokv.com",
        "twitch.tv",
        "ttvnw.net",
        "vimeo.com",
        "vimeocdn.com",
    ),
    "developer_and_productivity": (
        "archive.org",
        "archiveofourown.org",
        "box.com",
        "boxcdn.net",
        "dropbox.com",
        "dropboxapi.com",
        "dropboxstatic.com",
        "duck.com",
        "duckduckgo.com",
        "figma.com",
        "figma.net",
        "docker.com",
        "docker.io",
        "dockerstatic.com",
        "gcr.io",
        "ghcr.io",
        "github.com",
        "github.dev",
        "github.io",
        "githubassets.com",
        "githubcopilot.com",
        "githubstatus.com",
        "githubusercontent.com",
        "go.dev",
        "golang.org",
        "mega.io",
        "mega.nz",
        "notion.site",
        "notion.so",
        "notionusercontent.com",
        "npmjs.com",
        "npmjs.org",
        "office.com",
        "office.net",
        "onedrive.com",
        "pkg.dev",
        "proton.me",
        "protonmail.com",
        "protonvpn.com",
        "slack.com",
        "slack-edge.com",
        "slack-imgs.com",
        "slideshare.net",
        "scribd.com",
        "startpage.com",
        "substack.com",
        "torproject.org",
        "pypi.org",
        "pythonhosted.org",
        "quay.io",
        "sharepoint.com",
        "wordpress.com",
        "wp.com",
        "yarnpkg.com",
    ),
    "news_and_reference": (
        "bbc.co.uk",
        "bbc.com",
        "bloomberg.com",
        "bloomberg.net",
        "cnn.com",
        "dw.com",
        "economist.com",
        "ft.com",
        "theguardian.com",
        "medium.com",
        "mediawiki.org",
        "nytimes.com",
        "nyt.com",
        "rfa.org",
        "reuters.com",
        "reutersmedia.net",
        "time.com",
        "voanews.com",
        "washingtonpost.com",
        "wikibooks.org",
        "wikidata.org",
        "wikimedia.org",
        "wikinews.org",
        "wikipedia.org",
        "wikiquote.org",
        "wikisource.org",
        "wiktionary.org",
        "wsj.com",
        "wsj.net",
    ),
    "shared_infrastructure": (
        "akamai.net",
        "akamaihd.net",
        "akamaized.net",
        "amazonaws.com",
        "amplitude.com",
        "auth0.com",
        "azureedge.net",
        "azurefd.net",
        "braze.com",
        "cdn77.com",
        "cdn77.org",
        "cloudflare.com",
        "cloudflareinsights.com",
        "cloudfront.net",
        "contentful.com",
        "contentfulassets.com",
        "ctfassets.net",
        "datadoghq.com",
        "edgekey.net",
        "edgesuite.net",
        "fastly.com",
        "fastly.net",
        "fly.dev",
        "gravatar.com",
        "herokuapp.com",
        "hubspot.com",
        "hubspotusercontent.com",
        "imgix.net",
        "intercom.io",
        "intercomcdn.com",
        "jsdelivr.net",
        "launchdarkly.com",
        "netlify.app",
        "netlify.com",
        "onesignal.com",
        "optimizely.com",
        "pages.dev",
        "pusher.com",
        "railway.app",
        "render.com",
        "segment.com",
        "segment.io",
        "sendgrid.net",
        "sentry.io",
        "statsig.com",
        "statsigapi.net",
        "stripe.com",
        "stripe.network",
        "trafficmanager.net",
        "twilio.com",
        "unpkg.com",
        "vercel.app",
        "vercel.com",
        "windows.net",
        "workers.dev",
        "workos.com",
        "workoscdn.com",
        "zdassets.com",
        "zeabur.app",
        "zendesk.com",
    ),
}

DEFAULT_PROXY_DOMAINS = tuple(
    sorted(
        {
            domain
            for domains in DEFAULT_PROXY_DOMAIN_GROUPS.values()
            for domain in domains
        }
    )
)
DEFAULT_CONNECT_PORTS = (443, 5228, 5229, 5230)

_HEADER_LIMIT = 65_536
_TLS_CLIENT_HELLO_LIMIT = 65_536
_TLS_RECORD_LIMIT = 18_432
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
_LOGGER = logging.getLogger("minbot_selective_proxy")


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    username: str
    password: str
    domains: tuple[str, ...]
    domains_state_path: str = ""
    additional_users: tuple[tuple[str, str], ...] = ()
    max_connections: int = 256
    connect_timeout_seconds: float = 10.0
    idle_timeout_seconds: float = 120.0
    tunnel_max_seconds: float = 1_800.0
    allowed_connect_ports: tuple[int, ...] = DEFAULT_CONNECT_PORTS


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
        max_connections=max(1, int(os.getenv("PROXY_MAX_CONNECTIONS", "256"))),
        connect_timeout_seconds=max(
            1.0, float(os.getenv("PROXY_CONNECT_TIMEOUT_SECONDS", "10"))
        ),
        idle_timeout_seconds=max(
            10.0, float(os.getenv("PROXY_IDLE_TIMEOUT_SECONDS", "120"))
        ),
        tunnel_max_seconds=max(
            60.0, float(os.getenv("PROXY_TUNNEL_MAX_SECONDS", "1800"))
        ),
        allowed_connect_ports=_load_allowed_connect_ports(
            os.getenv("PROXY_ALLOWED_CONNECT_PORTS", "")
        ),
    )


def load_tls_context() -> ssl.SSLContext | None:
    """Build the optional TLS server context without persisting key material."""
    certificate_pem = os.getenv("PROXY_TLS_CERT_PEM", "")
    private_key_pem = os.getenv("PROXY_TLS_KEY_PEM", "")
    if not certificate_pem and not private_key_pem:
        return None
    if not certificate_pem or not private_key_pem:
        raise RuntimeError(
            "PROXY_TLS_CERT_PEM and PROXY_TLS_KEY_PEM must be configured together"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    paths: list[str] = []
    try:
        for value in (certificate_pem, private_key_pem):
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as temporary:
                temporary.write(value)
                paths.append(temporary.name)
            os.chmod(paths[-1], 0o600)
        context.load_cert_chain(certfile=paths[0], keyfile=paths[1])
    finally:
        for path in paths:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
    return context


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


def _load_allowed_connect_ports(raw_value: str) -> tuple[int, ...]:
    if not raw_value.strip():
        return DEFAULT_CONNECT_PORTS
    try:
        ports = {int(value.strip()) for value in raw_value.split(",")}
    except ValueError as exc:
        raise RuntimeError("PROXY_ALLOWED_CONNECT_PORTS must contain integers") from exc
    if not ports or any(port < 1 or port > 65_535 for port in ports):
        raise RuntimeError("PROXY_ALLOWED_CONNECT_PORTS contains an invalid port")
    return tuple(sorted(ports))


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
            except (
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
                TimeoutError,
                ValueError,
            ):
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
                if self._slots.locked():
                    await _send_response(
                        writer,
                        503,
                        "Service Unavailable",
                        b"Proxy connection capacity is exhausted\n",
                        "text/plain",
                        extra_headers={"Retry-After": "1"},
                    )
                    return
                await self._slots.acquire()
                try:
                    if method == "CONNECT":
                        await self._handle_connect(target, writer, reader)
                        return
                    await self._handle_http(
                        method, target, version, headers, writer, reader
                    )
                finally:
                    self._slots.release()
            except PermissionError as exc:
                await _send_error(writer, 403, "Forbidden", str(exc))
            except (ConnectionError, OSError, TimeoutError) as exc:
                _LOGGER.warning("proxy connection failed: %s", exc)
                await _send_error(writer, 502, "Bad Gateway")
        except (ConnectionError, OSError, TimeoutError):
            # Clients can disconnect while the proxy is resolving, connecting,
            # replying, or closing. These are normal transport events and must
            # not escape asyncio's client callback as unhandled tracebacks.
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, asyncio.CancelledError):
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
        if port not in self.config.allowed_connect_ports:
            raise PermissionError("destination port is not allowed")
        if _is_ip_literal(host):
            await self._handle_tls_ip_connect(
                host,
                port,
                client_writer,
                client_reader,
            )
            return
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

    async def _handle_tls_ip_connect(
        self,
        host: str,
        port: int,
        client_writer: asyncio.StreamWriter,
        client_reader: asyncio.StreamReader,
    ) -> None:
        """Safely recover an allowlisted TLS hostname from an IP CONNECT.

        sing-box can select this proxy using a sniffed or FakeIP-backed domain
        while retaining the origin server's real IP as the CONNECT authority.
        The proxy must acknowledge CONNECT before the client sends its TLS
        ClientHello, so policy failures after this point are enforced by
        closing the tunnel instead of returning another HTTP response.
        """
        if port != 443:
            raise PermissionError("IP destinations are only supported for TLS port 443")
        _require_public_ip(host)

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        upstream_writer: asyncio.StreamWriter | None = None
        try:
            server_name, client_hello = await _read_tls_client_hello_sni(
                client_reader,
                timeout=self.config.connect_timeout_seconds,
            )
            if not domain_is_allowed(server_name, self.allowlist.domains):
                raise PermissionError("TLS server name is outside the proxy allowlist")

            upstream_reader, upstream_writer = await _open_public_connection(
                server_name,
                port,
                self.config,
                self.allowlist.domains,
            )
            upstream_writer.write(client_hello)
            await upstream_writer.drain()
            with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                async with asyncio.timeout(self.config.tunnel_max_seconds):
                    await _relay_bidirectionally(
                        client_reader,
                        client_writer,
                        upstream_reader,
                        upstream_writer,
                        idle_timeout=self.config.idle_timeout_seconds,
                    )
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
            PermissionError,
            TimeoutError,
            ValueError,
        ) as exc:
            _LOGGER.info("rejected TLS IP CONNECT: %s", exc)
        finally:
            if upstream_writer is not None:
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


def _require_public_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError as exc:
        raise PermissionError("destination is not an IP address") from exc
    if not address.is_global:
        raise PermissionError("IP destination is not public")
    return address


async def _read_tls_client_hello_sni(
    reader: asyncio.StreamReader,
    *,
    timeout: float,
) -> tuple[str, bytes]:
    """Read a bounded TLS ClientHello and return its normalized SNI and bytes."""
    records = bytearray()
    handshake = bytearray()
    expected_handshake_size: int | None = None

    async with asyncio.timeout(timeout):
        while expected_handshake_size is None or len(handshake) < expected_handshake_size:
            header = await reader.readexactly(5)
            if header[0] != 22:
                raise PermissionError("TLS ClientHello is required")
            record_size = int.from_bytes(header[3:5], "big")
            if record_size <= 0 or record_size > _TLS_RECORD_LIMIT:
                raise ValueError("invalid TLS record size")
            if len(records) + 5 + record_size > _TLS_CLIENT_HELLO_LIMIT:
                raise ValueError("TLS ClientHello is too large")
            payload = await reader.readexactly(record_size)
            records.extend(header)
            records.extend(payload)
            handshake.extend(payload)

            if expected_handshake_size is None and len(handshake) >= 4:
                if handshake[0] != 1:
                    raise PermissionError("TLS ClientHello is required")
                expected_handshake_size = 4 + int.from_bytes(handshake[1:4], "big")
                if expected_handshake_size > _TLS_CLIENT_HELLO_LIMIT:
                    raise ValueError("TLS ClientHello is too large")

    if expected_handshake_size is None:
        raise ValueError("incomplete TLS ClientHello")
    server_name = _parse_tls_client_hello_sni(bytes(handshake[:expected_handshake_size]))
    return server_name, bytes(records)


def _parse_tls_client_hello_sni(handshake: bytes) -> str:
    if len(handshake) < 4 or handshake[0] != 1:
        raise PermissionError("TLS ClientHello is required")
    body_size = int.from_bytes(handshake[1:4], "big")
    if body_size != len(handshake) - 4:
        raise ValueError("invalid TLS ClientHello size")
    body = memoryview(handshake)[4:]
    cursor = 34  # legacy_version (2) and random (32)
    if len(body) < cursor + 1:
        raise ValueError("truncated TLS ClientHello")

    session_id_size = body[cursor]
    cursor += 1 + session_id_size
    if len(body) < cursor + 2:
        raise ValueError("truncated TLS cipher suites")
    cipher_suites_size = int.from_bytes(body[cursor : cursor + 2], "big")
    if cipher_suites_size < 2 or cipher_suites_size % 2:
        raise ValueError("invalid TLS cipher suites")
    cursor += 2 + cipher_suites_size
    if len(body) < cursor + 1:
        raise ValueError("truncated TLS compression methods")
    compression_size = body[cursor]
    cursor += 1 + compression_size
    if len(body) < cursor + 2:
        raise PermissionError("TLS SNI is required")

    extensions_size = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    extensions_end = cursor + extensions_size
    if extensions_end != len(body):
        raise ValueError("invalid TLS extensions size")

    while cursor < extensions_end:
        if cursor + 4 > extensions_end:
            raise ValueError("truncated TLS extension")
        extension_type = int.from_bytes(body[cursor : cursor + 2], "big")
        extension_size = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        cursor += 4
        extension_end = cursor + extension_size
        if extension_end > extensions_end:
            raise ValueError("truncated TLS extension data")
        if extension_type == 0:
            return _parse_tls_sni_extension(bytes(body[cursor:extension_end]))
        cursor = extension_end
    raise PermissionError("TLS SNI is required")


def _parse_tls_sni_extension(extension: bytes) -> str:
    if len(extension) < 2:
        raise ValueError("truncated TLS SNI extension")
    names_size = int.from_bytes(extension[:2], "big")
    if names_size != len(extension) - 2:
        raise ValueError("invalid TLS SNI extension size")
    cursor = 2
    while cursor < len(extension):
        if cursor + 3 > len(extension):
            raise ValueError("truncated TLS server name")
        name_type = extension[cursor]
        name_size = int.from_bytes(extension[cursor + 1 : cursor + 3], "big")
        cursor += 3
        name_end = cursor + name_size
        if name_end > len(extension):
            raise ValueError("truncated TLS server name value")
        if name_type == 0:
            try:
                raw_name = extension[cursor:name_end].decode("ascii")
            except UnicodeDecodeError as exc:
                raise PermissionError("TLS server name must be ASCII") from exc
            normalized = normalize_domains([raw_name])
            if len(normalized) != 1 or _is_ip_literal(normalized[0]):
                raise PermissionError("invalid TLS server name")
            return normalized[0]
        cursor = name_end
    raise PermissionError("TLS SNI hostname is required")


async def _open_public_connection(
    host: str,
    port: int,
    config: ProxyConfig,
    domains: tuple[str, ...] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if not domain_is_allowed(host, domains if domains is not None else config.domains):
        raise PermissionError("destination is outside the proxy allowlist")
    addresses = await _resolve_public_addresses(host, port)
    async def connect(
        row: tuple[int, int, int, str, tuple[object, ...]],
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        family, _socktype, protocol, _canonname, sockaddr = row
        return await asyncio.open_connection(
            host=str(sockaddr[0]),
            port=port,
            family=family,
            proto=protocol,
        )

    tasks = [asyncio.create_task(connect(row)) for row in addresses[:8]]
    last_error: BaseException | None = None
    try:
        async with asyncio.timeout(config.connect_timeout_seconds):
            for completed in asyncio.as_completed(tasks):
                try:
                    connection = await completed
                except OSError as exc:
                    last_error = exc
                    continue
                for task in tasks:
                    if not task.done():
                        task.cancel()
                return connection
    except TimeoutError as exc:
        last_error = exc
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
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
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config()
    port = int(os.getenv("PORT", "8080"))
    tls_port = int(os.getenv("PROXY_TLS_PORT", "8443"))
    tls_context = load_tls_context()
    server = SelectiveProxyServer(config)
    listeners = [await asyncio.start_server(
        server.handle_client,
        host="0.0.0.0",
        port=port,
        limit=_HEADER_LIMIT,
        start_serving=True,
    )]
    if tls_context is not None:
        listeners.append(
            await asyncio.start_server(
                server.handle_client,
                host="0.0.0.0",
                port=tls_port,
                ssl=tls_context,
                limit=_HEADER_LIMIT,
                start_serving=True,
            )
        )
    _LOGGER.info(
        "proxy listeners ready plain_port=%d tls_port=%s max_connections=%d",
        port,
        tls_port if tls_context is not None else "disabled",
        config.max_connections,
    )
    try:
        await asyncio.gather(*(listener.serve_forever() for listener in listeners))
    finally:
        for listener in listeners:
            listener.close()
        await asyncio.gather(*(listener.wait_closed() for listener in listeners))


if __name__ == "__main__":
    asyncio.run(main())
