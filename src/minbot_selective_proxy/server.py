"""Authenticated public-network proxy with selective client routing.

The allowlist controls PAC and client routing. After authentication, the
server permits every public destination and TCP port while continuing to
reject private, loopback, link-local, reserved, and metadata IPs.
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
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_PROXY_DOMAIN_GROUPS = {
    "ai": (
        "anthropic.com",
        "character.ai",
        "chatgpt.com",
        "challenges.cloudflare.com",
        "claude.ai",
        "claude.com",
        "claudeusercontent.com",
        "codeium.com",
        "cursor.com",
        "cursor.sh",
        "cursorapi.com",
        "gamma.app",
        "grok.com",
        "heygen.com",
        "hf.co",
        "hf.space",
        "huggingface.co",
        "midjourney.com",
        "oaistatic.com",
        "oaistatsig.com",
        "oaiusercontent.com",
        "openai.com",
        "perplexity.ai",
        "poe.com",
        "pplx.ai",
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
        "biggggg.com",
        "dailymotion.com",
        "dmcdn.net",
        "haiwaikan.com",
        "hulu.com",
        "iole.tv",
        "iyf.tv",
        "mudvod.tv",
        "nbys.tv",
        "nbys1.tv",
        "nbyy.tv",
        "netflix.com",
        "newpppp.com",
        "nflxext.com",
        "nflximg.com",
        "nflximg.net",
        "nflxso.net",
        "nflxvideo.net",
        "nivod.tv",
        "nivodi.tv",
        "nivodz.com",
        "olehd.com",
        "olelive.com",
        "olemovienews.com",
        "olevod.com",
        "olevod.io",
        "olevod.tv",
        "olevodtv.com",
        "pipecdn.vip",
        "scdn.co",
        "sndcdn.com",
        "soundcloud.com",
        "spotify.com",
        "spotifycdn.com",
        "tiktok.com",
        "tiktokcdn.com",
        "tiktokv.com",
        "ttvnw.net",
        "twitch.tv",
        "vimeo.com",
        "vimeocdn.com",
        "vod360.net",
        "yfsp.tv",
    ),
    "developer_and_productivity": (
        "archive.org",
        "archiveofourown.org",
        "dropbox.com",
        "dropboxapi.com",
        "dropboxstatic.com",
        "duck.com",
        "duckduckgo.com",
        "figma.com",
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
        "auth0.com",
        "azureedge.net",
        "azurefd.net",
        "cdn77.com",
        "cdn77.org",
        "cloudflare.com",
        "cloudflareinsights.com",
        "cloudfront.net",
        "contentful.com",
        "ctfassets.net",
        "edgekey.net",
        "edgesuite.net",
        "fastly.com",
        "fastly.net",
        "fly.dev",
        "gravatar.com",
        "herokuapp.com",
        "imgix.net",
        "intercom.io",
        "intercomcdn.com",
        "jsdelivr.net",
        "netlify.app",
        "netlify.com",
        "pages.dev",
        "sentry.io",
        "stripe.com",
        "stripe.network",
        "trafficmanager.net",
        "twilio.com",
        "unpkg.com",
        "vercel.app",
        "vercel.com",
        "windows.net",
        "workers.dev",
        "zdassets.com",
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
DEFAULT_PROXY_IP_CIDRS = (
    "157.240.0.0/16",
)

_HEADER_LIMIT = 65_536
_TLS_CLIENT_HELLO_LIMIT = 65_536
_TLS_RECORD_LIMIT = 18_432
_ADMIN_BODY_LIMIT = 16_384
_STREAM_LIMIT = 64 * 1024
# A close waits this long without write-buffer progress before aborting, and
# never longer than _STREAM_CLOSE_MAX in total, so slow clients still receive
# the tail of a response while stuck peers are released.
_STREAM_CLOSE_TIMEOUT = 5.0
_STREAM_CLOSE_MAX = 60.0
_RELAY_WRITE_HIGH_WATER = 256 * 1024
_RELAY_WRITE_LOW_WATER = 64 * 1024
# RFC 8305 connection-attempt delay: start the next address only when the
# previous attempt has neither succeeded nor failed within this delay.
_HAPPY_EYEBALLS_DELAY = 0.25
_MAX_CONNECT_ATTEMPTS = 12
_ADDRESS_PENALTY_SECONDS = 60.0
_ADDRESS_PENALTY_LIMIT = 4096
_DNS_CACHE_LIMIT = 4096
_DNS_NEGATIVE_TTL = 5.0
_DNS_STALE_TTL = 600.0
# How long a request waits for a refresh before using a stale answer.
_DNS_STALE_WAIT = 1.0
_DEFAULT_LISTEN_BACKLOG = 1024
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
    tunnel_max_seconds: float = 0.0
    dns_cache_seconds: float = 30.0
    dns_workers: int = 32
    listen_backlog: int = _DEFAULT_LISTEN_BACKLOG


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
            0.0, float(os.getenv("PROXY_TUNNEL_MAX_SECONDS", "0"))
        ),
        dns_cache_seconds=max(
            0.0, float(os.getenv("PROXY_DNS_CACHE_SECONDS", "30"))
        ),
        dns_workers=max(4, int(os.getenv("PROXY_DNS_WORKERS", "32"))),
        listen_backlog=max(
            16,
            int(os.getenv("PROXY_LISTEN_BACKLOG", str(_DEFAULT_LISTEN_BACKLOG))),
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
        except Exception:
            # One malformed or unexpected connection must never take down the
            # listener callback or leak its socket.
            _LOGGER.exception("unexpected proxy connection error")
        finally:
            await _close_writer(writer)

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
                        {"ip_cidr": list(DEFAULT_PROXY_IP_CIDRS)},
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
        if _is_ip_literal(host) and port == 443:
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
        )
        try:
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                async with asyncio.timeout(self.config.tunnel_max_seconds or None):
                    await _relay_bidirectionally(
                        client_reader,
                        client_writer,
                        upstream_reader,
                        upstream_writer,
                        idle_timeout=self.config.idle_timeout_seconds,
                    )
        finally:
            await _close_writer(upstream_writer)

    async def _handle_tls_ip_connect(
        self,
        host: str,
        port: int,
        client_writer: asyncio.StreamWriter,
        client_reader: asyncio.StreamReader,
    ) -> None:
        """Recover a TLS hostname from an authenticated public-IP CONNECT."""
        _require_public_ip(host)
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        upstream_writer: asyncio.StreamWriter | None = None
        try:
            server_name, client_hello = await _read_tls_client_hello_sni(
                client_reader,
                timeout=self.config.connect_timeout_seconds,
            )
            upstream_reader, upstream_writer = await _open_public_connection(
                server_name,
                port,
                self.config,
            )
            upstream_writer.write(client_hello)
            await upstream_writer.drain()
            with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                async with asyncio.timeout(self.config.tunnel_max_seconds or None):
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
        ):
            pass
        finally:
            if upstream_writer is not None:
                await _close_writer(upstream_writer)

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
        if headers.get("transfer-encoding"):
            raise PermissionError("chunked HTTP requests are not supported")
        upstream_reader, upstream_writer = await _open_public_connection(
            parsed.hostname,
            port,
            self.config,
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
        try:
            upstream_writer.write(("\r\n".join(request_head) + "\r\n\r\n").encode("latin-1"))
            await upstream_writer.drain()
            with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                async with asyncio.timeout(self.config.tunnel_max_seconds or None):
                    await _relay_bidirectionally(
                        client_reader,
                        client_writer,
                        upstream_reader,
                        upstream_writer,
                        idle_timeout=self.config.idle_timeout_seconds,
                    )
        finally:
            await _close_writer(upstream_writer)


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
    try:
        parsed = urlsplit(f"//{authority}")
    except ValueError as exc:
        raise PermissionError("invalid destination") from exc
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


_AddressRow = tuple[int, int, int, str, tuple[object, ...]]


async def _open_public_connection(
    host: str,
    port: int,
    config: ProxyConfig,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Resolve and connect within one deadline, racing addresses per RFC 8305."""
    last_error: BaseException | None = None
    phase = "dns"
    try:
        async with asyncio.timeout(config.connect_timeout_seconds):
            addresses = await _resolve_public_addresses(host, port)
            phase = "tcp"
            return await _connect_staggered(_order_addresses(addresses), port)
    except (TimeoutError, OSError) as exc:
        if isinstance(exc, PermissionError):
            raise
        last_error = exc
    raise ConnectionError(
        f"upstream {phase} connection failed ({type(last_error).__name__})"
    ) from last_error


async def _connect_staggered(
    rows: list[_AddressRow],
    port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Happy Eyeballs: one attempt at a time, the next after a short delay.

    A failed attempt immediately starts the next address, so unreachable
    addresses cost nothing, while a healthy first address costs a single TCP
    handshake instead of one per resolved address.
    """
    loop = asyncio.get_running_loop()
    attempts: dict[asyncio.Task, tuple[str, float]] = {}
    pending: set[asyncio.Task] = set()
    candidates = iter(rows)
    exhausted = False
    last_error: BaseException | None = None
    handed_over: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    try:
        while True:
            if not exhausted:
                row = next(candidates, None)
                if row is None:
                    exhausted = True
                else:
                    task = loop.create_task(_connect_address(row, port))
                    attempts[task] = (str(row[4][0]), loop.time())
                    pending.add(task)
            if not pending:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=None if exhausted else _HAPPY_EYEBALLS_DELAY,
                return_when=asyncio.FIRST_COMPLETED,
            )
            winner: asyncio.Task | None = None
            for task in done:
                if task.cancelled():
                    continue
                error = task.exception()
                if error is not None:
                    last_error = error
                    _penalize_address(attempts[task][0])
                elif winner is None:
                    winner = task
            if winner is not None:
                # Addresses that were started earlier but are still silent are
                # probably black-holed; try them last next time.
                for task in pending:
                    if attempts[task][1] < attempts[winner][1]:
                        _penalize_address(attempts[task][0])
                handed_over = winner.result()
                return handed_over
    finally:
        for task in attempts:
            if not task.done():
                task.cancel()
        try:
            await asyncio.gather(*attempts, return_exceptions=True)
        except BaseException:
            # Cancelled during cleanup: the winner never reaches the caller.
            handed_over = None
            raise
        finally:
            for task in attempts:
                if task.done() and not task.cancelled() and task.exception() is None:
                    connection = task.result()
                    if connection is not handed_over:
                        connection[1].close()
    raise last_error or OSError("no public address accepted the connection")


async def _connect_address(
    row: _AddressRow,
    port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    family, _socktype, protocol, _canonname, sockaddr = row
    return await asyncio.open_connection(
        host=str(sockaddr[0]),
        port=port,
        family=family,
        proto=protocol,
        limit=_STREAM_LIMIT,
    )


_ADDRESS_PENALTIES: dict[str, float] = {}


def _penalize_address(address: str) -> None:
    now = _monotonic()
    if len(_ADDRESS_PENALTIES) >= _ADDRESS_PENALTY_LIMIT:
        for key, expires in list(_ADDRESS_PENALTIES.items()):
            if expires <= now:
                del _ADDRESS_PENALTIES[key]
        if len(_ADDRESS_PENALTIES) >= _ADDRESS_PENALTY_LIMIT:
            _ADDRESS_PENALTIES.clear()
    _ADDRESS_PENALTIES[address] = now + _ADDRESS_PENALTY_SECONDS


def _order_addresses(rows: list[_AddressRow]) -> list[_AddressRow]:
    """Dedupe, interleave address families (RFC 8305) and demote failures."""
    now = _monotonic()
    seen: set[str] = set()
    by_family: dict[int, list[_AddressRow]] = {}
    for row in rows:
        address = str(row[4][0])
        if address in seen:
            continue
        seen.add(address)
        by_family.setdefault(row[0], []).append(row)
    interleaved: list[_AddressRow] = []
    queues = list(by_family.values())
    while queues:
        for queue in queues:
            interleaved.append(queue.pop(0))
        queues = [queue for queue in queues if queue]
    interleaved.sort(key=lambda row: _ADDRESS_PENALTIES.get(str(row[4][0]), 0.0) > now)
    return interleaved[:_MAX_CONNECT_ATTEMPTS]


def _monotonic() -> float:
    return asyncio.get_running_loop().time()


@dataclass(slots=True)
class _DnsEntry:
    rows: list[_AddressRow] | None
    error: OSError | None
    expires: float
    refresh_at: float
    stale_until: float


class _DnsCache:
    """Coalesced, TTL-bounded name resolution.

    getaddrinfo runs in a thread pool and cannot be cancelled. Without
    coalescing, a burst of tunnels to one new hostname, or a few lookups that
    hang on a slow resolver, occupy every worker thread and stall DNS for all
    tunnels. Concurrent lookups for one host share a single resolution,
    popular hosts are refreshed before they expire, and a stale answer is used
    when the resolver is slow or temporarily failing (RFC 8767).
    Addresses are re-validated as public on every use.
    """

    def __init__(self, ttl: float = 30.0) -> None:
        self.ttl = ttl
        self._entries: OrderedDict[str, _DnsEntry] = OrderedDict()
        self._inflight: dict[str, asyncio.Task] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def clear(self) -> None:
        self._entries.clear()
        self._inflight.clear()

    async def lookup(self, host: str) -> list[_AddressRow]:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            self.clear()
            self._loop = loop
        if self.ttl <= 0:
            return await _getaddrinfo(host)
        key = host.casefold()
        now = loop.time()
        entry = self._entries.get(key)
        if entry is not None:
            if now < entry.expires:
                self._entries.move_to_end(key)
                if entry.error is not None:
                    raise socket.gaierror(entry.error.errno, entry.error.strerror)
                if now >= entry.refresh_at:
                    self._refresh(key)
                assert entry.rows is not None
                return entry.rows
            if entry.rows is not None and now < entry.stale_until:
                refresh = self._refresh(key)
                done, _ = await asyncio.wait({refresh}, timeout=_DNS_STALE_WAIT)
                if not done or refresh.cancelled() or refresh.exception() is not None:
                    return entry.rows
                return refresh.result()
        return await asyncio.shield(self._refresh(key))

    def _refresh(self, key: str) -> asyncio.Task:
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.get_running_loop().create_task(self._resolve(key))
            self._inflight[key] = task
            task.add_done_callback(lambda done: self._finish(key, done))
        return task

    def _finish(self, key: str, task: asyncio.Task) -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        if not task.cancelled():
            task.exception()

    async def _resolve(self, key: str) -> list[_AddressRow]:
        loop = asyncio.get_running_loop()
        try:
            rows = await _getaddrinfo(key)
        except OSError as exc:
            now = loop.time()
            if isinstance(exc, socket.gaierror) and exc.errno in _DNS_NAME_ERRORS:
                self._store(key, _DnsEntry(None, exc, now + _DNS_NEGATIVE_TTL, 0.0, 0.0))
            raise
        now = loop.time()
        self._store(
            key,
            _DnsEntry(
                rows,
                None,
                now + self.ttl,
                now + self.ttl * 0.8,
                now + max(self.ttl, _DNS_STALE_TTL),
            ),
        )
        return rows

    def _store(self, key: str, entry: _DnsEntry) -> None:
        self._entries[key] = entry
        self._entries.move_to_end(key)
        while len(self._entries) > _DNS_CACHE_LIMIT:
            self._entries.popitem(last=False)


_DNS_NAME_ERRORS = frozenset(
    code
    for code in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))
    if code is not None
)
_DNS_CACHE = _DnsCache()


async def _getaddrinfo(host: str) -> list[_AddressRow]:
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(
        host,
        None,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )


async def _resolve_public_addresses(
    host: str,
    port: int,
) -> list[_AddressRow]:
    candidate = host.strip("[]")
    try:
        literal = ipaddress.ip_address(candidate)
    except ValueError:
        rows = await _DNS_CACHE.lookup(host)
    else:
        # IP literals need no resolver round trip through the thread pool.
        if literal.version == 4:
            rows = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (candidate, port))]
        else:
            rows = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (candidate, port, 0, 0))]
    public_rows: list[_AddressRow] = []
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


def _require_public_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError as exc:
        raise PermissionError("destination is not an IP address") from exc
    if not address.is_global:
        raise PermissionError("destination did not resolve to a public address")
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
    cursor = 34
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


async def _relay_bidirectionally(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    *,
    idle_timeout: float,
) -> None:
    """Splice two connections at the transport level until both sides finish.

    Each side's transport is switched to a small protocol that writes received
    data straight to the peer transport. Compared with a StreamReader copy loop
    this removes a buffer copy and two task wake-ups per chunk, and uses
    transport flow control (pause/resume) for backpressure. A half-close from
    one plain-TCP side is forwarded as EOF so the other direction can finish
    (e.g. a request sent with shutdown(SHUT_WR) still receives its response).
    The tunnel ends when both directions are done, either side is lost, or
    neither side has made progress for ``idle_timeout`` seconds.
    """
    relay = _Relay(asyncio.get_running_loop(), idle_timeout)
    client = _RelayEnd(relay, client_reader, client_writer)
    upstream = _RelayEnd(relay, upstream_reader, upstream_writer)
    client.peer, upstream.peer = upstream, client
    try:
        client.attach()
        upstream.attach()
        client.start()
        upstream.start()
        relay.arm()
        await relay.done
    finally:
        relay.stop()
        client.detach()
        upstream.detach()


class _Relay:
    __slots__ = ("loop", "idle_timeout", "last_activity", "done", "_timer", "_ends", "_last_pending")

    def __init__(self, loop: asyncio.AbstractEventLoop, idle_timeout: float) -> None:
        self.loop = loop
        self.idle_timeout = idle_timeout
        self.last_activity = loop.time()
        self.done: asyncio.Future[None] = loop.create_future()
        self._timer: asyncio.TimerHandle | None = None
        self._ends: list[_RelayEnd] = []
        self._last_pending = 0

    def finish(self) -> None:
        if not self.done.done():
            self.done.set_result(None)

    def arm(self) -> None:
        if not self.done.done():
            self._timer = self.loop.call_at(
                self.last_activity + self.idle_timeout, self._check_idle
            )

    def stop(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _check_idle(self) -> None:
        self._timer = None
        # Data still draining from a write buffer to a slow peer is progress.
        pending = sum(end.pending_writes() for end in self._ends)
        if pending != self._last_pending:
            self._last_pending = pending
            self.last_activity = self.loop.time()
        if self.loop.time() - self.last_activity >= self.idle_timeout:
            self.finish()
        else:
            self.arm()


class _RelayEnd(asyncio.Protocol):
    def __init__(
        self,
        relay: _Relay,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.relay = relay
        self.reader = reader
        self.transport: asyncio.Transport = writer.transport  # type: ignore[assignment]
        self.previous: asyncio.BaseProtocol | None = None
        self.peer: _RelayEnd
        self.eof = False
        self.lost = False
        self.tls = writer.get_extra_info("sslcontext") is not None
        self._backlog = b""
        self._initial_eof = False
        relay._ends.append(self)

    def attach(self) -> None:
        """Take the transport over from the StreamReader protocol."""
        transport = self.transport
        self.previous = transport.get_protocol()
        # Bytes the client pipelined after its request head (or an upstream
        # sent early) are still buffered in the StreamReader.
        buffer = getattr(self.reader, "_buffer", None)
        if buffer:
            self._backlog = bytes(buffer)
            buffer.clear()
        self._initial_eof = self.reader.at_eof() or bool(
            getattr(self.reader, "_eof", False)
        )
        transport.set_protocol(self)
        if transport.is_closing():
            self.lost = True
            return
        with contextlib.suppress(AttributeError, NotImplementedError, RuntimeError):
            transport.set_write_buffer_limits(
                high=_RELAY_WRITE_HIGH_WATER, low=_RELAY_WRITE_LOW_WATER
            )

    def start(self) -> None:
        if self._backlog:
            data, self._backlog = self._backlog, b""
            self.data_received(data)
        if self.lost or self.peer.lost:
            self.relay.finish()
            return
        if self._initial_eof:
            if not self.eof_received():
                self.relay.finish()
            return
        # The StreamReader may have paused reading when its buffer filled.
        with contextlib.suppress(AttributeError, NotImplementedError, RuntimeError):
            if not self.transport.is_reading():
                self.transport.resume_reading()

    def detach(self) -> None:
        # Stop forwarding; the callers close both transports afterwards.
        if not self.lost:
            with contextlib.suppress(AttributeError, NotImplementedError, RuntimeError):
                self.transport.pause_reading()

    def pending_writes(self) -> int:
        try:
            return self.transport.get_write_buffer_size()
        except (AttributeError, NotImplementedError, RuntimeError):
            return 0

    # asyncio.Protocol callbacks ------------------------------------------
    def data_received(self, data: bytes) -> None:
        relay = self.relay
        relay.last_activity = relay.loop.time()
        peer = self.peer
        if peer.lost or relay.done.done():
            return
        peer.transport.write(data)

    def eof_received(self) -> bool:
        if self.eof:
            return not self.tls
        self.eof = True
        self.relay.last_activity = self.relay.loop.time()
        peer = self.peer
        if self.tls or peer.lost or not peer.transport.can_write_eof():
            # Half-close cannot be expressed on this pair (TLS has no
            # half-close); end the tunnel once queued data is flushed.
            self.relay.finish()
            return False
        try:
            peer.transport.write_eof()
        except (OSError, RuntimeError):
            self.relay.finish()
            return False
        if peer.eof:
            # Both directions are complete; the callers close the sockets.
            self.relay.finish()
        # Keep our side open so the peer's remaining data can reach it.
        return True

    def pause_writing(self) -> None:
        # Our outgoing buffer is full: stop reading from the peer.
        if not self.peer.lost:
            with contextlib.suppress(AttributeError, NotImplementedError, RuntimeError):
                self.peer.transport.pause_reading()

    def resume_writing(self) -> None:
        peer = self.peer
        if not peer.lost and not peer.eof and not self.relay.done.done():
            with contextlib.suppress(AttributeError, NotImplementedError, RuntimeError):
                peer.transport.resume_reading()

    def connection_lost(self, exc: Exception | None) -> None:
        self.lost = True
        self.relay.finish()
        # Let the original StreamReader/StreamWriter observe the close so
        # StreamWriter.wait_closed() keeps working for the callers.
        if self.previous is not None:
            with contextlib.suppress(Exception):
                self.previous.connection_lost(exc)


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Close gracefully while the peer keeps draining, then force release.

    The transport flushes queued data before closing. A slow but live client
    keeps the close alive as long as its write buffer keeps shrinking (so the
    end of a response is not cut off), while a stuck peer or TLS shutdown is
    aborted after ``_STREAM_CLOSE_TIMEOUT`` seconds without progress.
    """
    closed = False
    writer.close()
    waiter = asyncio.ensure_future(writer.wait_closed())
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _STREAM_CLOSE_MAX
        pending = _write_buffer_size(writer)
        while True:
            done, _ = await asyncio.wait({waiter}, timeout=_STREAM_CLOSE_TIMEOUT)
            if done:
                with contextlib.suppress(ConnectionError, OSError):
                    waiter.result()
                    closed = True
                break
            remaining = _write_buffer_size(writer)
            if not remaining or remaining >= pending or loop.time() >= deadline:
                break
            pending = remaining
    finally:
        if not closed:
            writer.transport.abort()
        if not waiter.done():
            waiter.cancel()
        waiter.add_done_callback(_retrieve_result)


def _write_buffer_size(writer: asyncio.StreamWriter) -> int:
    try:
        return int(writer.transport.get_write_buffer_size())
    except (AttributeError, NotImplementedError, RuntimeError, TypeError, ValueError):
        return 0


def _retrieve_result(future: asyncio.Future) -> None:
    if not future.cancelled():
        future.exception()


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
    # getaddrinfo blocks a worker thread per lookup; the default pool has only
    # min(32, cpus + 4) threads, which is 5 on a one-CPU container.
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=config.dns_workers, thread_name_prefix="dns")
    )
    _DNS_CACHE.ttl = config.dns_cache_seconds
    listeners = [await asyncio.start_server(
        server.handle_client,
        host="0.0.0.0",
        port=port,
        limit=_HEADER_LIMIT,
        # asyncio defaults to 100; browsers open dozens of tunnels at once and
        # an overflowing accept queue costs clients a 1 s SYN retransmit.
        backlog=config.listen_backlog,
        start_serving=True,
    )]
    if tls_context is not None:
        listeners.append(
            await asyncio.start_server(
                server.handle_client,
                host="0.0.0.0",
                port=tls_port,
                ssl=tls_context,
                ssl_handshake_timeout=config.connect_timeout_seconds,
                limit=_HEADER_LIMIT,
                backlog=config.listen_backlog,
                start_serving=True,
            )
        )
    _LOGGER.info(
        "proxy listeners ready plain_port=%d tls_port=%s max_connections=%d "
        "dns_cache_seconds=%g",
        port,
        tls_port if tls_context is not None else "disabled",
        config.max_connections,
        config.dns_cache_seconds,
    )
    try:
        await asyncio.gather(*(listener.serve_forever() for listener in listeners))
    finally:
        for listener in listeners:
            listener.close()
        await asyncio.gather(*(listener.wait_closed() for listener in listeners))


if __name__ == "__main__":
    asyncio.run(main())
