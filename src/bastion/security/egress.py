"""Egress control (control C7): URL validation, SSRF protection and URL provenance.

Three layers, each independent:

1. ``normalize_url`` rejects anything that is not a plain http(s) URL to a public host on an
   allowed port: other schemes, embedded credentials, internal names, and IP literals in
   private ranges or ambiguous numeric encodings (``0x7f.1``, ``2130706433``, ``127.1``).
2. ``GuardedBackend`` re-checks at *connect time*: it resolves the hostname itself, refuses if
   any address is non-public, and connects to the address it validated. Because the check and
   the connection use the same resolution, DNS rebinding cannot swap in an internal address.
   TLS still verifies the certificate against the original hostname.
3. ``UrlProvenance`` lets the agent fetch only URLs that came from the owner's own messages or
   from search results, so a hijacked model cannot construct an exfiltration URL such as
   ``https://evil.example/?d=<secrets>``.
"""

import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import anyio
import httpcore2
import httpx2

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type Resolver = Callable[[str, int], Awaitable[list[str]]]

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_ALLOWED_PORTS = frozenset({80, 443})
MAX_URL_LENGTH = 2048
USER_AGENT = "Bastion-Agent/0.1"

_DEFAULT_PORT = {"http": 80, "https": 443}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".corp")
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|\d+)$", re.IGNORECASE)
_HOSTNAME = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?)]}'\""
_NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


class EgressError(Exception):
    """An outbound request was refused by egress policy."""


# ----------------------------------------------------------------- addresses


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 address tunnelled inside an IPv6 one (mapped, 6to4, NAT64), if any."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if any(ip in network for network in _NAT64_NETWORKS):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_ip(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            return is_public_ip(embedded)
        if ip.teredo is not None or ip.is_site_local:
            return False
    return ip.is_global and not (
        ip.is_multicast
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )


# ---------------------------------------------------------------------- URLs


def _normalize_host(hostname: str | None) -> str:
    if not hostname:
        raise EgressError("URL has no host")
    host = hostname.rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not is_public_ip(ip):
            raise EgressError("address is not public")
        return host
    if _NUMERIC_LABEL.match(host.rsplit(".", 1)[-1]):
        raise EgressError("ambiguous numeric host")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise EgressError("invalid hostname") from exc
    if "." not in ascii_host:
        raise EgressError("single-label hostnames are not allowed")
    if ascii_host == "localhost" or ascii_host.endswith(_BLOCKED_SUFFIXES):
        raise EgressError("internal hostnames are not allowed")
    if not _HOSTNAME.match(ascii_host):
        raise EgressError("invalid hostname")
    return ascii_host


def normalize_url(raw: str, *, allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS) -> str:
    """Validate a URL and return its canonical form (fragment dropped, default port omitted)."""
    if len(raw) > MAX_URL_LENGTH:
        raise EgressError("URL is too long")
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError as exc:
        raise EgressError("malformed URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        # Never echo the scheme: for redirects it is chosen by a remote server.
        raise EgressError("only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise EgressError("credentials in URLs are not allowed")
    host = _normalize_host(parts.hostname)
    effective_port = port or _DEFAULT_PORT[scheme]
    if effective_port not in allowed_ports:
        raise EgressError(f"port {effective_port} is not allowed")
    netloc = f"[{host}]" if ":" in host else host
    if effective_port != _DEFAULT_PORT[scheme]:
        netloc = f"{netloc}:{effective_port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _try_normalize(url: str) -> str | None:
    try:
        return normalize_url(url)
    except EgressError:
        return None


def extract_urls(text: str) -> tuple[str, ...]:
    """URLs mentioned in free text, in order, without trailing punctuation."""
    found = (match.rstrip(_TRAILING_PUNCTUATION) for match in _URL_IN_TEXT.findall(text))
    return tuple(dict.fromkeys(url for url in found if url))


@dataclass(frozen=True)
class UrlProvenance:
    """The set of URLs the agent may fetch: only those it was *given*, never ones it made up."""

    urls: frozenset[str] = frozenset()

    def add(self, urls: Iterable[str]) -> "UrlProvenance":
        valid = {n for n in (_try_normalize(u) for u in urls) if n is not None}
        return self if valid <= self.urls else UrlProvenance(self.urls | valid)

    def allows(self, url: str) -> bool:
        normalized = _try_normalize(url)
        return normalized is not None and normalized in self.urls


# ------------------------------------------------------- connect-time guard


async def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EgressError(f"could not resolve {host}") from exc
    return [str(info[4][0]) for info in infos]


class GuardedBackend(httpcore2.AsyncNetworkBackend):
    """Network backend that only ever opens TCP connections to validated public addresses."""

    def __init__(
        self,
        resolver: Resolver = system_resolver,
        inner: httpcore2.AsyncNetworkBackend | None = None,
    ) -> None:
        self._resolver = resolver
        self._inner = inner if inner is not None else httpcore2.AnyIOBackend()

    async def _resolve_public(self, host: str, port: int) -> list[str]:
        """All addresses for ``host``; refuses if *any* of them is not public."""
        addresses = await self._resolver(host, port)
        if not addresses:
            raise EgressError(f"could not resolve {host}")
        validated: list[str] = []
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise EgressError(f"invalid address returned for {host}") from exc
            if not is_public_ip(ip):
                raise EgressError(f"{host} resolves to a non-public address")
            validated.append(str(ip))
        return list(dict.fromkeys(validated))

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        failures: list[Exception] = []
        for address in await self._resolve_public(host, port):
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore2.ConnectError, httpcore2.ConnectTimeout) as exc:
                failures.append(exc)  # e.g. an IPv6 address on a host without IPv6: try the next
        raise failures[-1]

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        raise EgressError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _GuardedTransport(httpx2.AsyncHTTPTransport):
    """httpx2 transport whose connection pool uses the guarded network backend."""

    def __init__(self, backend: GuardedBackend) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=httpx2.create_ssl_context(trust_env=False),
            network_backend=backend,
            max_connections=10,
        )


def guarded_client(
    *,
    resolver: Resolver = system_resolver,
    timeout: float = 15.0,
    network: httpcore2.AsyncNetworkBackend | None = None,
) -> httpx2.AsyncClient:
    """HTTP client for fetching untrusted URLs.

    Ignores proxy environment variables (a proxy would bypass the IP check) and never follows
    redirects on its own: callers must re-validate each hop with ``normalize_url``. ``network``
    replaces the real network below the address checks (the red-team sandbox uses this).
    """
    return httpx2.AsyncClient(
        transport=_GuardedTransport(GuardedBackend(resolver=resolver, inner=network)),
        trust_env=False,
        follow_redirects=False,
        timeout=timeout,
        # Uncompressed responses keep the size cap meaningful (no decompression bombs).
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
    )
