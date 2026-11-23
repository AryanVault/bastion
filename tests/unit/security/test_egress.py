from collections.abc import Iterable, Mapping
from ipaddress import ip_address
from typing import Any

import httpcore2
import pytest

from bastion.security.egress import (
    EgressError,
    GuardedBackend,
    Resolver,
    UrlProvenance,
    extract_urls,
    guarded_client,
    is_public_ip,
    normalize_url,
)


def fake_resolver(table: Mapping[str, list[str]]) -> Resolver:
    async def resolve(host: str, port: int) -> list[str]:
        return table.get(host, [])

    return resolve


class ConnectedError(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


class RecordingBackend(httpcore2.AsyncNetworkBackend):
    """Stands in for the real network: records where a connection would go."""

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        raise ConnectedError(host)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        raise AssertionError("unix sockets must never be reached")

    async def sleep(self, seconds: float) -> None:
        return None


# ------------------------------------------------------------ normalize_url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/a?b=c",
        "https://EXAMPLE.com:443/x",
        "https://bücher.example/",
        "https://93.184.216.34/",
    ],
)
def test_ordinary_public_urls_are_accepted(url: str) -> None:
    normalize_url(url)


def test_normalization_is_canonical() -> None:
    normalized = normalize_url("HTTPS://Example.COM:443/Path?q=1#fragment")

    assert normalized == "https://example.com/Path?q=1"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com/",
        "https://user:pass@example.com/",
        "https://example.com:8080/",
        "http://localhost/",
        "http://printer.local/",
        "http://intranet/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0x7f.1/",
        "http://2130706433/",
        "http://017700000001/",
        "http://127.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://100.64.0.1/",
        "https://",
        "not a url",
        "https://example.com/" + "a" * 2100,
    ],
)
def test_dangerous_or_internal_urls_are_rejected(url: str) -> None:
    with pytest.raises(EgressError):
        normalize_url(url)


# -------------------------------------------------------------- is_public_ip


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses(ip: str) -> None:
    assert is_public_ip(ip_address(ip))


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "::ffff:10.0.0.1",
        "2002:7f00:1::",
        "64:ff9b::a00:1",
        "2001::1",
    ],
)
def test_non_public_addresses(ip: str) -> None:
    assert not is_public_ip(ip_address(ip))


# -------------------------------------------------------------- provenance


def test_provenance_allows_only_exact_registered_urls() -> None:
    provenance = UrlProvenance().add(["https://example.com/a?x=1#frag"])

    assert provenance.allows("https://EXAMPLE.com/a?x=1")
    assert not provenance.allows("https://example.com/a?x=2")
    assert not provenance.allows("https://example.com/a?x=1&data=secret")


def test_provenance_ignores_invalid_urls() -> None:
    provenance = UrlProvenance().add(["javascript:alert(1)", "http://127.0.0.1/", "junk"])

    assert provenance.urls == frozenset()


def test_provenance_is_immutable() -> None:
    empty = UrlProvenance()
    empty.add(["https://example.com/"])

    assert empty.urls == frozenset()


def test_extract_urls_strips_trailing_punctuation() -> None:
    text = "see https://example.com/a, and (https://foo.org/b). Also https://bar.net/c?d=1!"

    assert extract_urls(text) == (
        "https://example.com/a",
        "https://foo.org/b",
        "https://bar.net/c?d=1",
    )


# ---------------------------------------------- connect-time SSRF protection


async def test_backend_connects_to_the_validated_ip() -> None:
    backend = GuardedBackend(
        resolver=fake_resolver({"example.com": ["93.184.216.34"]}), inner=RecordingBackend()
    )

    with pytest.raises(ConnectedError) as connected:
        await backend.connect_tcp("example.com", 443)

    assert connected.value.host == "93.184.216.34"


async def test_backend_blocks_names_resolving_to_private_addresses() -> None:
    backend = GuardedBackend(
        resolver=fake_resolver({"rebind.example": ["10.0.0.5"]}), inner=RecordingBackend()
    )

    with pytest.raises(EgressError, match="non-public"):
        await backend.connect_tcp("rebind.example", 443)


async def test_backend_blocks_if_any_resolved_address_is_private() -> None:
    backend = GuardedBackend(
        resolver=fake_resolver({"mixed.example": ["93.184.216.34", "127.0.0.1"]}),
        inner=RecordingBackend(),
    )

    with pytest.raises(EgressError):
        await backend.connect_tcp("mixed.example", 443)


async def test_backend_blocks_unresolvable_names() -> None:
    backend = GuardedBackend(resolver=fake_resolver({}), inner=RecordingBackend())

    with pytest.raises(EgressError, match="resolve"):
        await backend.connect_tcp("nowhere.example", 443)


async def test_backend_refuses_unix_sockets() -> None:
    backend = GuardedBackend(resolver=fake_resolver({}), inner=RecordingBackend())

    with pytest.raises(EgressError):
        await backend.connect_unix_socket("/var/run/docker.sock")


async def test_client_blocks_dns_rebinding_end_to_end() -> None:
    client = guarded_client(resolver=fake_resolver({"rebind.example": ["127.0.0.1"]}))

    async with client:
        with pytest.raises(EgressError):
            await client.get("http://rebind.example/")
