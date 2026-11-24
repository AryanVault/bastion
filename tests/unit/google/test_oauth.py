import asyncio
import base64
import hashlib
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest

from bastion.google.oauth import (
    AUTH_URL,
    CHANGED,
    REVOKE_URL,
    TOKEN_URL,
    AuthRevoked,
    ClientCredentials,
    GoogleAuth,
    LoopbackReceiver,
    OAuthError,
    authorization_url,
    exchange_code,
    new_pkce,
    refresh_access,
    revoke,
    valid_client_id,
    valid_client_secret,
)
from bastion.security.redact import REDACTED, Redactor

CREDS = ClientCredentials(
    "123456789-abcdefgh12345678.apps.googleusercontent.com", "GOCSPX-test-secret"
)
CRLF = "\r\n"

type Handler = Callable[[httpx2.Request], httpx2.Response]


def client(handler: Handler) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


def form(request: httpx2.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def token_response(**fields: Any) -> httpx2.Response:
    body = {
        "access_token": "ya29.access-token-value-0001",
        "expires_in": 3599,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "token_type": "Bearer",
    }
    return httpx2.Response(200, json=body | fields)


async def raw_request(port: int, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    response = await reader.read()
    writer.close()
    return response


def get(path: str) -> bytes:
    return f"GET {path} HTTP/1.1{CRLF}Host: 127.0.0.1{CRLF}{CRLF}".encode()


def port_of(receiver: LoopbackReceiver) -> int:
    port = urlsplit(receiver.redirect_uri).port
    assert port is not None
    return port


# ------------------------------------------------------------------ basics


def test_client_credential_formats() -> None:
    assert valid_client_id(CREDS.client_id)
    assert not valid_client_id("123-abc.apps.googleusercontent.com.evil.example")
    assert not valid_client_id("not an id")
    assert valid_client_secret("GOCSPX-abc123_DEF")
    assert not valid_client_secret("short")
    assert not valid_client_secret("has spaces in it")


def test_credentials_never_show_the_secret() -> None:
    assert "GOCSPX" not in repr(CREDS)


def test_pkce_challenge_is_the_s256_of_the_verifier() -> None:
    pkce = new_pkce()

    digest = hashlib.sha256(pkce.verifier.encode()).digest()
    assert pkce.challenge == base64.urlsafe_b64encode(digest).decode().rstrip("=")
    assert 43 <= len(pkce.verifier) <= 128
    assert new_pkce().verifier != pkce.verifier


def test_authorization_url_requests_code_with_pkce_and_state() -> None:
    url = authorization_url(
        CREDS.client_id, "http://127.0.0.1:5555", ["scope-a", "scope-b"], "st4te", "chall"
    )

    assert url.startswith(AUTH_URL + "?")
    params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    assert params == {
        "client_id": CREDS.client_id,
        "redirect_uri": "http://127.0.0.1:5555",
        "response_type": "code",
        "scope": "scope-a scope-b",
        "state": "st4te",
        "code_challenge": "chall",
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }


# --------------------------------------------------------- loopback listener


@pytest.mark.security
async def test_listener_binds_loopback_only_and_returns_the_code() -> None:
    async with LoopbackReceiver("good-state") as receiver:
        assert receiver.addresses == ("127.0.0.1",)
        reply = await raw_request(port_of(receiver), get("/?state=good-state&code=4/0AbCdEf123"))
        code = await receiver.wait(wait_seconds=5)

    assert code == "4/0AbCdEf123"
    assert reply.startswith(b"HTTP/1.1 200 OK")
    assert b"Bastion is connected" in reply
    assert b"Cache-Control: no-store" in reply


@pytest.mark.security
async def test_a_redirect_with_the_wrong_state_is_ignored() -> None:
    async with LoopbackReceiver("good-state") as receiver:
        port = port_of(receiver)
        planted = await raw_request(port, get("/?state=evil&code=4/0AttackerCode"))
        missing = await raw_request(port, get("/?code=4/0AttackerCode"))
        genuine = await raw_request(port, get("/?state=good-state&code=4/0RealCode123"))
        code = await receiver.wait(wait_seconds=5)

    assert planted.startswith(b"HTTP/1.1 400")
    assert missing.startswith(b"HTTP/1.1 400")
    assert genuine.startswith(b"HTTP/1.1 200")
    assert code == "4/0RealCode123"


@pytest.mark.security
async def test_the_page_never_reflects_the_request() -> None:
    async with LoopbackReceiver("s") as receiver:
        reply = await raw_request(port_of(receiver), get("/?state=<script>alert(1)</script>"))

    assert b"<script>alert" not in reply


@pytest.mark.security
async def test_only_one_sign_in_is_accepted() -> None:
    async with LoopbackReceiver("s") as receiver:
        port = port_of(receiver)
        await raw_request(port, get("/?state=s&code=4/0FirstCode12"))
        second = await raw_request(port, get("/?state=s&code=4/0SecondCode1"))
        code = await receiver.wait(wait_seconds=5)

    assert code == "4/0FirstCode12"
    assert second.startswith(b"HTTP/1.1 400")


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (f"POST /?state=s&code=4/0AbCdEf123 HTTP/1.1{CRLF}{CRLF}".encode(), b"405"),
        (get("/favicon.ico"), b"404"),
        (b"garbage" + CRLF.encode() * 2, b"405"),
        (get("/?" + "&".join(f"k{i}=v" for i in range(20))), b"400"),
    ],
)
async def test_unexpected_requests_are_rejected(request_bytes: bytes, status: bytes) -> None:
    async with LoopbackReceiver("s") as receiver:
        reply = await raw_request(port_of(receiver), request_bytes)
        with pytest.raises(OAuthError, match="not completed in time"):
            await receiver.wait(wait_seconds=0.05)

    assert reply.startswith(b"HTTP/1.1 " + status)


@pytest.mark.security
async def test_oversized_requests_are_dropped_and_the_listener_keeps_waiting() -> None:
    async with LoopbackReceiver("s") as receiver:
        port = port_of(receiver)
        dropped = await raw_request(port, b"GET /?" + b"a" * 20_000)
        await raw_request(port, get("/?state=s&code=4/0AbCdEf123"))
        code = await receiver.wait(wait_seconds=5)

    assert dropped == b""
    assert code == "4/0AbCdEf123"


async def test_a_cancelled_sign_in_is_reported() -> None:
    async with LoopbackReceiver("s") as receiver:
        reply = await raw_request(port_of(receiver), get("/?state=s&error=access_denied"))
        with pytest.raises(OAuthError, match="access_denied"):
            await receiver.wait(wait_seconds=5)

    assert b"did not finish" in reply


@pytest.mark.security
async def test_error_codes_and_codes_from_the_redirect_are_validated() -> None:
    async with LoopbackReceiver("s") as receiver:
        await raw_request(port_of(receiver), get("/?state=s&error=%3Cb%3Ex"))
        with pytest.raises(OAuthError, match="unknown error"):
            await receiver.wait(wait_seconds=5)
    async with LoopbackReceiver("s") as receiver:
        await raw_request(port_of(receiver), get("/?state=s&code=bad%20code%0D%0A"))
        with pytest.raises(OAuthError, match="malformed"):
            await receiver.wait(wait_seconds=5)


async def test_wait_requires_the_context_manager() -> None:
    with pytest.raises(RuntimeError):
        await LoopbackReceiver("s").wait(wait_seconds=0.01)


# ------------------------------------------------------------ token endpoint


async def test_exchange_code_sends_the_verifier_and_returns_the_grant() -> None:
    seen: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return token_response(refresh_token="1//refresh-token-value-0001")

    async with client(handle) as http:
        grant = await exchange_code(
            http, CREDS, code="4/0code", verifier="v" * 50, redirect_uri="http://127.0.0.1:1"
        )

    assert str(seen[0].url) == TOKEN_URL
    assert form(seen[0]) == {
        "code": "4/0code",
        "client_id": CREDS.client_id,
        "client_secret": CREDS.client_secret,
        "redirect_uri": "http://127.0.0.1:1",
        "grant_type": "authorization_code",
        "code_verifier": "v" * 50,
    }
    assert grant.refresh_token == "1//refresh-token-value-0001"
    assert grant.access.scopes == {"https://www.googleapis.com/auth/gmail.readonly"}
    assert "refresh-token" not in repr(grant)
    assert "access-token" not in repr(grant)


async def test_exchange_without_a_refresh_token_fails() -> None:
    async with client(lambda _: token_response()) as http:
        with pytest.raises(OAuthError, match="refresh token"):
            await exchange_code(http, CREDS, code="c", verifier="v", redirect_uri="r")


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(200, json={"access_token": "x"}),
        httpx2.Response(200, json={"access_token": "x", "expires_in": "3600"}),
        httpx2.Response(200, json=["not", "an", "object"]),
        httpx2.Response(200, text="<html>"),
    ],
)
async def test_incomplete_token_responses_are_refused(response: httpx2.Response) -> None:
    async with client(lambda _: response) as http:
        with pytest.raises(OAuthError, match="token response"):
            await refresh_access(http, CREDS, "1//r")


async def test_refresh_reports_revoked_access() -> None:
    async def handle(request: httpx2.Request) -> httpx2.Response:
        assert form(request)["grant_type"] == "refresh_token"
        return httpx2.Response(400, json={"error": "invalid_grant", "error_description": "Bad"})

    async with client(handle) as http:
        with pytest.raises(AuthRevoked, match="revoked or expired"):
            await refresh_access(http, CREDS, "1//r")


async def test_other_token_errors_show_only_a_safe_code() -> None:
    def handle(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, json={"error": "<script>"})

    async with client(handle) as http:
        with pytest.raises(OAuthError, match=r"HTTP 401, unknown") as info:
            await refresh_access(http, CREDS, "1//r")

    assert not isinstance(info.value, AuthRevoked)


@pytest.mark.security
async def test_transport_errors_do_not_chain_the_request() -> None:
    def handle(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("boom", request=request)

    async with client(handle) as http:
        with pytest.raises(OAuthError, match="could not reach Google") as info:
            await refresh_access(http, CREDS, "1//secret-refresh")

    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


@pytest.mark.parametrize(
    ("response", "revoked"),
    [
        (httpx2.Response(200), True),
        (httpx2.Response(400, json={"error": "invalid_token"}), True),
        (httpx2.Response(400, json={"error": "invalid_request"}), False),
        (httpx2.Response(503), False),
    ],
)
async def test_revoke(response: httpx2.Response, revoked: bool) -> None:
    seen: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return response

    async with client(handle) as http:
        assert await revoke(http, "1//token") is revoked

    assert str(seen[0].url) == REVOKE_URL
    assert form(seen[0]) == {"token": "1//token"}


async def test_revoke_survives_network_errors() -> None:
    def handle(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("down", request=request)

    async with client(handle) as http:
        assert await revoke(http, "1//token") is False


# --------------------------------------------------------------- GoogleAuth


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def test_access_tokens_are_cached_refreshed_and_redacted() -> None:
    calls: list[int] = []

    def handle(_: httpx2.Request) -> httpx2.Response:
        calls.append(1)
        return token_response(access_token=f"ya29.token-number-{len(calls):04d}", expires_in=3600)

    clock, redactor = Clock(), Redactor()
    async with client(handle) as http:
        auth = GoogleAuth(http, CREDS, "1//r", redactor=redactor, clock=clock)
        first = await auth.token()
        again = await auth.token()
        clock.now += 3600 - 59  # inside the refresh margin
        refreshed = await auth.token()

    assert first == again == "ya29.token-number-0001"
    assert refreshed == "ya29.token-number-0002"
    assert len(calls) == 2
    assert redactor.redact(f"Bearer {first}") == f"Bearer {REDACTED}"
    assert "token-number" not in repr(auth)


async def test_concurrent_callers_share_one_refresh() -> None:
    calls: list[int] = []

    async def handle(_: httpx2.Request) -> httpx2.Response:
        calls.append(1)
        await asyncio.sleep(0.01)
        return token_response()

    async with client(handle) as http:
        auth = GoogleAuth(http, CREDS, "1//r", redactor=Redactor())
        tokens = await asyncio.gather(*(auth.token() for _ in range(5)))

    assert len(set(tokens)) == 1
    assert len(calls) == 1


async def test_invalidate_forces_a_refresh() -> None:
    calls: list[int] = []

    def handle(_: httpx2.Request) -> httpx2.Response:
        calls.append(1)
        return token_response()

    async with client(handle) as http:
        auth = GoogleAuth(http, CREDS, "1//r", redactor=Redactor())
        await auth.token()
        auth.invalidate()
        await auth.token()

    assert len(calls) == 2


@pytest.mark.security
async def test_disconnecting_stops_access_immediately() -> None:
    connected = [True]
    calls: list[int] = []

    def handle(_: httpx2.Request) -> httpx2.Response:
        calls.append(1)
        return token_response()

    async with client(handle) as http:
        auth = GoogleAuth(
            http, CREDS, "1//r", redactor=Redactor(), still_connected=lambda: connected[0]
        )
        await auth.token()
        connected[0] = False
        with pytest.raises(AuthRevoked, match="disconnected"):
            await auth.token()

    assert len(calls) == 1


async def test_invalidate_only_forgets_the_token_that_was_rejected() -> None:
    calls: list[int] = []

    def handle(_: httpx2.Request) -> httpx2.Response:
        calls.append(1)
        return token_response(access_token=f"ya29.token-number-{len(calls):04d}")

    async with client(handle) as http:
        auth = GoogleAuth(http, CREDS, "1//r", redactor=Redactor())
        await auth.token()
        auth.invalidate("ya29.some-older-token-0000")
        await auth.token()
        auth.invalidate("ya29.token-number-0001")
        await auth.token()

    assert len(calls) == 2


async def test_a_changed_connection_says_how_to_recover() -> None:
    async with client(lambda _: token_response()) as http:
        auth = GoogleAuth(http, CREDS, "1//r", redactor=Redactor(), still_connected=lambda: False)
        with pytest.raises(AuthRevoked) as info:
            await auth.token()

    assert str(info.value) == CHANGED


@pytest.mark.security
async def test_a_malformed_url_does_not_break_the_listener() -> None:
    async with LoopbackReceiver("s") as receiver:
        port = port_of(receiver)
        await raw_request(port, get("//[x"))
        await raw_request(port, get("/?state=s&code=4/0AbCdEf123"))
        code = await receiver.wait(wait_seconds=5)

    assert code == "4/0AbCdEf123"


# ------------------------------------------------------- headless sign-in


REDIRECT = "http://127.0.0.1:8765"
STATE = "s" * 43


def test_a_pasted_redirect_yields_its_code() -> None:
    from bastion.google.oauth import code_from_redirect

    address = f"  {REDIRECT}/?state={STATE}&code=4/0AbCdEf123&scope=x  "

    assert code_from_redirect(address, STATE, REDIRECT) == "4/0AbCdEf123"


@pytest.mark.security
@pytest.mark.parametrize(
    ("address", "reason"),
    [
        (f"{REDIRECT}/?state={'t' * 43}&code=4/0AbCdEf123", "different sign-in"),
        (f"http://127.0.0.1:9999/?state={STATE}&code=4/0AbCdEf123", "not the sign-in address"),
        (f"https://evil.example/?state={STATE}&code=4/0AbCdEf123", "not the sign-in address"),
        (f"{REDIRECT}/other?state={STATE}&code=4/0AbCdEf123", "not the sign-in address"),
        (f"{REDIRECT}/?state={STATE}&error=access_denied", "access_denied"),
        (f"{REDIRECT}/?state={STATE}&code=<script>", "malformed"),
        (f"{REDIRECT}/?" + "&".join(f"k{i}=v" for i in range(20)), "malformed"),
    ],
)
def test_a_pasted_redirect_must_belong_to_this_sign_in(address: str, reason: str) -> None:
    from bastion.google.oauth import OAuthError, code_from_redirect

    with pytest.raises(OAuthError, match=reason):
        code_from_redirect(address, STATE, REDIRECT)
