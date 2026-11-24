"""Google OAuth for a desktop app: the owner signs in once; a refresh token stays in the keyring.

Google allows only one flow for desktop apps with Gmail or Calendar access: a browser sign-in
that redirects to a listener on this machine (RFC 8252). Bastion keeps that exposure small:

* the listener binds ``127.0.0.1`` only, on a random port, during ``bastion google connect``
  alone, and closes after the first valid redirect or five minutes;
* ``state`` is a random value the redirect must echo, so no other sign-in result can be
  planted;
* PKCE (S256): an intercepted code is useless without the verifier, which never leaves this
  process;
* the page it serves is static: nothing from the request is reflected into it.

Access tokens exist only in memory, are registered with the redactor, and are refreshed shortly
before they expire. ``GoogleAuth`` re-checks the keyring before each use, so
``bastion google disconnect`` also stops a running daemon.
"""

import asyncio
import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx2

from bastion.security.redact import Redactor

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105  # nosec B105: a URL, not a secret
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
LOOPBACK_HOST = "127.0.0.1"
CONNECT_TIMEOUT_SECONDS = 300.0
REFRESH_MARGIN_SECONDS = 60.0
MAX_REQUEST_BYTES = 8192
REQUEST_READ_SECONDS = 10.0

_CLIENT_ID = re.compile(r"[0-9]{5,30}-[a-z0-9]{8,64}\.apps\.googleusercontent\.com")
_CLIENT_SECRET = re.compile(r"[A-Za-z0-9_-]{10,100}")
_CODE = re.compile(r"[A-Za-z0-9/_.~-]{10,512}")
_ERROR_CODE = re.compile(r"[a-z_]{1,40}")
_CRLF = "\r\n"

_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Bastion</title>"
    "<body style='font-family:sans-serif;margin:3em'><h1>{heading}</h1><p>{text}</p></body>"
)
_DONE = _PAGE.format(heading="Bastion is connected", text="You can close this tab.")
_CANCELLED = _PAGE.format(heading="Sign-in did not finish", text="Return to the terminal.")
_REJECTED = _PAGE.format(heading="Not accepted", text="This request did not come from Bastion.")


class OAuthError(Exception):
    """Signing in or refreshing access failed. The message is safe to show."""


class AuthRevoked(OAuthError):
    """The refresh token no longer works (revoked, expired, or disconnected locally)."""


class ConnectionChanged(AuthRevoked):
    """The keyring no longer holds the token this process started with."""


CHANGED = (
    "Bastion's Google connection changed since it started (disconnected or reconnected). If "
    "the owner reconnected, Bastion must be restarted; otherwise ask them to run: "
    "bastion google connect"
)


def valid_client_id(value: str) -> bool:
    return _CLIENT_ID.fullmatch(value) is not None


def valid_client_secret(value: str) -> bool:
    return _CLIENT_SECRET.fullmatch(value) is not None


@dataclass(frozen=True)
class ClientCredentials:
    """The owner's own OAuth client (type "Desktop app") from the Google Cloud console."""

    client_id: str
    client_secret: str

    def __repr__(self) -> str:
        return f"ClientCredentials(client_id={self.client_id!r}, client_secret=<redacted>)"


@dataclass(frozen=True)
class Pkce:
    verifier: str
    challenge: str


def new_pkce() -> Pkce:
    verifier = secrets.token_urlsafe(64)  # 86 characters from the unreserved set
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return Pkce(verifier, challenge)


def authorization_url(
    client_id: str, redirect_uri: str, scopes: Iterable[str], state: str, challenge: str
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",  # always issue a fresh refresh token
    }
    return f"{AUTH_URL}?{urlencode(params, quote_via=quote)}"


# ---------------------------------------------------------------- loopback listener


def _response(status: str, body: str) -> bytes:
    payload = body.encode("utf-8")
    head = _CRLF.join(
        [
            f"HTTP/1.1 {status}",
            "Content-Type: text/html; charset=utf-8",
            f"Content-Length: {len(payload)}",
            "Connection: close",
            "Cache-Control: no-store",
            "Referrer-Policy: no-referrer",
            "X-Content-Type-Options: nosniff",
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'",
        ]
    )
    return (head + _CRLF + _CRLF).encode("ascii") + payload


def _first(params: Mapping[str, list[str]], name: str) -> str:
    values = params.get(name)
    return values[0] if values else ""


class LoopbackReceiver:
    """Receives the browser's redirect after sign-in, once, on 127.0.0.1."""

    def __init__(self, state: str, *, port: int = 0) -> None:
        self._state = state.encode("ascii")
        self._port = port
        self._server: asyncio.Server | None = None
        self._result: asyncio.Future[str] | None = None

    async def __aenter__(self) -> Self:
        self._result = asyncio.get_running_loop().create_future()
        self._server = await asyncio.start_server(
            self._handle, LOOPBACK_HOST, self._port, limit=MAX_REQUEST_BYTES
        )
        self._port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._result is not None and not self._result.done():
            self._result.cancel()

    @property
    def redirect_uri(self) -> str:
        return f"http://{LOOPBACK_HOST}:{self._port}"

    @property
    def addresses(self) -> tuple[str, ...]:
        sockets = self._server.sockets if self._server is not None else ()
        return tuple(str(s.getsockname()[0]) for s in sockets)

    async def wait(self, wait_seconds: float = CONNECT_TIMEOUT_SECONDS) -> str:
        """The authorization code, once the browser comes back."""
        if self._result is None:
            raise RuntimeError("use LoopbackReceiver as an async context manager")
        try:
            async with asyncio.timeout(wait_seconds):
                return await asyncio.shield(self._result)
        except TimeoutError:
            raise OAuthError("the Google sign-in was not completed in time") from None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(REQUEST_READ_SECONDS):
                head = await reader.readuntil(b"\r\n\r\n")
            writer.write(self._answer(head))
            await writer.drain()
        except (
            TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            OSError,
            ValueError,  # e.g. a malformed URL from some other local program
        ):
            pass  # a stray, slow or oversized connection: drop it, keep waiting
        finally:
            writer.close()

    def _answer(self, head: bytes) -> bytes:
        parts = head.split(b"\r\n", 1)[0].decode("ascii", "replace").split(" ")
        if len(parts) != 3 or parts[0] != "GET":
            return _response("405 Method Not Allowed", _REJECTED)
        target = urlsplit(parts[1])
        if target.path != "/":
            return _response("404 Not Found", _REJECTED)
        try:
            params = parse_qs(target.query, max_num_fields=10)
        except ValueError:  # too many fields
            return _response("400 Bad Request", _REJECTED)
        state = _first(params, "state").encode("ascii", "replace")
        result = self._result
        if result is None or result.done() or not hmac.compare_digest(state, self._state):
            return _response("400 Bad Request", _REJECTED)
        error = _first(params, "error")
        if error:
            reason = error if _ERROR_CODE.fullmatch(error) else "unknown error"
            result.set_exception(OAuthError(f"Google sign-in was not completed ({reason})"))
            return _response("200 OK", _CANCELLED)
        code = _first(params, "code")
        if not _CODE.fullmatch(code):
            result.set_exception(OAuthError("Google returned a malformed sign-in code"))
            return _response("400 Bad Request", _CANCELLED)
        result.set_result(code)
        return _response("200 OK", _DONE)


# ---------------------------------------------------------------- token endpoint


@dataclass(frozen=True)
class AccessToken:
    token: str
    expires_in: float
    scopes: frozenset[str]

    def __repr__(self) -> str:
        return f"AccessToken(<redacted>, expires_in={self.expires_in}, scopes={self.scopes})"


@dataclass(frozen=True)
class TokenGrant:
    access: AccessToken
    refresh_token: str

    def __repr__(self) -> str:
        return f"TokenGrant({self.access!r}, refresh_token=<redacted>)"


def _error_code(response: httpx2.Response) -> str:
    try:
        error = response.json().get("error")
    except (ValueError, AttributeError):
        return "unknown"
    return error if isinstance(error, str) and _ERROR_CODE.fullmatch(error) else "unknown"


async def _post_form(client: httpx2.AsyncClient, url: str, form: Mapping[str, str]) -> Any:
    try:
        response = await client.post(url, data=dict(form))
    except httpx2.HTTPError as exc:
        # `from None`: the cause can describe the request, and the form holds credentials.
        raise OAuthError(f"could not reach Google ({type(exc).__name__})") from None
    if response.status_code >= 400:
        code = _error_code(response)
        if code == "invalid_grant":
            raise AuthRevoked("Google no longer accepts Bastion's access (revoked or expired)")
        raise OAuthError(f"Google refused the request (HTTP {response.status_code}, {code})")
    try:
        data = response.json()
    except ValueError:
        raise OAuthError("Google returned an unreadable token response") from None
    if not isinstance(data, Mapping):
        raise OAuthError("Google returned an unreadable token response")
    return data


def _access_token(data: Mapping[str, Any]) -> AccessToken:
    token, expires, scope = data.get("access_token"), data.get("expires_in"), data.get("scope")
    if not isinstance(token, str) or not token or type(expires) is not int or expires <= 0:
        raise OAuthError("Google returned an incomplete token response")
    scopes = frozenset(scope.split()) if isinstance(scope, str) else frozenset()
    return AccessToken(token, float(expires), scopes)


async def exchange_code(
    client: httpx2.AsyncClient,
    credentials: ClientCredentials,
    *,
    code: str,
    verifier: str,
    redirect_uri: str,
) -> TokenGrant:
    data = await _post_form(
        client,
        TOKEN_URL,
        {
            "code": code,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        },
    )
    refresh_token = data.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise OAuthError("Google did not issue a refresh token; try connecting again")
    return TokenGrant(_access_token(data), refresh_token)


async def refresh_access(
    client: httpx2.AsyncClient, credentials: ClientCredentials, refresh_token: str
) -> AccessToken:
    data = await _post_form(
        client,
        TOKEN_URL,
        {
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
    )
    return _access_token(data)


async def revoke(client: httpx2.AsyncClient, token: str) -> bool:
    """Revoke a token at Google. True if it no longer works (including "already invalid")."""
    try:
        response = await client.post(REVOKE_URL, data={"token": token})
    except httpx2.HTTPError:
        return False
    if response.status_code == 200:
        return True
    return response.status_code == 400 and _error_code(response) == "invalid_token"


class GoogleAuth:
    """Short-lived access tokens for API calls, from the refresh token in the keyring."""

    def __init__(
        self,
        client: httpx2.AsyncClient,
        credentials: ClientCredentials,
        refresh_token: str,
        *,
        redactor: Redactor,
        still_connected: Callable[[], bool] = lambda: True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._credentials = credentials
        self._refresh_token = refresh_token
        self._redactor = redactor
        self._still_connected = still_connected
        self._clock = clock
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._expires_at = 0.0

    def __repr__(self) -> str:
        return "GoogleAuth(<redacted>)"

    async def token(self) -> str:
        # The keyring read runs in a thread: a backend waiting to be unlocked must not stall
        # the event loop (and every timeout with it).
        if not await asyncio.to_thread(self._still_connected):
            self._token = None
            raise ConnectionChanged(CHANGED)
        async with self._lock:
            if self._token is None or self._clock() >= self._expires_at - REFRESH_MARGIN_SECONDS:
                access = await refresh_access(self._client, self._credentials, self._refresh_token)
                self._redactor.register_secret(access.token)
                self._token = access.token
                self._expires_at = self._clock() + access.expires_in
            return self._token

    def invalidate(self, token: str | None = None) -> None:
        """Forget the cached access token after Google rejected it.

        Only if it is the one that was rejected: a concurrent call may already have refreshed.
        """
        if token is None or token == self._token:
            self._token = None
