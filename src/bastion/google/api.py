"""Authenticated calls to Google's REST APIs (Gmail and Calendar).

* One HTTP client that ignores proxy settings (a proxy would see bearer tokens) and never
  follows redirects; request URL logging is silenced (Gmail search queries are private).
* An expired access token (HTTP 401) is refreshed once and the call retried.
* Responses are size-capped.
* Error messages reach the model, so they are built from the status code and Google's short
  reason codes only, never from free text in the response.
"""

import json
import re
from collections.abc import Mapping
from typing import Any, Protocol

import httpx2

from bastion.google.oauth import AuthRevoked, ConnectionChanged, OAuthError
from bastion.net import quiet_request_logs
from bastion.security.egress import USER_AGENT
from bastion.tools.base import ToolError

MAX_RESPONSE_BYTES = 8_000_000
TIMEOUT_SECONDS = 20.0
RECONNECT = "Ask the owner to run: bastion google connect"

_REASON = re.compile(r"[A-Za-z_]{1,60}")
_SCOPE_REASONS = frozenset({"insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"})
_RATE_REASONS = frozenset(
    {"rateLimitExceeded", "userRateLimitExceeded", "RATE_LIMIT_EXCEEDED", "quotaExceeded"}
)


class GoogleApiError(ToolError):
    """A Google API call failed. The message is safe to show the model."""


class TokenSource(Protocol):
    async def token(self) -> str: ...

    def invalidate(self, token: str) -> None: ...


def google_client() -> httpx2.AsyncClient:
    quiet_request_logs()
    return httpx2.AsyncClient(
        trust_env=False,
        follow_redirects=False,
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT},
    )


def _reasons(body: bytes) -> set[str]:
    try:
        error = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return set()
    if not isinstance(error, Mapping):
        return set()
    found: list[Any] = [error.get("status")]
    for key in ("errors", "details"):
        items = error.get(key)
        if isinstance(items, list):
            found += [item.get("reason") for item in items if isinstance(item, Mapping)]
    return {r for r in found if isinstance(r, str) and _REASON.fullmatch(r)}


def _failure(status: int, body: bytes) -> GoogleApiError:
    reasons = _reasons(body)
    if status == 401:
        return GoogleApiError(f"Google rejected Bastion's access. {RECONNECT}")
    if status == 403 and reasons & _SCOPE_REASONS:
        return GoogleApiError(
            "Bastion's Google access does not include this. The owner can grant it with: "
            "bastion google connect"
        )
    if status == 429 or (status == 403 and reasons & _RATE_REASONS):
        return GoogleApiError("Google's rate limit was reached; try again shortly")
    if status == 404:
        return GoogleApiError("Google says it was not found")
    if status == 410:
        return GoogleApiError("it no longer exists")
    if status == 412:
        return GoogleApiError("it changed since it was read; read it again before changing it")
    if status >= 500:
        return GoogleApiError(f"Google is unavailable right now (HTTP {status})")
    detail = ", ".join(sorted(reasons)[:3]) or "no reason given"
    return GoogleApiError(f"Google refused the request (HTTP {status}: {detail})")


class GoogleApi:
    def __init__(
        self,
        auth: TokenSource,
        client: httpx2.AsyncClient,
        *,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._auth = auth
        self._client = client
        self._max_bytes = max_bytes

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """The parsed JSON response (``None`` for an empty one)."""
        for attempt in range(2):
            token = await self._token()
            status, body = await self._send(method, url, token, params, json_body, headers)
            if status == 401 and attempt == 0:
                self._auth.invalidate(token)  # expired early or revoked: refresh, retry once
                continue
            if status >= 400:
                raise _failure(status, body)
            if not body.strip():
                return None
            try:
                return json.loads(body)
            except ValueError:
                raise GoogleApiError("Google returned an unreadable response") from None
        raise _failure(401, b"")  # unreachable: the second 401 is raised above

    async def _token(self) -> str:
        try:
            return await self._auth.token()
        except ConnectionChanged as exc:
            raise GoogleApiError(str(exc)) from None
        except AuthRevoked as exc:
            raise GoogleApiError(f"{exc}. {RECONNECT}") from None
        except OAuthError as exc:
            raise GoogleApiError(str(exc)) from None

    async def _send(
        self,
        method: str,
        url: str,
        token: str,
        params: Mapping[str, Any] | None,
        json_body: Mapping[str, Any] | None,
        headers: Mapping[str, str] | None,
    ) -> tuple[int, bytes]:
        all_headers = {"Authorization": f"Bearer {token}", **(headers or {})}
        try:
            async with self._client.stream(
                method, url, params=params, json=json_body, headers=all_headers
            ) as response:
                return response.status_code, await self._read(response)
        except httpx2.HTTPError as exc:
            # `from None`: the cause carries the request, including the bearer token.
            raise GoogleApiError(f"could not reach Google ({type(exc).__name__})") from None

    async def _read(self, response: httpx2.Response) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self._max_bytes:
                raise GoogleApiError("Google's response was too large to read")
            chunks.append(chunk)
        return b"".join(chunks)
