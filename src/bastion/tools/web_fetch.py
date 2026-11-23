"""``web_fetch``: read a web page, under every egress control (C7).

* Only URLs the agent was *given* (owner messages, search results) may be fetched.
* Every URL, including each redirect hop, must pass ``normalize_url``.
* Connections go through the guarded client, which re-validates addresses at connect time.
* Responses are size-capped, limited to text content types, and returned as untrusted.
* Error messages never echo anything the remote server chose (headers, redirect targets):
  error text reaches the model, so it must not become an injection channel.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx2
from pydantic import Field

from bastion.security.egress import EgressError, guarded_client, normalize_url
from bastion.tools.base import (
    RiskTier,
    Tool,
    ToolArgs,
    ToolContext,
    ToolDenied,
    ToolError,
    ToolOutput,
    Trust,
    fingerprint,
)
from bastion.tools.html_text import html_to_text

MAX_BYTES = 2_000_000
MAX_PARSE_CHARS = 1_000_000
MAX_REDIRECTS = 5
MAX_CHARS = 20_000
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_TEXT_TYPES = frozenset(
    {"text/plain", "text/markdown", "text/csv", "application/json", "application/xml", "text/xml"}
)

type ClientFactory = Callable[[], httpx2.AsyncClient]


class WebFetchArgs(ToolArgs):
    url: str = Field(
        min_length=1,
        max_length=2048,
        description="A URL from a search result or from the owner's own message.",
    )


@dataclass(frozen=True)
class _Page:
    url: str
    content_type: str
    text: str
    truncated: bool


def _source(url: str) -> str:
    return f"web_fetch:{urlsplit(url).hostname or 'unknown'}"


async def _read_capped(response: httpx2.Response) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_BYTES:
            return b"".join(chunks)[:MAX_BYTES], True
    return b"".join(chunks), False


def _decode(body: bytes, charset: str | None) -> str:
    try:
        return body.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _next_hop(current: str, response: httpx2.Response) -> str:
    location = response.headers.get("location")
    if not location:
        raise ToolError("the server sent a redirect without a location")
    try:
        return normalize_url(urljoin(current, location))
    except (EgressError, ValueError) as exc:
        # The target was chosen by the remote server: report the fact, never the text.
        raise ToolDenied(
            "the page redirected to a disallowed URL", untrusted_source=_source(current)
        ) from exc


async def _read_page(response: httpx2.Response) -> _Page:
    if response.status_code >= 400:
        raise ToolError(f"the server returned HTTP {response.status_code}")
    header = response.headers.get("content-type", "")
    content_type = header.split(";", 1)[0].strip().lower()
    if content_type not in _HTML_TYPES | _TEXT_TYPES:
        raise ToolError("the page is not text or HTML")
    body, truncated = await _read_capped(response)
    return _Page(
        str(response.url), content_type, _decode(body, response.charset_encoding), truncated
    )


class WebFetchTool(Tool[WebFetchArgs]):
    name = "web_fetch"
    description = (
        "Fetch a web page and return its readable text. Only URLs that appeared in search "
        "results or in the owner's own messages can be fetched."
    )
    args_model = WebFetchArgs
    risk = RiskTier.READ

    def __init__(self, client_factory: ClientFactory = guarded_client) -> None:
        self._client_factory = client_factory

    def audit_view(self, args: WebFetchArgs) -> dict[str, Any]:
        # The host is useful in the log; paths and query strings can carry private tokens.
        return {"host": urlsplit(args.url).hostname, "url_sha256": fingerprint(args.url)}

    async def run(self, args: WebFetchArgs, ctx: ToolContext) -> ToolOutput:
        try:
            url = normalize_url(args.url)
        except EgressError as exc:
            raise ToolDenied(f"URL refused: {exc}") from exc
        if not ctx.provenance.allows(url):
            raise ToolDenied(
                "URL refused: it did not come from a search result or the owner's message. "
                "Ask the owner to paste the link if they want it read."
            )
        async with self._client_factory() as client:
            page = await self._fetch(client, url)
        title, body = await self._render(page)
        truncated = page.truncated or len(body) > MAX_CHARS
        note = "\n\n[Content truncated.]" if truncated else ""
        return ToolOutput(
            content=f"URL: {page.url}\nTitle: {title or '(none)'}\n\n{body[:MAX_CHARS]}{note}",
            trust=Trust.UNTRUSTED,
            source=_source(page.url),
        )

    async def _render(self, page: _Page) -> tuple[str, str]:
        if page.content_type not in _HTML_TYPES:
            return "", page.text.strip()
        # Parse in a worker thread so even a slow, hostile document can never stall the event
        # loop (and with it every timeout). pyproject also requires a CPython whose HTMLParser
        # is linear-time on malformed input.
        return await asyncio.to_thread(html_to_text, page.text[:MAX_PARSE_CHARS])

    async def _fetch(self, client: httpx2.AsyncClient, url: str) -> _Page:
        for hop in range(MAX_REDIRECTS + 1):
            try:
                async with client.stream("GET", url) as response:
                    if response.is_redirect:
                        url = _next_hop(url, response)
                        continue
                    return await _read_page(response)
            except EgressError as exc:
                if hop == 0:
                    raise ToolDenied(f"URL refused: {exc}") from exc
                raise ToolDenied(
                    "the page redirected to a disallowed address", untrusted_source=_source(url)
                ) from exc
            except httpx2.HTTPError as exc:
                raise ToolError(f"could not fetch the page ({type(exc).__name__})") from exc
        raise ToolError("too many redirects")
