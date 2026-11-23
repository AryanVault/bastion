"""``web_search``: search the web through a pluggable backend (Brave Search by default).

Titles and snippets are written by whoever controls the result pages, so results are returned
as untrusted. The result URLs are registered as fetchable (URL provenance, control C7).
"""

import html
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import httpx2
from pydantic import Field

from bastion.security.egress import USER_AGENT
from bastion.tools.base import RiskTier, Tool, ToolArgs, ToolContext, ToolError, ToolOutput, Trust

_TAGS = re.compile(r"<[^>]+>")

type ClientFactory = Callable[[], httpx2.AsyncClient]


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str


class SearchBackend(Protocol):
    async def search(self, query: str, count: int) -> list[SearchResult]: ...


def _plain(text: Any) -> str:
    return html.unescape(_TAGS.sub("", str(text or ""))).strip()


def _default_client() -> httpx2.AsyncClient:
    return httpx2.AsyncClient(timeout=15.0, trust_env=False, headers={"User-Agent": USER_AGENT})


class BraveSearch:
    ENDPOINT = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, api_key: str, client_factory: ClientFactory = _default_client) -> None:
        self._api_key = api_key
        self._client_factory = client_factory

    async def search(self, query: str, count: int) -> list[SearchResult]:
        headers = {"X-Subscription-Token": self._api_key, "Accept": "application/json"}
        try:
            async with self._client_factory() as client:
                response = await client.get(
                    self.ENDPOINT, params={"q": query, "count": count}, headers=headers
                )
        except httpx2.HTTPError as exc:
            raise ToolError(f"web search failed ({type(exc).__name__})") from exc
        if response.status_code in (401, 403):
            raise ToolError("the search API rejected the key")
        if response.status_code == 429:
            raise ToolError("the search API rate limit was hit; try again shortly")
        if response.status_code >= 400:
            raise ToolError(f"the search API returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ToolError("the search API returned an unreadable response") from exc
        web = data.get("web") if isinstance(data, dict) else None
        results = web.get("results") if isinstance(web, dict) else None
        if not isinstance(results, list):
            return []
        return [
            SearchResult(
                _plain(r.get("title")), str(r.get("url", "")), _plain(r.get("description"))
            )
            for r in results[:count]
            if isinstance(r, dict) and r.get("url")
        ]


class WebSearchArgs(ToolArgs):
    query: str = Field(min_length=1, max_length=400, description="What to search for.")
    count: int = Field(default=5, ge=1, le=10, description="Number of results.")


class WebSearchTool(Tool[WebSearchArgs]):
    name = "web_search"
    description = "Search the web. Returns titles, URLs and snippets; URLs can then be fetched."
    args_model = WebSearchArgs
    risk = RiskTier.READ

    def __init__(self, backend: SearchBackend) -> None:
        self._backend = backend

    async def run(self, args: WebSearchArgs, ctx: ToolContext) -> ToolOutput:
        results = await self._backend.search(args.query, args.count)
        if not results:
            return ToolOutput("No results.", Trust.UNTRUSTED, "web_search")
        lines = [
            f"{i}. {r.title}\n   {r.url}\n   {r.snippet}" for i, r in enumerate(results, start=1)
        ]
        return ToolOutput(
            content="\n".join(lines),
            trust=Trust.UNTRUSTED,
            source="web_search",
            discovered_urls=tuple(r.url for r in results),
        )
