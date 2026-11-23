from typing import Any

import httpx2
import pytest

from bastion.security.egress import UrlProvenance
from bastion.tools.base import ToolContext, ToolError, Trust
from bastion.tools.web_search import BraveSearch, SearchResult, WebSearchArgs, WebSearchTool

CTX = ToolContext(provenance=UrlProvenance(), tainted=False)


def brave(status: int, body: Any) -> tuple[BraveSearch, list[httpx2.Request]]:
    seen: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(status, json=body)

    def factory() -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))

    return BraveSearch("BSA-test-key-123", client_factory=factory), seen


async def test_brave_results_are_parsed_and_cleaned() -> None:
    body = {
        "web": {
            "results": [
                {
                    "title": "Py <strong>3.13</strong>",
                    "url": "https://python.org",
                    "description": "Fast &amp; new",
                },
                {"title": "no url"},
            ]
        }
    }
    backend, seen = brave(200, body)

    results = await backend.search("python", 5)

    assert results == [SearchResult("Py 3.13", "https://python.org", "Fast & new")]
    assert seen[0].headers["X-Subscription-Token"] == "BSA-test-key-123"
    assert seen[0].url.params["q"] == "python"


@pytest.mark.parametrize(
    ("status", "message"), [(401, "rejected the key"), (429, "rate limit"), (500, "HTTP 500")]
)
async def test_brave_errors_are_reported(status: int, message: str) -> None:
    backend, _ = brave(status, {})

    with pytest.raises(ToolError, match=message):
        await backend.search("python", 5)


class StaticBackend:
    def __init__(self, results: list[SearchResult]) -> None:
        self.results = results

    async def search(self, query: str, count: int) -> list[SearchResult]:
        return self.results[:count]


async def test_results_are_untrusted_and_their_urls_become_fetchable() -> None:
    tool = WebSearchTool(StaticBackend([SearchResult("A", "https://a.example/x", "snippet")]))

    output = await tool.run(WebSearchArgs(query="anything"), CTX)

    assert output.trust is Trust.UNTRUSTED
    assert output.discovered_urls == ("https://a.example/x",)
    assert "https://a.example/x" in output.content


async def test_no_results() -> None:
    output = await WebSearchTool(StaticBackend([])).run(WebSearchArgs(query="zzz"), CTX)

    assert output.content == "No results."


@pytest.mark.parametrize("body", [[1, 2], {"web": None}, {"web": {"results": "nope"}}, "text"])
async def test_unexpected_response_shapes_mean_no_results(body: Any) -> None:
    backend, _ = brave(200, body)

    assert await backend.search("python", 5) == []
