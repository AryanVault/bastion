"""The landing page (site/) stays truthful and self-contained.

It lists every red-team attack with the outcome the suite actually expects, its numbers match
the code, and it loads nothing from other hosts (the page promises no trackers, and its
Content-Security-Policy only allows its own files).
"""

import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from bastion.redteam.scenarios import SCENARIOS

SITE = Path(__file__).parents[2] / "site"


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, str]] = []
        self.resources: list[str] = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self._row: dict[str, str] | None = None
        self._field: str | None = None
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        classes = a.get("class", "").split()
        if "style" in a:
            self.inline_styles += 1
        if tag == "style":
            self.inline_styles += 1
        if tag == "script":
            if "src" in a:
                self.resources.append(a["src"])
            else:
                self._in_script = True
        if tag in {"link", "img", "source", "iframe"}:
            self.resources.append(a.get("href") or a.get("src") or "")
        if tag == "li" and "row" in classes:
            self._row = {"vector": a.get("data-vector", "")}
        elif self._row is not None:
            if "row-title" in classes:
                self._field = "title"
            elif "stamp" in classes:
                self._field = "outcome"

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False
        if tag == "li" and self._row is not None:
            self.rows.append(self._row)
            self._row = None
        if tag in {"p", "span"}:
            self._field = None

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_scripts += 1
        if self._row is not None and self._field:
            self._row[self._field] = self._row.get(self._field, "") + data


@pytest.fixture(scope="module")
def html() -> str:
    return (SITE / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def page(html: str) -> _Page:
    parser = _Page()
    parser.feed(html)
    return parser


def test_the_scoreboard_lists_every_attack_with_its_real_outcome(page: _Page) -> None:
    listed = [(r["title"], r["vector"], r["outcome"]) for r in page.rows]
    expected = [(s.title, s.vector.value, s.expect.short) for s in SCENARIOS]

    assert listed == expected


def test_the_attack_count_on_the_page_matches_the_suite(html: str) -> None:
    counts = set(re.findall(r'class="count" data-to="(\d+)">(\d+)<', html))
    total = str(len(SCENARIOS))

    assert (total, total) in counts
    assert f"one of the {total} attacks" in html


def test_every_filter_matches_at_least_one_attack(html: str) -> None:
    vectors = {s.vector.value for s in SCENARIOS}
    filters = set(re.findall(r'data-filter="([^"]+)"', html)) - {"all"}

    assert filters == vectors


def test_the_page_loads_only_its_own_files(page: _Page) -> None:
    assert page.resources
    for resource in page.resources:
        assert not re.match(r"^(https?:)?//", resource), resource
        assert (SITE / resource).is_file(), resource


def test_the_stylesheet_loads_only_its_own_fonts() -> None:
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    urls = re.findall(r"url\(\"?([^\")]+)\"?\)", css)

    assert urls
    for url in urls:
        assert (SITE / url).is_file(), url
    assert "@import" not in css


def test_nothing_inline_needs_a_weaker_content_security_policy(page: _Page) -> None:
    assert page.inline_scripts == 0
    assert page.inline_styles == 0


def test_the_deployment_sends_a_strict_content_security_policy() -> None:
    config = json.loads((SITE / "vercel.json").read_text(encoding="utf-8"))
    headers = {h["key"]: h["value"] for rule in config["headers"] for h in rule["headers"]}
    csp = headers["Content-Security-Policy"]

    assert "default-src 'none'" in csp
    assert "script-src 'self';" in csp
    assert "unsafe" not in csp
    assert headers["Referrer-Policy"] == "no-referrer"
