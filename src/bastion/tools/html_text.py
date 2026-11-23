"""Readable text from HTML, using only the standard library.

Drops scripts, styles and embedded objects, plus content hidden from human readers
(``hidden``, ``aria-hidden="true"``, ``display:none``, ``visibility:hidden``, zero font size):
hidden text is a favourite place to plant prompt injections. The goal is to drop exactly what a
browser would not show, so omitted end tags (``<p>``, ``<li>``, ...) are closed the way a
browser closes them. This is a mitigation, not a guarantee, which is why fetched pages are
still treated as untrusted.
"""

import re
from html.parser import HTMLParser

_SKIP = frozenset(
    {"script", "style", "noscript", "template", "svg", "iframe", "object", "embed", "canvas"}
)
_BLOCK = frozenset(
    {
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "figcaption",
        "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav",
        "ol", "p", "pre", "section", "table", "td", "th", "tr", "ul",
    }
)  # fmt: skip
_VOID = frozenset(
    {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr",
    }
)  # fmt: skip
# Start tags that implicitly close an open element whose end tag was omitted (HTML spec).
_P_CLOSERS = frozenset(
    {
        "address", "article", "aside", "blockquote", "details", "div", "dl", "fieldset",
        "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
        "hgroup", "hr", "main", "menu", "nav", "ol", "p", "pre", "section", "table", "ul",
    }
)  # fmt: skip
_IMPLICIT_CLOSERS = {
    "p": _P_CLOSERS,
    "li": frozenset({"li"}),
    "dt": frozenset({"dt", "dd"}),
    "dd": frozenset({"dt", "dd"}),
    "td": frozenset({"td", "th", "tr"}),
    "th": frozenset({"td", "th", "tr"}),
    "tr": frozenset({"tr"}),
    "option": frozenset({"option", "optgroup"}),
}
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])", re.IGNORECASE
)
_SPACES = re.compile(r"[ \t\r\f\v]+")
_BLANK_LINES = re.compile(r"\n\s*\n(\s*\n)+")


def _is_hidden(attrs: list[tuple[str, str | None]]) -> bool:
    for name, value in attrs:
        if name == "hidden":
            return True
        if name == "aria-hidden" and (value or "").lower() == "true":
            return True
        if name == "style" and value and _HIDDEN_STYLE.search(value):
            return True
    return False


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self._skipped: list[str] = []  # open elements inside a hidden region, outermost first
        self._in_title = False

    def _implicitly_closes_hidden_root(self, tag: str) -> bool:
        root = self._skipped[0]
        return len(self._skipped) == 1 and tag in _IMPLICIT_CLOSERS.get(root, frozenset())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._skipped:
            if not self._implicitly_closes_hidden_root(tag):
                if tag not in _VOID:
                    self._skipped.append(tag)
                return
            self._skipped.clear()  # e.g. <p hidden>secret<p>shown: the new <p> ends the hidden one
        if tag in _VOID:
            if tag in _BLOCK:
                self.parts.append("\n")
            return
        if tag in _SKIP or _is_hidden(attrs):
            self._skipped.append(tag)
            return
        if tag == "title":
            self._in_title = True
        elif tag in _BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self._skipped:
            if tag in self._skipped:
                # Close this element and any children whose end tags were omitted.
                index = len(self._skipped) - 1 - self._skipped[::-1].index(tag)
                del self._skipped[index:]
            return
        if tag == "title":
            self._in_title = False
        elif tag in _BLOCK and tag not in _VOID:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skipped:
            return
        (self.title_parts if self._in_title else self.parts).append(data)


def _tidy(text: str) -> str:
    lines = (_SPACES.sub(" ", line).strip() for line in text.splitlines())
    return _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()


def html_to_text(html: str) -> tuple[str, str]:
    """Return ``(title, text)`` for an HTML document."""
    extractor = _Extractor()
    extractor.feed(html)
    extractor.close()
    return _tidy(" ".join(extractor.title_parts)), _tidy("".join(extractor.parts))
