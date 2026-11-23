"""Invisible and control characters in untrusted text (control C16).

Attackers use characters people cannot see: ANSI escape sequences that rewrite a terminal,
bidirectional overrides that reorder text, zero-width and filler characters that disguise a
value, and Unicode "tag" characters that models read but humans do not ("ASCII smuggling").
Lone surrogates are included because they are not valid text and break encoders.

``strip_invisible`` removes them (for text shown to the owner or handed to the model);
``reveal_invisible`` turns them into visible ``\\uXXXX`` escapes (for approval prompts, where
the owner must see exactly what will run).
"""

import re

_INVISIBLE = re.compile(
    "["
    "\x00-\x08\x0b-\x1f\x7f-\x9f"  # C0 controls (except tab and newline), DEL, C1 controls
    "\u00ad\u034f\u061c"  # soft hyphen, combining grapheme joiner, Arabic letter mark
    "\u115f\u1160\u17b4\u17b5\u180b-\u180f"  # Hangul and Khmer fillers, Mongolian selectors
    "\u200b-\u200f\u2028-\u202e\u2060-\u206f"  # zero-width, separators, bidi, invisible ops
    "\u3164\ufe00-\ufe0f\ufeff\uffa0"  # Hangul filler, variation selectors, BOM
    "\ud800-\udfff"  # lone surrogates
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef"  # tag characters, variation selectors
    "]"
)


def _escape(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def strip_invisible(text: str) -> str:
    return _INVISIBLE.sub("", text)


def reveal_invisible(text: str) -> str:
    return _INVISIBLE.sub(_escape, text)
