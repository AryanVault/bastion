import pytest

from bastion.text import reveal_invisible, strip_invisible

TAGS = "".join(chr(0xE0000 + ord(c)) for c in "hidden order")


@pytest.mark.security
def test_escape_sequences_and_invisible_characters_are_stripped() -> None:
    text = "ok\x1b[2Jx\u202eevil\u200b\n\tend\x07\x9b"

    assert strip_invisible(text) == "ok[2Jxevil\n\tend"


@pytest.mark.security
def test_ascii_smuggling_tag_characters_are_stripped() -> None:
    assert strip_invisible(f"recipe{TAGS} ideas") == "recipe ideas"


@pytest.mark.security
def test_lone_surrogates_are_stripped() -> None:
    assert strip_invisible("bad\ud800text") == "badtext"


@pytest.mark.security
def test_invisible_characters_are_revealed_for_review() -> None:
    assert reveal_invisible("alice\u202e@evil.example") == "alice\\u202e@evil.example"
    assert reveal_invisible(chr(0xE0041)) == "\\U000e0041"


def test_ordinary_text_is_untouched() -> None:
    text = "Plain café, naïve résumé, 東京, emoji 🙂 and tabs\tand\nnewlines"

    assert strip_invisible(text) == text
    assert reveal_invisible(text) == text
