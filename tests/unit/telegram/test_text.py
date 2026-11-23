from datetime import UTC, datetime, timedelta

import pytest

from bastion.security.approvals import ApprovalRequest
from bastion.telegram.api import utf16_len
from bastion.telegram.text import STEP_UP_NOTE, chunk_text, render_approval
from bastion.tools.base import RiskTier

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def request(
    *, step_up: bool = False, summary: str = "Send an email", args: str = "{}"
) -> ApprovalRequest:
    return ApprovalRequest(
        id="abcdef1234567890",
        tool="send_email",
        tier=RiskTier.DESTRUCTIVE if step_up else RiskTier.SEND,
        arguments_json=args,
        digest="0" * 64,
        summary=summary,
        reason="send actions need approval",
        step_up=step_up,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


def test_short_text_is_one_chunk() -> None:
    assert chunk_text("hello") == ["hello"]


def test_long_text_splits_at_newlines_within_the_limit() -> None:
    text = "\n".join(f"line {i:03d} " + "x" * 30 for i in range(200))

    chunks = chunk_text(text, limit=500)

    assert "".join(chunks) == text
    assert all(utf16_len(chunk) <= 500 for chunk in chunks)
    assert all(chunk.endswith("\n") for chunk in chunks[:-1])


def test_astral_characters_count_double_and_are_never_split() -> None:
    text = "\U0001f600" * 300  # 600 UTF-16 units

    chunks = chunk_text(text, limit=101)

    assert "".join(chunks) == text
    assert all(utf16_len(chunk) <= 101 for chunk in chunks)


def test_a_single_unbroken_line_is_hard_split() -> None:
    chunks = chunk_text("y" * 250, limit=100)

    assert [len(chunk) for chunk in chunks] == [100, 100, 50]


@pytest.mark.parametrize("text", ["", "   ", "\n\n"])
def test_empty_text_never_produces_an_empty_message(text: str) -> None:
    assert chunk_text(text) == ["(empty)"]


@pytest.mark.security
def test_the_approval_prompt_shows_hidden_characters() -> None:
    rlo = chr(0x202E)  # right-to-left override
    hidden = rlo + "".join(chr(0xE0000 + ord(c)) for c in "evil")

    text = render_approval(request(summary=f"Send to bob{hidden}", args=f'{{"to": "a{hidden}"}}'))

    assert rlo not in text
    assert chr(0xE0000 + ord("e")) not in text
    assert "\\u202e" in text


def test_the_approval_prompt_shows_risk_reason_arguments_and_expiry() -> None:
    text = render_approval(request(args='{"to": "bob@example.com"}'))

    assert "Risk: send" in text
    assert "send actions need approval" in text
    assert "bob@example.com" in text
    assert "12:10 UTC" in text
    assert STEP_UP_NOTE not in text


def test_step_up_prompts_explain_the_code() -> None:
    assert STEP_UP_NOTE in render_approval(request(step_up=True))
