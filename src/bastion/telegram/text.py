"""Outgoing Telegram text: plain text, split to fit Telegram's message limit."""

from bastion.security.approvals import ApprovalRequest
from bastion.telegram.api import MAX_MESSAGE_CHARS
from bastion.text import reveal_invisible

STEP_UP_NOTE = (
    "This action also needs the 6-digit code from your authenticator app: tap Approve, "
    "then send the code."
)


def _fit(text: str, limit: int) -> int:
    """Length of the longest prefix of ``text`` that fits in ``limit`` UTF-16 units."""
    units = 0
    for index, char in enumerate(text):
        units += 2 if ord(char) > 0xFFFF else 1
        if units > limit:
            return index
    return len(text)


def chunk_text(text: str, limit: int = MAX_MESSAGE_CHARS) -> list[str]:
    """Split ``text`` into messages Telegram accepts, preferring to break at newlines."""
    chunks: list[str] = []
    rest = text
    while _fit(rest, limit) < len(rest):
        cut = _fit(rest, limit)
        newline = rest.rfind("\n", 0, cut)
        if newline >= cut // 2:
            cut = newline + 1
        chunks.append(rest[:cut])
        rest = rest[cut:]
    chunks.append(rest)
    return [chunk for chunk in chunks if chunk.strip()] or ["(empty)"]


def render_approval(request: ApprovalRequest) -> str:
    """The approval prompt: exactly what will run, with hidden characters made visible."""
    lines = [
        "Approval needed",
        "",
        reveal_invisible(request.summary),
        f"Risk: {request.tier.value}",
        f"Why you are asked: {reveal_invisible(request.reason)}",
        "",
        "Exact arguments (the approval is bound to these):",
        reveal_invisible(request.arguments_json),
        "",
        f"Request {request.id[:8]}, expires {request.expires_at:%H:%M} UTC.",
    ]
    if request.step_up:
        lines += ["", STEP_UP_NOTE]
    return "\n".join(lines)
