"""Secret redaction for audit entries, logs and error messages (control C8)."""

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
_MIN_REGISTERED_LENGTH = 8

# Patterns whose whole match is a secret. Order matters: multi-line blocks first.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        r"\bsk-ant-[A-Za-z0-9_\-]{20,}",  # Anthropic
        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",  # OpenAI-style
        r"\bAIza[0-9A-Za-z_\-]{35}",  # Google API key
        r"\bya29\.[0-9A-Za-z_\-]{20,}",  # Google OAuth access token
        r"\b1//[0-9A-Za-z_\-]{20,}",  # Google OAuth refresh token
        r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b",  # Telegram bot token
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",  # AWS access key id
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",  # GitHub token
        r"\bgithub_pat_[A-Za-z0-9_]{22,}",  # GitHub fine-grained token
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",  # Slack token
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",  # JWT
    )
)

# Patterns where only the named group "secret" is sensitive; the label is kept for context.
_LABELLED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/\-]{16,}=*)"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b[\"']?\s*[:=]\s*[\"']?"
        r"(?P<secret>[^\s\"',;]{8,})"
    ),
)


def _replace_secret_group(match: re.Match[str]) -> str:
    start, end = match.span("secret")
    offset = match.start()
    whole = match.group(0)
    return whole[: start - offset] + REDACTED + whole[end - offset :]


class Redactor:
    """Replaces known secret formats and explicitly registered secret values with a marker.

    Registered values (for example, API keys loaded from the vault) are redacted even when they
    match no known format. The registry only grows; it is shared by the whole process.
    """

    def __init__(self) -> None:
        self._registered: frozenset[str] = frozenset()

    def register_secret(self, value: str) -> None:
        if len(value) >= _MIN_REGISTERED_LENGTH:
            self._registered = self._registered | {value}

    def redact(self, text: str) -> str:
        for secret in sorted(self._registered, key=len, reverse=True):
            text = text.replace(secret, REDACTED)
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(REDACTED, text)
        for pattern in _LABELLED_PATTERNS:
            text = pattern.sub(_replace_secret_group, text)
        return text

    def redact_obj(self, obj: Any) -> Any:
        """Return a redacted deep copy of JSON-like data. The input is never modified."""
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, Mapping):
            return {str(key): self.redact_obj(value) for key, value in obj.items()}
        if isinstance(obj, list | tuple):
            return [self.redact_obj(value) for value in obj]
        return obj
