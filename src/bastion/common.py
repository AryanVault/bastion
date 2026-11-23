"""Small helpers shared across packages."""

import json
from datetime import UTC, datetime
from typing import Any


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace. Used wherever bytes are hashed or MACed.

    ASCII-only output means attacker-supplied lone surrogates (invalid in UTF-8) are escaped
    rather than crashing the encoder, e.g. when an audit entry is written.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def utc_now() -> datetime:
    return datetime.now(UTC)
