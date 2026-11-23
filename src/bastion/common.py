"""Small helpers shared across packages."""

import json
from datetime import UTC, datetime
from typing import Any


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace. Used wherever bytes are hashed or MACed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def utc_now() -> datetime:
    return datetime.now(UTC)
