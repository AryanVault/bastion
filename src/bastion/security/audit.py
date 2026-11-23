"""Tamper-evident audit log (control C10).

Every entry carries an HMAC-SHA256 over its own fields plus the previous entry's MAC, forming a
chain. Editing, forging, reordering or deleting an entry from the middle breaks verification,
and an attacker without the key (held in the OS keyring) cannot recompute valid MACs.
Database triggers additionally reject UPDATE and DELETE on the table.

Truncating the *tail* of a log leaves a valid shorter chain, so the chain head is also
checkpointed in an anchor outside the database (the OS keyring) at the end of each turn;
``verify`` reports a log that no longer reaches its checkpoint. Entries written after the last
checkpoint remain unprotected against truncation (see docs/THREAT_MODEL.md).
"""

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from bastion.common import canonical_json, utc_now
from bastion.security.redact import Redactor

GENESIS = "0" * 64
MIN_KEY_BYTES = 32


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    event: str
    data: Mapping[str, Any]
    prev: str
    mac: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    reason: str = ""


class AnchorStore(Protocol):
    """Somewhere outside the database to keep the chain head (``"<seq>:<mac>"``)."""

    def get(self) -> str | None: ...

    def set(self, value: str) -> None: ...


def _misses_anchor(anchor: tuple[int, str] | None, seq: int, mac: str) -> bool:
    return anchor is not None and seq == anchor[0] and not hmac.compare_digest(mac, anchor[1])


def _parse_anchor(value: str) -> tuple[int, str] | None:
    seq, _, mac = value.partition(":")
    if not seq.isdigit() or len(mac) != len(GENESIS):
        return None
    return int(seq), mac


class AuditLog:
    def __init__(
        self,
        conn: sqlite3.Connection,
        key: bytes,
        redactor: Redactor,
        clock: Callable[[], datetime] = utc_now,
        anchor: AnchorStore | None = None,
    ) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"audit key must be at least {MIN_KEY_BYTES} bytes")
        self._conn = conn
        self._key = key
        self._redactor = redactor
        self._clock = clock
        self._anchor = anchor

    def _mac(self, seq: int, ts: str, event: str, data: Any, prev: str) -> str:
        body = canonical_json({"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev})
        return hmac.new(self._key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def append(
        self, event: str, data: Mapping[str, Any], *, checkpoint: bool = False
    ) -> AuditEntry:
        """Append an entry. ``checkpoint`` also records it as the chain head in the anchor."""
        entry = self._insert(event, data)
        if checkpoint and self._anchor is not None:
            self._anchor.set(f"{entry.seq}:{entry.mac}")
        return entry

    def _insert(self, event: str, data: Mapping[str, Any]) -> AuditEntry:
        # Normalise through JSON first so the MAC covers exactly what is stored.
        clean = json.loads(canonical_json(self._redactor.redact_obj(data)))
        ts = self._clock().isoformat()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq, prev = (int(row[0]) + 1, str(row[1])) if row else (1, GENESIS)
            mac = self._mac(seq, ts, event, clean, prev)
            self._conn.execute(
                "INSERT INTO audit_log (seq, ts, event, data, prev, mac) VALUES (?, ?, ?, ?, ?, ?)",
                (seq, ts, event, canonical_json(clean), prev, mac),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return AuditEntry(seq=seq, ts=ts, event=event, data=clean, prev=prev, mac=mac)

    def verify(self) -> VerifyResult:
        raw_anchor = self._anchor.get() if self._anchor is not None else None
        anchor = _parse_anchor(raw_anchor) if raw_anchor is not None else None
        if raw_anchor is not None and anchor is None:
            return VerifyResult(ok=False, entries=0, reason="the audit checkpoint is corrupt")
        expected_seq, prev, verified = 1, GENESIS, 0
        rows = self._conn.execute(
            "SELECT seq, ts, event, data, prev, mac FROM audit_log ORDER BY seq"
        )
        for seq, ts, event, data_json, row_prev, mac in rows:
            problem = self._check_row(expected_seq, prev, seq, ts, event, data_json, row_prev, mac)
            if problem is None and _misses_anchor(anchor, seq, mac):
                problem = "entry does not match the last checkpoint"
            if problem is not None:
                return VerifyResult(ok=False, entries=verified, first_bad_seq=seq, reason=problem)
            expected_seq, prev, verified = seq + 1, mac, verified + 1
        if anchor and anchor[0] >= expected_seq:
            return VerifyResult(
                ok=False,
                entries=verified,
                first_bad_seq=expected_seq,
                reason=f"the log ends at entry {expected_seq - 1} but was checkpointed at "
                f"entry {anchor[0]}: entries were removed",
            )
        return VerifyResult(ok=True, entries=verified)

    def _check_row(
        self,
        expected_seq: int,
        expected_prev: str,
        seq: int,
        ts: str,
        event: str,
        data_json: str,
        prev: str,
        mac: str,
    ) -> str | None:
        if seq != expected_seq:
            return f"sequence gap: expected entry {expected_seq}"
        if prev != expected_prev:
            return "chain broken: entry does not link to its predecessor"
        try:
            data = json.loads(data_json)
        except json.JSONDecodeError:
            return "entry data is corrupt"
        if not hmac.compare_digest(self._mac(seq, ts, event, data, prev), mac):
            return "MAC mismatch: entry was modified or forged"
        return None

    def tail(self, n: int) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT seq, ts, event, data, prev, mac FROM audit_log ORDER BY seq DESC LIMIT ?",
            (n,),
        ).fetchall()
        return [
            AuditEntry(seq=r[0], ts=r[1], event=r[2], data=json.loads(r[3]), prev=r[4], mac=r[5])
            for r in reversed(rows)
        ]
