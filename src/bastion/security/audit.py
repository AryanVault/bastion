"""Tamper-evident audit log (control C10).

Every entry carries an HMAC-SHA256 over its own fields plus the previous entry's MAC, forming a
chain. Editing, forging, reordering or deleting an entry from the middle breaks verification,
and an attacker without the key (held in the OS keyring) cannot recompute valid MACs.
Database triggers additionally reject UPDATE and DELETE on the table.

Known limitation: truncating the *tail* of the log leaves a valid shorter chain. Detecting that
needs an external anchor (see docs/THREAT_MODEL.md).
"""

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

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


class AuditLog:
    def __init__(
        self,
        conn: sqlite3.Connection,
        key: bytes,
        redactor: Redactor,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"audit key must be at least {MIN_KEY_BYTES} bytes")
        self._conn = conn
        self._key = key
        self._redactor = redactor
        self._clock = clock

    def _mac(self, seq: int, ts: str, event: str, data: Any, prev: str) -> str:
        body = canonical_json({"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev})
        return hmac.new(self._key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def append(self, event: str, data: Mapping[str, Any]) -> AuditEntry:
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
        expected_seq, prev, verified = 1, GENESIS, 0
        rows = self._conn.execute(
            "SELECT seq, ts, event, data, prev, mac FROM audit_log ORDER BY seq"
        )
        for seq, ts, event, data_json, row_prev, mac in rows:
            problem = self._check_row(expected_seq, prev, seq, ts, event, data_json, row_prev, mac)
            if problem is not None:
                return VerifyResult(ok=False, entries=verified, first_bad_seq=seq, reason=problem)
            expected_seq, prev, verified = seq + 1, mac, verified + 1
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
