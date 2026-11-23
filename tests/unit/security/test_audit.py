import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bastion.security.audit import GENESIS, AuditLog
from bastion.security.redact import Redactor
from bastion.storage.db import connect

KEY = b"k" * 32


def _clock() -> Callable[[], datetime]:
    state = {"now": datetime(2026, 11, 23, 10, 0, tzinfo=UTC)}

    def tick() -> datetime:
        state["now"] += timedelta(seconds=1)
        return state["now"]

    return tick


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "bastion.db"


@pytest.fixture
def conn(db_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(connect(db_path)) as connection:
        yield connection


@pytest.fixture
def log(conn: sqlite3.Connection) -> AuditLog:
    return AuditLog(conn, KEY, Redactor(), clock=_clock())


def _tamper(conn: sqlite3.Connection, sql: str, params: tuple[object, ...]) -> None:
    """Simulate an attacker with direct database access (bypassing the triggers)."""
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute(sql, params)
    conn.commit()


def test_entries_are_sequential_and_chained(log: AuditLog) -> None:
    first = log.append("session.start", {"n": 1})
    second = log.append("tool.call", {"n": 2})

    assert (first.seq, second.seq) == (1, 2)
    assert first.prev == GENESIS
    assert second.prev == first.mac


def test_intact_log_verifies(log: AuditLog) -> None:
    for i in range(3):
        log.append("event", {"i": i})

    result = log.verify()

    assert result.ok
    assert result.entries == 3


def test_empty_log_verifies(log: AuditLog) -> None:
    assert log.verify().ok


def test_secrets_are_redacted_before_storage(log: AuditLog, conn: sqlite3.Connection) -> None:
    entry = log.append("llm.call", {"auth": "Bearer abcdefghijklmnopqrstuvwxyz123456"})

    stored = conn.execute("SELECT data FROM audit_log WHERE seq = ?", (entry.seq,)).fetchone()[0]
    assert "abcdefghijklmnopqrstuvwxyz" not in stored
    assert "abcdefghijklmnopqrstuvwxyz" not in entry.data["auth"]


def test_updates_are_blocked_by_the_database(log: AuditLog, conn: sqlite3.Connection) -> None:
    log.append("event", {"n": 1})

    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_log SET data = '{}' WHERE seq = 1")


def test_deletes_are_blocked_by_the_database(log: AuditLog, conn: sqlite3.Connection) -> None:
    log.append("event", {"n": 1})

    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE seq = 1")


def test_modified_entry_is_detected(log: AuditLog, conn: sqlite3.Connection) -> None:
    for i in range(3):
        log.append("tool.call", {"to": f"alice{i}@example.com"})

    _tamper(conn, "UPDATE audit_log SET data = ? WHERE seq = 2", ('{"to":"x@evil.example"}',))
    result = log.verify()

    assert not result.ok
    assert result.first_bad_seq == 2


def test_deleted_middle_entry_is_detected(log: AuditLog, conn: sqlite3.Connection) -> None:
    for i in range(3):
        log.append("event", {"i": i})

    _tamper(conn, "DELETE FROM audit_log WHERE seq = ?", (2,))
    result = log.verify()

    assert not result.ok
    assert result.first_bad_seq == 3


def test_forged_entry_without_the_key_is_detected(log: AuditLog, conn: sqlite3.Connection) -> None:
    log.append("event", {"i": 1})
    row = conn.execute("SELECT seq, ts, event, prev FROM audit_log WHERE seq = 1").fetchone()
    forged_data = {"i": 999}
    body = {"seq": row[0], "ts": row[1], "event": row[2], "data": forged_data, "prev": row[3]}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    attacker_mac = hmac.new(b"wrong-key" * 4, canonical.encode(), hashlib.sha256).hexdigest()

    _tamper(
        conn,
        "UPDATE audit_log SET data = ?, mac = ? WHERE seq = 1",
        (json.dumps(forged_data), attacker_mac),
    )

    assert not log.verify().ok


def test_verifying_with_the_wrong_key_fails(log: AuditLog, conn: sqlite3.Connection) -> None:
    log.append("event", {"i": 1})

    assert not AuditLog(conn, b"x" * 32, Redactor()).verify().ok


def test_tail_returns_latest_entries_oldest_first(log: AuditLog) -> None:
    for i in range(5):
        log.append("event", {"i": i})

    assert [e.data["i"] for e in log.tail(2)] == [3, 4]


def test_two_writers_on_one_database_keep_the_chain_intact(db_path: Path) -> None:
    with closing(connect(db_path)) as conn_a, closing(connect(db_path)) as conn_b:
        writer_a = AuditLog(conn_a, KEY, Redactor())
        writer_b = AuditLog(conn_b, KEY, Redactor())

        for i in range(4):
            (writer_a if i % 2 == 0 else writer_b).append("event", {"i": i})

        result = writer_a.verify()
    assert result.ok
    assert result.entries == 4


def test_rejects_short_keys(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        AuditLog(conn, b"short", Redactor())


# ------------------------------------------------------- chain checkpoints


class MemoryAnchor:
    def __init__(self) -> None:
        self.value: str | None = None

    def get(self) -> str | None:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


def _anchored(conn: sqlite3.Connection, anchor: MemoryAnchor) -> AuditLog:
    return AuditLog(conn, KEY, Redactor(), anchor=anchor)


def test_a_checkpoint_records_the_chain_head(conn: sqlite3.Connection) -> None:
    anchor = MemoryAnchor()

    entry = _anchored(conn, anchor).append("turn.end", {}, checkpoint=True)

    assert anchor.value == f"{entry.seq}:{entry.mac}"


def test_entries_after_the_checkpoint_verify(conn: sqlite3.Connection) -> None:
    log = _anchored(conn, MemoryAnchor())
    log.append("turn.end", {}, checkpoint=True)
    log.append("event", {})

    assert log.verify().ok


@pytest.mark.security
def test_removing_checkpointed_entries_from_the_end_is_detected(conn: sqlite3.Connection) -> None:
    log = _anchored(conn, MemoryAnchor())
    for i in range(3):
        log.append("event", {"i": i}, checkpoint=True)

    _tamper(conn, "DELETE FROM audit_log WHERE seq = ?", (3,))
    result = log.verify()

    assert not result.ok
    assert "removed" in result.reason


@pytest.mark.security
def test_a_wiped_log_is_detected(conn: sqlite3.Connection, tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    _anchored(conn, anchor).append("setup.init", {}, checkpoint=True)

    with closing(connect(tmp_path / "fresh.db")) as fresh:
        result = _anchored(fresh, anchor).verify()

    assert not result.ok


@pytest.mark.security
def test_a_checkpoint_that_does_not_match_is_detected(conn: sqlite3.Connection) -> None:
    anchor = MemoryAnchor()
    log = _anchored(conn, anchor)
    log.append("event", {}, checkpoint=True)
    anchor.value = "1:" + "0" * 64

    assert not log.verify().ok


def test_a_corrupt_checkpoint_is_reported(conn: sqlite3.Connection) -> None:
    anchor = MemoryAnchor()
    anchor.value = "garbage"

    result = _anchored(conn, anchor).verify()

    assert not result.ok
    assert "corrupt" in result.reason
