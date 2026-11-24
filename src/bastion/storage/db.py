"""SQLite connection setup and versioned migrations.

One database file holds all local state. WAL mode lets the always-on daemon and the CLI use it
at the same time; writers take ``BEGIN IMMEDIATE`` so cross-process appends stay ordered.
"""

import os
import sqlite3
from pathlib import Path

_BUSY_TIMEOUT_MS = 10_000

# Each migration is a tuple of single statements (trigger bodies contain semicolons, so
# scripts are never split on ';').
_MIGRATIONS: tuple[tuple[str, ...], ...] = (
    (
        """
        CREATE TABLE audit_log (
            seq   INTEGER PRIMARY KEY,
            ts    TEXT NOT NULL,
            event TEXT NOT NULL,
            data  TEXT NOT NULL,
            prev  TEXT NOT NULL,
            mac   TEXT NOT NULL
        )
        """,
        """
        CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END
        """,
        """
        CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END
        """,
    ),
    (
        """
        CREATE TABLE memories (
            id         TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            trust      TEXT NOT NULL CHECK (trust IN ('trusted', 'untrusted')),
            source     TEXT NOT NULL,
            content    TEXT NOT NULL
        )
        """,
    ),
    (
        # A task's definition is sealed in `spec` (see autonomy/tasks.py); the other
        # columns are scheduling state only.
        """
        CREATE TABLE tasks (
            id         TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            spec       TEXT NOT NULL,
            enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            next_run   TEXT,
            failures   INTEGER NOT NULL DEFAULT 0
        )
        """,
        """
        CREATE TABLE task_runs (
            id          INTEGER PRIMARY KEY,
            task_id     TEXT NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
            started_at  TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            outcome     TEXT NOT NULL,
            tokens      INTEGER NOT NULL,
            tool_calls  INTEGER NOT NULL
        )
        """,
        "CREATE INDEX task_runs_by_task ON task_runs (task_id, started_at)",
    ),
)


def connect(path: Path) -> sqlite3.Connection:
    """Open (creating if needed) the database and bring its schema up to date."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    if os.name == "posix":
        path.chmod(0o600)
    _migrate(conn)
    return conn


def _current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0] or 0)


def _migrate(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    for version, statements in enumerate(_MIGRATIONS, start=1):
        if _current_version(conn) >= version:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Re-check under the write lock: another process may have just migrated.
            if _current_version(conn) < version:
                for statement in statements:
                    conn.execute(statement)
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
