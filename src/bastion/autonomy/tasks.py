"""Scheduled tasks, sealed at rest (controls C11, C13).

A task's definition (name, schedule, instructions, granted tools) is one AES-GCM sealed JSON
document bound to the task's id. Editing the database therefore cannot widen a task's grant or
change what it does: an edited or transplanted definition fails to decrypt, and the task is
refused (shown as unreadable, never run). Only scheduling state is stored in clear: when the
task next runs, whether it is paused, and how many runs in a row failed.

Claiming a run is a compare-and-set on the stored next-run time, so two processes (the daemon
and ``bastion tasks run``) never start the same scheduled run twice.
"""

import json
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from typing import Any

from bastion.autonomy.schedule import Schedule, ScheduleError, local_text, parse_schedule
from bastion.common import utc_now
from bastion.security.crypto import DecryptionError, FieldCipher
from bastion.text import strip_invisible

MAX_NAME_CHARS = 60
MAX_INSTRUCTIONS_CHARS = 2_000
MAX_GRANTED_TOOLS = 12
KEPT_RUNS = 200  # per task: over a week of hourly runs, enough for the daily budget
# "cli": typed by the owner (bastion tasks add); "assistant": proposed by the model and
# approved by the owner with their authenticator code.
ORIGINS = ("cli", "assistant")
_SPEC_VERSION = 1
_TASK_ID = re.compile(r"[0-9a-f]{8}")


class TaskError(Exception):
    """A task cannot be created or changed. The message is written for the owner."""


class TaskCorrupt(TaskError):
    """A stored task failed to decrypt or validate: it was edited outside Bastion."""


def is_task_id(text: str) -> bool:
    return _TASK_ID.fullmatch(text) is not None


def validate_name(name: str) -> str:
    clean = " ".join(name.split())
    if not clean or len(clean) > MAX_NAME_CHARS:
        raise TaskError(f"a task name is 1 to {MAX_NAME_CHARS} characters on one line")
    if strip_invisible(clean) != clean:
        raise TaskError("the task name contains hidden or control characters")
    return clean


def validate_instructions(text: str) -> str:
    clean = text.replace("\r\n", "\n").strip()
    if not clean or len(clean) > MAX_INSTRUCTIONS_CHARS:
        raise TaskError(f"task instructions are 1 to {MAX_INSTRUCTIONS_CHARS} characters")
    # Hidden characters could make the owner approve instructions other than the ones they read.
    if strip_invisible(clean) != clean:
        raise TaskError("the instructions contain hidden or control characters")
    return clean


def validate_tools(names: Iterable[str], grantable: frozenset[str]) -> tuple[str, ...]:
    unique = tuple(dict.fromkeys(names))
    if len(unique) > MAX_GRANTED_TOOLS:
        raise TaskError(f"a task can use at most {MAX_GRANTED_TOOLS} tools")
    refused = [name for name in unique if name not in grantable]
    if refused:
        allowed = ", ".join(sorted(grantable)) or "none"
        raise TaskError(
            f"these tools cannot be given to a task: {', '.join(refused)} (allowed: {allowed})"
        )
    return unique


def _schedule(text: str) -> Schedule:
    try:
        return parse_schedule(text)
    except ScheduleError as exc:
        raise TaskError(f"invalid schedule: {exc}") from exc


def _iso(moment: datetime) -> str:
    # Every stored time goes through here (UTC, whole seconds), so stored times compare
    # correctly as strings in SQL (`claim`, `tokens_since`).
    return moment.astimezone(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class TaskSpec:
    name: str
    schedule: Schedule
    instructions: str
    tools: tuple[str, ...]
    created_at: datetime
    created_via: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "v": _SPEC_VERSION,
                "name": self.name,
                "schedule": self.schedule.text,
                "instructions": self.instructions,
                "tools": list(self.tools),
                "created_at": _iso(self.created_at),
                "created_via": self.created_via,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> "TaskSpec":
        try:
            data: Any = json.loads(text)
            if data["v"] != _SPEC_VERSION or data["created_via"] not in ORIGINS:
                raise TaskError("unsupported task format")
            tools = data["tools"]
            if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
                raise TaskError("invalid tool list")
            created_at = datetime.fromisoformat(data["created_at"])
            if created_at.tzinfo is None:
                raise TaskError("naive creation time")
            return cls(
                name=validate_name(data["name"]),
                schedule=_schedule(data["schedule"]),
                instructions=validate_instructions(data["instructions"]),
                tools=tuple(tools),
                created_at=created_at,
                created_via=data["created_via"],
            )
        except (TaskError, ValueError, KeyError, TypeError) as exc:
            raise TaskCorrupt("the stored task is invalid") from exc


@dataclass(frozen=True)
class Task:
    id: str
    spec: TaskSpec
    enabled: bool
    next_run: datetime | None
    failures: int

    @property
    def name(self) -> str:
        return self.spec.name


@dataclass(frozen=True)
class TaskListing:
    tasks: tuple[Task, ...]
    unreadable: tuple[str, ...]  # ids of tasks that failed to decrypt: refused, never run


@dataclass(frozen=True)
class RunRecord:
    started_at: datetime
    finished_at: datetime
    outcome: str
    tokens: int
    tool_calls: int


def _context(task_id: str) -> str:
    return f"task:{task_id}"


class TaskStore:
    def __init__(
        self,
        conn: sqlite3.Connection,
        cipher: FieldCipher,
        *,
        clock: Callable[[], datetime] = utc_now,
        tz: tzinfo | None = None,
    ) -> None:
        self._conn = conn
        self._cipher = cipher
        self._clock = clock
        self._tz = tz

    @property
    def tz(self) -> tzinfo | None:
        return self._tz

    def now(self) -> datetime:
        return self._clock()

    # ------------------------------------------------------------- definitions

    def new_spec(
        self,
        *,
        name: str,
        schedule: str,
        instructions: str,
        tools: Iterable[str],
        grantable: frozenset[str],
        created_via: str,
    ) -> TaskSpec:
        """A validated definition (not yet stored). Raises TaskError with a readable reason."""
        if created_via not in ORIGINS:
            raise TaskError(f"unknown origin {created_via!r}")
        return TaskSpec(
            name=validate_name(name),
            schedule=_schedule(schedule),
            instructions=validate_instructions(instructions),
            tools=validate_tools(tools, grantable),
            created_at=self._clock().astimezone(UTC).replace(microsecond=0),
            created_via=created_via,
        )

    def next_run(self, spec: TaskSpec, after: datetime) -> datetime:
        return spec.schedule.next_after(after, anchor=spec.created_at, tz=self._tz)

    def add(self, spec: TaskSpec, *, limit: int) -> Task:
        task_id = secrets.token_hex(4)
        next_run = self.next_run(spec, self._clock())
        sealed = self._cipher.encrypt(spec.to_json(), context=_context(task_id))
        # One statement, so the cap holds even if the CLI and the daemon add at the same time.
        cursor = self._conn.execute(
            "INSERT INTO tasks (id, created_at, spec, enabled, next_run, failures) "
            "SELECT ?, ?, ?, 1, ?, 0 WHERE (SELECT COUNT(*) FROM tasks) < ?",
            (task_id, _iso(spec.created_at), sealed, _iso(next_run), limit),
        )
        if cursor.rowcount != 1:
            raise TaskError(f"there are already {limit} scheduled tasks; remove one first")
        return Task(task_id, spec, True, next_run, 0)

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0])

    def _from_row(self, row: tuple[Any, ...]) -> Task:
        task_id, sealed, enabled, next_run, failures = row
        try:
            spec = TaskSpec.from_json(self._cipher.decrypt(sealed, context=_context(task_id)))
        except DecryptionError as exc:
            raise TaskCorrupt("the stored task does not decrypt") from exc
        # The scheduling columns are in clear text: a bad value marks the task as tampered with
        # (refused) instead of breaking every listing and the scheduler.
        try:
            when = datetime.fromisoformat(next_run) if next_run is not None else None
        except (TypeError, ValueError) as exc:
            raise TaskCorrupt("the stored next run time is invalid") from exc
        if when is not None and when.tzinfo is None:
            raise TaskCorrupt("the stored next run time has no time zone")
        if enabled not in (0, 1) or not isinstance(failures, int):
            raise TaskCorrupt("the stored scheduling state is invalid")
        return Task(task_id, spec, bool(enabled), when, failures)

    def get(self, task_id: str) -> Task | None:
        """The task, or None if there is none. Raises TaskCorrupt if it was tampered with."""
        row = self._conn.execute(
            "SELECT id, spec, enabled, next_run, failures FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        return None if row is None else self._from_row(row)

    def listing(self) -> TaskListing:
        tasks: list[Task] = []
        unreadable: list[str] = []
        rows = self._conn.execute(
            "SELECT id, spec, enabled, next_run, failures FROM tasks ORDER BY created_at, id"
        )
        for row in rows.fetchall():
            try:
                tasks.append(self._from_row(row))
            except TaskCorrupt:
                unreadable.append(row[0])
        return TaskListing(tuple(tasks), tuple(unreadable))

    def remove(self, task_id: str) -> bool:
        return self._conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,)).rowcount > 0

    # ------------------------------------------------------------- scheduling

    def set_enabled(self, task: Task, enabled: bool) -> Task:
        """Pause, or resume from now (a resumed task does not catch up on missed runs)."""
        if not enabled:
            # Only the flag: the next run time may have just been moved by a claim elsewhere.
            self._conn.execute("UPDATE tasks SET enabled = 0 WHERE id = ?", (task.id,))
            return Task(task.id, task.spec, False, task.next_run, task.failures)
        next_run = self.next_run(task.spec, self._clock())
        self._conn.execute(
            "UPDATE tasks SET enabled = 1, next_run = ?, failures = 0 WHERE id = ?",
            (_iso(next_run), task.id),
        )
        return Task(task.id, task.spec, True, next_run, 0)

    def claim(self, task: Task, now: datetime) -> Task | None:
        """Move a due task to its next run. None if another process got there first."""
        if task.next_run is None:
            return None
        following = self.next_run(task.spec, max(now, task.next_run))
        cursor = self._conn.execute(
            "UPDATE tasks SET next_run = ? WHERE id = ? AND next_run = ? AND enabled = 1",
            (_iso(following), task.id, _iso(task.next_run)),
        )
        if cursor.rowcount != 1:
            return None
        return Task(task.id, task.spec, task.enabled, following, task.failures)

    def note_failure(self, task_id: str) -> int:
        """Count a failed run; returns how many runs in a row have now failed."""
        self._conn.execute("UPDATE tasks SET failures = failures + 1 WHERE id = ?", (task_id,))
        row = self._conn.execute("SELECT failures FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return int(row[0]) if row else 0

    def note_success(self, task_id: str) -> None:
        self._conn.execute("UPDATE tasks SET failures = 0 WHERE id = ?", (task_id,))

    def pause(self, task_id: str) -> None:
        self._conn.execute("UPDATE tasks SET enabled = 0 WHERE id = ?", (task_id,))

    # ------------------------------------------------------------------- runs

    def record_run(self, task_id: str, record: RunRecord) -> bool:
        """Record a run (keeping the latest ``KEPT_RUNS``). False if the task was removed
        while it ran."""
        cursor = self._conn.execute(
            "INSERT INTO task_runs (task_id, started_at, finished_at, outcome, tokens, tool_calls) "
            "SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM tasks WHERE id = ?)",
            (
                task_id,
                _iso(record.started_at),
                _iso(record.finished_at),
                record.outcome,
                record.tokens,
                record.tool_calls,
                task_id,
            ),
        )
        self._conn.execute(
            "DELETE FROM task_runs WHERE task_id = ? AND id NOT IN "
            "(SELECT id FROM task_runs WHERE task_id = ? ORDER BY id DESC LIMIT ?)",
            (task_id, task_id, KEPT_RUNS),
        )
        return cursor.rowcount == 1

    def tokens_since(self, task_id: str, since: datetime) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(tokens), 0) FROM task_runs WHERE task_id = ? AND started_at >= ?",
            (task_id, _iso(since)),
        ).fetchone()
        return int(row[0])

    def recent_runs(self, task_id: str, limit: int = 5) -> tuple[RunRecord, ...]:
        rows = self._conn.execute(
            "SELECT started_at, finished_at, outcome, tokens, tool_calls FROM task_runs "
            "WHERE task_id = ? ORDER BY id DESC LIMIT ?",
            (task_id, limit),
        ).fetchall()
        return tuple(
            RunRecord(
                datetime.fromisoformat(started),
                datetime.fromisoformat(finished),
                outcome,
                int(tokens),
                int(calls),
            )
            for started, finished, outcome, tokens, calls in rows
        )


def describe_task(task: Task, tz: tzinfo | None = None) -> str:
    """One line about a task, for listings (CLI, Telegram and the task_list tool)."""
    if not task.enabled:
        state = "paused"
    elif task.next_run is not None:
        state = f"next run {local_text(task.next_run, tz)}"
    else:
        state = "not scheduled"
    tools = ", ".join(task.spec.tools) or "no tools"
    failing = f", {task.failures} failed run(s) in a row" if task.failures else ""
    return f"{task.name} ({task.id}): {task.spec.schedule.text}, {state}{failing}; uses {tools}"


def render_listing(listing: TaskListing, tz: tzinfo | None = None) -> str:
    if not listing.tasks and not listing.unreadable:
        return "No scheduled tasks."
    lines = [f"- {describe_task(task, tz)}" for task in listing.tasks]
    lines += [
        f"- ({task_id}): changed outside Bastion, so it will not run. "
        f"Remove it with: bastion tasks remove {task_id}"
        for task_id in listing.unreadable
    ]
    return "\n".join(lines)
