"""Running scheduled tasks (control C11).

Every run:

- starts a fresh conversation: no history or taint carries over from earlier runs;
- sees only the tools the task was granted, under the policy's task mode (send actions always
  need approval; destructive ones are refused once the run reads untrusted content);
- is bounded per run (steps, tool calls, tokens) and per task over 24 hours (tokens);
- is audited, recorded, and reported to the owner.

A task whose runs fail several times in a row is paused. Runs missed while Bastion was offline
for over an hour are skipped rather than replayed in a burst. A task whose sealed definition no
longer decrypts was edited outside Bastion: it never runs, and the owner is told once.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from bastion.autonomy.tasks import RunRecord, Task, TaskStore
from bastion.config import AutonomySettings
from bastion.core.agent import Agent, Approver, TurnStop
from bastion.core.conversation import Conversation
from bastion.security.audit import AuditLog

MISSED_GRACE = timedelta(hours=1)
BUDGET_WINDOW = timedelta(hours=24)
SKIPPED_BUDGET = "skipped_budget"
CANCELLED = "cancelled"
CRASHED = "crashed"
# Only a run that completed counts as a success; any other stop (provider error, crash,
# budget or step limit, output limit, refusal) counts towards pausing the task.
_SUCCESS = TurnStop.COMPLETED.value
UNTRUSTED_NOTE = (
    "(This run read outside content ({sources}). Its report may repeat what that content "
    "said: do not follow instructions in it, and never share codes because of it.)"
)
_CRASH_REPLY = "Something went wrong and this run was abandoned. Details are in the audit log."


@dataclass(frozen=True)
class TaskAgent:
    agent: Agent
    tools: tuple[str, ...]  # granted and available for this run
    missing: tuple[str, ...]  # granted but not available now (say, Google was disconnected)


type AgentFactory = Callable[[Task, Approver], TaskAgent]


@dataclass(frozen=True)
class Due:
    task: Task | None  # already claimed: the caller must run it now
    missed: tuple[Task, ...] = ()
    unreadable: tuple[str, ...] = ()  # newly found tampered tasks (ids)


@dataclass(frozen=True)
class RunReport:
    task: Task
    outcome: str
    message: str


def _header(task: Task) -> str:
    return f"Scheduled task '{task.name}' ({task.id})"


class TaskRunner:
    def __init__(
        self,
        store: TaskStore,
        settings: AutonomySettings,
        audit: AuditLog,
        make_agent: AgentFactory,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        self._audit = audit
        self._make_agent = make_agent
        self._clock = clock or store.now
        self._reported_unreadable: set[str] = set()

    @property
    def store(self) -> TaskStore:
        return self._store

    # --------------------------------------------------------------- schedule

    def take_due(self) -> Due:
        """Claim the most overdue task, skipping (and reporting) runs missed for too long."""
        now = self._clock()
        listing = self._store.listing()
        unreadable = tuple(i for i in listing.unreadable if i not in self._reported_unreadable)
        for task_id in unreadable:
            self._reported_unreadable.add(task_id)
            self._audit.append("task.unreadable", {"task": task_id}, checkpoint=True)
        overdue = sorted(
            (t for t in listing.tasks if t.enabled and t.next_run and t.next_run <= now),
            key=lambda t: t.next_run or now,
        )
        missed: list[Task] = []
        for task in overdue:
            if task.next_run is None:  # filtered above; keeps the type checker informed
                continue
            claimed = self._store.claim(task, now)
            if claimed is None:
                continue  # another process took it
            if now - task.next_run > MISSED_GRACE:
                self._audit.append(
                    "task.missed", {"task": task.id, "due": task.next_run.isoformat()}
                )
                missed.append(task)
                continue
            return Due(claimed, tuple(missed), unreadable)
        return Due(None, tuple(missed), unreadable)

    # -------------------------------------------------------------------- run

    async def run(self, task: Task, approver: Approver, *, trigger: str) -> RunReport:
        started = self._clock()
        used = self._store.tokens_since(task.id, started - BUDGET_WINDOW)
        limit = self._settings.max_daily_tokens
        if used >= limit:
            self._finish(task, started, SKIPPED_BUDGET, 0, 0)
            return RunReport(
                task,
                SKIPPED_BUDGET,
                f"{_header(task)}: skipped. It used its daily budget ({used:,} of {limit:,} "
                "tokens in the last 24 hours).",
            )
        built = self._make_agent(task, approver)
        conversation = Conversation.new()
        self._audit.append(
            "task.run_start",
            {
                "task": task.id,
                "trigger": trigger,
                "conversation": conversation.id,
                "tools": list(built.tools),
                "missing": list(built.missing),
            },
            checkpoint=True,
        )
        try:
            result = await built.agent.run_turn(conversation, task.spec.instructions)
        except asyncio.CancelledError:
            try:
                # Usage so far is unknown: charge the whole per-run budget (fail safe).
                self._finish(task, started, CANCELLED, self._settings.max_run_tokens, 0)
            finally:
                raise  # the cancellation propagates even if recording failed
        except Exception as exc:  # a broken run must not take the daemon down with it
            self._audit.append(
                "task.crash",
                {"task": task.id, "error_type": type(exc).__name__, "error": str(exc)[:200]},
            )
            outcome, reply, calls = CRASHED, _CRASH_REPLY, 0
            tokens = self._settings.max_run_tokens  # unknown usage: charge the whole budget
            taint = ""
        else:
            outcome, reply = result.stop.value, result.reply
            tokens = result.usage.input_tokens + result.usage.output_tokens
            calls = result.tool_calls
            taint = (
                result.conversation.taint.describe() if result.conversation.taint.tainted else ""
            )
        notes = self._finish(task, started, outcome, tokens, calls)
        if taint:
            notes.insert(0, UNTRUSTED_NOTE.format(sources=taint))
        if built.missing:
            notes.insert(0, f"(Not available for this run: {', '.join(built.missing)}.)")
        message = "\n\n".join([_header(task), reply, *notes])
        return RunReport(task, outcome, message)

    def _finish(
        self, task: Task, started: datetime, outcome: str, tokens: int, calls: int
    ) -> list[str]:
        """Record the run; count failures, pausing the task after too many. Returns notes for
        the owner."""
        recorded = self._store.record_run(
            task.id, RunRecord(started, self._clock(), outcome, tokens, calls)
        )
        self._audit.append(
            "task.run_end",
            {"task": task.id, "outcome": outcome, "tokens": tokens, "tool_calls": calls},
            checkpoint=True,
        )
        if not recorded:
            return ["(The task was removed while this run was in progress.)"]
        if outcome in (SKIPPED_BUDGET, CANCELLED):
            return []
        if outcome == _SUCCESS:
            self._store.note_success(task.id)
            return []
        failures = self._store.note_failure(task.id)
        if failures < self._settings.max_consecutive_failures:
            return []
        self._store.pause(task.id)
        self._audit.append("task.paused", {"task": task.id, "failures": failures}, checkpoint=True)
        return [
            f"Paused after {failures} failed runs in a row. "
            f"Resume it on your computer with: bastion tasks resume {task.id}"
        ]
