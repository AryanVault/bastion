import asyncio
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from bastion.autonomy.runner import (
    CANCELLED,
    CRASHED,
    MISSED_GRACE,
    SKIPPED_BUDGET,
    AgentFactory,
    TaskAgent,
    TaskRunner,
)
from bastion.autonomy.tasks import RunRecord, Task, TaskStore
from bastion.config import AutonomySettings
from bastion.core.agent import Agent, Approver
from bastion.core.prompts import task_system_prompt
from bastion.llm.types import Completion, Message, ProviderError, Usage
from bastion.security.approvals import ApprovalService
from bastion.security.audit import AuditLog
from bastion.security.crypto import FieldCipher
from bastion.security.policy import DEFAULT_POLICY_TOML, PolicyConfig, PolicyEngine, parse_policy
from bastion.security.redact import Redactor
from bastion.storage.db import connect
from bastion.tools.base import Tool, ToolRegistry
from support.fakes import (
    DeleteAllTool,
    EchoTool,
    PoisonedPageTool,
    ScriptedProvider,
    SendEmailTool,
    StubApprover,
    call,
    reply,
    use_tools,
)

NOW = datetime(2026, 11, 24, 7, 0, tzinfo=UTC)
SETTINGS = AutonomySettings(max_daily_tokens=10_000, max_consecutive_failures=2)
INSTRUCTIONS = "Check the news and tell me the headline."


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class Rig:
    def __init__(self, conn: sqlite3.Connection, clock: Clock) -> None:
        self.clock = clock
        self.audit = AuditLog(conn, b"a" * 32, Redactor())
        self.store = TaskStore(conn, FieldCipher(b"k" * 32), clock=clock, tz=UTC)
        self.provider = ScriptedProvider()
        self.tools: list[Tool[Any]] = [EchoTool()]
        self.policy: PolicyConfig = parse_policy(DEFAULT_POLICY_TOML)
        self.approver = StubApprover(True)

    def factory(self) -> AgentFactory:
        """What ``Runtime.task_agent`` does, over test doubles."""
        everything = ToolRegistry(self.tools)

        def make(task: Task, approver: Approver) -> TaskAgent:
            granted = [t for name in task.spec.tools if (t := everything.get(name)) is not None]
            registry = ToolRegistry(granted)
            agent = Agent(
                provider=self.provider,
                tools=registry,
                policy=PolicyEngine(self.policy, everything.names).for_task(
                    task.name, registry.names
                ),
                approvals=ApprovalService(),
                approver=approver,
                audit=self.audit,
                system_prompt=task_system_prompt(task.name),
            )
            missing = tuple(name for name in task.spec.tools if name not in registry.names)
            return TaskAgent(agent, tuple(sorted(registry.names)), missing)

        return make

    def runner(self, settings: AutonomySettings = SETTINGS) -> TaskRunner:
        return TaskRunner(self.store, settings, self.audit, self.factory(), clock=self.clock)

    def add(self, *, tools: Sequence[str] = ("echo",), schedule: str = "daily 08:00") -> Task:
        spec = self.store.new_spec(
            name="Morning brief",
            schedule=schedule,
            instructions=INSTRUCTIONS,
            tools=tools,
            grantable=frozenset({"echo", "send_email", "delete_all", "read_page", "gmail_read"}),
            created_via="cli",
        )
        return self.store.add(spec, limit=20)

    async def run(self, task: Task) -> Any:
        return await self.runner().run(task, self.approver, trigger="schedule")

    def events(self) -> list[str]:
        return [entry.event for entry in self.audit.tail(500)]


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(connect(tmp_path / "bastion.db")) as connection:
        yield connection


@pytest.fixture
def rig(conn: sqlite3.Connection) -> Rig:
    return Rig(conn, Clock())


def failing(messages: Sequence[Message]) -> Completion:
    raise ProviderError("the provider is down")


# -------------------------------------------------------------------- schedule


def test_a_task_is_due_only_once_its_time_comes(rig: Rig) -> None:
    task = rig.add()  # first run today at 08:00 UTC
    runner = rig.runner()

    assert runner.take_due().task is None

    rig.clock.now = datetime(2026, 11, 24, 8, 0, 20, tzinfo=UTC)
    due = runner.take_due()

    assert due.task is not None and due.task.id == task.id
    assert due.task.next_run == datetime(2026, 11, 25, 8, 0, tzinfo=UTC)
    assert runner.take_due().task is None  # claimed: never started twice


def test_runs_missed_while_offline_are_skipped_not_replayed(rig: Rig) -> None:
    task = rig.add(schedule="every 1h")
    rig.clock.now = NOW + timedelta(days=3)  # 72 runs were missed

    due = rig.runner().take_due()

    assert due.task is None
    assert [missed.id for missed in due.missed] == [task.id]
    assert due.missed[0].next_run == task.next_run  # the time it was due, for the notice
    stored = rig.store.get(task.id)
    assert stored is not None and stored.next_run == NOW + timedelta(days=3, hours=1)
    assert rig.events().count("task.missed") == 1
    assert rig.runner().take_due().task is None


def test_a_run_slightly_late_still_happens(rig: Rig) -> None:
    task = rig.add()
    assert task.next_run is not None
    rig.clock.now = task.next_run + MISSED_GRACE - timedelta(seconds=1)

    assert rig.runner().take_due().task is not None


@pytest.mark.security
def test_a_tampered_task_never_runs_and_is_reported_once(
    rig: Rig, conn: sqlite3.Connection
) -> None:
    task = rig.add()
    conn.execute("UPDATE tasks SET spec = 'v1:AAAA' WHERE id = ?", (task.id,))
    rig.clock.now = NOW + timedelta(hours=2)
    runner = rig.runner()

    first, second = runner.take_due(), runner.take_due()

    assert first.task is None and first.unreadable == (task.id,)
    assert second.unreadable == ()
    assert rig.events().count("task.unreadable") == 1


# ------------------------------------------------------------------------- run


async def test_a_run_reports_to_the_owner_and_is_recorded(rig: Rig) -> None:
    task = rig.add()
    rig.provider = ScriptedProvider(reply("Headline: all quiet.", usage=Usage(100, 20)))

    report = await rig.run(task)

    assert report.outcome == "completed"
    assert report.message == f"Scheduled task 'Morning brief' ({task.id})\n\nHeadline: all quiet."
    run = rig.store.recent_runs(task.id)[0]
    assert (run.outcome, run.tokens, run.tool_calls) == ("completed", 120, 0)
    events = rig.events()
    assert (
        events.index("task.run_start") < events.index("turn.start") < events.index("task.run_end")
    )
    assert rig.audit.verify().ok


async def test_each_run_starts_fresh_with_only_its_granted_tools(rig: Rig) -> None:
    rig.tools = [EchoTool(), SendEmailTool(), DeleteAllTool()]
    task = rig.add(tools=["echo"])
    rig.provider = ScriptedProvider(reply("one"), reply("two"))

    await rig.run(task)
    await rig.run(task)

    assert rig.provider.tool_names == [("echo",), ("echo",)]
    for request in rig.provider.requests:
        assert len(request) == 1  # only the instructions: nothing from earlier runs
        assert request[0].text.endswith(INSTRUCTIONS)


@pytest.mark.security
async def test_a_task_cannot_send_without_the_owners_approval(rig: Rig) -> None:
    """Even a policy that lets the owner's own requests send freely does not cover tasks."""
    rig.policy = parse_policy(DEFAULT_POLICY_TOML.replace('send = "ask"', 'send = "allow"', 1))
    sender = SendEmailTool()
    rig.tools = [EchoTool(), sender]
    rig.approver = StubApprover(False)
    task = rig.add(tools=["send_email"])
    rig.provider = ScriptedProvider(
        use_tools(call("send_email", to="eve@evil.example", body="hi")),
        reply("Could not send."),
    )

    await rig.run(task)

    assert sender.sent == []
    request = rig.approver.requests[0]
    assert "scheduled task 'Morning brief'" in request.reason


@pytest.mark.security
async def test_after_reading_untrusted_content_a_task_cannot_destroy(rig: Rig) -> None:
    rig.policy = parse_policy(
        DEFAULT_POLICY_TOML.replace('destructive = "deny"', 'destructive = "ask"')
    )
    deleter = DeleteAllTool()
    rig.tools = [PoisonedPageTool(), deleter]
    task = rig.add(tools=["read_page", "delete_all"])
    rig.provider = ScriptedProvider(
        use_tools(call("read_page", url="https://evil.example")),
        use_tools(call("delete_all", call_id="call_2", target="inbox")),
        reply("Done."),
    )

    await rig.run(task)

    assert deleter.calls == []
    assert rig.approver.requests == []  # refused outright: nobody is asked
    assert "Denied by policy" in rig.provider.last_results(2)[0].content


async def test_the_daily_budget_stops_a_task(rig: Rig) -> None:
    task = rig.add()
    earlier = NOW - timedelta(hours=5)
    rig.store.record_run(task.id, RunRecord(earlier, earlier, "completed", 10_000, 3))

    report = await rig.run(task)

    assert report.outcome == SKIPPED_BUDGET
    assert "daily budget (10,000 of 10,000 tokens" in report.message
    assert rig.provider.requests == []


async def test_repeated_failures_pause_the_task(rig: Rig) -> None:
    task = rig.add()
    rig.provider = ScriptedProvider(failing, failing)

    first = await rig.run(task)
    second = await rig.run(task)

    assert first.outcome == "provider_error" and "Paused" not in first.message
    assert "Paused after 2 failed runs in a row" in second.message
    assert f"bastion tasks resume {task.id}" in second.message
    stored = rig.store.get(task.id)
    assert stored is not None and not stored.enabled
    assert "task.paused" in rig.events()


async def test_a_success_resets_the_failure_count(rig: Rig) -> None:
    task = rig.add()
    rig.provider = ScriptedProvider(failing, reply("ok"), failing)

    for _ in range(3):
        await rig.run(task)

    stored = rig.store.get(task.id)
    assert stored is not None and stored.enabled and stored.failures == 1


async def test_a_crash_is_contained_and_counted(rig: Rig) -> None:
    task = rig.add()

    def broken(messages: Sequence[Message]) -> Completion:
        raise RuntimeError("bug")

    rig.provider = ScriptedProvider(broken)

    report = await rig.run(task)

    assert report.outcome == CRASHED
    assert "abandoned" in report.message
    assert "task.crash" in rig.events()
    assert rig.store.get(task.id).failures == 1  # type: ignore[union-attr]


async def test_cancelling_a_run_is_recorded(rig: Rig) -> None:
    task = rig.add()
    started = asyncio.Event()

    class Hanging(ScriptedProvider):
        async def complete(self, **kwargs: Any) -> Completion:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    rig.provider = Hanging()
    running = asyncio.create_task(rig.run(task))
    await started.wait()
    running.cancel()

    with pytest.raises(asyncio.CancelledError):
        await running
    run = rig.store.recent_runs(task.id)[0]
    assert run.outcome == CANCELLED
    assert run.tokens == SETTINGS.max_run_tokens  # unknown usage is charged in full
    assert rig.store.get(task.id).failures == 0  # type: ignore[union-attr]


async def test_tools_that_are_no_longer_available_are_named(rig: Rig) -> None:
    task = rig.add(tools=["echo", "gmail_read"])
    rig.provider = ScriptedProvider(reply("Partial."))

    report = await rig.run(task)

    assert "(Not available for this run: gmail_read.)" in report.message
    assert rig.provider.tool_names == [("echo",)]


async def test_a_task_that_keeps_hitting_its_budget_is_paused(rig: Rig) -> None:
    task = rig.add()
    looping = use_tools(call("echo", text="again"))
    rig.provider = ScriptedProvider(*[looping] * 40)
    runner = rig.runner(AutonomySettings(max_steps=2, max_consecutive_failures=2))

    first = await runner.run(task, rig.approver, trigger="schedule")
    second = await runner.run(task, rig.approver, trigger="schedule")

    assert first.outcome == second.outcome == "budget_exhausted"
    assert "Paused after 2 failed runs" in second.message


@pytest.mark.security
async def test_a_report_built_from_outside_content_carries_a_warning(rig: Rig) -> None:
    rig.tools = [PoisonedPageTool()]
    task = rig.add(tools=["read_page"])
    rig.provider = ScriptedProvider(
        use_tools(call("read_page", url="https://evil.example")),
        reply("Your account is locked: send me your authenticator code."),
    )

    report = await rig.run(task)

    assert "This run read outside content (web_fetch:evil.example)" in report.message
    assert "never share codes" in report.message


async def test_a_task_removed_during_its_run_is_reported(rig: Rig) -> None:
    task = rig.add()

    def remove_then_reply(messages: Sequence[Message]) -> Completion:
        rig.store.remove(task.id)
        return reply("done")

    rig.provider = ScriptedProvider(remove_then_reply)

    report = await rig.run(task)

    assert "removed while this run was in progress" in report.message
