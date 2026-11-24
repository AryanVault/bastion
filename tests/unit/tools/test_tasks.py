import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from bastion.autonomy.tasks import TaskStore
from bastion.core.agent import Agent
from bastion.core.conversation import Conversation
from bastion.llm.types import ToolCall
from bastion.security.approvals import ApprovalService
from bastion.security.audit import AuditLog
from bastion.security.crypto import FieldCipher
from bastion.security.egress import UrlProvenance
from bastion.security.policy import DEFAULT_POLICY_TOML, PolicyEngine, parse_policy
from bastion.security.redact import Redactor
from bastion.storage.db import connect
from bastion.tools.base import RiskTier, Tool, ToolContext, ToolError, ToolRegistry, Trust
from bastion.tools.tasks import (
    TASK_TOOLS,
    TaskListTool,
    TaskRemoveArgs,
    TaskRemoveTool,
    TaskScheduleArgs,
    TaskScheduleTool,
)
from support.fakes import (
    EchoTool,
    PoisonedPageTool,
    ScriptedProvider,
    StubApprover,
    call,
    reply,
    use_tools,
)

NOW = datetime(2026, 11, 24, 7, 0, tzinfo=UTC)
GRANTABLE = frozenset({"echo", "read_page", *TASK_TOOLS})
CTX = ToolContext(provenance=UrlProvenance(), tainted=False)
SCHEDULE = {
    "name": "Morning brief",
    "schedule": "daily 08:00",
    "instructions": "Tell me the headline of the day.",
    "tools": ["echo"],
}


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(connect(tmp_path / "bastion.db")) as connection:
        yield connection


@pytest.fixture
def store(conn: sqlite3.Connection) -> TaskStore:
    return TaskStore(conn, FieldCipher(b"k" * 32), clock=lambda: NOW, tz=UTC)


@pytest.fixture
def audit(conn: sqlite3.Connection) -> AuditLog:
    return AuditLog(conn, b"a" * 32, Redactor())


def scheduler(store: TaskStore, max_tasks: int = 20) -> TaskScheduleTool:
    return TaskScheduleTool(store, GRANTABLE, max_tasks=max_tasks)


def agent(
    store: TaskStore,
    audit: AuditLog,
    provider: ScriptedProvider,
    approver: StubApprover,
    *,
    policy: str = DEFAULT_POLICY_TOML,
) -> Agent:
    tools: list[Tool[Any]] = [EchoTool(), PoisonedPageTool(), scheduler(store), TaskListTool(store)]
    registry = ToolRegistry(tools)
    return Agent(
        provider=provider,
        tools=registry,
        policy=PolicyEngine(parse_policy(policy), registry.names),
        approvals=ApprovalService(),
        approver=approver,
        audit=audit,
    )


def args(**overrides: Any) -> TaskScheduleArgs:
    """Arguments validated the way the agent validates them (with the grantable tools)."""
    return TaskScheduleArgs.model_validate(
        {**SCHEDULE, **overrides}, context={"grantable": GRANTABLE - TASK_TOOLS}
    )


def schedule_call(call_id: str = "call_1", **overrides: Any) -> ToolCall:
    # Built directly: the fakes' call() helper has its own "name" parameter.
    return ToolCall(id=call_id, name="task_schedule", arguments={**SCHEDULE, **overrides})


# ----------------------------------------------------------------- scheduling


@pytest.mark.security
async def test_scheduling_always_needs_approval_and_the_code(
    store: TaskStore, audit: AuditLog
) -> None:
    approver = StubApprover(True)
    provider = ScriptedProvider(use_tools(schedule_call()), reply("Done."))

    await agent(store, audit, provider, approver).run_turn(Conversation.new(), "Brief me daily")

    request = approver.requests[0]
    assert request.step_up and request.tier is RiskTier.WRITE  # write is "allow" when clean
    assert request.summary == (
        "Schedule a new task: daily 08:00 (first run Tue 2026-11-24 08:00 +0000), using echo. "
        "Every run follows the instructions below without you watching."
    )
    assert '"name": "Morning brief"' in request.arguments_json
    assert "Tell me the headline of the day." in request.arguments_json
    (task,) = store.listing().tasks
    assert task.spec.created_via == "assistant"
    assert task.spec.tools == ("echo",)


@pytest.mark.security
async def test_a_policy_file_cannot_waive_the_approval(store: TaskStore, audit: AuditLog) -> None:
    lenient = DEFAULT_POLICY_TOML + '\n[tools.task_schedule]\nclean = "allow"\n'
    approver = StubApprover(False)
    provider = ScriptedProvider(use_tools(schedule_call()), reply("OK."))

    await agent(store, audit, provider, approver, policy=lenient).run_turn(
        Conversation.new(), "Brief me daily"
    )

    assert len(approver.requests) == 1
    assert store.count() == 0  # declined: nothing stored


@pytest.mark.security
async def test_untrusted_content_cannot_plant_a_task(store: TaskStore, audit: AuditLog) -> None:
    approver = StubApprover(True)
    provider = ScriptedProvider(
        use_tools(call("read_page", url="https://evil.example")),
        use_tools(schedule_call("call_2")),
        reply("I could not schedule it."),
    )

    await agent(store, audit, provider, approver).run_turn(
        Conversation.new(), "Read https://evil.example"
    )

    assert approver.requests == []  # refused outright: the owner is not even asked
    assert store.count() == 0
    result = provider.last_results(2)[0]
    assert result.is_error and "refused once the conversation contains untrusted" in result.content


@pytest.mark.security
@pytest.mark.parametrize("tools", [["task_schedule"], ["task_remove"], ["gmail_send"]])
async def test_tasks_cannot_be_granted_task_tools_or_unknown_tools(
    store: TaskStore, audit: AuditLog, tools: list[str]
) -> None:
    approver = StubApprover(True)
    provider = ScriptedProvider(use_tools(schedule_call(tools=tools)), reply("OK."))

    await agent(store, audit, provider, approver).run_turn(Conversation.new(), "Schedule it")

    assert approver.requests == []
    result = provider.last_results(1)[0]
    assert result.is_error and "cannot be given to a task" in result.content


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schedule", "every 10 minutes", "use one of"),
        ("name", "", "1 to 60"),
        ("instructions", "Hi" + chr(0x200B), "hidden"),
    ],
)
def test_invalid_arguments_are_explained(field: str, value: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        args(**{field: value})


def test_arguments_are_normalised() -> None:
    parsed = args(schedule="Daily 8:00", tools=["echo", "echo"], name=" Morning   brief ")

    assert (parsed.schedule, parsed.tools, parsed.name) == (
        "daily 08:00",
        ["echo"],
        "Morning brief",
    )


def test_the_model_is_told_which_tools_a_task_can_use(store: TaskStore) -> None:
    spec = scheduler(store).spec()

    assert spec.description.endswith("Tools a task can use: echo, read_page.")
    assert "task_schedule" not in spec.description.split("Tools a task can use:")[1]


def test_the_audit_log_records_the_grant_but_not_the_instructions(store: TaskStore) -> None:
    view = scheduler(store).audit_view(args())

    assert view["schedule"] == "daily 08:00" and view["tools"] == ["echo"]
    assert "headline" not in str(view)


async def test_the_number_of_tasks_is_capped(store: TaskStore) -> None:
    tool = scheduler(store, max_tasks=1)
    await tool.run(args(), CTX)

    with pytest.raises(ToolError, match="already 1 scheduled tasks"):
        await tool.run(args(), CTX)


async def test_scheduling_reports_the_new_task(store: TaskStore) -> None:
    output = await scheduler(store).run(args(), CTX)

    (task,) = store.listing().tasks
    assert output.trust is Trust.TRUSTED
    assert f"Scheduled 'Morning brief' (id {task.id})" in output.content
    assert "first run Tue 2026-11-24 08:00 +0000" in output.content


# ------------------------------------------------------------- list and remove


async def test_tasks_can_be_listed(store: TaskStore) -> None:
    await scheduler(store).run(args(), CTX)

    output = await TaskListTool(store).run(TaskListTool.args_model(), CTX)

    assert output.trust is Trust.TRUSTED
    assert "Morning brief" in output.content and "daily 08:00" in output.content


async def test_tasks_can_be_removed(store: TaskStore) -> None:
    await scheduler(store).run(args(), CTX)
    (task,) = store.listing().tasks
    remover = TaskRemoveTool(store)
    target = TaskRemoveArgs(task_id=task.id)

    assert remover.describe(target) == f"Remove the scheduled task 'Morning brief' ({task.id})"
    await remover.run(target, CTX)

    assert store.count() == 0
    assert remover.describe(target) == f"Remove the scheduled task {task.id}"
    with pytest.raises(ToolError, match="no task"):
        await remover.run(target, CTX)


def test_task_ids_are_validated() -> None:
    with pytest.raises(ValidationError, match="8 lowercase"):
        TaskRemoveArgs(task_id="../../etc")


@pytest.mark.security
def test_removing_a_task_always_asks() -> None:
    assert TaskRemoveTool.always_ask and TaskScheduleTool.always_ask
