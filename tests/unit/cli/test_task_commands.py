import re
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from bastion.autonomy.tasks import TaskStore
from bastion.cli import app, deps
from bastion.config import DATABASE_FILE
from bastion.security.audit import AuditLog
from bastion.security.crypto import FieldCipher
from bastion.security.killswitch import KillSwitch
from bastion.security.redact import Redactor
from bastion.security.vault import AUDIT_KEY, STORAGE_KEY, MemoryStore, Vault
from bastion.storage.db import connect
from support.fakes import ScriptedProvider, reply

INSTRUCTIONS = "Summarise the news on example.com"
ADD = [
    "tasks",
    "add",
    "--name",
    "Morning brief",
    "--schedule",
    "daily 08:00",
    "--tools",
    "web_fetch, memory_search",
]


@dataclass
class Env:
    home: Path
    store: MemoryStore
    monkeypatch: pytest.MonkeyPatch

    def use_provider(self, provider: ScriptedProvider) -> ScriptedProvider:
        self.monkeypatch.setattr(deps, "provider_override", lambda: provider)
        return provider

    def tasks(self) -> TaskStore:
        vault = Vault(self.store, Redactor())
        conn = connect(self.home / DATABASE_FILE)
        return TaskStore(conn, FieldCipher(vault.key(STORAGE_KEY)), tz=UTC)

    def events(self) -> list[str]:
        vault = Vault(self.store, Redactor())
        with closing(connect(self.home / DATABASE_FILE)) as conn:
            log = AuditLog(conn, vault.key(AUDIT_KEY), Redactor())
            return [entry.event for entry in log.tail(200)]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    store = MemoryStore()
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(deps, "secret_store", lambda: store)
    environment = Env(tmp_path / "home", store, monkeypatch)
    environment.use_provider(ScriptedProvider())
    result = run(["init", "--provider", "ollama", "--model", "llama3"], stdin="\n")
    assert result.exit_code == 0, result.output
    yield environment


def run(args: list[str], stdin: str | None = None) -> Result:
    return CliRunner().invoke(app, args, input=stdin)


def flat(result: Result) -> str:
    return " ".join(result.output.split())


def added(env: Env, *extra: str) -> str:
    result = run([*ADD, "--instructions", INSTRUCTIONS, "--yes", *extra])
    assert result.exit_code == 0, result.output
    match = re.search(r"Added task ([0-9a-f]{8})", flat(result))
    assert match is not None, result.output
    return match.group(1)


# ------------------------------------------------------------------ managing


def test_a_task_can_be_added_listed_shown_paused_resumed_and_removed(env: Env) -> None:
    task_id = added(env)

    listing = flat(run(["tasks", "list"]))
    shown = run(["tasks", "show", task_id])
    paused = run(["tasks", "pause", task_id])
    paused_listing = flat(run(["tasks", "list"]))
    resumed = run(["tasks", "resume", task_id])
    removed = run(["tasks", "remove", task_id])

    assert task_id in listing and "Morning brief" in listing and "daily 08:00" in listing
    assert "web_fetch, memory_search" in listing
    assert shown.exit_code == 0 and INSTRUCTIONS in flat(shown) and "by you" in flat(shown)
    assert "Paused 'Morning brief'" in flat(paused) and "paused" in paused_listing
    assert "Resumed 'Morning brief'. Next run" in flat(resumed)
    assert removed.exit_code == 0 and env.tasks().count() == 0
    assert [event for event in env.events() if event.startswith("task.")] == [
        "task.created",
        "task.paused",
        "task.resumed",
        "task.removed",
    ]


def test_adding_shows_the_task_and_asks_first(env: Env) -> None:
    declined = run(ADD, stdin=f"{INSTRUCTIONS}\nn\n")
    accepted = run(ADD, stdin=f"{INSTRUCTIONS}\ny\n")

    assert "Task 'Morning brief': daily 08:00 (first run" in flat(declined)
    assert "Not added." in declined.output
    assert "Added task" in accepted.output
    (task,) = env.tasks().listing().tasks
    assert task.spec.instructions == INSTRUCTIONS
    assert task.spec.created_via == "cli"


@pytest.mark.security
@pytest.mark.parametrize("tools", ["gmail_send", "task_schedule", "web_fetch,task_remove"])
def test_tools_that_are_not_available_cannot_be_granted(env: Env, tools: str) -> None:
    result = run([*ADD[:-1], tools, "--instructions", INSTRUCTIONS, "--yes"])

    assert result.exit_code == 1
    assert "cannot be given to a task" in flat(result)
    assert env.tasks().count() == 0


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("--schedule", "every 5m", "invalid schedule"),
        ("--name", "", "1 to 60"),
        ("--instructions", "Hi" + chr(0x202E), "hidden"),
    ],
)
def test_invalid_tasks_are_refused(env: Env, option: str, value: str, message: str) -> None:
    args = [*ADD, "--instructions", INSTRUCTIONS, "--yes"]
    args[args.index(option) + 1] = value

    result = run(args)

    assert result.exit_code == 1 and message in flat(result)


@pytest.mark.parametrize("command", ["show", "pause", "resume", "remove", "run"])
def test_unknown_tasks_are_reported(env: Env, command: str) -> None:
    task_id = "../../x" if command == "remove" else "ffffffff"
    result = run(["tasks", command, task_id])

    assert result.exit_code == 1
    assert f"No task {task_id}" in flat(result)


def test_an_empty_list_says_how_to_add_a_task(env: Env) -> None:
    assert "No scheduled tasks." in run(["tasks", "list"]).output


def test_commands_need_bastion_to_be_set_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "empty"))

    result = run(["tasks", "list"])

    assert result.exit_code == 1 and "bastion init" in result.output


@pytest.mark.security
def test_a_task_changed_outside_bastion_is_flagged(env: Env) -> None:
    task_id = added(env)
    with closing(connect(env.home / DATABASE_FILE)) as conn:
        conn.execute("UPDATE tasks SET spec = 'v1:AAAA' WHERE id = ?", (task_id,))

    listing = flat(run(["tasks", "list"]))
    shown = run(["tasks", "show", task_id])

    assert "changed outside Bastion, so it will not run" in listing
    assert shown.exit_code == 1 and "changed outside Bastion" in flat(shown)
    assert run(["tasks", "remove", task_id]).exit_code == 0


# ----------------------------------------------------------------------- run


def test_a_task_can_be_run_now_in_the_terminal(env: Env) -> None:
    task_id = added(env)
    provider = env.use_provider(ScriptedProvider(reply("Headline: all calm.")))

    result = run(["tasks", "run", task_id])

    assert result.exit_code == 0, result.output
    assert f"Scheduled task 'Morning brief' ({task_id})" in result.output
    assert "Headline: all calm." in result.output
    assert provider.tool_names == [("memory_search", "web_fetch")]
    assert env.tasks().recent_runs(task_id)[0].outcome == "completed"
    assert "task.run_start" in env.events()


@pytest.mark.security
def test_tasks_do_not_run_while_bastion_is_stopped(env: Env) -> None:
    task_id = added(env)
    KillSwitch(env.home).engage(via="telegram", at=datetime(2026, 11, 24, tzinfo=UTC))
    provider = env.use_provider(ScriptedProvider())

    result = run(["tasks", "run", task_id])

    assert result.exit_code == 1 and "bastion resume" in flat(result)
    assert provider.requests == []
