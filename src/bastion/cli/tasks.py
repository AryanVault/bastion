"""``bastion tasks``: scheduled tasks, managed from the computer.

Adding a task here needs no authenticator code: whoever can use this computer's keyring already
controls Bastion. (The assistant can also propose a task over Telegram; that needs the owner's
approval and code.) Every change is audited. ``run`` runs a task once, now, in this terminal,
with approvals asked here.
"""

import asyncio
from collections.abc import Iterator
from contextlib import closing, contextmanager
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from bastion.autonomy.schedule import EXAMPLES, local_text
from bastion.autonomy.tasks import (
    Task,
    TaskCorrupt,
    TaskError,
    TaskStore,
    describe_task,
    is_task_id,
    render_listing,
)
from bastion.cli import deps
from bastion.cli.approver import ConsoleApprover
from bastion.cli.chat import open_session_runtime
from bastion.config import DATABASE_FILE, ConfigError, bastion_home, load_settings
from bastion.runtime import open_audit_log
from bastion.security.audit import AuditLog
from bastion.security.crypto import FieldCipher
from bastion.security.killswitch import KillSwitch
from bastion.security.redact import Redactor
from bastion.security.vault import STORAGE_KEY, Vault, VaultError
from bastion.storage.db import connect
from bastion.text import strip_invisible
from bastion.tools.tasks import TASK_TOOLS

tasks_app = typer.Typer(
    pretty_exceptions_show_locals=False,  # tracebacks must never print secrets
    help="Scheduled tasks: list, add, pause, resume, remove, or run one now.",
    no_args_is_help=True,
)

TaskId = Annotated[str, typer.Argument(help="The task's 8-character id (see: bastion tasks list).")]


def _fail(console: Console, message: str) -> typer.Exit:
    console.print(f"[red]{escape(message)}[/]")
    return typer.Exit(1)


@contextmanager
def _session(console: Console) -> Iterator[tuple[TaskStore, AuditLog]]:
    """The task store and audit log, without starting a model provider or any network client."""
    path = bastion_home() / DATABASE_FILE
    if not path.exists():
        raise _fail(console, "Bastion is not set up yet. Run: bastion init")
    vault = Vault(deps.secret_store(), Redactor())
    try:
        cipher = FieldCipher(vault.key(STORAGE_KEY))
    except VaultError as exc:
        raise _fail(console, str(exc)) from exc
    with closing(connect(path)) as conn:
        yield TaskStore(conn, cipher), open_audit_log(conn, vault, Redactor())


def _task(store: TaskStore, task_id: str, console: Console) -> Task:
    try:
        task = store.get(task_id) if is_task_id(task_id) else None
    except TaskCorrupt as exc:
        raise _fail(
            console,
            f"Task {task_id} was changed outside Bastion and will not run. "
            f"Remove it with: bastion tasks remove {task_id}",
        ) from exc
    if task is None:
        raise _fail(console, f"No task {task_id}. See: bastion tasks list")
    return task


@tasks_app.command("list")
def list_tasks() -> None:
    """Show every scheduled task."""
    console = Console()
    with _session(console) as (store, _):
        listing = store.listing()
        if not listing.tasks and not listing.unreadable:
            console.print("No scheduled tasks. Add one with: bastion tasks add --help")
            return
        console.print(Text(render_listing(listing, store.tz)))


@tasks_app.command("show")
def show(task_id: TaskId) -> None:
    """Show a task's instructions and its recent runs."""
    console = Console()
    with _session(console) as (store, _):
        task = _task(store, task_id, console)
        console.print(Text(describe_task(task, store.tz)))
        author = "you" if task.spec.created_via == "cli" else "the assistant, approved by you"
        created = local_text(task.spec.created_at, store.tz)
        console.print(Text(f"Created {created} by {author}.", style="dim"))
        console.print(Text("\nInstructions:", style="bold"))
        console.print(Text(task.spec.instructions))
        runs = store.recent_runs(task.id)
        if runs:
            table = Table("Started", "Outcome", "Tokens", "Tool calls", title="Recent runs")
            for run in runs:
                table.add_row(
                    local_text(run.started_at, store.tz),
                    run.outcome,
                    f"{run.tokens:,}",
                    str(run.tool_calls),
                )
            console.print(table)


def _grantable(console: Console) -> frozenset[str]:
    """The tools available right now (depends on Google and web-search setup)."""
    runtime = open_session_runtime(console)
    try:
        return runtime.tools.names - TASK_TOOLS
    finally:
        try:
            asyncio.run(runtime.aclose())
        finally:
            runtime.close()


@tasks_app.command("add")
def add(
    name: Annotated[str, typer.Option("--name", help="A short name, one line.")],
    schedule: Annotated[str, typer.Option("--schedule", help=f"When it runs: {EXAMPLES}.")],
    tools: Annotated[
        str, typer.Option("--tools", help="Comma-separated tools each run may use (and no others).")
    ] = "",
    instructions: Annotated[
        str | None,
        typer.Option("--instructions", help="What to do on each run (asked if omitted)."),
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", help="Add without asking for confirmation.")
    ] = False,
) -> None:
    """Schedule a task. Each run starts fresh, uses only the listed tools, and reports to you
    on Telegram (while `bastion daemon` runs)."""
    console = Console()
    try:
        settings = load_settings(bastion_home())
    except ConfigError as exc:
        raise _fail(console, str(exc)) from exc
    text = instructions if instructions is not None else typer.prompt("Instructions")
    names = [part.strip() for part in tools.split(",") if part.strip()]
    grantable = _grantable(console)
    with _session(console) as (store, audit):
        try:
            spec = store.new_spec(
                name=name,
                schedule=schedule,
                instructions=text,
                tools=names,
                grantable=grantable,
                created_via="cli",
            )
        except TaskError as exc:
            raise _fail(console, f"Cannot add the task: {exc}") from exc
        first = local_text(store.next_run(spec, store.now()), store.tz)
        console.print(
            Text(
                f"Task '{spec.name}': {spec.schedule.text} (first run {first}), "
                f"using {', '.join(spec.tools) or 'no tools'}."
            )
        )
        console.print(Text(spec.instructions, style="dim"))
        if not settings.autonomy.enabled:
            console.print(
                Text(
                    "! Scheduled tasks are off ([autonomy] enabled = false in config.toml): "
                    "it will not run until you turn them on.",
                    style="yellow",
                )
            )
        if not yes and not typer.confirm("Add this task?", default=False):
            console.print("Not added.")
            return
        try:
            task = store.add(spec, limit=settings.autonomy.max_tasks)
        except TaskError as exc:
            raise _fail(console, f"Cannot add the task: {exc}") from exc
        audit.append(
            "task.created",
            {
                "task": task.id,
                "via": "cli",
                "schedule": spec.schedule.text,
                "tools": list(spec.tools),
            },
            checkpoint=True,
        )
    console.print(
        f"[green]Added[/] task {task.id}. It runs while `bastion daemon` is running and "
        "reports to you on Telegram."
    )


def _set_enabled(task_id: str, enabled: bool) -> None:
    console = Console()
    with _session(console) as (store, audit):
        task = store.set_enabled(_task(store, task_id, console), enabled)
        audit.append(
            "task.resumed" if enabled else "task.paused",
            {"task": task.id, "via": "cli"},
            checkpoint=True,
        )
    if enabled and task.next_run is not None:
        console.print(
            Text(f"Resumed '{task.name}'. Next run {local_text(task.next_run, store.tz)}.")
        )
    else:
        console.print(Text(f"Paused '{task.name}'."))


@tasks_app.command("pause")
def pause(task_id: TaskId) -> None:
    """Stop a task from running until you resume it."""
    _set_enabled(task_id, False)


@tasks_app.command("resume")
def resume(task_id: TaskId) -> None:
    """Resume a paused task from now on (missed runs are not caught up)."""
    _set_enabled(task_id, True)


@tasks_app.command("remove")
def remove(task_id: TaskId) -> None:
    """Delete a task and its run history."""
    console = Console()
    with _session(console) as (store, audit):
        if not is_task_id(task_id) or not store.remove(task_id):
            raise _fail(console, f"No task {task_id}. See: bastion tasks list")
        audit.append("task.removed", {"task": task_id, "via": "cli"}, checkpoint=True)
    console.print(f"Removed task {task_id}.")


@tasks_app.command("run")
def run(task_id: TaskId) -> None:
    """Run a task once, now, in this terminal (approvals are asked here). Its schedule and
    daily budget still apply."""
    console = Console()
    if KillSwitch(bastion_home()).engaged():
        raise _fail(console, "Bastion is stopped. Run `bastion resume` first.")
    runtime = open_session_runtime(console)
    try:
        with asyncio.Runner() as loop:
            try:
                task = _task(runtime.tasks, task_id, console)
                runner = runtime.task_runner()
                report = loop.run(runner.run(task, ConsoleApprover(console), trigger="manual"))
            except KeyboardInterrupt:
                console.print("Cancelled.")
                return
            finally:
                loop.run(runtime.aclose())
        console.print(Text(strip_invisible(report.message)))
    finally:
        runtime.close()
