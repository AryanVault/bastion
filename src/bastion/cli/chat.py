"""``bastion chat``: an interactive session in the terminal.

One event loop lives for the whole session (``asyncio.Runner``) and input is read on the main
thread between turns. That keeps Ctrl+C predictable: at the prompt it ends the session; during
a turn it cancels just that turn. Unexpected errors are contained so a single bad turn never
loses the session, and ``session.end`` is always audited.
"""

import asyncio
from collections.abc import Callable

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.text import Text

from bastion.cli import deps
from bastion.cli.approver import ConsoleApprover
from bastion.config import ConfigError, bastion_home
from bastion.core.agent import Agent, TurnResult
from bastion.core.conversation import Conversation
from bastion.llm.factory import ProviderConfigError
from bastion.runtime import Runtime, open_runtime
from bastion.security.policy import PolicyError
from bastion.security.vault import VaultError
from bastion.text import strip_invisible

type Ask = Callable[[str], str]

COMMANDS = frozenset({"/new", "/status", "/help", "/exit", "/quit"})
HELP = """\
Commands:
  /new     start a new conversation (clears untrusted-content taint)
  /status  show the conversation's security state
  /exit    quit
Ctrl+C cancels a running request; at the prompt it quits."""


def open_session_runtime(console: Console) -> Runtime:
    """The runtime for an interactive session; exits with a message if it cannot start."""
    try:
        return open_runtime(bastion_home(), deps.secret_store(), provider=deps.provider_override())
    except (ConfigError, PolicyError, VaultError, ProviderConfigError) as exc:
        console.print(f"[red]Cannot start:[/] {escape(str(exc))}")
        raise typer.Exit(1) from exc


def _status(conversation: Conversation, console: Console) -> None:
    taint = conversation.taint
    state = f"tainted by {taint.describe()}" if taint.tainted else "clean"
    console.print(
        Text(
            f"Conversation {conversation.id}: {len(conversation.messages)} messages, "
            f"context {state}, {len(conversation.provenance.urls)} fetchable URLs."
        )
    )


def _command(text: str, conversation: Conversation, console: Console) -> Conversation | None:
    """Handle a slash command. Returns the conversation to continue with, or None to exit."""
    command = text.split()[0].lower()
    if command in ("/exit", "/quit"):
        return None
    if command == "/new":
        console.print("Started a new conversation.")
        return Conversation.new()
    if command == "/status":
        _status(conversation, console)
        return conversation
    console.print(HELP)
    return conversation


def _show(result: TurnResult, console: Console) -> None:
    console.print(Markdown(strip_invisible(result.reply), hyperlinks=False))
    if result.conversation.taint.tainted:
        console.print(
            Text(
                "! Untrusted content is in this conversation; sending actions need approval. "
                "/new to reset.",
                style="dim yellow",
            )
        )


def _turn(
    runner: asyncio.Runner,
    agent: Agent,
    runtime: Runtime,
    console: Console,
    conversation: Conversation,
    text: str,
) -> Conversation:
    try:
        result = runner.run(agent.run_turn(conversation, text))
    except KeyboardInterrupt:
        console.print("Cancelled.")
        return conversation
    except Exception as exc:  # keep the session alive; the details go to the audit log
        runtime.audit.append(
            "turn.crash",
            {"error_type": type(exc).__name__, "error": str(exc)[:200]},
            checkpoint=True,
        )
        console.print(
            "[red]Something went wrong and this request was abandoned.[/] "
            "Details are in the audit log (bastion audit tail)."
        )
        return conversation
    _show(result, console)
    return result.conversation


def _loop(
    runner: asyncio.Runner, agent: Agent, runtime: Runtime, console: Console, ask: Ask
) -> None:
    conversation = Conversation.new()
    while True:
        try:
            text = ask("\nyou > ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not text:
            continue
        if text.split()[0].lower() in COMMANDS:
            next_conversation = _command(text, conversation, console)
            if next_conversation is None:
                return
            conversation = next_conversation
            continue
        conversation = _turn(runner, agent, runtime, console, conversation, text)


def _session(runner: asyncio.Runner, runtime: Runtime, console: Console, ask: Ask) -> None:
    agent = runtime.agent(ConsoleApprover(console, ask=ask))
    for notice in runtime.notices:
        console.print(Text(f"! {notice}", style="yellow"))
    model = f"{escape(runtime.provider.name)} / {escape(runtime.provider.model)}"
    console.print(f"Bastion ({model}). /help for commands.")
    runtime.audit.append(
        "session.start",
        {"channel": "cli", "provider": runtime.provider.name, "model": runtime.provider.model},
        checkpoint=True,
    )
    try:
        _loop(runner, agent, runtime, console, ask)
    finally:
        runtime.audit.append("session.end", {"channel": "cli"}, checkpoint=True)
        console.print("Bye.")


def chat() -> None:
    """Chat with Bastion in this terminal."""
    console = Console()
    runtime = open_session_runtime(console)

    def ask(prompt: str) -> str:
        return console.input(prompt, markup=False)

    try:
        with asyncio.Runner() as runner:
            try:
                _session(runner, runtime, console, ask)
            finally:
                runner.run(runtime.aclose())
    finally:
        runtime.close()
