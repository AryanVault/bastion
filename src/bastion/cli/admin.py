"""Administrative commands: ``bastion audit``, ``bastion secrets``, ``bastion policy``."""

from collections.abc import Iterator
from contextlib import closing, contextmanager
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from bastion.cli import deps
from bastion.common import canonical_json
from bastion.config import DATABASE_FILE, POLICY_FILE, ConfigError, bastion_home, load_settings
from bastion.llm.factory import PRESETS
from bastion.runtime import open_audit_log
from bastion.security.audit import MIN_CHECKPOINT_CHARS, AuditLog, parse_checkpoint
from bastion.security.policy import PolicyError, load_policy
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    BRAVE_API_KEY,
    STORAGE_KEY,
    TELEGRAM_OWNER,
    TELEGRAM_TOKEN,
    TOTP_SECRET,
    Vault,
    VaultError,
    llm_api_key,
)
from bastion.storage.db import connect
from bastion.text import reveal_invisible
from bastion.tools.base import RiskTier

audit_app = typer.Typer(
    help="Inspect and verify the tamper-evident audit log.", no_args_is_help=True
)
secrets_app = typer.Typer(
    help="Manage secrets in the OS keyring (values are never shown).", no_args_is_help=True
)
policy_app = typer.Typer(help="Show the action policy.", no_args_is_help=True)

_DETAIL_WIDTH = 90


def _vault() -> Vault:
    return Vault(deps.secret_store(), Redactor())


def _fail(console: Console, message: str) -> typer.Exit:
    console.print(f"[red]{escape(message)}[/]")
    return typer.Exit(1)


@contextmanager
def audit_session(console: Console) -> Iterator[AuditLog]:
    """The audit log for a one-off CLI command; exits with a message if Bastion is not set up."""
    path = bastion_home() / DATABASE_FILE
    if not path.exists():
        raise _fail(console, "No audit log yet. Run: bastion init")
    vault = _vault()
    try:
        vault.key(AUDIT_KEY)
    except VaultError as exc:
        raise _fail(console, str(exc)) from exc
    with closing(connect(path)) as conn:
        yield open_audit_log(conn, vault, Redactor())


# -------------------------------------------------------------------- audit


@audit_app.command("verify")
def audit_verify(
    checkpoint: Annotated[
        list[str] | None,
        typer.Option(
            "--checkpoint",
            help="A checkpoint recorded elsewhere, as ENTRY:CHAIN (e.g. from the daily "
            "Telegram message). Repeatable.",
        ),
    ] = None,
) -> None:
    """Check the audit log's HMAC chain for tampering."""
    console = Console()
    try:
        checkpoints = [parse_checkpoint(value) for value in checkpoint or ()]
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--checkpoint") from exc
    with audit_session(console) as audit:
        result = audit.verify(checkpoints)
        head = audit.head()
    if result.ok:
        console.print(f"[green]OK[/]: {result.entries} entries verified, chain intact.")
        if checkpoints:
            console.print(f"{len(checkpoints)} recorded checkpoint(s) matched.")
        if head is not None:
            console.print(f"Chain head: {head.seq}:{head.mac[:MIN_CHECKPOINT_CHARS]}")
        return
    console.print(
        f"[red]TAMPERED[/]: entry {result.first_bad_seq}: {escape(result.reason)} "
        f"({result.entries} entries verified before it)."
    )
    raise typer.Exit(1)


@audit_app.command("tail")
def audit_tail(
    count: Annotated[
        int, typer.Option("--count", "-n", min=1, max=1000, help="Entries to show.")
    ] = 20,
) -> None:
    """Show the most recent audit entries."""
    console = Console()
    with audit_session(console) as audit:
        entries = audit.tail(count)
    table = Table("seq", "time (UTC)", "event", "details")
    for entry in entries:
        details = canonical_json(entry.data)
        if len(details) > _DETAIL_WIDTH:
            details = details[: _DETAIL_WIDTH - 3] + "..."
        # Entries can hold model-influenced strings: show hidden characters, never obey them.
        table.add_row(str(entry.seq), entry.ts[:19], entry.event, Text(reveal_invisible(details)))
    console.print(table)


# ------------------------------------------------------------------ secrets


def _known_secret_names() -> list[str]:
    try:
        provider = load_settings(bastion_home()).llm.provider
        providers = (
            [provider] if PRESETS.get(provider, None) and PRESETS[provider].needs_key else []
        )
    except ConfigError:
        providers = [name for name, preset in PRESETS.items() if preset.needs_key]
    return [
        *(llm_api_key(p) for p in providers),
        BRAVE_API_KEY,
        AUDIT_KEY,
        STORAGE_KEY,
        TELEGRAM_TOKEN,
        TELEGRAM_OWNER,
        TOTP_SECRET,
    ]


@secrets_app.command("set")
def secrets_set(
    name: Annotated[str, typer.Argument(help="Secret name, e.g. search.brave.api_key")],
) -> None:
    """Store a secret. The value is read from a hidden prompt."""
    console = Console()
    value = typer.prompt(f"Value for {name} (input hidden)", hide_input=True).strip()
    try:
        _vault().set(name, value)
    except VaultError as exc:
        raise _fail(console, str(exc)) from exc
    console.print(f"Stored {escape(name)} in the OS keyring.")


@secrets_app.command("delete")
def secrets_delete(name: Annotated[str, typer.Argument(help="Secret name.")]) -> None:
    """Delete a secret from the OS keyring."""
    console = Console()
    try:
        _vault().delete(name)
    except VaultError as exc:
        raise _fail(console, str(exc)) from exc
    console.print(f"Deleted {escape(name)}.")


@secrets_app.command("status")
def secrets_status() -> None:
    """Show which secrets are set. Values are never displayed."""
    vault = _vault()
    table = Table("secret", "status")
    for name in _known_secret_names():
        try:
            status = "[green]set[/]" if vault.get(name) is not None else "[yellow]missing[/]"
        except VaultError as exc:  # e.g. a locked keyring: not the same thing as "missing"
            status = f"[red]error[/]: {escape(str(exc))}"
        table.add_row(name, status)
    Console().print(table)


# ------------------------------------------------------------------- policy


@policy_app.command("show")
def policy_show() -> None:
    """Show the effective policy, including the floors enforced in code."""
    console = Console()
    path = bastion_home() / POLICY_FILE
    try:
        config = load_policy(path)
    except FileNotFoundError as exc:
        raise _fail(console, f"{path} not found. Run: bastion init") from exc
    except PolicyError as exc:
        raise _fail(console, str(exc)) from exc
    table = Table("risk tier", "clean context", "tainted context", "step-up")
    for tier in RiskTier:
        step_up = "yes" if tier in config.step_up.tiers else ""
        table.add_row(
            tier.value,
            config.clean.for_tier(tier).value,
            config.tainted.for_tier(tier).value,
            step_up,
        )
    console.print(table)
    for tool, rule in sorted(config.tools.items()):
        console.print(f"override {escape(tool)}: clean={rule.clean}, tainted={rule.tainted}")
    console.print(
        "Floors enforced in code: destructive actions always need approval; send actions "
        "always need approval in a tainted context. Unknown tools are always denied."
    )
