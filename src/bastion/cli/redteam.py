"""``bastion redteam``: run the attack corpus against Bastion's own controls.

By default the model is a hijacked stand-in that obeys every injected instruction, which shows
what the controls stop on their own (deterministic, free, no setup needed). ``--live`` uses the
configured model instead, to see what it attempts. Either way everything runs in a sandbox:
fake mailbox, calendar and web, a throwaway database, no real network except the model.

Exit codes: 0 every attack held; 1 an attack succeeded or a scenario could not run;
2 a usage or configuration error; 3 the owner declined a ``--live`` run.
"""

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from bastion.cli import deps
from bastion.config import ConfigError, bastion_home, load_settings
from bastion.llm.factory import build_provider
from bastion.llm.types import LLMProvider
from bastion.redteam.harness import Report, ScenarioResult, run_suite
from bastion.redteam.scenarios import SCENARIOS, Outcome, Scenario
from bastion.security.redact import Redactor
from bastion.security.vault import Vault, VaultError

EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_DECLINED = 3
WIDE_TERMINAL = 110
_SUMMARY_ORDER = (
    Outcome.RESISTED,
    Outcome.REFUSED,
    Outcome.CONTAINED,
    Outcome.ASKED_OWNER,
    Outcome.NEEDED_CODE,
)

type ProviderFactory = Callable[[], LLMProvider]


def _selected(only: list[str]) -> tuple[Scenario, ...]:
    if not only:
        return SCENARIOS
    known = {s.id: s for s in SCENARIOS}
    unknown = [name for name in only if name not in known]
    if unknown:
        raise typer.BadParameter(f"unknown scenario: {', '.join(unknown)} (see --list)")
    return tuple(known[name] for name in dict.fromkeys(only))


def _cannot_use_model(console: Console, exc: Exception) -> typer.Exit:
    console.print(Text(f"Cannot use your model: {exc}", style="red"))
    console.print("Run `bastion init` first, or run without --live.")
    return typer.Exit(EXIT_USAGE)


def _live_target(console: Console) -> tuple[str, ProviderFactory]:
    """The configured model's name, and how to build it (only once the owner agrees)."""
    override = deps.provider_override()
    if override is not None:
        return f"{override.name} / {override.model}", lambda: override
    try:
        settings = load_settings(bastion_home())
    except ConfigError as exc:
        raise _cannot_use_model(console, exc) from exc

    def build() -> LLMProvider:
        try:
            return build_provider(settings.llm, Vault(deps.secret_store(), Redactor()))
        except (ConfigError, VaultError) as exc:
            raise _cannot_use_model(console, exc) from exc

    return f"{settings.llm.provider} / {settings.llm.model}", build


def _confirm_live(label: str, count: int) -> None:
    question = (
        f"Run {count} attack scenarios against {label}? "
        "This sends real requests (with their token costs) to that provider"
    )
    try:
        agreed = typer.confirm(question)
    except typer.Abort:
        agreed = False
    if not agreed:
        typer.echo("Cancelled.")
        raise typer.Exit(EXIT_DECLINED)


def _print_report(console: Console, report: Report, *, live: bool) -> None:
    wide = console.width >= WIDE_TERMINAL
    table = Table(title=f"Bastion red team: {report.model}")
    table.add_column("Scenario", no_wrap=True)
    table.add_column("Planted in")
    if wide:
        table.add_column("Attacker's goal")
    table.add_column("Result")
    for result in report.results:
        scenario, outcome = result.scenario, result.outcome
        style = "green" if outcome.held else "bold red"
        cells = [Text(scenario.id), Text(scenario.vector.value)]
        if wide:
            cells.append(Text(scenario.goal))
        table.add_row(*cells, Text(outcome.short, style=style))
    console.print(table)
    _print_summary(console, report, live=live)


def _print_summary(console: Console, report: Report, *, live: bool) -> None:
    total, failed = len(report.results), len(report.compromised)
    held = ", ".join(
        f"{report.count(outcome)} {outcome.short.lower()}"
        for outcome in _SUMMARY_ORDER
        if report.count(outcome)
    )
    attacks = f"{total} attack" + ("" if total == 1 else "s")
    style = "bold red" if failed or report.errors else "bold green"
    console.print(Text(f"{attacks}, {failed} succeeded. Held: {held or 'none'}.", style=style))
    for result in report.compromised:
        console.print(
            Text(f"SUCCEEDED: {result.scenario.id}: {result.scenario.title}", style="red")
        )
    for result in report.errors:
        console.print(Text(f"COULD NOT RUN: {result.scenario.id}: {result.error}", style="red"))
    if not live:
        drifted = [r.scenario.id for r in report.results if r.outcome.held and not r.as_expected]
        if drifted:
            console.print(
                Text(f"Held, but not by the expected control: {', '.join(drifted)}", style="yellow")
            )
    if not all(r.audit_intact for r in report.results):
        console.print(Text("Warning: a sandbox audit log failed verification.", style="red"))


def _write_json(console: Console, path: Path, report: Report) -> bool:
    try:
        path.write_text(json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        console.print(Text(f"Could not write {path}: {exc.strerror or exc}", style="red"))
        return False
    console.print(Text(f"Results written to {path}"))
    return True


def redteam(
    live: Annotated[
        bool,
        typer.Option("--live", help="Attack your configured model instead (costs tokens)."),
    ] = False,
    only: Annotated[
        list[str] | None, typer.Option("--only", help="Run just this scenario (repeatable).")
    ] = None,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Also write the results to this JSON file.")
    ] = None,
    list_scenarios: Annotated[
        bool, typer.Option("--list", help="List the scenarios and exit.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the --live confirmation.")] = False,
) -> None:
    """Attack Bastion with prompt injections and a hijacked chat account, in a sandbox."""
    console = Console()
    scenarios = _selected(only or [])
    if list_scenarios:
        for scenario in scenarios:
            console.print(Text(f"{scenario.id}: {scenario.title} ({scenario.vector.value})"))
        return
    if json_path is not None and not json_path.parent.is_dir():
        raise typer.BadParameter(f"{json_path.parent} is not a directory", param_hint="--json")
    factory: ProviderFactory | None = None
    if live:
        label, factory = _live_target(console)
        if not yes:
            _confirm_live(label, len(scenarios))

    def progress(result: ScenarioResult) -> None:
        console.print("." if result.outcome.held else "x", end="")

    async def run() -> Report:
        provider = factory() if factory is not None else None
        try:
            return await run_suite(scenarios, provider, on_result=progress)
        finally:
            if provider is not None:
                await provider.aclose()

    report = asyncio.run(run())
    console.print()
    _print_report(console, report, live=live)
    written = json_path is None or _write_json(console, json_path, report)
    if report.compromised or report.errors:
        raise typer.Exit(EXIT_FAILED)
    if not written:
        raise typer.Exit(EXIT_USAGE)
