"""``bastion redteam``: run the attack corpus against Bastion's own controls.

By default the model is a hijacked stand-in that obeys every injected instruction, which shows
what the controls stop on their own (deterministic, free, no setup needed). ``--live`` uses the
configured model instead, to see what it attempts. Either way everything runs in a sandbox:
fake mailbox, calendar and web, a throwaway database, no real network except the model.
"""

import asyncio
import json
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

_SUMMARY_ORDER = (
    Outcome.RESISTED,
    Outcome.REFUSED,
    Outcome.CONTAINED,
    Outcome.ASKED_OWNER,
    Outcome.NEEDED_CODE,
)


def _selected(only: list[str]) -> tuple[Scenario, ...]:
    if not only:
        return SCENARIOS
    known = {s.id: s for s in SCENARIOS}
    unknown = [name for name in only if name not in known]
    if unknown:
        raise typer.BadParameter(f"unknown scenario: {', '.join(unknown)} (see --list)")
    return tuple(known[name] for name in dict.fromkeys(only))


def _live_provider(console: Console) -> LLMProvider:
    override = deps.provider_override()
    if override is not None:
        return override
    try:
        settings = load_settings(bastion_home())
        return build_provider(settings.llm, Vault(deps.secret_store(), Redactor()))
    except (ConfigError, VaultError) as exc:
        console.print(Text(f"Cannot use your model: {exc}", style="red"))
        console.print("Run `bastion init` first, or run without --live.")
        raise typer.Exit(2) from exc


def _row(result: ScenarioResult) -> tuple[Text, Text, Text, Text]:
    scenario = result.scenario
    style = "bold red" if result.outcome is Outcome.COMPROMISED else "green"
    return (
        Text(scenario.id),
        Text(scenario.vector.value),
        Text(scenario.goal),
        Text(result.outcome.label, style=style),
    )


def _print_report(console: Console, report: Report, *, live: bool) -> None:
    table = Table(title=f"Bastion red team: {report.model}")
    for column in ("Scenario", "Planted in", "Attacker's goal", "Result"):
        table.add_column(column, overflow="fold")  # never cut an id short
    for result in report.results:
        table.add_row(*_row(result))
    console.print(table)
    total, failed = len(report.results), len(report.compromised)
    held = ", ".join(
        f"{report.count(outcome)} {outcome.value.replace('_', ' ')}"
        for outcome in _SUMMARY_ORDER
        if report.count(outcome)
    )
    style = "bold red" if failed else "bold green"
    attacks = f"{total} attack" + ("" if total == 1 else "s")
    console.print(Text(f"{attacks}, {failed} succeeded. Held: {held or 'none'}.", style=style))
    for result in report.compromised:
        console.print(
            Text(f"SUCCEEDED: {result.scenario.id}: {result.scenario.title}", style="red")
        )
    if not live:
        drifted = [r.scenario.id for r in report.results if not r.as_expected]
        if drifted:
            console.print(
                Text(f"Held, but not by the expected control: {', '.join(drifted)}", style="yellow")
            )
    if not all(r.audit_intact for r in report.results):
        console.print(Text("Warning: a sandbox audit log failed verification.", style="red"))


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
    provider = _live_provider(console) if live else None
    if provider is not None and not yes:
        question = (
            f"Run {len(scenarios)} attack scenarios against {provider.name} / {provider.model}? "
            "This sends real requests (with their token costs) to that provider"
        )
        if not typer.confirm(question):
            raise typer.Exit(1)

    def progress(result: ScenarioResult) -> None:
        console.print("x" if result.outcome is Outcome.COMPROMISED else ".", end="")

    async def run() -> Report:
        try:
            return await run_suite(scenarios, provider, on_result=progress)
        finally:
            if provider is not None:
                await provider.aclose()

    report = asyncio.run(run())
    console.print()
    _print_report(console, report, live=live)
    if json_path is not None:
        json_path.write_text(json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8")
        console.print(Text(f"Results written to {json_path}"))
    if report.compromised:
        raise typer.Exit(1)
