import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bastion.cli import app, deps
from bastion.redteam.harness import SimulatedOwner
from bastion.redteam.scenarios import SCENARIOS
from bastion.security.approvals import ApprovalRequest
from support.fakes import ScriptedProvider, reply

runner = CliRunner()
PHISH = ["redteam", "--only", "email-forward-invoices"]


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("COLUMNS", "200")
    return tmp_path


def test_it_runs_without_any_setup_and_reports_no_successful_attack(tmp_path: Path) -> None:
    out = tmp_path / "results.json"

    result = runner.invoke(app, [*PHISH, "--only", "web-ssrf-rebinding", "--json", str(out)])

    assert result.exit_code == 0, result.output
    assert "2 attacks, 0 succeeded. Held: 1 refused, 1 asked you." in result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["compromised"] == 0
    assert [r["outcome"] for r in data["results"]] == ["asked_owner", "refused"]


def test_list_shows_every_scenario() -> None:
    result = runner.invoke(app, ["redteam", "--list"])

    assert result.exit_code == 0
    for scenario in SCENARIOS:
        assert scenario.id in result.output


def test_an_unknown_scenario_is_an_error() -> None:
    result = runner.invoke(app, ["redteam", "--only", "nope"])

    assert result.exit_code == 2
    assert "unknown scenario" in result.output


def test_a_successful_attack_fails_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    async def approve(self: SimulatedOwner, request: ApprovalRequest) -> bool:
        return True

    monkeypatch.setattr(SimulatedOwner, "request_approval", approve)

    result = runner.invoke(app, PHISH)

    assert result.exit_code == 1
    assert "1 attack, 1 succeeded." in result.output
    assert "SUCCEEDED: email-forward-invoices" in result.output


def test_live_runs_use_the_configured_model_after_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = ScriptedProvider(reply("That looks like phishing; I won't forward anything."))
    monkeypatch.setattr(deps, "provider_override", lambda: model)

    declined = runner.invoke(app, [*PHISH, "--live"], input="n\n")
    assert declined.exit_code == 3 and model.requests == []

    result = runner.invoke(app, [*PHISH, "--live"], input="y\n")

    assert result.exit_code == 0, result.output
    assert "sends real requests" in result.output
    assert "1 attack, 0 succeeded. Held: 1 resisted." in result.output
    assert model.closed


def test_live_needs_a_configured_model() -> None:
    result = runner.invoke(app, ["redteam", "--live", "--yes"])

    assert result.exit_code == 2
    assert "bastion init" in result.output


def test_a_bad_json_path_is_refused_before_anything_runs(tmp_path: Path) -> None:
    result = runner.invoke(app, [*PHISH, "--json", str(tmp_path / "missing" / "out.json")])

    assert result.exit_code == 2
    assert "is not a directory" in result.output


def test_a_narrow_terminal_keeps_ids_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "60")

    result = runner.invoke(app, PHISH)

    assert result.exit_code == 0
    assert "email-forward-invoices" in result.output
