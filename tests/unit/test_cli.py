from typer.testing import CliRunner

import bastion
from bastion.cli import app

runner = CliRunner()


def test_version_flag_prints_package_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"bastion {bastion.__version__}"


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])

    assert "Usage" in result.output
