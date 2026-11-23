from pathlib import Path

import pytest

from bastion.config import (
    CONFIG_FILE,
    ConfigError,
    LLMSettings,
    Settings,
    bastion_home,
    load_settings,
    render_config,
)


def _write(home: Path, text: str) -> None:
    (home / CONFIG_FILE).write_text(text, encoding="utf-8")


def test_defaults_round_trip_through_toml(tmp_path: Path) -> None:
    _write(tmp_path, render_config(Settings()))

    assert load_settings(tmp_path) == Settings()


def test_unusual_values_round_trip(tmp_path: Path) -> None:
    settings = Settings(
        llm=LLMSettings(
            provider="custom",
            model='model "quoted" \\ name',
            base_url="https://x.example/v1",
            effort=None,
        )
    )
    _write(tmp_path, render_config(settings))

    assert load_settings(tmp_path) == settings


def test_config_never_contains_secrets() -> None:
    assert "api_key" not in render_config(Settings())


def test_missing_config_explains_how_to_fix_it(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="bastion init"):
        load_settings(tmp_path)


def test_unknown_keys_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path, '[llm]\nprovidr = "anthropic"\n')

    with pytest.raises(ConfigError, match="providr"):
        load_settings(tmp_path)


def test_invalid_toml_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, "[llm\n")

    with pytest.raises(ConfigError, match="not valid TOML"):
        load_settings(tmp_path)


def test_out_of_range_limits_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "[limits]\nmax_steps = 0\n")

    with pytest.raises(ConfigError, match="max_steps"):
        load_settings(tmp_path)


def test_home_defaults_to_dot_bastion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BASTION_HOME", raising=False)

    assert bastion_home() == Path.home() / ".bastion"


def test_home_can_be_overridden(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BASTION_HOME", str(tmp_path))

    assert bastion_home() == tmp_path
