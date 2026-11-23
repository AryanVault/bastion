import sqlite3
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from bastion.cli import app, deps
from bastion.config import CONFIG_FILE, DATABASE_FILE, POLICY_FILE
from bastion.llm.types import LLMProvider
from bastion.security.vault import AUDIT_KEY, BRAVE_API_KEY, STORAGE_KEY, MemoryStore
from support.fakes import ScriptedProvider, reply

API_KEY = "sk-ant-test-key-123456"


@dataclass
class Env:
    home: Path
    store: MemoryStore
    monkeypatch: pytest.MonkeyPatch

    def use_provider(self, provider: LLMProvider) -> None:
        self.monkeypatch.setattr(deps, "provider_override", lambda: provider)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    store = MemoryStore()
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(deps, "secret_store", lambda: store)
    yield Env(tmp_path / "home", store, monkeypatch)


def run(args: list[str], stdin: str | None = None) -> Result:
    return CliRunner().invoke(app, args, input=stdin)


def flat(result: Result) -> str:
    return " ".join(result.output.split())


def init_anthropic() -> Result:
    # provider, model (default), API key (hidden), Brave key (skip)
    return run(["init"], stdin=f"anthropic\n\n{API_KEY}\n\n")


def init_local() -> Result:
    return run(["init", "--provider", "ollama", "--model", "llama3"], stdin="\n")


# --------------------------------------------------------------------- init


def test_init_stores_keys_in_the_keyring_and_writes_config(env: Env) -> None:
    result = init_anthropic()

    assert result.exit_code == 0, result.output
    assert env.store.get("llm.anthropic.api_key") == API_KEY
    assert env.store.get(AUDIT_KEY) and env.store.get(STORAGE_KEY)
    assert (env.home / POLICY_FILE).exists() and (env.home / DATABASE_FILE).exists()
    assert API_KEY not in (env.home / CONFIG_FILE).read_text(encoding="utf-8")
    assert API_KEY not in result.output


def test_init_stores_an_optional_search_key(env: Env) -> None:
    result = run(
        ["init", "--provider", "ollama", "--model", "llama3"], stdin="BSA-search-key-123\n"
    )

    assert result.exit_code == 0, result.output
    assert env.store.get(BRAVE_API_KEY) == "BSA-search-key-123"


def test_init_does_not_overwrite_an_existing_setup(env: Env) -> None:
    init_local()

    result = init_local()

    assert result.exit_code == 1
    assert "--force" in flat(result)


def test_init_rejects_an_insecure_base_url(env: Env) -> None:
    result = run(
        ["init", "--provider", "custom", "--model", "m", "--base-url", "http://llm.example.com/v1"]
    )

    assert result.exit_code != 0
    assert "https" in flat(result)


def test_init_rejects_unknown_providers(env: Env) -> None:
    assert run(["init", "--provider", "mystery"]).exit_code != 0


# --------------------------------------------------------------------- chat


def test_chat_round_trip(env: Env) -> None:
    init_local()
    env.use_provider(ScriptedProvider(reply("Hi there!")))

    result = run(["chat"], stdin="hello\n/exit\n")

    assert result.exit_code == 0, result.output
    assert "Hi there!" in result.output


@pytest.mark.security
def test_chat_neutralises_terminal_escape_sequences(env: Env) -> None:
    init_local()
    env.use_provider(ScriptedProvider(reply("safe\x1b[2Jtext")))

    result = run(["chat"], stdin="hello\n")

    assert "\x1b[2J" not in result.output


def test_chat_slash_commands(env: Env) -> None:
    init_local()
    env.use_provider(ScriptedProvider())

    result = run(["chat"], stdin="/status\n/new\n/help\n/exit\n")

    output = flat(result)
    assert "context clean" in output
    assert "Started a new conversation" in output
    assert "Commands:" in output


def test_chat_without_setup_explains_what_to_do(env: Env) -> None:
    result = run(["chat"])

    assert result.exit_code == 1
    assert "bastion init" in flat(result)


# -------------------------------------------------------------------- audit


@pytest.mark.security
def test_audit_verify_detects_tampering(env: Env) -> None:
    init_local()
    assert run(["audit", "verify"]).exit_code == 0

    with closing(sqlite3.connect(env.home / DATABASE_FILE)) as conn:
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("UPDATE audit_log SET data = '{}' WHERE seq = 1")
        conn.commit()
    result = run(["audit", "verify"])

    assert result.exit_code == 1
    assert "TAMPERED" in result.output


def test_audit_tail_lists_recent_events(env: Env) -> None:
    init_local()

    result = run(["audit", "tail", "-n", "5"])

    assert result.exit_code == 0
    assert "setup.init" in result.output


def test_audit_commands_need_setup(env: Env) -> None:
    assert run(["audit", "verify"]).exit_code == 1


# ------------------------------------------------------------------ secrets


@pytest.mark.security
def test_secrets_status_never_shows_values(env: Env) -> None:
    init_anthropic()

    result = run(["secrets", "status"])

    assert "llm.anthropic.api_key" in result.output
    assert API_KEY not in result.output


def test_secrets_set_and_delete(env: Env) -> None:
    assert run(["secrets", "set", BRAVE_API_KEY], stdin="BSA-value-123456\n").exit_code == 0
    assert env.store.get(BRAVE_API_KEY) == "BSA-value-123456"

    assert run(["secrets", "delete", BRAVE_API_KEY]).exit_code == 0
    assert env.store.get(BRAVE_API_KEY) is None


def test_secrets_set_rejects_invalid_names(env: Env) -> None:
    assert run(["secrets", "set", "Not A Name"], stdin="value-12345\n").exit_code == 1


# ------------------------------------------------------------------- policy


def test_policy_show_lists_tiers_and_floors(env: Env) -> None:
    init_local()

    result = run(["policy", "show"])

    output = flat(result)
    assert result.exit_code == 0
    assert "destructive" in output
    assert "Floors enforced in code" in output


def test_policy_show_needs_setup(env: Env) -> None:
    assert run(["policy", "show"]).exit_code == 1


# ------------------------------------------------------ review regressions


def test_chat_survives_an_unexpected_error_in_one_turn(env: Env) -> None:
    init_local()

    def crash(messages: object) -> object:
        raise RuntimeError("database is locked")

    env.use_provider(ScriptedProvider(crash, reply("second turn works")))  # type: ignore[arg-type]

    result = run(["chat"], stdin="first\nsecond\n/exit\n")

    assert result.exit_code == 0, result.output
    assert "Something went wrong" in flat(result)
    assert "second turn works" in result.output


def test_unknown_slash_text_is_sent_to_the_model(env: Env) -> None:
    init_local()
    env.use_provider(ScriptedProvider(reply("not a command after all")))

    result = run(["chat"], stdin="/shrug hello\n/exit\n")

    assert "not a command after all" in result.output


def test_session_end_is_always_audited(env: Env) -> None:
    init_local()
    env.use_provider(ScriptedProvider())

    run(["chat"], stdin="")  # end of input straight away

    assert "session.end" in run(["audit", "tail", "-n", "3"]).output


@pytest.mark.security
def test_audit_verify_detects_a_wiped_log(env: Env) -> None:
    init_local()

    with closing(sqlite3.connect(env.home / DATABASE_FILE)) as conn:
        conn.execute("DROP TRIGGER audit_no_delete")
        conn.execute("DELETE FROM audit_log")
        conn.commit()
    result = run(["audit", "verify"])

    assert result.exit_code == 1
    assert "TAMPERED" in result.output


def test_secrets_status_distinguishes_errors_from_missing(env: Env) -> None:
    from bastion.security.vault import VaultError

    class LockedStore(MemoryStore):
        def get(self, name: str) -> str | None:
            raise VaultError("the OS keyring is unavailable (KeyringLocked)")

    env.monkeypatch.setattr(deps, "secret_store", lambda: LockedStore())

    result = run(["secrets", "status"])

    assert "error" in result.output
    assert "missing" not in result.output
