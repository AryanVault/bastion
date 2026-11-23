from pathlib import Path

import pytest

from bastion.config import (
    CONFIG_FILE,
    POLICY_FILE,
    ConfigError,
    LLMSettings,
    Settings,
    render_config,
)
from bastion.core.conversation import Conversation
from bastion.runtime import open_runtime
from bastion.security.policy import DEFAULT_POLICY_TOML
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    BRAVE_API_KEY,
    STORAGE_KEY,
    MemoryStore,
    MissingSecretError,
    Vault,
)
from support.fakes import ScriptedProvider, StubApprover, reply


def make_home(tmp_path: Path, *, with_keys: bool = True) -> tuple[Path, MemoryStore]:
    settings = Settings(llm=LLMSettings(provider="ollama", model="llama3", effort=None))
    (tmp_path / CONFIG_FILE).write_text(render_config(settings), encoding="utf-8")
    (tmp_path / POLICY_FILE).write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    store = MemoryStore()
    if with_keys:
        vault = Vault(store, Redactor())
        vault.key(AUDIT_KEY, create=True)
        vault.key(STORAGE_KEY, create=True)
    return tmp_path, store


def test_runtime_wires_tools_policy_and_audit(tmp_path: Path) -> None:
    home, store = make_home(tmp_path)

    runtime = open_runtime(home, store, provider=ScriptedProvider())
    try:
        assert {"web_fetch", "memory_save", "memory_search", "memory_delete"} <= runtime.tools.names
        assert "web_search" not in runtime.tools.names
        assert any("Brave" in notice for notice in runtime.notices)
    finally:
        runtime.close()


def test_web_search_is_enabled_when_a_key_is_stored(tmp_path: Path) -> None:
    home, store = make_home(tmp_path)
    store.set(BRAVE_API_KEY, "BSA-test-key-123")

    runtime = open_runtime(home, store, provider=ScriptedProvider())
    try:
        assert "web_search" in runtime.tools.names
        assert runtime.notices == ()
    finally:
        runtime.close()


async def test_runtime_agent_completes_a_turn_with_an_intact_audit_chain(tmp_path: Path) -> None:
    home, store = make_home(tmp_path)
    runtime = open_runtime(home, store, provider=ScriptedProvider(reply("hello")))
    try:
        result = await runtime.agent(StubApprover(answer=False)).run_turn(Conversation.new(), "hi")

        assert result.reply == "hello"
        assert runtime.audit.verify().ok
    finally:
        runtime.close()


def test_a_missing_policy_file_is_reported(tmp_path: Path) -> None:
    home, store = make_home(tmp_path)
    (home / POLICY_FILE).unlink()

    with pytest.raises(ConfigError, match="bastion init"):
        open_runtime(home, store, provider=ScriptedProvider())


def test_missing_keys_tell_the_owner_to_run_init(tmp_path: Path) -> None:
    home, store = make_home(tmp_path, with_keys=False)

    with pytest.raises(MissingSecretError, match="bastion init"):
        open_runtime(home, store, provider=ScriptedProvider())
