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
from bastion.google.grant import CalendarLevel, GmailLevel, Grant, save_client, save_grant
from bastion.google.oauth import ClientCredentials
from bastion.runtime import GOOGLE_OFF_NOTICE, open_runtime
from bastion.security.policy import DEFAULT_POLICY_TOML
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    BRAVE_API_KEY,
    GOOGLE_GRANT,
    GOOGLE_REFRESH_TOKEN,
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
        assert not any("Brave" in notice for notice in runtime.notices)
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


# ------------------------------------------------------------------- Google

GOOGLE_TOOLS = ("gmail_", "calendar_")
ALL_GOOGLE = {
    "gmail_search",
    "gmail_read",
    "gmail_draft",
    "gmail_send",
    "calendar_list_events",
    "calendar_create_event",
    "calendar_update_event",
    "calendar_delete_event",
}


def connect_google(store: MemoryStore, gmail: GmailLevel, calendar: CalendarLevel) -> None:
    vault = Vault(store, Redactor())
    client_id = "123456789-abcdefgh12345678.apps.googleusercontent.com"
    save_client(vault, ClientCredentials(client_id, "GOCSPX-test-secret"))
    vault.set(GOOGLE_REFRESH_TOKEN, "1//refresh-token-value-0001")
    save_grant(vault, Grant("me@example.com", gmail, calendar, frozenset()))


def test_google_tools_are_off_until_connected(tmp_path: Path) -> None:
    home, store = make_home(tmp_path)

    runtime = open_runtime(home, store, provider=ScriptedProvider())
    try:
        assert not any(name.startswith(GOOGLE_TOOLS) for name in runtime.tools.names)
        assert GOOGLE_OFF_NOTICE in runtime.notices
        assert runtime.clients == ()
    finally:
        runtime.close()


@pytest.mark.security
@pytest.mark.parametrize(
    ("gmail", "calendar", "expected"),
    [
        ("read", "off", {"gmail_search", "gmail_read"}),
        (
            "draft",
            "read",
            {"gmail_search", "gmail_read", "gmail_draft", "calendar_list_events"},
        ),
        ("off", "write", {name for name in ALL_GOOGLE if name.startswith("calendar_")}),
        ("send", "write", ALL_GOOGLE),
    ],
)
async def test_google_tools_match_the_granted_access(
    tmp_path: Path, gmail: GmailLevel, calendar: CalendarLevel, expected: set[str]
) -> None:
    home, store = make_home(tmp_path)
    connect_google(store, gmail, calendar)

    runtime = open_runtime(home, store, provider=ScriptedProvider())
    try:
        google = {name for name in runtime.tools.names if name.startswith(GOOGLE_TOOLS)}
        assert google == expected
        assert GOOGLE_OFF_NOTICE not in runtime.notices
        assert len(runtime.clients) == 1
        await runtime.aclose()
        assert runtime.clients[0].is_closed
    finally:
        runtime.close()


def test_a_corrupt_google_record_turns_google_off(tmp_path: Path) -> None:
    home, store = make_home(tmp_path)
    connect_google(store, "send", "write")
    store.set(GOOGLE_GRANT, "not json")

    runtime = open_runtime(home, store, provider=ScriptedProvider())
    try:
        assert not any(name.startswith(GOOGLE_TOOLS) for name in runtime.tools.names)
        assert any("corrupt" in notice for notice in runtime.notices)
    finally:
        runtime.close()


def test_google_is_set_up_only_after_everything_else_succeeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import bastion.runtime as runtime_module
    from bastion.security.policy import PolicyError

    home, store = make_home(tmp_path)
    connect_google(store, "send", "write")
    (home / POLICY_FILE).write_text("not [valid toml", encoding="utf-8")
    calls: list[object] = []
    monkeypatch.setattr(runtime_module, "build_google_tools", lambda *args: calls.append(args))

    with pytest.raises(PolicyError):
        open_runtime(home, store, provider=ScriptedProvider())

    assert calls == []  # so no HTTP client was created only to leak


def task_for(runtime: object, tools: list[str]) -> object:
    from bastion.runtime import Runtime

    assert isinstance(runtime, Runtime)
    spec = runtime.tasks.new_spec(
        name="Brief",
        schedule="daily 08:00",
        instructions="Look something up.",
        tools=tools,
        grantable=runtime.tools.names,
        created_via="cli",
    )
    return runtime.tasks.add(spec, limit=20)


@pytest.mark.security
async def test_a_task_agent_sees_only_its_granted_tools(tmp_path: Path) -> None:
    from bastion.autonomy.tasks import Task
    from bastion.core.prompts import task_system_prompt

    home, store = make_home(tmp_path)
    provider = ScriptedProvider(reply("done"))
    runtime = open_runtime(home, store, provider=provider)
    try:
        assert {"task_schedule", "task_list", "task_remove"} <= runtime.tools.names
        task = task_for(runtime, ["web_fetch", "memory_search"])
        assert isinstance(task, Task)

        built = runtime.task_agent(task, StubApprover(False))
        result = await built.agent.run_turn(Conversation.new(), task.spec.instructions)

        assert built.tools == ("memory_search", "web_fetch") and built.missing == ()
        assert provider.tool_names == [("memory_search", "web_fetch")]
        assert result.reply == "done"
        assert task_system_prompt("Brief").endswith("remove tasks.\n")
    finally:
        await runtime.aclose()
        runtime.close()


def test_task_tools_are_off_when_autonomy_is_disabled(tmp_path: Path) -> None:
    from bastion.config import AutonomySettings

    home, store = make_home(tmp_path)
    settings = Settings(
        llm=LLMSettings(provider="ollama", model="llama3", effort=None),
        autonomy=AutonomySettings(enabled=False),
    )
    (home / CONFIG_FILE).write_text(render_config(settings), encoding="utf-8")

    runtime = open_runtime(home, store, provider=ScriptedProvider())
    try:
        assert not {"task_schedule", "task_list", "task_remove"} & runtime.tools.names
    finally:
        runtime.close()
