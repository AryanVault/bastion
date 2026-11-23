import pytest
from rich.console import Console

from bastion.cli.approver import ConsoleApprover
from bastion.security.approvals import ApprovalRequest, ApprovalService
from bastion.tools.base import RiskTier
from support.fakes import EmailArgs


def request(*, to: str = "alice@example.com", step_up: bool = False) -> ApprovalRequest:
    return ApprovalService().create(
        tool="send_email",
        tier=RiskTier.DESTRUCTIVE if step_up else RiskTier.SEND,
        args=EmailArgs(to=to, body="hello"),
        summary=f"Send an email to {to}",
        reason="send actions need approval",
        step_up=step_up,
    )


def approver(answer: str, console: Console | None = None) -> ConsoleApprover:
    return ConsoleApprover(console or Console(record=True), ask=lambda prompt: answer)


@pytest.mark.parametrize(
    ("answer", "expected"), [("y", True), ("YES", True), ("", False), ("n", False), ("sure", False)]
)
async def test_only_an_explicit_yes_approves(answer: str, expected: bool) -> None:
    assert await approver(answer).request_approval(request()) is expected


@pytest.mark.security
async def test_step_up_requires_typing_the_tool_name() -> None:
    assert await approver("y").request_approval(request(step_up=True)) is False
    assert await approver("send_email").request_approval(request(step_up=True)) is True


@pytest.mark.security
async def test_the_prompt_shows_the_exact_arguments_with_hidden_characters_revealed() -> None:
    console = Console(record=True, width=120)

    await approver("n", console).request_approval(request(to="alice\u202e@evil.example"))

    shown = console.export_text()
    assert "\\u202e" in shown
    assert "send actions need approval" in shown
