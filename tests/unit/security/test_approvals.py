from datetime import UTC, datetime, timedelta

import pytest

from bastion.security.approvals import ApprovalError, ApprovalRequest, ApprovalService
from bastion.tools.base import RiskTier, ToolArgs


class SendArgs(ToolArgs):
    to: str
    body: str


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def service(clock: Clock) -> ApprovalService:
    return ApprovalService(clock=clock, ttl=timedelta(minutes=5))


def _request(service: ApprovalService, to: str = "alice@example.com") -> ApprovalRequest:
    return service.create(
        tool="gmail_send",
        tier=RiskTier.SEND,
        args=SendArgs(to=to, body="hi"),
        summary=f"Send an email to {to}",
        reason="send actions need approval",
        step_up=False,
    )


def test_approved_request_can_be_consumed_exactly_once(service: ApprovalService) -> None:
    request = _request(service)
    service.record_decision(request.id, approved=True)

    service.consume(request.id, "gmail_send", SendArgs(to="alice@example.com", body="hi"))

    with pytest.raises(ApprovalError, match="already used"):
        service.consume(request.id, "gmail_send", SendArgs(to="alice@example.com", body="hi"))


def test_cannot_consume_without_approval(service: ApprovalService) -> None:
    request = _request(service)

    with pytest.raises(ApprovalError, match="not approved"):
        service.consume(request.id, "gmail_send", SendArgs(to="alice@example.com", body="hi"))


def test_denied_request_cannot_be_consumed(service: ApprovalService) -> None:
    request = _request(service)
    service.record_decision(request.id, approved=False)

    with pytest.raises(ApprovalError, match="not approved"):
        service.consume(request.id, "gmail_send", SendArgs(to="alice@example.com", body="hi"))


def test_changed_arguments_are_rejected(service: ApprovalService) -> None:
    """The owner approved a mail to Alice; executing a mail to Mallory must fail."""
    request = _request(service)
    service.record_decision(request.id, approved=True)

    with pytest.raises(ApprovalError, match="do not match"):
        service.consume(request.id, "gmail_send", SendArgs(to="mallory@evil.example", body="hi"))


def test_a_different_tool_is_rejected(service: ApprovalService) -> None:
    request = _request(service)
    service.record_decision(request.id, approved=True)

    with pytest.raises(ApprovalError, match="do not match"):
        service.consume(request.id, "gmail_forward", SendArgs(to="alice@example.com", body="hi"))


def test_expired_approval_cannot_be_consumed(service: ApprovalService, clock: Clock) -> None:
    request = _request(service)
    service.record_decision(request.id, approved=True)
    clock.advance(timedelta(minutes=6))

    with pytest.raises(ApprovalError, match="expired"):
        service.consume(request.id, "gmail_send", SendArgs(to="alice@example.com", body="hi"))


def test_cannot_approve_after_expiry(service: ApprovalService, clock: Clock) -> None:
    request = _request(service)
    clock.advance(timedelta(minutes=6))

    with pytest.raises(ApprovalError, match="expired"):
        service.record_decision(request.id, approved=True)


def test_cannot_decide_twice(service: ApprovalService) -> None:
    request = _request(service)
    service.record_decision(request.id, approved=False)

    with pytest.raises(ApprovalError, match="already decided"):
        service.record_decision(request.id, approved=True)


def test_unknown_request_is_rejected(service: ApprovalService) -> None:
    with pytest.raises(ApprovalError, match="unknown"):
        service.record_decision("does-not-exist", approved=True)


def test_request_ids_are_long_and_unique(service: ApprovalService) -> None:
    first, second = _request(service), _request(service)

    assert first.id != second.id
    assert len(first.id) >= 16


def test_digest_depends_only_on_tool_and_arguments(service: ApprovalService) -> None:
    assert _request(service).digest == _request(service).digest
    assert _request(service).digest != _request(service, to="bob@example.com").digest


def test_request_shows_exact_arguments_for_review(service: ApprovalService) -> None:
    request = _request(service)

    assert '"to": "alice@example.com"' in request.arguments_json
