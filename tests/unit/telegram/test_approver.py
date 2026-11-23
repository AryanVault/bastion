import asyncio
from collections.abc import Callable, Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyotp
import pytest

from bastion.security.approvals import ApprovalRequest, ApprovalService
from bastion.security.audit import AuditLog
from bastion.security.redact import REDACTED, Redactor
from bastion.security.totp import TotpVerifier
from bastion.storage.db import connect
from bastion.telegram.api import CallbackQuery, TelegramError
from bastion.telegram.approver import MAX_CODE_ATTEMPTS, NO_AUTHENTICATOR, TelegramApprover
from bastion.telegram.pairing import Owner
from bastion.tools.base import RiskTier
from support.fakes import EmailArgs
from support.telegram import OWNER_ID, STRANGER_ID, FakeTelegramApi, query, settle

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
NOW = datetime(2026, 11, 23, 12, 0, 15, tzinfo=UTC)
OWNER = Owner(OWNER_ID, OWNER_ID)


@pytest.fixture
def audit(tmp_path: Path) -> Iterator[AuditLog]:
    with closing(connect(tmp_path / "bastion.db")) as conn:
        yield AuditLog(conn, b"k" * 32, Redactor())


def make_request(
    *, step_up: bool = False, body: str = "hi", ttl: timedelta = timedelta(minutes=10)
) -> ApprovalRequest:
    return ApprovalService(ttl=ttl).create(
        tool="send_email",
        tier=RiskTier.DESTRUCTIVE if step_up else RiskTier.SEND,
        args=EmailArgs(to="bob@example.com", body=body),
        summary="Send an email to bob@example.com",
        reason="needs approval",
        step_up=step_up,
    )


def make_approver(
    api: FakeTelegramApi,
    audit: AuditLog,
    *,
    totp: bool = True,
    redactor: Redactor | None = None,
) -> TelegramApprover:
    verifier = TotpVerifier(SECRET, clock=lambda: NOW) if totp else None
    return TelegramApprover(api, OWNER, audit=audit, totp=verifier, redactor=redactor or Redactor())


async def start(
    approver: TelegramApprover, api: FakeTelegramApi, request: ApprovalRequest
) -> asyncio.Task[bool]:
    task = asyncio.create_task(approver.request_approval(request))
    await settle(lambda: any(sent.buttons for sent in api.sent) or task.done())
    return task


def events(audit: AuditLog) -> list[str]:
    return [entry.event for entry in audit.tail(100)]


# ------------------------------------------------------------------ buttons


async def test_approve_returns_true_and_closes_the_prompt(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())
    prompt = api.last_keyboard()

    await approver.handle_callback(query(prompt.button("Approve"), prompt.message_id))

    assert await task is True
    assert api.answers[-1][1] == "Approved."
    assert api.edits[-1][1] == prompt.message_id and api.edits[-1][2].endswith("Approved.")


async def test_deny_returns_false(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())
    prompt = api.last_keyboard()

    await approver.handle_callback(query(prompt.button("Deny"), prompt.message_id))

    assert await task is False


@pytest.mark.security
async def test_buttons_carry_an_opaque_token_not_the_action(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())

    data = api.last_keyboard().button("Approve")

    assert "bob" not in data and "send_email" not in data
    assert len(data.encode()) <= 64
    task.cancel()


@pytest.mark.security
@pytest.mark.parametrize(
    "forge",
    [
        lambda data, mid: query(data, mid, user_id=STRANGER_ID),  # someone else taps
        lambda data, mid: query(data, mid + 1),  # a different message
        lambda data, mid: query(data.replace(data.split(":")[1], "forged-token"), mid),
        lambda data, mid: query("ap:x", mid),  # malformed
    ],
)
async def test_only_the_owners_tap_on_the_live_prompt_counts(
    audit: AuditLog, forge: Callable[[str, int], CallbackQuery]
) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())
    prompt = api.last_keyboard()

    await approver.handle_callback(forge(prompt.button("Approve"), prompt.message_id))

    assert not task.done()
    assert api.answers[-1][1] == "This request is no longer pending."
    await approver.handle_callback(query(prompt.button("Deny"), prompt.message_id))
    assert await task is False


@pytest.mark.security
async def test_a_decision_cannot_be_changed_by_a_second_tap(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())
    prompt = api.last_keyboard()
    await approver.handle_callback(query(prompt.button("Deny"), prompt.message_id))

    await approver.handle_callback(query(prompt.button("Approve"), prompt.message_id))

    assert await task is False
    assert api.answers[-1][1] == "This request is no longer pending."


@pytest.mark.security
async def test_an_unanswered_request_expires_as_denied(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)

    approved = await approver.request_approval(make_request(ttl=timedelta(milliseconds=20)))

    assert approved is False
    assert "Expired" in api.edits[-1][2]


async def test_long_prompts_are_split_with_buttons_on_the_last_part(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request(body="word " * 2000))

    assert len(api.sent) >= 3
    assert [bool(sent.buttons) for sent in api.sent] == [False] * (len(api.sent) - 1) + [True]
    task.cancel()


@pytest.mark.security
async def test_known_secrets_are_redacted_from_the_prompt(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    redactor = Redactor()
    redactor.register_secret("opaque-secret-value-123")
    approver = make_approver(api, audit, redactor=redactor)
    task = await start(approver, api, make_request(body="key opaque-secret-value-123"))

    assert "opaque-secret-value-123" not in api.last_keyboard().text
    assert REDACTED in api.last_keyboard().text
    task.cancel()


async def test_withdrawing_cancels_the_request_and_updates_the_prompt(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())

    await approver.withdraw_all("Cancelled.")

    with pytest.raises(asyncio.CancelledError):
        await task
    assert api.edits[-1][2].endswith("Cancelled.")


async def test_a_failed_edit_falls_back_to_a_new_message(
    audit: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = FakeTelegramApi()

    async def broken_edit(chat_id: int, message_id: int, text: str) -> None:
        raise TelegramError("Telegram API 400: message can't be edited", status=400)

    monkeypatch.setattr(api, "edit_message", broken_edit)
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request())
    prompt = api.last_keyboard()

    await approver.handle_callback(query(prompt.button("Approve"), prompt.message_id))

    assert await task is True
    assert api.texts[-1] == "Approved."


# ------------------------------------------------------------------ step-up


@pytest.mark.security
async def test_step_up_is_refused_without_an_authenticator(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit, totp=False)

    approved = await approver.request_approval(make_request(step_up=True))

    assert approved is False
    assert NO_AUTHENTICATOR in api.texts[-1]
    assert not any(sent.buttons for sent in api.sent)
    assert "approval.step_up_unavailable" in events(audit)


@pytest.mark.security
async def test_step_up_needs_a_valid_code_after_the_tap(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request(step_up=True))
    prompt = api.last_keyboard()

    await approver.handle_callback(query(prompt.button("Approve"), prompt.message_id))

    assert not task.done()  # a tap alone is not enough
    assert approver.awaiting_code()
    assert await approver.handle_code(pyotp.TOTP(SECRET).at(NOW)) is True
    assert await task is True
    assert "authenticator code" in api.edits[-1][2]


@pytest.mark.security
async def test_wrong_codes_deny_the_request(audit: AuditLog) -> None:
    api = FakeTelegramApi()
    approver = make_approver(api, audit)
    task = await start(approver, api, make_request(step_up=True))
    prompt = api.last_keyboard()
    await approver.handle_callback(query(prompt.button("Approve"), prompt.message_id))

    for _ in range(MAX_CODE_ATTEMPTS):
        await approver.handle_code("000000")

    assert await task is False
    assert "too many wrong codes" in api.edits[-1][2]
    assert events(audit).count("approval.step_up") == MAX_CODE_ATTEMPTS


async def test_codes_are_ignored_when_nothing_awaits_one(audit: AuditLog) -> None:
    approver = make_approver(FakeTelegramApi(), audit)

    assert approver.awaiting_code() is False
    assert await approver.handle_code("123456") is False
