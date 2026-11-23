"""Approvals over Telegram: inline buttons, plus an authenticator code for step-up (C4, C5).

- The prompt shows exactly what will run. If anything in it looks like a secret, the request is
  refused instead: redacting it would let the owner approve arguments they never saw (the
  approval binds the real ones), and showing it would send the secret to Telegram.
- The buttons carry only an opaque random token, never the action or its arguments; what runs
  is still checked against the argument digest by the approval service.
- A tap counts only if it comes from the owner, on the message for a request that is still
  pending. Each request is decided once, and its buttons are then removed.
- Step-up actions also need a current authenticator code. Three wrong codes deny the request;
  five wrong codes within an hour, across requests, trigger a lockout (the bot then engages the
  kill switch). With no authenticator enrolled, step-up actions are refused (fail closed).
- Unanswered requests expire with the approval (default 10 minutes) and count as "no".
"""

import asyncio
import contextlib
import secrets
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import partial

from bastion.common import utc_now
from bastion.security.approvals import ApprovalRequest
from bastion.security.audit import AuditLog
from bastion.security.redact import Redactor
from bastion.security.totp import TotpVerifier
from bastion.telegram.api import (
    SEND_ATTEMPTS,
    CallbackQuery,
    TelegramApi,
    TelegramError,
    retry_transient,
)
from bastion.telegram.pairing import Owner
from bastion.telegram.text import chunk_text, render_approval

CALLBACK_PREFIX = "ap"
APPROVE, DENY = "y", "n"
MAX_CODE_ATTEMPTS = 3  # per request
MAX_FAILED_CODES = 5  # across requests, per window: then lock out
FAILED_CODE_WINDOW_SECONDS = 3600.0
NO_AUTHENTICATOR = (
    "Refused: this action needs a code from an authenticator app, and none is set up. "
    "Set one up on your computer with: bastion telegram totp"
)
REFUSED_SENSITIVE = (
    "Refused: its arguments contain something that looks like a secret (an API key, token, "
    "password or private key), so they are not shown here and the action was not run."
)
LOCKED_OUT = "Denied: too many wrong codes. Bastion is stopping as a precaution."


@dataclass
class _Pending:
    request: ApprovalRequest
    decision: asyncio.Future[bool]
    message_id: int
    text: str
    awaiting_code: bool = False
    code_attempts: int = 0


def _parse_callback(data: str | None) -> tuple[str, str] | None:
    parts = (data or "").split(":")
    if len(parts) != 3 or parts[0] != CALLBACK_PREFIX or parts[2] not in (APPROVE, DENY):
        return None
    return parts[1], parts[2]


class TelegramApprover:
    def __init__(
        self,
        api: TelegramApi,
        owner: Owner,
        *,
        audit: AuditLog,
        totp: TotpVerifier | None,
        redactor: Redactor,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._api = api
        self._owner = owner
        self._audit = audit
        self._totp = totp
        self._redactor = redactor
        self._clock = clock
        self._monotonic = monotonic
        self._sleep = sleep
        self._pending: dict[str, _Pending] = {}
        self._failed_codes: list[float] = []
        self._lockout = False

    @property
    def step_up_available(self) -> bool:
        return self._totp is not None

    def consume_lockout(self) -> bool:
        """True once after too many wrong codes: the caller should stop the agent."""
        locked, self._lockout = self._lockout, False
        return locked

    # ----------------------------------------------------------------- asking

    async def request_approval(self, request: ApprovalRequest) -> bool:
        text = render_approval(request)
        if self._redactor.redact(text) != text:
            self._audit.append("approval.refused_secret", {"id": request.id})
            await self._send(f"{request.tool}: {REFUSED_SENSITIVE}")
            return False
        if request.step_up and self._totp is None:
            self._audit.append("approval.step_up_unavailable", {"id": request.id})
            await self._send(f"{text}\n\n{NO_AUTHENTICATOR}")
            return False
        token = secrets.token_urlsafe(12)
        *earlier, last = chunk_text(text)
        for chunk in earlier:
            await self._send_message(chunk)
        buttons = (
            ("Approve", f"{CALLBACK_PREFIX}:{token}:{APPROVE}"),
            ("Deny", f"{CALLBACK_PREFIX}:{token}:{DENY}"),
        )
        message_id = await self._send_message(last, buttons)
        pending = _Pending(request, asyncio.get_running_loop().create_future(), message_id, last)
        self._pending[token] = pending
        seconds_left = (request.expires_at - self._clock()).total_seconds()
        try:
            async with asyncio.timeout(max(0.0, seconds_left)):
                return await pending.decision
        except TimeoutError:
            self._pending.pop(token, None)  # a tap during the clean-up below must not count
            await self._close(pending, "Expired without a decision: not approved.")
            return False
        finally:
            self._pending.pop(token, None)

    # ------------------------------------------------------------- answering

    async def handle_callback(self, query: CallbackQuery) -> None:
        parsed = _parse_callback(query.data)
        pending = self._pending.get(parsed[0]) if parsed else None
        if (
            parsed is None
            or pending is None
            or pending.decision.done()
            or query.sender.id != self._owner.user_id
            or query.message_id != pending.message_id
        ):
            await self._answer(query.id, "This request is no longer pending.")
            return
        if parsed[1] == DENY:
            pending.decision.set_result(False)
            await self._answer(query.id, "Denied.")
            await self._close(pending, "Denied.")
        elif not pending.request.step_up:
            pending.decision.set_result(True)
            await self._answer(query.id, "Approved.")
            await self._close(pending, "Approved.")
        else:
            pending.awaiting_code = True
            await self._answer(query.id, "Now send your authenticator code.")
            await self._send(
                "Send the 6-digit code from your authenticator app to approve, or tap Deny."
            )

    def awaiting_code(self) -> bool:
        return self._awaiting() is not None

    def _awaiting(self) -> _Pending | None:
        return next(
            (p for p in self._pending.values() if p.awaiting_code and not p.decision.done()),
            None,
        )

    async def handle_code(self, code: str) -> bool:
        """Treat ``code`` as the step-up code for the pending request. False if none waits."""
        pending = self._awaiting()
        if pending is None or self._totp is None:
            return False
        if self._totp.verify(code):
            self._audit.append("approval.step_up", {"id": pending.request.id, "ok": True})
            pending.decision.set_result(True)
            await self._close(pending, "Approved with your authenticator code.")
            return True
        pending.code_attempts += 1
        now = self._monotonic()
        self._failed_codes = [
            at for at in self._failed_codes if now - at < FAILED_CODE_WINDOW_SECONDS
        ] + [now]
        self._audit.append(
            "approval.step_up",
            {"id": pending.request.id, "ok": False, "attempt": pending.code_attempts},
        )
        if len(self._failed_codes) >= MAX_FAILED_CODES:
            self._failed_codes.clear()
            self._lockout = True
            self._audit.append("approval.step_up_lockout", {"id": pending.request.id})
            pending.decision.set_result(False)
            await self._close(pending, LOCKED_OUT)
        elif pending.code_attempts >= MAX_CODE_ATTEMPTS:
            pending.decision.set_result(False)
            await self._close(pending, "Denied: too many wrong codes.")
        else:
            left = MAX_CODE_ATTEMPTS - pending.code_attempts
            await self._send(f"That code is not valid. {left} attempt(s) left.")
        return True

    # ----------------------------------------------------------- withdrawing

    def withdraw(self) -> Sequence[_Pending]:
        """Abandon every pending request at once (each counts as "no"). Synchronous, so it
        takes effect before a cancelled request's own clean-up can run."""
        pendings = list(self._pending.values())
        self._pending.clear()
        for pending in pendings:
            if not pending.decision.done():
                pending.decision.cancel()
        return pendings

    async def report_withdrawn(self, pendings: Sequence[_Pending], outcome: str) -> None:
        for pending in pendings:
            await self._close(pending, outcome)

    async def withdraw_all(self, outcome: str) -> None:
        await self.report_withdrawn(self.withdraw(), outcome)

    # ----------------------------------------------------------------- output

    async def _close(self, pending: _Pending, outcome: str) -> None:
        """Show the outcome on the prompt (which removes its buttons). Best effort: the
        decision is already final, so a Telegram failure here must not change anything."""
        try:
            await self._api.edit_message(
                self._owner.chat_id, pending.message_id, f"{pending.text}\n\n{outcome}"
            )
        except (TelegramError, ValueError):
            with contextlib.suppress(TelegramError):
                await self._send(outcome)

    async def _answer(self, callback_id: str, text: str) -> None:
        with contextlib.suppress(TelegramError):  # only dismisses the tap's spinner
            await self._api.answer_callback(callback_id, text)

    async def _send_message(self, text: str, buttons: Sequence[tuple[str, str]] = ()) -> int:
        send = partial(self._api.send_message, self._owner.chat_id, text, buttons=buttons)
        return await retry_transient(send, attempts=SEND_ATTEMPTS, sleep=self._sleep)

    async def _send(self, text: str) -> None:
        for chunk in chunk_text(text):
            await self._send_message(chunk)
