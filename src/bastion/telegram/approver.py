"""Approvals over Telegram: inline buttons, plus an authenticator code for step-up (C4, C5).

- The buttons carry only an opaque random token, never the action or its arguments; what runs
  is still checked against the argument digest by the approval service.
- A tap counts only if it comes from the owner, on the message for a request that is still
  pending. Each request is decided once, and its buttons are then removed.
- Step-up actions also need a current authenticator code. Three wrong codes deny the request.
  With no authenticator enrolled, step-up actions are refused outright (fail closed).
- Unanswered requests expire with the approval (default 10 minutes) and count as "no".
"""

import asyncio
import contextlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from bastion.common import utc_now
from bastion.security.approvals import ApprovalRequest
from bastion.security.audit import AuditLog
from bastion.security.redact import Redactor
from bastion.security.totp import TotpVerifier
from bastion.telegram.api import CallbackQuery, TelegramApi, TelegramError
from bastion.telegram.pairing import Owner
from bastion.telegram.text import chunk_text, render_approval

CALLBACK_PREFIX = "ap"
APPROVE, DENY = "y", "n"
MAX_CODE_ATTEMPTS = 3
NO_AUTHENTICATOR = (
    "Refused: this action needs a code from an authenticator app, and none is set up. "
    "Set one up on your computer with: bastion telegram totp"
)


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
    ) -> None:
        self._api = api
        self._owner = owner
        self._audit = audit
        self._totp = totp
        self._redactor = redactor
        self._clock = clock
        self._pending: dict[str, _Pending] = {}

    @property
    def step_up_available(self) -> bool:
        return self._totp is not None

    async def request_approval(self, request: ApprovalRequest) -> bool:
        text = self._redactor.redact(render_approval(request))
        if request.step_up and self._totp is None:
            self._audit.append("approval.step_up_unavailable", {"id": request.id})
            await self._send(f"{text}\n\n{NO_AUTHENTICATOR}")
            return False
        token = secrets.token_urlsafe(12)
        *earlier, last = chunk_text(text)
        for chunk in earlier:
            await self._api.send_message(self._owner.chat_id, chunk)
        buttons = (
            ("Approve", f"{CALLBACK_PREFIX}:{token}:{APPROVE}"),
            ("Deny", f"{CALLBACK_PREFIX}:{token}:{DENY}"),
        )
        message_id = await self._api.send_message(self._owner.chat_id, last, buttons=buttons)
        pending = _Pending(request, asyncio.get_running_loop().create_future(), message_id, last)
        self._pending[token] = pending
        seconds_left = (request.expires_at - self._clock()).total_seconds()
        try:
            async with asyncio.timeout(max(0.0, seconds_left)):
                return await pending.decision
        except TimeoutError:
            await self._close(pending, "Expired without a decision: not approved.")
            return False
        finally:
            self._pending.pop(token, None)

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
            await self._api.answer_callback(query.id, "This request is no longer pending.")
            return
        if parsed[1] == DENY:
            pending.decision.set_result(False)
            await self._api.answer_callback(query.id, "Denied.")
            await self._close(pending, "Denied.")
        elif not pending.request.step_up:
            pending.decision.set_result(True)
            await self._api.answer_callback(query.id, "Approved.")
            await self._close(pending, "Approved.")
        else:
            pending.awaiting_code = True
            await self._api.answer_callback(query.id, "Now send your authenticator code.")
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
        self._audit.append(
            "approval.step_up",
            {"id": pending.request.id, "ok": False, "attempt": pending.code_attempts},
        )
        if pending.code_attempts >= MAX_CODE_ATTEMPTS:
            pending.decision.set_result(False)
            await self._close(pending, "Denied: too many wrong codes.")
        else:
            left = MAX_CODE_ATTEMPTS - pending.code_attempts
            await self._send(f"That code is not valid. {left} attempt(s) left.")
        return True

    async def withdraw_all(self, outcome: str) -> None:
        """Abandon every pending request (on /cancel, /stop or /new): each counts as "no"."""
        pendings = list(self._pending.values())
        self._pending.clear()
        for pending in pendings:  # decide everything first: notifying can fail
            if not pending.decision.done():
                pending.decision.cancel()
        for pending in pendings:
            with contextlib.suppress(TelegramError):
                await self._close(pending, outcome)

    async def _close(self, pending: _Pending, outcome: str) -> None:
        """Show the outcome on the approval message, which also removes its buttons."""
        try:
            await self._api.edit_message(
                self._owner.chat_id, pending.message_id, f"{pending.text}\n\n{outcome}"
            )
        except (TelegramError, ValueError):
            # Cosmetic only: the decision is already final. Fall back to a fresh message.
            await self._send(outcome)

    async def _send(self, text: str) -> None:
        for chunk in chunk_text(text):
            await self._api.send_message(self._owner.chat_id, chunk)
