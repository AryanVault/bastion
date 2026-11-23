"""The always-on Telegram bot behind ``bastion daemon``.

- **Outbound only.** Bastion long-polls api.telegram.org; it never opens a port.
- **Owner only.** Every update is checked against the paired owner (user *and* private chat)
  before anything else happens. Everything else is dropped without a reply, and audited with a
  rate limit so strangers cannot flood the log.
- **One request at a time.** A request runs as a background task, so the poll loop keeps
  receiving approval taps, authenticator codes and ``/stop`` while the agent works.
- **Forwarded messages are untrusted.** Their words are someone else's: they are fenced like web
  content and taint the conversation, so they cannot steer sends or deletions on their own.
- **Kill switch.** ``/stop`` cancels the running request and refuses all work until the owner
  runs ``bastion resume`` on the computer.
- **Off-machine audit anchor.** The chain head is sent to the owner at startup and daily, so a
  rewritten log can be caught later with ``bastion audit verify --checkpoint``.
"""

import asyncio
import math
import time
from collections.abc import Awaitable, Callable

from bastion.common import utc_now
from bastion.config import TelegramSettings
from bastion.core.agent import Agent
from bastion.core.conversation import Conversation
from bastion.core.prompts import fence_untrusted
from bastion.security.audit import MIN_CHECKPOINT_CHARS, AuditLog
from bastion.security.killswitch import KillSwitch
from bastion.security.ratelimit import TokenBucket
from bastion.security.redact import Redactor
from bastion.security.totp import looks_like_code
from bastion.telegram.api import (
    POLL_TIMEOUT,
    CallbackQuery,
    IncomingMessage,
    TelegramApi,
    TelegramError,
    Update,
    User,
    skip_backlog,
)
from bastion.telegram.approver import TelegramApprover
from bastion.telegram.pairing import Owner
from bastion.telegram.text import chunk_text
from bastion.text import strip_invisible

COMMANDS = (
    ("new", "Start a new conversation"),
    ("status", "Conversation and safety state"),
    ("cancel", "Cancel the current request"),
    ("stop", "Emergency stop (resume from your computer)"),
    ("help", "Show the commands"),
)
HELP = """Commands:
/new - start a new conversation (clears untrusted-content taint)
/status - conversation and safety state
/cancel - cancel the current request
/stop - emergency stop: Bastion refuses all work until you run "bastion resume" on your computer
/help - this message"""
STOPPED = 'Bastion is stopped. To resume it, run "bastion resume" on your computer.'
BUSY = "Still working on your previous request. Send /cancel to abandon it."
TAINT_NOTICE = (
    "\n\n(Untrusted content is now in this conversation, so sending and deleting need your "
    "approval. Send /new to start fresh.)"
)
FORWARDED_SOURCE = "telegram:forwarded"
FORWARD_PREAMBLE = "I forwarded you this message from someone else:\n"
DIGEST_INTERVAL_SECONDS = 24 * 60 * 60
TYPING_INTERVAL_SECONDS = 4.5
MAX_BACKOFF_SECONDS = 60.0
REJECTION_WINDOW_SECONDS = 3600.0
MAX_REJECTIONS_AUDITED = 20  # distinct senders per window


def _command(text: str) -> str | None:
    """``/name`` or ``/name@BotName`` at the start of ``text``, lowercased, without the slash."""
    if not text.startswith("/"):
        return None
    return text.split(maxsplit=1)[0][1:].split("@", 1)[0].lower()


class TelegramBot:
    def __init__(
        self,
        *,
        api: TelegramApi,
        owner: Owner,
        agent: Agent,
        approver: TelegramApprover,
        audit: AuditLog,
        switch: KillSwitch,
        redactor: Redactor,
        settings: TelegramSettings,
        model_label: str,
        warn: Callable[[str], None] = lambda message: None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._sleep = sleep
        self._api = api
        self._owner = owner
        self._agent = agent
        self._approver = approver
        self._audit = audit
        self._switch = switch
        self._redactor = redactor
        self._settings = settings
        self._model_label = model_label
        self._warn = warn
        self._monotonic = monotonic
        self._bucket = TokenBucket(settings.message_burst, settings.messages_per_hour, monotonic)
        self._conversation = Conversation.new()
        self._last_activity = monotonic()
        self._turn: asyncio.Task[None] | None = None
        self._rejections: dict[int, float] = {}
        self._conflict_audited_at: float | None = None

    # ---------------------------------------------------------------- lifecycle

    async def run(self) -> None:
        """Poll until cancelled (Ctrl+C) or until Telegram rejects the token."""
        offset = await skip_backlog(self._api)
        await self._quietly(self._api.set_commands(COMMANDS))
        self._audit.append("session.start", {"channel": "telegram"}, checkpoint=True)
        await self._quietly(self._say(self._online_message()))
        digest = asyncio.create_task(self._digest_loop())
        try:
            await self._poll(offset)
        finally:
            digest.cancel()
            self._cancel_turn()
            self._audit.append("session.end", {"channel": "telegram"}, checkpoint=True)

    async def wait_for_turn(self) -> None:
        """Wait for the running request, if any, to finish (or be cancelled)."""
        if self._turn is not None:
            await asyncio.wait([self._turn])

    async def _poll(self, offset: int | None) -> None:
        backoff = 1.0
        while True:
            try:
                updates = await self._api.get_updates(offset, POLL_TIMEOUT)
            except TelegramError as exc:
                if exc.unauthorized:
                    raise
                await self._sleep(self._poll_delay(exc, backoff))
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            backoff = 1.0
            for update in updates:
                offset = update.update_id + 1
                await self._dispatch(update)

    def _poll_delay(self, exc: TelegramError, backoff: float) -> float:
        if exc.conflict:
            now = self._monotonic()
            if (
                self._conflict_audited_at is None
                or now - self._conflict_audited_at > REJECTION_WINDOW_SECONDS
            ):
                self._conflict_audited_at = now
                self._audit.append("telegram.conflict", {"error": str(exc)})
                self._warn(
                    "Another program is reading this bot's messages. If it is not another "
                    "copy of Bastion, your bot token may be stolen: revoke it in @BotFather."
                )
        return max(exc.retry_after or 0.0, backoff)

    async def _dispatch(self, update: Update) -> None:
        try:
            await self.handle_update(update)
        except TelegramError as exc:
            self._audit.append("telegram.send_failed", {"error": str(exc)})
        except Exception as exc:  # an always-on bot must survive a bad update
            self._audit.append(
                "telegram.update_crash", {"error_type": type(exc).__name__}, checkpoint=True
            )

    # ------------------------------------------------------------------ updates

    async def handle_update(self, update: Update) -> None:
        if update.callback is not None:
            await self._on_callback(update.callback)
        elif update.message is not None:
            await self._on_message(update.message)

    async def _on_callback(self, query: CallbackQuery) -> None:
        if query.sender.id != self._owner.user_id or query.chat_id != self._owner.chat_id:
            self._reject(query.sender, query.chat_id, "callback")
            return
        await self._approver.handle_callback(query)

    async def _on_message(self, message: IncomingMessage) -> None:
        if not self._owner.matches(message.sender, message.chat):
            self._reject(message.sender, message.chat.id, "message")
            return
        text = message.text
        if text is None or not text.strip():
            await self._say("I can only read text messages for now.")
            return
        # Someone else's words never act as the owner's commands or codes.
        command = None if message.forwarded else _command(text)
        if command is not None:
            await self._on_command(command)
        elif not message.forwarded and self._approver.awaiting_code() and looks_like_code(text):
            await self._approver.handle_code(text)
        elif self._switch.engaged():
            await self._say(STOPPED)
        elif self._busy():
            await self._say(BUSY)
        elif not self._bucket.take():
            self._audit.append("telegram.rate_limited", {})
            minutes = math.ceil(self._bucket.seconds_until_available() / 60)
            await self._say(f"Too many requests. Try again in about {minutes} minute(s).")
        else:
            self._start_turn(text, forwarded=message.forwarded)

    def _reject(self, sender: User | None, chat_id: int | None, kind: str) -> None:
        """Drop an update from anyone but the owner: no reply, and a rate-limited audit entry."""
        now = self._monotonic()
        self._rejections = {
            key: at for key, at in self._rejections.items() if now - at < REJECTION_WINDOW_SECONDS
        }
        key = sender.id if sender is not None else (chat_id or 0)
        if key in self._rejections or len(self._rejections) >= MAX_REJECTIONS_AUDITED:
            return
        self._rejections[key] = now
        self._audit.append(
            "telegram.rejected",
            {
                "kind": kind,
                "user_id": sender.id if sender else None,
                "is_bot": sender.is_bot if sender else None,
                "chat_id": chat_id,
            },
        )

    async def _on_command(self, command: str) -> None:
        if command in ("new", "cancel", "stop", "status"):
            self._audit.append("telegram.command", {"command": command})
        if command == "stop":
            self._switch.engage(via="telegram", at=utc_now())
            await self._cancel_and_withdraw("Cancelled: Bastion was stopped.")
            self._audit.append("killswitch.engaged", {"via": "telegram"}, checkpoint=True)
            await self._say(f"Stopped. {STOPPED}")
        elif command == "cancel":
            busy = self._busy()
            await self._cancel_and_withdraw("Cancelled.")
            await self._say("Cancelled." if busy else "Nothing is running.")
        elif command == "new":
            await self._cancel_and_withdraw("Cancelled: you started a new conversation.")
            self._conversation = Conversation.new()
            await self._say("Started a new conversation.")
        elif command == "status":
            await self._say(self._status())
        elif command == "pair":
            await self._say("This bot is already paired with you.")
        else:
            await self._say(HELP)

    # -------------------------------------------------------------------- turns

    def _busy(self) -> bool:
        return self._turn is not None and not self._turn.done()

    def _cancel_turn(self) -> None:
        if self._busy() and self._turn is not None:
            self._turn.cancel()

    async def _cancel_and_withdraw(self, outcome: str) -> None:
        self._cancel_turn()
        await self._approver.withdraw_all(outcome)

    def _current_conversation(self) -> Conversation:
        now = self._monotonic()
        if now - self._last_activity > self._settings.idle_reset_minutes * 60:
            self._conversation = Conversation.new()  # a fresh start also clears old taint
        self._last_activity = now
        return self._conversation

    def _start_turn(self, text: str, *, forwarded: bool) -> None:
        conversation = self._current_conversation()
        was_tainted = conversation.taint.tainted
        prompt = text
        if forwarded:
            conversation = conversation.tainted_by(FORWARDED_SOURCE)
            prompt = FORWARD_PREAMBLE + fence_untrusted(strip_invisible(text), FORWARDED_SOURCE)
        self._turn = asyncio.create_task(self._run_turn(conversation, prompt, was_tainted))

    async def _run_turn(self, conversation: Conversation, prompt: str, was_tainted: bool) -> None:
        await self._quietly(self._api.send_typing(self._owner.chat_id))
        typing = asyncio.create_task(self._keep_typing())
        try:
            result = await self._agent.run_turn(conversation, prompt)
        except asyncio.CancelledError:
            self._audit.append("turn.cancelled", {"conversation": conversation.id}, checkpoint=True)
            raise
        except Exception as exc:  # keep the bot alive; the details go to the audit log
            self._audit.append(
                "turn.crash",
                {"error_type": type(exc).__name__, "error": str(exc)[:200]},
                checkpoint=True,
            )
            await self._quietly(self._say("Something went wrong and this request was abandoned."))
            return
        finally:
            typing.cancel()
        self._conversation = result.conversation
        self._last_activity = self._monotonic()
        reply = result.reply
        if result.conversation.taint.tainted and not was_tainted:
            reply += TAINT_NOTICE
        await self._quietly(self._say(reply))

    async def _keep_typing(self) -> None:
        """Telegram shows "typing..." for about five seconds per call: renew it."""
        while True:
            await asyncio.sleep(TYPING_INTERVAL_SECONDS)
            await self._quietly(self._api.send_typing(self._owner.chat_id))

    # ------------------------------------------------------------------ output

    async def _say(self, text: str) -> None:
        # Last line of defence: invisible characters out, known secrets redacted.
        clean = self._redactor.redact(strip_invisible(text))
        for chunk in chunk_text(clean):
            await self._api.send_message(self._owner.chat_id, chunk)

    async def _quietly(self, action: Awaitable[None]) -> None:
        """Run a Telegram call whose failure must not stop the bot; failures are audited."""
        try:
            await action
        except TelegramError as exc:
            self._audit.append("telegram.send_failed", {"error": str(exc)})

    def _checkpoint(self) -> str:
        head = self._audit.head()
        if head is None:
            return ""
        mark = f"{head.seq}:{head.mac[:MIN_CHECKPOINT_CHARS]}"
        return (
            f"Audit checkpoint {mark}\n"
            f"To check the log later, run: bastion audit verify --checkpoint {mark}"
        )

    def _online_message(self) -> str:
        lines = [
            "Bastion is online. Messages sent while it was offline were ignored. "
            "Send /help for commands."
        ]
        if self._switch.engaged():
            lines.append(STOPPED)
        if not self._approver.step_up_available:
            lines.append(
                "Note: no authenticator app is set up, so actions that need one are refused. "
                "Set one up with: bastion telegram totp"
            )
        lines.append(self._checkpoint())
        return "\n\n".join(line for line in lines if line)

    async def _digest_loop(self) -> None:
        while True:
            await asyncio.sleep(DIGEST_INTERVAL_SECONDS)
            checkpoint = self._checkpoint()
            if checkpoint:
                await self._quietly(self._say(checkpoint))

    def _status(self) -> str:
        conversation = self._conversation
        taint = conversation.taint
        context = f"tainted by {taint.describe()}" if taint.tainted else "clean"
        authenticator = "set up" if self._approver.step_up_available else "NOT set up"
        return "\n".join(
            [
                f"Model: {self._model_label}",
                f"Conversation {conversation.id}: {len(conversation.messages)} messages, "
                f"context {context}.",
                "Working on a request." if self._busy() else "Idle.",
                STOPPED if self._switch.engaged() else "Kill switch: off (/stop engages it).",
                f"Authenticator for step-up approvals: {authenticator}.",
            ]
        )
