"""The always-on Telegram bot behind ``bastion daemon``.

- **Outbound only.** Bastion long-polls api.telegram.org; it never opens a port.
- **Owner only.** Every update is checked against the paired owner (user *and* private chat)
  before anything else happens. Everything else is dropped without a reply, and audited with a
  rate limit so strangers cannot flood the log. If the owner or authenticator is changed on the
  computer (``bastion telegram unpair|pair|totp``), the running bot stops at the next update.
- **One request at a time.** A request runs as a background task, so the poll loop keeps
  receiving approval taps, authenticator codes and ``/stop`` while the agent works.
- **Forwarded messages are untrusted.** Their words are someone else's: they are fenced like web
  content, taint the conversation, and their links are not made fetchable.
- **Kill switch.** ``/stop`` (or too many wrong authenticator codes) cancels the running request
  and refuses all work until the owner runs ``bastion resume`` on the computer.
- **Scheduled tasks share the one request slot.** A due task starts only when the bot is idle
  and not stopped, so ``/cancel`` and ``/stop`` cover it and its approvals use the same buttons
  and codes. The owner is told about every run, every skipped run, and any task that was
  changed outside Bastion.
- **Off-machine audit anchor.** The chain head is sent to the owner at startup and daily, so a
  rewritten log can be caught later with ``bastion audit verify --checkpoint``.
- **Always on.** Network failures are retried with backoff; a failure handling one update, or
  writing one audit entry, is contained instead of stopping the bot.
"""

import asyncio
import math
import sqlite3
import time
from collections.abc import Awaitable, Callable, Mapping
from functools import partial
from typing import Any

from bastion.autonomy.runner import TaskRunner
from bastion.autonomy.schedule import local_text
from bastion.autonomy.tasks import Task, render_listing
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
    SEND_ATTEMPTS,
    CallbackQuery,
    IncomingMessage,
    TelegramApi,
    TelegramError,
    Update,
    User,
    retry_transient,
    skip_backlog,
)
from bastion.telegram.approver import TelegramApprover
from bastion.telegram.pairing import Owner
from bastion.telegram.text import chunk_text
from bastion.text import strip_invisible

COMMANDS = (
    ("new", "Start a new conversation"),
    ("status", "Conversation and safety state"),
    ("tasks", "List scheduled tasks"),
    ("cancel", "Cancel the current request"),
    ("stop", "Emergency stop (resume from your computer)"),
    ("help", "Show the commands"),
)
HELP = """Commands:
/new - start a new conversation (clears untrusted-content taint)
/status - conversation and safety state
/tasks - list scheduled tasks (pause or remove them on your computer: bastion tasks)
/cancel - cancel the current request
/stop - emergency stop: Bastion refuses all work until you run "bastion resume" on your computer
/help - this message"""
STOPPED = 'Bastion is stopped. To resume it, run "bastion resume" on your computer.'
BUSY = "Still working on your previous request. Send /cancel to abandon it."
NO_CODE_EXPECTED = "No approval is waiting for a code."
TAINT_NOTICE = (
    "\n\n(Untrusted content is now in this conversation, so sending and deleting need your "
    "approval. Send /new to start fresh.)"
)
FORWARDED_SOURCE = "telegram:forwarded"
FORWARD_PREAMBLE = "I forwarded you this message from someone else:\n"
DIGEST_INTERVAL_SECONDS = 24 * 60 * 60
TYPING_INTERVAL_SECONDS = 4.5
MAX_BACKOFF_SECONDS = 60.0
SHUTDOWN_GRACE_SECONDS = 5.0
REJECTION_WINDOW_SECONDS = 3600.0
SCHEDULE_CHECK_SECONDS = 30.0
TASKS_OFF = "Scheduled tasks are off (enabled = false under [autonomy] in config.toml)."
TASKS_FOOTER = "Pause or remove a task on your computer: bastion tasks pause|remove <id>"
MAX_REJECTIONS_AUDITED = 20  # distinct senders per window


class ConfigurationChanged(Exception):
    """The paired owner or the authenticator changed on the computer: the bot must restart."""


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
        still_valid: Callable[[], bool] = lambda: True,
        warn: Callable[[str], None] = lambda message: None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        tasks: TaskRunner | None = None,
    ) -> None:
        self._api = api
        self._owner = owner
        self._agent = agent
        self._approver = approver
        self._audit = audit
        self._switch = switch
        self._redactor = redactor
        self._settings = settings
        self._model_label = model_label
        self._still_valid = still_valid
        self._warn = warn
        self._monotonic = monotonic
        self._sleep = sleep
        self._bucket = TokenBucket(settings.message_burst, settings.messages_per_hour, monotonic)
        self._conversation = Conversation.new()
        self._last_activity = monotonic()
        self._turn: asyncio.Task[None] | None = None
        self._tasks = tasks
        self._task_name: str | None = None  # the scheduled task in the request slot, if any
        self._rejections: dict[int, float] = {}
        self._conflict_audited_at: float | None = None
        # Set if /stop could not be saved to disk: the bot then stays stopped until restarted.
        self._halted = False

    # ---------------------------------------------------------------- lifecycle

    async def run(self) -> None:
        """Poll until cancelled (Ctrl+C), until Telegram rejects the token, or until the owner
        or authenticator changes on the computer (``ConfigurationChanged``)."""
        offset = await retry_transient(
            partial(skip_backlog, self._api), sleep=self._sleep, on_retry=self._unreachable
        )
        await self._quietly(self._api.set_commands(COMMANDS))
        self._audit.append("session.start", {"channel": "telegram"}, checkpoint=True)
        await self._quietly(self._say(self._online_message()))
        loops = [asyncio.create_task(self._digest_loop())]
        if self._tasks is not None:
            loops.append(asyncio.create_task(self._schedule_loop()))
        try:
            await self._poll(offset)
        finally:
            for loop in loops:
                loop.cancel()
            await self._shut_down()
            self._note("session.end", {"channel": "telegram"}, checkpoint=True)

    async def wait_for_turn(self) -> None:
        """Wait for the running request, if any, to finish (or be cancelled)."""
        if self._turn is not None:
            await asyncio.wait([self._turn])

    async def _shut_down(self) -> None:
        """Abandon the running request and its approval, and say so, within a short grace."""
        withdrawn = self._approver.withdraw()
        self._cancel_turn()
        if self._turn is not None:
            await asyncio.wait([self._turn], timeout=SHUTDOWN_GRACE_SECONDS)
        if withdrawn:
            notice = asyncio.ensure_future(
                self._approver.report_withdrawn(withdrawn, "Cancelled: Bastion shut down.")
            )
            await asyncio.wait([notice], timeout=SHUTDOWN_GRACE_SECONDS)

    def _unreachable(self, exc: TelegramError, wait: float) -> None:
        self._warn(f"Cannot reach Telegram ({exc}); retrying in {wait:.0f}s.")

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
                if not self._still_valid():
                    raise ConfigurationChanged(
                        "the paired Telegram account or the authenticator changed"
                    )
                await self._dispatch(update)

    def _poll_delay(self, exc: TelegramError, backoff: float) -> float:
        if exc.conflict:
            now = self._monotonic()
            if (
                self._conflict_audited_at is None
                or now - self._conflict_audited_at > REJECTION_WINDOW_SECONDS
            ):
                self._conflict_audited_at = now
                self._note("telegram.conflict", {"error": str(exc)})
                self._warn(
                    "Another program is reading this bot's messages. If it is not another "
                    "copy of Bastion, your bot token may be stolen: revoke it in @BotFather."
                )
        return max(exc.retry_after or 0.0, backoff)

    async def _dispatch(self, update: Update) -> None:
        try:
            await self.handle_update(update)
        except TelegramError as exc:
            self._note("telegram.send_failed", {"error": str(exc)})
        except Exception as exc:  # an always-on bot must survive a bad update
            self._note("telegram.update_crash", {"error_type": type(exc).__name__})

    def _note(self, event: str, data: Mapping[str, Any], *, checkpoint: bool = False) -> None:
        """Audit from an error path: a locked database must not turn one failure into two."""
        try:
            self._audit.append(event, data, checkpoint=checkpoint)
        except sqlite3.Error as exc:
            self._warn(f"Could not write the audit entry {event} ({type(exc).__name__}).")

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
        elif not message.forwarded and looks_like_code(text):
            await self._on_code(text)
        elif self._stopped():
            await self._say(STOPPED)
        elif self._busy():
            await self._say(self._busy_message())
        elif not self._bucket.take():
            self._audit.append("telegram.rate_limited", {})
            minutes = math.ceil(self._bucket.seconds_until_available() / 60)
            await self._say(f"Too many requests. Try again in about {minutes} minute(s).")
        else:
            self._start_turn(text, forwarded=message.forwarded)

    async def _on_code(self, text: str) -> None:
        # A code is never sent to the model, even when nothing is waiting for one.
        if not await self._approver.handle_code(text):
            await self._say(NO_CODE_EXPECTED)
        if self._approver.consume_lockout():
            await self._stop("too many wrong authenticator codes")

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
        self._note(
            "telegram.rejected",
            {
                "kind": kind,
                "user_id": sender.id if sender else None,
                "is_bot": sender.is_bot if sender else None,
                "chat_id": chat_id,
            },
        )

    async def _on_command(self, command: str) -> None:
        if command in ("new", "cancel", "stop", "status", "tasks"):
            self._audit.append("telegram.command", {"command": command})
        if command == "stop":
            await self._stop("/stop")
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
        elif command == "tasks":
            await self._say(self._task_listing())
        elif command == "pair":
            await self._say("This bot is already paired with you.")
        else:
            await self._say(HELP)

    async def _stop(self, reason: str) -> None:
        """Engage the kill switch. Work stops first, so a failure to save it fails closed."""
        await self._cancel_and_withdraw("Cancelled: Bastion was stopped.")
        try:
            self._switch.engage(via="telegram", at=utc_now())
        except OSError as exc:
            self._halted = True  # still stopped, in memory, until the daemon restarts
            self._note("killswitch.save_failed", {"error_type": type(exc).__name__})
        self._note("killswitch.engaged", {"via": "telegram", "reason": reason}, checkpoint=True)
        await self._say(f"Stopped ({reason}). {STOPPED}")

    # -------------------------------------------------------------------- turns

    def _stopped(self) -> bool:
        return self._halted or self._switch.engaged()

    def _busy(self) -> bool:
        return self._turn is not None and not self._turn.done()

    def _cancel_turn(self) -> None:
        if self._busy() and self._turn is not None:
            self._turn.cancel()

    async def _cancel_and_withdraw(self, outcome: str) -> None:
        withdrawn = self._approver.withdraw()
        self._cancel_turn()
        await self._approver.report_withdrawn(withdrawn, outcome)

    def _current_conversation(self) -> Conversation:
        now = self._monotonic()
        if now - self._last_activity > self._settings.idle_reset_minutes * 60:
            self._conversation = Conversation.new()  # a fresh start also clears old taint
        self._last_activity = now
        return self._conversation

    def _start_turn(self, text: str, *, forwarded: bool) -> None:
        conversation = self._current_conversation()
        was_tainted = conversation.taint.tainted
        self._task_name = None
        prompt = text
        if forwarded:
            conversation = conversation.tainted_by(FORWARDED_SOURCE)
            prompt = FORWARD_PREAMBLE + fence_untrusted(strip_invisible(text), FORWARDED_SOURCE)
        self._turn = asyncio.create_task(
            self._run_turn(conversation, prompt, was_tainted=was_tainted, from_owner=not forwarded)
        )

    async def _run_turn(
        self, conversation: Conversation, prompt: str, *, was_tainted: bool, from_owner: bool
    ) -> None:
        await self._quietly(self._api.send_typing(self._owner.chat_id))
        typing = asyncio.create_task(self._keep_typing())
        try:
            result = await self._agent.run_turn(conversation, prompt, from_owner=from_owner)
        except asyncio.CancelledError:
            self._note("turn.cancelled", {"conversation": conversation.id}, checkpoint=True)
            raise
        except Exception as exc:  # keep the bot alive; the details go to the audit log
            self._note(
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

    # ---------------------------------------------------------- scheduled tasks

    async def _schedule_loop(self) -> None:
        while True:
            await asyncio.sleep(SCHEDULE_CHECK_SECONDS)
            await self.check_schedule()

    async def check_schedule(self) -> None:
        """Start the most overdue task if the bot is free and not stopped. Never raises."""
        if self._tasks is None or self._stopped() or self._busy():
            return
        try:
            due = self._tasks.take_due()
        except Exception as exc:  # the schedule loop must outlive any one bad check
            self._note("task.schedule_failed", {"error_type": type(exc).__name__})
            return
        # Start the claimed run before any await: an owner message arriving while the notices
        # below are sent must find the slot taken, not leave a claimed run that never starts.
        if due.task is not None:
            self._task_name = due.task.name
            self._turn = asyncio.create_task(self._run_task(due.task))
        tz = self._tasks.store.tz
        for task in due.missed:
            when = local_text(task.next_run, tz) if task.next_run else "earlier"
            await self._quietly(
                self._say(
                    f"Skipped the scheduled task '{task.name}' ({task.id}): it was due "
                    f"{when}, while Bastion was offline."
                )
            )
        for task_id in due.unreadable:
            await self._quietly(
                self._say(
                    f"The scheduled task {task_id} was changed outside Bastion, so it will not "
                    f"run. Remove it on your computer with: bastion tasks remove {task_id}"
                )
            )

    async def _run_task(self, task: Task) -> None:
        if self._tasks is None:  # pragma: no cover - only started when tasks are on
            return
        try:
            report = await self._tasks.run(task, self._approver, trigger="schedule")
        except asyncio.CancelledError:
            raise  # the runner has recorded the cancellation
        except Exception as exc:  # the runner contains agent failures; this is storage
            self._note(
                "task.crash",
                {"task": task.id, "error_type": type(exc).__name__},
                checkpoint=True,
            )
            await self._quietly(
                self._say(f"The scheduled task '{task.name}' ({task.id}) failed to run.")
            )
            return
        finally:
            self._task_name = None
        await self._quietly(self._say(report.message))

    def _busy_message(self) -> str:
        if self._task_name is None:
            return BUSY
        return (
            f"Running the scheduled task '{self._task_name}'. Send /cancel to abandon it, or "
            "wait for its report."
        )

    def _task_listing(self) -> str:
        if self._tasks is None:
            return TASKS_OFF
        store = self._tasks.store
        return f"{render_listing(store.listing(), store.tz)}\n\n{TASKS_FOOTER}"

    def _tasks_status(self) -> str:
        if self._tasks is None:
            return "Scheduled tasks: off."
        listing = self._tasks.store.listing()
        active = sum(task.enabled for task in listing.tasks)
        return f"Scheduled tasks: {active} active, {len(listing.tasks) - active} paused."

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
            send = partial(self._api.send_message, self._owner.chat_id, chunk)
            await retry_transient(send, attempts=SEND_ATTEMPTS, sleep=self._sleep)

    async def _quietly(self, action: Awaitable[None]) -> None:
        """Run a Telegram call whose failure must not stop the bot; failures are audited."""
        try:
            await action
        except TelegramError as exc:
            self._note("telegram.send_failed", {"error": str(exc)})

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
        if self._stopped():
            lines.append(STOPPED)
        if not self._approver.step_up_available:
            lines.append(
                "Note: no authenticator app is set up, so actions that need one are refused. "
                "Set one up with: bastion telegram totp"
            )
        lines.append(self._checkpoint())
        return "\n\n".join(line for line in lines if line)

    async def send_checkpoint(self) -> None:
        """Send the audit chain head to the owner. Never raises: the daily loop must go on."""
        try:
            checkpoint = self._checkpoint()
            if checkpoint:
                await self._say(checkpoint)
        except (TelegramError, sqlite3.Error) as exc:
            self._note("telegram.checkpoint_failed", {"error_type": type(exc).__name__})

    async def _digest_loop(self) -> None:
        while True:
            await asyncio.sleep(DIGEST_INTERVAL_SECONDS)
            await self.send_checkpoint()

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
                self._busy_message() if self._busy() else "Idle.",
                self._tasks_status(),
                STOPPED if self._stopped() else "Kill switch: off (/stop engages it).",
                f"Authenticator for step-up approvals: {authenticator}.",
            ]
        )
