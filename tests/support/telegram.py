"""A scripted stand-in for the Telegram Bot API, plus builders for incoming updates."""

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from bastion.telegram.api import (
    MAX_MESSAGE_CHARS,
    CallbackQuery,
    Chat,
    IncomingMessage,
    TelegramError,
    Update,
    User,
    utf16_len,
)

OWNER_ID = 4242
STRANGER_ID = 6666
BOT = User(1, True, "Bastion", "bastion_test_bot")

type Batch = Sequence[Update] | TelegramError


def person(user_id: int = OWNER_ID, *, is_bot: bool = False, name: str = "Ada") -> User:
    return User(user_id, is_bot, name, name.lower())


def message(
    update_id: int,
    text: str | None,
    *,
    user_id: int = OWNER_ID,
    chat_id: int | None = None,
    chat_type: str = "private",
    forwarded: bool = False,
    is_bot: bool = False,
) -> Update:
    chat = Chat(chat_id if chat_id is not None else user_id, chat_type)
    sender = person(user_id, is_bot=is_bot)
    return Update(
        update_id, message=IncomingMessage(update_id * 10, chat, sender, 0, text, forwarded)
    )


def tap(
    update_id: int,
    data: str,
    message_id: int,
    *,
    user_id: int = OWNER_ID,
    chat_id: int | None = None,
) -> Update:
    chat = chat_id if chat_id is not None else user_id
    return Update(
        update_id,
        callback=CallbackQuery(f"cb{update_id}", person(user_id), data, chat, message_id),
    )


def query(data: str, message_id: int, *, user_id: int = OWNER_ID) -> CallbackQuery:
    callback = tap(0, data, message_id, user_id=user_id).callback
    assert callback is not None
    return callback


@dataclass(frozen=True)
class Sent:
    chat_id: int
    text: str
    buttons: tuple[tuple[str, str], ...]
    message_id: int

    def button(self, label: str) -> str:
        return dict(self.buttons)[label]


class FakeTelegramApi:
    """Plays back batches of updates, then idles (blocking, like a quiet long poll)."""

    def __init__(self, *batches: Batch, block_when_idle: bool = True) -> None:
        self._batches = list(batches)
        self.block_when_idle = block_when_idle
        self.me = BOT
        self.sent: list[Sent] = []
        self.edits: list[tuple[int, int, str]] = []
        self.answers: list[tuple[str, str | None]] = []
        self.polls: list[tuple[int | None, int]] = []
        self.commands: list[tuple[str, str]] = []
        self.typing = 0
        self.closed = False
        self.fail_sends = False
        self.idle = asyncio.Event()
        self._next_id = 100

    def feed(self, *batches: Batch) -> None:
        self._batches.extend(batches)

    @property
    def texts(self) -> list[str]:
        return [sent.text for sent in self.sent]

    def last_keyboard(self) -> Sent:
        return next(sent for sent in reversed(self.sent) if sent.buttons)

    async def get_me(self) -> User:
        return self.me

    async def get_updates(self, offset: int | None, wait_seconds: int) -> list[Update]:
        self.polls.append((offset, wait_seconds))
        if self._batches:
            batch = self._batches.pop(0)
            if isinstance(batch, TelegramError):
                raise batch
            return list(batch)
        self.idle.set()
        if self.block_when_idle:
            await asyncio.Event().wait()
        return []

    async def send_message(
        self, chat_id: int, text: str, *, buttons: Sequence[tuple[str, str]] = ()
    ) -> int:
        if self.fail_sends:
            raise TelegramError("Telegram API 500: send failed", status=500)
        assert text.strip(), "Telegram rejects empty messages"
        assert utf16_len(text) <= MAX_MESSAGE_CHARS, "message over Telegram's limit"
        self._next_id += 1
        self.sent.append(Sent(chat_id, text, tuple(buttons), self._next_id))
        return self._next_id

    async def edit_message(self, chat_id: int, message_id: int, text: str) -> None:
        self.edits.append((chat_id, message_id, text))

    async def answer_callback(self, callback_id: str, text: str | None = None) -> None:
        self.answers.append((callback_id, text))

    async def send_typing(self, chat_id: int) -> None:
        self.typing += 1

    async def set_commands(self, commands: Sequence[tuple[str, str]]) -> None:
        self.commands = list(commands)

    async def aclose(self) -> None:
        self.closed = True


async def settle(condition: Callable[[], bool], *, rounds: int = 200) -> None:
    """Let background tasks run until ``condition`` holds (fails the test if it never does)."""
    for _ in range(rounds):
        if condition():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition never became true")
