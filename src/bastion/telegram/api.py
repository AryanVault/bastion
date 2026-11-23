"""A thin Telegram Bot API client: long polling only (no webhook, no inbound port).

Bastion talks to exactly one host, api.telegram.org, through this small client rather than a
bot framework, which keeps a second HTTP stack and its dependencies out of the trusted base.

The bot token is part of every request URL, so URLs must never be shown or stored:

- httpx2 logs each request URL at INFO level; its loggers are raised to WARNING;
- transport errors are re-raised with only their type name, and without the original
  exception attached (which would carry the request and its URL into tracebacks).

Updates are parsed into small frozen dataclasses with exact type checks. Malformed parts are
dropped, but the update itself is still returned so the poll loop can acknowledge it: a bad
update must never wedge the bot.
"""

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx2

from bastion.security.egress import USER_AGENT

API_BASE = "https://api.telegram.org"
POLL_TIMEOUT = 50  # seconds a getUpdates call may wait for new updates
MAX_MESSAGE_CHARS = 4096  # counted in UTF-16 code units
MAX_CALLBACK_BYTES = 64
MAX_CALLBACK_ANSWER_CHARS = 200
ALLOWED_UPDATES = ("message", "callback_query")

_TOKEN = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,80}$")
_REQUEST_LOGGERS = ("httpx2", "httpcore2")
_MAX_DETAIL = 200
_UNAUTHORIZED = frozenset({401, 404})  # a revoked token gets 401; a malformed one 404


def valid_token(token: str) -> bool:
    return bool(_TOKEN.match(token))


def utf16_len(text: str) -> int:
    """Length as Telegram counts it: characters outside the BMP take two units."""
    return len(text) + sum(1 for char in text if ord(char) > 0xFFFF)


class TelegramError(Exception):
    """A Bot API call failed. Messages never contain the request URL (or the token in it)."""

    def __init__(
        self, message: str, *, status: int | None = None, retry_after: float | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after

    @property
    def unauthorized(self) -> bool:
        return self.status in _UNAUTHORIZED

    @property
    def conflict(self) -> bool:
        """Another client is polling this bot (or a webhook is set)."""
        return self.status == 409


# ------------------------------------------------------------------- updates


@dataclass(frozen=True)
class User:
    id: int
    is_bot: bool
    first_name: str
    username: str | None = None

    def label(self) -> str:
        handle = f" (@{self.username})" if self.username else ""
        return f"{self.first_name}{handle}, Telegram user id {self.id}"


@dataclass(frozen=True)
class Chat:
    id: int
    type: str


@dataclass(frozen=True)
class IncomingMessage:
    message_id: int
    chat: Chat
    sender: User | None
    date: int
    text: str | None
    # Forwarded from elsewhere, or produced by another bot: the words are someone else's.
    forwarded: bool


@dataclass(frozen=True)
class CallbackQuery:
    id: str
    sender: User
    data: str | None
    chat_id: int | None
    message_id: int | None


@dataclass(frozen=True)
class Update:
    update_id: int
    message: IncomingMessage | None = None
    callback: CallbackQuery | None = None


def _int(raw: Mapping[str, Any], key: str) -> int | None:
    value = raw.get(key)
    return value if type(value) is int else None


def _str(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) else None


def _obj(raw: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    value = raw.get(key)
    return value if isinstance(value, dict) else None


def parse_user(raw: Any) -> User | None:
    if not isinstance(raw, dict):
        return None
    user_id, first_name = _int(raw, "id"), _str(raw, "first_name")
    if user_id is None or first_name is None:
        return None
    return User(user_id, raw.get("is_bot") is True, first_name, _str(raw, "username"))


def _parse_chat(raw: Mapping[str, Any] | None) -> Chat | None:
    if raw is None:
        return None
    chat_id, chat_type = _int(raw, "id"), _str(raw, "type")
    return Chat(chat_id, chat_type) if chat_id is not None and chat_type is not None else None


def _parse_message(raw: Mapping[str, Any] | None) -> IncomingMessage | None:
    if raw is None:
        return None
    message_id, date, chat = (
        _int(raw, "message_id"),
        _int(raw, "date"),
        _parse_chat(_obj(raw, "chat")),
    )
    if message_id is None or date is None or chat is None:
        return None
    forwarded = (
        "forward_origin" in raw or "via_bot" in raw or raw.get("is_automatic_forward") is True
    )
    return IncomingMessage(
        message_id, chat, parse_user(raw.get("from")), date, _str(raw, "text"), forwarded
    )


def _parse_callback(raw: Mapping[str, Any] | None) -> CallbackQuery | None:
    if raw is None:
        return None
    query_id, sender = _str(raw, "id"), parse_user(raw.get("from"))
    if query_id is None or sender is None:
        return None
    message = _obj(raw, "message") or {}
    chat = _parse_chat(_obj(message, "chat"))
    return CallbackQuery(
        query_id,
        sender,
        _str(raw, "data"),
        chat.id if chat else None,
        _int(message, "message_id"),
    )


def parse_update(raw: Any) -> Update | None:
    """An update, or None if it lacks even an id (which cannot be acknowledged anyway)."""
    if not isinstance(raw, dict):
        return None
    update_id = _int(raw, "update_id")
    if update_id is None:
        return None
    return Update(
        update_id,
        _parse_message(_obj(raw, "message")),
        _parse_callback(_obj(raw, "callback_query")),
    )


# -------------------------------------------------------------------- client


class TelegramApi(Protocol):
    async def get_me(self) -> User: ...

    async def get_updates(self, offset: int | None, wait_seconds: int) -> list[Update]: ...

    async def send_message(
        self, chat_id: int, text: str, *, buttons: Sequence[tuple[str, str]] = ()
    ) -> int: ...

    async def edit_message(self, chat_id: int, message_id: int, text: str) -> None: ...

    async def answer_callback(self, callback_id: str, text: str | None = None) -> None: ...

    async def send_typing(self, chat_id: int) -> None: ...

    async def set_commands(self, commands: Sequence[tuple[str, str]]) -> None: ...

    async def aclose(self) -> None: ...


def _quiet_request_logs() -> None:
    for name in _REQUEST_LOGGERS:
        logger = logging.getLogger(name)
        if logger.level < logging.WARNING:
            logger.setLevel(logging.WARNING)


def _check_text(text: str) -> None:
    if not text.strip():
        raise ValueError("Telegram messages cannot be empty")
    if utf16_len(text) > MAX_MESSAGE_CHARS:
        raise ValueError("message too long: split it with chunk_text first")


def _keyboard(buttons: Sequence[tuple[str, str]]) -> dict[str, Any]:
    for _, data in buttons:
        if not 1 <= len(data.encode("utf-8")) <= MAX_CALLBACK_BYTES:
            raise ValueError("callback data must be 1-64 bytes")
    return {
        "inline_keyboard": [[{"text": label, "callback_data": data} for label, data in buttons]]
    }


_NO_PREVIEW = {"is_disabled": True}


class BotApi:
    def __init__(
        self,
        token: str,
        *,
        client: httpx2.AsyncClient | None = None,
        base_url: str = API_BASE,
    ) -> None:
        if not valid_token(token):
            raise ValueError("that does not look like a Telegram bot token")
        _quiet_request_logs()
        self._url = f"{base_url}/bot{token}/"
        self._client = client or httpx2.AsyncClient(
            trust_env=False,  # a proxy would see the token
            follow_redirects=False,
            timeout=httpx2.Timeout(10.0, read=POLL_TIMEOUT + 15.0),
            headers={"User-Agent": USER_AGENT},
        )

    def __repr__(self) -> str:
        return "BotApi(token=<redacted>)"

    async def _call(self, method: str, payload: Mapping[str, Any]) -> Any:
        try:
            response = await self._client.post(self._url + method, json=dict(payload))
        except httpx2.HTTPError as exc:
            # `from None`: the original exception holds the request, whose URL holds the token.
            raise TelegramError(f"could not reach Telegram ({type(exc).__name__})") from None
        try:
            body = response.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            raise TelegramError(
                f"unexpected response from Telegram (HTTP {response.status_code})",
                status=response.status_code,
            )
        if body.get("ok") is True:
            return body.get("result")
        status = _int(body, "error_code") or response.status_code
        description = (_str(body, "description") or "request failed")[:_MAX_DETAIL]
        parameters = _obj(body, "parameters") or {}
        retry_after = _int(parameters, "retry_after")
        raise TelegramError(
            f"Telegram API {status}: {description}",
            status=status,
            retry_after=float(retry_after) if retry_after is not None else None,
        )

    async def get_me(self) -> User:
        user = parse_user(await self._call("getMe", {}))
        if user is None:
            raise TelegramError("unexpected getMe response")
        return user

    async def get_updates(self, offset: int | None, wait_seconds: int) -> list[Update]:
        payload: dict[str, Any] = {
            "timeout": max(0, min(wait_seconds, POLL_TIMEOUT)),
            "allowed_updates": list(ALLOWED_UPDATES),
        }
        if offset is not None:
            payload["offset"] = offset
        result = await self._call("getUpdates", payload)
        if not isinstance(result, list):
            raise TelegramError("unexpected getUpdates response")
        return [update for update in map(parse_update, result) if update is not None]

    async def send_message(
        self, chat_id: int, text: str, *, buttons: Sequence[tuple[str, str]] = ()
    ) -> int:
        _check_text(text)
        # Plain text only (no parse_mode): untrusted text can never become markup or a hidden
        # link, and previews are off so no URL is fetched on Telegram's side (threat T18).
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "link_preview_options": _NO_PREVIEW,
        }
        if buttons:
            payload["reply_markup"] = _keyboard(buttons)
        result = await self._call("sendMessage", payload)
        message_id = _int(result, "message_id") if isinstance(result, dict) else None
        if message_id is None:
            raise TelegramError("unexpected sendMessage response")
        return message_id

    async def edit_message(self, chat_id: int, message_id: int, text: str) -> None:
        """Replace a message's text. Its inline buttons are removed."""
        _check_text(text)
        await self._call(
            "editMessageText",
            {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "link_preview_options": _NO_PREVIEW,
            },
        )

    async def answer_callback(self, callback_id: str, text: str | None = None) -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text[:MAX_CALLBACK_ANSWER_CHARS]
        await self._call("answerCallbackQuery", payload)

    async def send_typing(self, chat_id: int) -> None:
        await self._call("sendChatAction", {"chat_id": chat_id, "action": "typing"})

    async def set_commands(self, commands: Sequence[tuple[str, str]]) -> None:
        await self._call(
            "setMyCommands",
            {"commands": [{"command": name, "description": text} for name, text in commands]},
        )

    async def aclose(self) -> None:
        await self._client.aclose()


async def skip_backlog(api: TelegramApi) -> int | None:
    """Forget updates queued while nothing was polling; returns the next offset to poll from.

    Requests sent while Bastion was offline are never executed later, when the owner may no
    longer expect them.
    """
    updates = await api.get_updates(-1, 0)
    return updates[-1].update_id + 1 if updates else None
