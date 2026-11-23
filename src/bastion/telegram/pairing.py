"""Pairing: binding the bot to exactly one Telegram account (control C6).

``bastion telegram pair`` prints a one-time code in the owner's terminal. The owner sends
``/pair <code>`` to the bot from a private chat; the terminal then shows who sent it and asks
the owner to confirm. Becoming the owner therefore needs control of the terminal *and* the
Telegram account. Afterwards every update from any other user or chat is dropped.

The owner record is kept in the OS keyring, not the database: whoever is the owner can approve
actions, so changing it must take more than write access to a file.
"""

import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from bastion.security.vault import TELEGRAM_OWNER, Vault, VaultError
from bastion.telegram.api import (
    POLL_TIMEOUT,
    Chat,
    IncomingMessage,
    TelegramApi,
    User,
    skip_backlog,
)

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I to misread
CODE_LENGTH = 8  # 40 bits; with at most MAX_ATTEMPTS guesses, guessing is hopeless
PAIRING_TTL_SECONDS = 600
MAX_ATTEMPTS = 5


class PairingError(Exception):
    """Pairing was abandoned (for example, after too many wrong codes)."""


@dataclass(frozen=True)
class Owner:
    user_id: int
    chat_id: int

    def matches(self, sender: User | None, chat: Chat) -> bool:
        """True only for the owner, writing in their private chat with the bot."""
        return (
            sender is not None
            and sender.id == self.user_id
            and chat.id == self.chat_id
            and chat.type == "private"
        )


def load_owner(vault: Vault) -> Owner | None:
    raw = vault.get(TELEGRAM_OWNER)
    if raw is None:
        return None
    user_id, separator, chat_id = raw.partition(":")
    try:
        if not separator:
            raise ValueError(raw)
        return Owner(int(user_id), int(chat_id))
    except ValueError as exc:
        raise VaultError(
            "the stored Telegram owner is corrupt. Run: bastion telegram pair"
        ) from exc


def save_owner(vault: Vault, owner: Owner) -> None:
    vault.set(TELEGRAM_OWNER, f"{owner.user_id}:{owner.chat_id}")


def clear_owner(vault: Vault) -> None:
    vault.delete(TELEGRAM_OWNER)


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def display_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


def _normalize(code: str) -> str:
    return code.upper().replace("-", "").replace(" ", "")


@dataclass(frozen=True)
class PairingRequest:
    user: User
    chat: Chat


def _offered_code(message: IncomingMessage | None) -> str | None:
    """The code in a ``/pair <code>`` message a person sent in a private chat, else None."""
    if message is None or message.text is None or message.sender is None:
        return None
    if message.chat.type != "private" or message.sender.is_bot or message.forwarded:
        return None
    command, *rest = message.text.split() or [""]
    if command.split("@", 1)[0].lower() != "/pair" or not rest:
        return None
    return "".join(rest)


async def wait_for_pairing(
    api: TelegramApi,
    code: str,
    *,
    timeout_seconds: float = PAIRING_TTL_SECONDS,
    max_attempts: int = MAX_ATTEMPTS,
    clock: Callable[[], float] = time.monotonic,
) -> PairingRequest | None:
    """Wait for ``/pair <code>``; returns who sent it, or None once the code has expired."""
    deadline = clock() + timeout_seconds
    offset = await skip_backlog(api)
    attempts = 0
    while (remaining := deadline - clock()) > 0:
        updates = await api.get_updates(offset, max(1, min(POLL_TIMEOUT, int(remaining))))
        for update in updates:
            offset = update.update_id + 1
            message = update.message
            offered = _offered_code(message)
            if offered is None or message is None or message.sender is None:
                continue
            attempts += 1
            if hmac.compare_digest(_normalize(offered).encode(), code.encode()):
                return PairingRequest(message.sender, message.chat)
            if attempts >= max_attempts:
                raise PairingError("too many wrong codes were sent, so pairing was cancelled")
    return None
