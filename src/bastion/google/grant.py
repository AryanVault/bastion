"""What Bastion may do in the owner's Google account, and where that is recorded.

The owner picks an access level per service at ``bastion google connect``; each level maps to
the fewest OAuth scopes that support it. Google lets people untick scopes on the consent
screen, so the level Bastion uses is the lower of what was asked for and what was granted.

Google has no drafts-only Gmail scope: ``gmail.compose`` also permits sending. At level
``draft`` the token could therefore send mail, but Bastion offers the model no tool for it;
``gmail_send`` exists only at level ``send``, and sending always passes the policy engine.
"""

import json
from dataclasses import dataclass
from typing import Literal, get_args

from bastion.google.oauth import ClientCredentials, valid_client_id, valid_client_secret
from bastion.security.vault import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_GRANT,
    GOOGLE_REFRESH_TOKEN,
    Vault,
    VaultError,
)

SCOPE_PREFIX = "https://www.googleapis.com/auth/"
GMAIL_READ = SCOPE_PREFIX + "gmail.readonly"
GMAIL_COMPOSE = SCOPE_PREFIX + "gmail.compose"
CALENDAR_READ = SCOPE_PREFIX + "calendar.events.readonly"
CALENDAR_WRITE = SCOPE_PREFIX + "calendar.events"

type GmailLevel = Literal["off", "read", "draft", "send"]
type CalendarLevel = Literal["off", "read", "write"]
GMAIL_LEVELS: tuple[GmailLevel, ...] = get_args(GmailLevel.__value__)
CALENDAR_LEVELS: tuple[CalendarLevel, ...] = get_args(CalendarLevel.__value__)

_GMAIL_SCOPES: dict[GmailLevel, tuple[str, ...]] = {
    "off": (),
    "read": (GMAIL_READ,),
    "draft": (GMAIL_READ, GMAIL_COMPOSE),
    "send": (GMAIL_READ, GMAIL_COMPOSE),
}
_CALENDAR_SCOPES: dict[CalendarLevel, tuple[str, ...]] = {
    "off": (),
    "read": (CALENDAR_READ,),
    "write": (CALENDAR_WRITE,),
}


def requested_scopes(gmail: GmailLevel, calendar: CalendarLevel) -> tuple[str, ...]:
    return (*_GMAIL_SCOPES[gmail], *_CALENDAR_SCOPES[calendar])


def effective_gmail(requested: GmailLevel, granted: frozenset[str]) -> GmailLevel:
    if requested == "off" or GMAIL_READ not in granted:
        return "off"
    if requested in ("draft", "send") and GMAIL_COMPOSE in granted:
        return requested
    return "read"


def effective_calendar(requested: CalendarLevel, granted: frozenset[str]) -> CalendarLevel:
    if requested == "off":
        return "off"
    if requested == "write" and CALENDAR_WRITE in granted:
        return "write"
    return "read" if granted & {CALENDAR_READ, CALENDAR_WRITE} else "off"


@dataclass(frozen=True)
class Grant:
    account: str
    gmail: GmailLevel
    calendar: CalendarLevel
    scopes: frozenset[str]

    def to_json(self) -> str:
        return json.dumps(
            {
                "account": self.account,
                "gmail": self.gmail,
                "calendar": self.calendar,
                "scopes": sorted(self.scopes),
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, text: str) -> "Grant":
        try:
            data = json.loads(text)
            account, gmail, calendar = data["account"], data["gmail"], data["calendar"]
            scopes = data["scopes"]
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultError("the stored Google connection record is corrupt") from exc
        valid = (
            isinstance(account, str)
            and gmail in GMAIL_LEVELS
            and calendar in CALENDAR_LEVELS
            and isinstance(scopes, list)
            and all(isinstance(s, str) for s in scopes)
        )
        if not valid:
            raise VaultError("the stored Google connection record is corrupt")
        return cls(account, gmail, calendar, frozenset(scopes))


def load_grant(vault: Vault) -> Grant | None:
    stored = vault.get(GOOGLE_GRANT)
    return None if stored is None else Grant.from_json(stored)


def save_grant(vault: Vault, grant: Grant) -> None:
    vault.set(GOOGLE_GRANT, grant.to_json())


def load_client(vault: Vault) -> ClientCredentials | None:
    client_id, secret = vault.get(GOOGLE_CLIENT_ID), vault.get(GOOGLE_CLIENT_SECRET)
    if client_id is None or secret is None:
        return None
    if not valid_client_id(client_id) or not valid_client_secret(secret):
        raise VaultError("the stored Google OAuth client is corrupt")
    return ClientCredentials(client_id, secret)


def save_client(vault: Vault, credentials: ClientCredentials) -> None:
    vault.set(GOOGLE_CLIENT_ID, credentials.client_id)
    vault.set(GOOGLE_CLIENT_SECRET, credentials.client_secret)


def clear_connection(vault: Vault, *, forget_client: bool = False) -> None:
    vault.delete(GOOGLE_REFRESH_TOKEN)
    vault.delete(GOOGLE_GRANT)
    if forget_client:
        vault.delete(GOOGLE_CLIENT_ID)
        vault.delete(GOOGLE_CLIENT_SECRET)
