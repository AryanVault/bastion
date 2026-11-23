import pytest

from bastion.google.grant import (
    CALENDAR_LEVELS,
    CALENDAR_READ,
    CALENDAR_WRITE,
    GMAIL_COMPOSE,
    GMAIL_LEVELS,
    GMAIL_READ,
    CalendarLevel,
    GmailLevel,
    Grant,
    clear_connection,
    effective_calendar,
    effective_gmail,
    load_client,
    load_grant,
    requested_scopes,
    save_client,
    save_grant,
)
from bastion.google.oauth import ClientCredentials
from bastion.security.redact import Redactor
from bastion.security.vault import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_GRANT,
    GOOGLE_REFRESH_TOKEN,
    MemoryStore,
    Vault,
    VaultError,
)

CREDS = ClientCredentials("123456789-abcdefgh12345678.apps.googleusercontent.com", "GOCSPX-secret1")


@pytest.fixture
def vault() -> Vault:
    return Vault(MemoryStore(), Redactor())


def test_levels_are_listed_in_order() -> None:
    assert GMAIL_LEVELS == ("off", "read", "draft", "send")
    assert CALENDAR_LEVELS == ("off", "read", "write")


@pytest.mark.parametrize(
    ("gmail", "calendar", "scopes"),
    [
        ("off", "off", ()),
        ("read", "off", (GMAIL_READ,)),
        ("draft", "read", (GMAIL_READ, GMAIL_COMPOSE, CALENDAR_READ)),
        ("send", "write", (GMAIL_READ, GMAIL_COMPOSE, CALENDAR_WRITE)),
    ],
)
def test_each_level_asks_for_the_fewest_scopes(
    gmail: GmailLevel, calendar: CalendarLevel, scopes: tuple[str, ...]
) -> None:
    assert requested_scopes(gmail, calendar) == scopes


@pytest.mark.security
@pytest.mark.parametrize(
    ("requested", "granted", "effective"),
    [
        ("send", {GMAIL_READ, GMAIL_COMPOSE}, "send"),
        ("draft", {GMAIL_READ, GMAIL_COMPOSE}, "draft"),
        ("draft", {GMAIL_READ}, "read"),  # the owner unticked "send and draft"
        ("send", {GMAIL_COMPOSE}, "off"),  # no read access: nothing usable
        ("read", {GMAIL_READ, GMAIL_COMPOSE}, "read"),  # never more than asked for
        ("off", {GMAIL_READ, GMAIL_COMPOSE}, "off"),
    ],
)
def test_gmail_level_is_the_lower_of_requested_and_granted(
    requested: GmailLevel, granted: set[str], effective: GmailLevel
) -> None:
    assert effective_gmail(requested, frozenset(granted)) == effective


@pytest.mark.security
@pytest.mark.parametrize(
    ("requested", "granted", "effective"),
    [
        ("write", {CALENDAR_WRITE}, "write"),
        ("write", {CALENDAR_READ}, "read"),
        ("read", {CALENDAR_WRITE}, "read"),
        ("write", set(), "off"),
        ("off", {CALENDAR_WRITE}, "off"),
    ],
)
def test_calendar_level_is_the_lower_of_requested_and_granted(
    requested: CalendarLevel, granted: set[str], effective: CalendarLevel
) -> None:
    assert effective_calendar(requested, frozenset(granted)) == effective


def test_grant_round_trips_through_the_vault(vault: Vault) -> None:
    grant = Grant("me@example.com", "draft", "write", frozenset({GMAIL_READ, CALENDAR_WRITE}))

    save_grant(vault, grant)

    assert load_grant(vault) == grant


def test_missing_grant_is_none(vault: Vault) -> None:
    assert load_grant(vault) is None


@pytest.mark.parametrize(
    "stored",
    [
        "not json",
        "[]",
        '{"account": "a"}',
        '{"account": "a", "gmail": "everything", "calendar": "off", "scopes": []}',
        '{"account": 5, "gmail": "read", "calendar": "off", "scopes": []}',
        '{"account": "a", "gmail": "read", "calendar": "off", "scopes": "x"}',
        '{"account": "a", "gmail": "read", "calendar": "off", "scopes": [1]}',
    ],
)
def test_corrupt_grants_are_refused(vault: Vault, stored: str) -> None:
    vault.set(GOOGLE_GRANT, stored)

    with pytest.raises(VaultError, match="corrupt"):
        load_grant(vault)


def test_client_credentials_round_trip_and_are_validated(vault: Vault) -> None:
    assert load_client(vault) is None

    save_client(vault, CREDS)

    assert load_client(vault) == CREDS
    vault.set(GOOGLE_CLIENT_ID, "evil.example")
    with pytest.raises(VaultError, match="corrupt"):
        load_client(vault)


def test_clear_connection_keeps_the_client_unless_asked(vault: Vault) -> None:
    save_client(vault, CREDS)
    vault.set(GOOGLE_REFRESH_TOKEN, "1//refresh-token")
    save_grant(vault, Grant("me@example.com", "read", "off", frozenset({GMAIL_READ})))

    clear_connection(vault)

    assert vault.get(GOOGLE_REFRESH_TOKEN) is None
    assert load_grant(vault) is None
    assert load_client(vault) == CREDS
    clear_connection(vault, forget_client=True)
    assert vault.get(GOOGLE_CLIENT_ID) is None
    assert vault.get(GOOGLE_CLIENT_SECRET) is None
