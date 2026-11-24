import asyncio
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from typer.testing import CliRunner, Result

from bastion.cli import app, deps
from bastion.cli.google import REVOKE_PAGE
from bastion.config import DATABASE_FILE
from bastion.google.grant import (
    CALENDAR_READ,
    CALENDAR_WRITE,
    GMAIL_COMPOSE,
    GMAIL_READ,
    Grant,
    load_client,
    load_grant,
    save_client,
    save_grant,
)
from bastion.google.oauth import ClientCredentials
from bastion.security.audit import AuditLog
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    GOOGLE_CLIENT_ID,
    GOOGLE_REFRESH_TOKEN,
    MemoryStore,
    Vault,
    VaultError,
)
from bastion.storage.db import connect
from support.google import FakeGoogle, form_of

CLIENT_ID = "123456789-abcdefgh12345678.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-secret"
NEW_REFRESH = "1//new-refresh-token-0001"
OLD_REFRESH = "1//old-refresh-token-0001"
CLIENT_INPUT = f"{CLIENT_ID}\n{CLIENT_SECRET}\n"
ALL_SCOPES = " ".join([GMAIL_READ, GMAIL_COMPOSE, CALENDAR_WRITE])


class FakeBrowser:
    """Plays the owner: follows the sign-in URL and comes back to the loopback redirect."""

    def __init__(self, *, code: str = "4/0AbCdEf123", error: str | None = None) -> None:
        self.code = code
        self.error = error
        self.urls: list[str] = []
        self.tasks: list[asyncio.Task[None]] = []

    def __call__(self, url: str) -> bool:
        self.urls.append(url)
        params = self.params()
        reply = f"error={self.error}" if self.error else f"code={self.code}"
        target = f"{params['redirect_uri']}/?state={params['state']}&{reply}"
        self.tasks.append(asyncio.get_running_loop().create_task(self._visit(target)))
        return True

    @staticmethod
    async def _visit(url: str) -> None:
        async with httpx2.AsyncClient(trust_env=False) as client:
            await client.get(url)

    def params(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlsplit(self.urls[-1]).query).items()}


@dataclass
class Env:
    home: Path
    store: MemoryStore
    google: FakeGoogle
    browser: FakeBrowser
    revoked: list[str] = field(default_factory=list)

    @property
    def vault(self) -> Vault:
        return Vault(self.store, Redactor())

    def events(self) -> list[str]:
        with closing(connect(self.home / DATABASE_FILE)) as conn:
            log = AuditLog(conn, self.vault.key(AUDIT_KEY), Redactor())
            return [entry.event for entry in log.tail(200)]

    def grants(self, scopes: str, refresh: str = NEW_REFRESH) -> None:
        def handle(request: httpx2.Request) -> httpx2.Response:
            body: dict[str, Any] = {
                "access_token": "ya29.access-token-value-0001",
                "expires_in": 3599,
                "scope": scopes,
                "token_type": "Bearer",
            }
            if form_of(request)["grant_type"] == "authorization_code":
                body["refresh_token"] = refresh
            return httpx2.Response(200, json=body)

        self.google.on("POST", "/token", handle)

    def connected(self, gmail: Any = "draft", calendar: Any = "write") -> None:
        save_client(self.vault, ClientCredentials(CLIENT_ID, CLIENT_SECRET))
        self.store.set(GOOGLE_REFRESH_TOKEN, OLD_REFRESH)
        save_grant(self.vault, Grant("me@example.com", gmail, calendar, frozenset()))


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    store = MemoryStore()
    google = FakeGoogle()
    browser = FakeBrowser()
    environment = Env(tmp_path / "home", store, google, browser)

    def revoke(request: httpx2.Request) -> httpx2.Response:
        environment.revoked.append(form_of(request)["token"])
        return httpx2.Response(200)

    google.on("POST", "/revoke", revoke)
    google.on("GET", "/gmail/v1/users/me/profile", {"emailAddress": "me@example.com"})
    google.on(
        "GET",
        "/calendar/v3/calendars/primary/events",
        {"summary": "cal@example.com", "items": []},
    )
    monkeypatch.setenv("BASTION_HOME", str(environment.home))
    monkeypatch.setattr(deps, "secret_store", lambda: store)
    monkeypatch.setattr(deps, "google_http", google.client)
    monkeypatch.setattr(deps, "open_browser", browser)
    result = run(["init", "--provider", "ollama", "--model", "llama3"], stdin="\n")
    assert result.exit_code == 0, result.output
    yield environment


def run(args: list[str], stdin: str | None = None) -> Result:
    return CliRunner().invoke(app, args, input=stdin)


def flat(result: Result) -> str:
    return " ".join(result.output.split())


# ------------------------------------------------------------------ connect


def test_connect_signs_in_and_stores_the_connection(env: Env) -> None:
    env.grants(ALL_SCOPES)

    result = run(["google", "connect"], stdin=CLIENT_INPUT)

    assert result.exit_code == 0, result.output
    assert env.store.get(GOOGLE_REFRESH_TOKEN) == NEW_REFRESH
    assert load_client(env.vault) == ClientCredentials(CLIENT_ID, CLIENT_SECRET)
    grant = load_grant(env.vault)
    assert grant == Grant("me@example.com", "draft", "write", frozenset(ALL_SCOPES.split()))
    assert "Connected to me@example.com" in flat(result)
    assert NEW_REFRESH not in result.output
    assert CLIENT_SECRET not in result.output
    assert "google.connected" in env.events()


@pytest.mark.security
def test_sign_in_uses_pkce_state_and_the_fewest_scopes(env: Env) -> None:
    env.grants(" ".join([GMAIL_READ, CALENDAR_READ]))

    result = run(["google", "connect", "--gmail", "read", "--calendar", "read"], stdin=CLIENT_INPUT)

    assert result.exit_code == 0, result.output
    params = env.browser.params()
    assert params["scope"] == f"{GMAIL_READ} {CALENDAR_READ}"
    assert params["code_challenge_method"] == "S256"
    assert params["redirect_uri"].startswith("http://127.0.0.1:")
    assert len(params["state"]) >= 32
    exchange = form_of(env.google.sent("POST", "/token")[0])
    assert exchange["code"] == env.browser.code
    assert len(exchange["code_verifier"]) >= 43
    assert exchange["redirect_uri"] == params["redirect_uri"]


@pytest.mark.security
def test_partial_consent_lowers_the_access_level(env: Env) -> None:
    env.grants(" ".join([GMAIL_READ, CALENDAR_READ]))

    result = run(["google", "connect", "--gmail", "send"], stdin=CLIENT_INPUT)

    assert result.exit_code == 0, result.output
    grant = load_grant(env.vault)
    assert grant is not None
    assert (grant.gmail, grant.calendar) == ("read", "read")
    assert "granted less than requested" in flat(result)


@pytest.mark.security
def test_a_grant_with_nothing_usable_is_revoked_and_not_stored(env: Env) -> None:
    env.grants("openid")

    result = run(["google", "connect"], stdin=CLIENT_INPUT)

    assert result.exit_code == 1
    assert "granted none" in flat(result)
    assert env.revoked == [NEW_REFRESH]
    assert env.store.get(GOOGLE_REFRESH_TOKEN) is None
    assert load_grant(env.vault) is None
    assert "google.connect_failed" in env.events()


def test_calendar_only_uses_the_calendar_id_as_the_account(env: Env) -> None:
    env.grants(CALENDAR_WRITE)

    result = run(["google", "connect", "--gmail", "off"], stdin=CLIENT_INPUT)

    assert result.exit_code == 0, result.output
    grant = load_grant(env.vault)
    assert grant is not None
    assert (grant.account, grant.gmail) == ("cal@example.com", "off")


@pytest.mark.security
def test_reconnecting_revokes_the_previous_token(env: Env) -> None:
    env.connected()
    env.grants(ALL_SCOPES)

    result = run(["google", "connect", "--gmail", "send"])  # the stored client is reused

    assert result.exit_code == 0, result.output
    assert env.revoked == [OLD_REFRESH]
    assert env.store.get(GOOGLE_REFRESH_TOKEN) == NEW_REFRESH
    grant = load_grant(env.vault)
    assert grant is not None and grant.gmail == "send"


def test_a_cancelled_sign_in_stores_nothing(env: Env) -> None:
    env.browser.error = "access_denied"

    result = run(["google", "connect"], stdin=CLIENT_INPUT)

    assert result.exit_code == 1
    assert "access_denied" in flat(result)
    assert env.store.get(GOOGLE_REFRESH_TOKEN) is None
    assert env.google.sent("POST", "/token") == []


@pytest.mark.parametrize(
    ("stdin", "message"),
    [("not-a-client\n", "client ID"), (f"{CLIENT_ID}\nshort\n", "client secret")],
)
def test_malformed_client_credentials_are_refused(env: Env, stdin: str, message: str) -> None:
    result = run(["google", "connect"], stdin=stdin)

    assert result.exit_code == 1
    assert f"does not look like a {message}" in flat(result)
    assert env.store.get(GOOGLE_CLIENT_ID) is None


@pytest.mark.parametrize(
    "args",
    [
        ["--gmail", "everything"],
        ["--calendar", "admin"],
        ["--gmail", "off", "--calendar", "off"],
    ],
)
def test_invalid_access_levels_are_refused(env: Env, args: list[str]) -> None:
    result = run(["google", "connect", *args])

    assert result.exit_code == 2
    assert env.browser.urls == []


# ------------------------------------------------------------------- status


def test_status_when_not_connected(env: Env) -> None:
    result = run(["google", "status"])

    assert result.exit_code == 0
    assert "Not connected" in result.output


def test_status_checks_that_access_still_works(env: Env) -> None:
    env.connected()
    env.grants(ALL_SCOPES)

    result = run(["google", "status"])

    assert result.exit_code == 0, result.output
    assert "Connected to me@example.com" in flat(result)
    assert "Access works" in result.output
    assert form_of(env.google.sent("POST", "/token")[0])["refresh_token"] == OLD_REFRESH


def test_status_reports_revoked_access(env: Env) -> None:
    env.connected()
    env.google.on("POST", "/token", httpx2.Response(400, json={"error": "invalid_grant"}))

    result = run(["google", "status"])

    assert result.exit_code == 1
    assert "revoked or expired" in flat(result)
    assert "bastion google connect" in flat(result)


# --------------------------------------------------------------- disconnect


@pytest.mark.security
def test_disconnect_revokes_at_google_and_deletes_locally(env: Env) -> None:
    env.connected()

    result = run(["google", "disconnect"])

    assert result.exit_code == 0, result.output
    assert env.revoked == [OLD_REFRESH]
    assert env.store.get(GOOGLE_REFRESH_TOKEN) is None
    assert load_grant(env.vault) is None
    assert load_client(env.vault) is not None  # kept for an easy reconnect
    assert "Google revoked Bastion's access" in flat(result)
    assert "google.disconnected" in env.events()


def test_disconnect_when_google_is_unreachable_still_deletes(env: Env) -> None:
    env.connected()
    env.google.on("POST", "/revoke", httpx2.Response(503))

    result = run(["google", "disconnect", "--forget-client"])

    assert result.exit_code == 0, result.output
    assert env.store.get(GOOGLE_REFRESH_TOKEN) is None
    assert load_client(env.vault) is None
    assert REVOKE_PAGE in flat(result)


def test_disconnect_when_not_connected(env: Env) -> None:
    result = run(["google", "disconnect"])

    assert result.exit_code == 0
    assert "was not connected" in result.output
    assert env.revoked == []


def test_secrets_status_lists_the_google_entries(env: Env) -> None:
    env.connected()

    result = run(["secrets", "status"])

    assert result.exit_code == 0
    for name in ("google.client_id", "google.client_secret", "google.refresh_token"):
        assert name in result.output
    assert OLD_REFRESH not in result.output


@pytest.mark.security
def test_a_failed_save_removes_the_half_written_connection(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.connected()
    env.grants(ALL_SCOPES)
    original = env.store.set

    def failing(name: str, value: str) -> None:
        if name == GOOGLE_REFRESH_TOKEN:
            raise VaultError("the OS keyring is unavailable (KeyringError)")
        original(name, value)

    monkeypatch.setattr(env.store, "set", failing)

    result = run(["google", "connect"])

    assert result.exit_code == 1
    assert "it was removed" in flat(result)
    assert sorted(env.revoked) == sorted([NEW_REFRESH, OLD_REFRESH])
    assert load_grant(env.vault) is None
    assert env.store.get(GOOGLE_REFRESH_TOKEN) is None


@pytest.mark.security
def test_tracebacks_never_show_local_variables() -> None:
    from bastion.cli import admin
    from bastion.cli import google as google_cli
    from bastion.cli import telegram as telegram_cli

    apps = (
        app,
        admin.audit_app,
        admin.secrets_app,
        admin.policy_app,
        google_cli.google_app,
        telegram_cli.telegram_app,
    )
    assert all(typer_app.pretty_exceptions_show_locals is False for typer_app in apps)


def test_no_browser_sign_in_takes_the_pasted_address(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.parse import parse_qs, urlsplit

    from bastion.cli import google as google_cli

    env.grants(ALL_SCOPES)
    shown: list[str] = []

    def paste(console: object, url: str, redirect_uri: str) -> str:
        shown.append(url)
        state = parse_qs(urlsplit(url).query)["state"][0]
        return f"{redirect_uri}/?state={state}&code=4/0AbCdEf123"

    monkeypatch.setattr(google_cli, "_paste_redirect", paste)

    result = run(["google", "connect", "--no-browser"], stdin=CLIENT_INPUT)

    assert result.exit_code == 0, result.output
    assert env.browser.urls == []  # no browser was opened
    assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A8765" in shown[0]
    assert env.store.get(GOOGLE_REFRESH_TOKEN) == NEW_REFRESH
    exchange = form_of(env.google.sent("POST", "/token")[0])
    assert exchange["redirect_uri"] == "http://127.0.0.1:8765"
