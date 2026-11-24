"""``bastion google``: connect Gmail and Google Calendar with the owner's own OAuth client.

Bastion has no OAuth client of its own: the owner creates one in their Google Cloud project,
so no third party ever holds access to their account. Signing in happens once, in a browser;
the refresh token goes to the OS keyring and never appears on screen.
"""

import asyncio
import contextlib
import secrets
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from bastion.cli import deps
from bastion.cli.admin import audit_session
from bastion.google.api import GoogleApi, GoogleApiError
from bastion.google.calendar import CalendarClient
from bastion.google.gmail import GmailClient
from bastion.google.grant import (
    CALENDAR_LEVELS,
    GMAIL_LEVELS,
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
from bastion.google.oauth import (
    LOOPBACK_HOST,
    AuthRevoked,
    ClientCredentials,
    LoopbackReceiver,
    OAuthError,
    TokenGrant,
    authorization_url,
    code_from_redirect,
    exchange_code,
    new_pkce,
    refresh_access,
    revoke,
    valid_client_id,
    valid_client_secret,
)
from bastion.security.redact import Redactor
from bastion.security.vault import GOOGLE_REFRESH_TOKEN, Vault, VaultError

google_app = typer.Typer(
    pretty_exceptions_show_locals=False,  # tracebacks must never print secrets
    help="Connect Gmail and Google Calendar (tokens stay in your secret store).",
    no_args_is_help=True,
)

CLIENT_HELP = """\
Bastion signs in with your own Google OAuth client, so no third party holds access to your
account. One-time setup at https://console.cloud.google.com :
  1. Create a project, then enable the Gmail API and the Google Calendar API.
  2. Google Auth Platform > Audience: choose "Personal" if offered (no weekly sign-in);
     otherwise "External", and add your own address as a test user.
  3. Clients > Create client > "Desktop app". Copy its client ID and client secret."""

GMAIL_ACCESS = {
    "off": "off",
    "read": "search and read",
    "draft": "search, read and save drafts (sending is off: --gmail send turns it on)",
    "send": "search, read, save drafts and send (sending always passes the policy engine)",
}
CALENDAR_ACCESS = {
    "off": "off",
    "read": "list events",
    "write": "list, create, change and delete events",
}
REVOKE_PAGE = "https://myaccount.google.com/permissions"
# The redirect for --no-browser sign-ins: nothing listens on it, the owner pastes it back.
NO_BROWSER_PORT = 8765


class _FixedToken:
    """The access token from the sign-in, used once to find out which account it belongs to."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def token(self) -> str:
        return self._token

    def invalidate(self, token: str) -> None:
        pass


def _vault() -> Vault:
    return Vault(deps.secret_store(), Redactor())


def _fail(console: Console, message: str) -> typer.Exit:
    console.print(f"[red]{escape(message)}[/]")
    return typer.Exit(1)


def _gmail_level(value: str) -> GmailLevel:
    for level in GMAIL_LEVELS:
        if value == level:
            return level
    raise typer.BadParameter(f"choose one of: {', '.join(GMAIL_LEVELS)}", param_hint="--gmail")


def _calendar_level(value: str) -> CalendarLevel:
    for level in CALENDAR_LEVELS:
        if value == level:
            return level
    raise typer.BadParameter(
        f"choose one of: {', '.join(CALENDAR_LEVELS)}", param_hint="--calendar"
    )


def _ask_client(console: Console) -> ClientCredentials:
    console.print(CLIENT_HELP, markup=False, highlight=False)
    client_id = str(typer.prompt("Client ID")).strip()
    if not valid_client_id(client_id):
        raise _fail(console, "That does not look like a client ID (…apps.googleusercontent.com).")
    secret = str(typer.prompt("Client secret (input hidden)", hide_input=True)).strip()
    if not valid_client_secret(secret):
        raise _fail(console, "That does not look like a client secret.")
    return ClientCredentials(client_id, secret)


def _client(console: Console, vault: Vault, new_client: bool) -> ClientCredentials:
    stored = None if new_client else load_client(vault)
    if stored is not None:
        return stored
    credentials = _ask_client(console)
    save_client(vault, credentials)
    return credentials


def _paste_redirect(console: Console, url: str, redirect_uri: str) -> str:
    console.print("On any device, open this address and sign in with Google:")
    console.print(url, markup=False, highlight=False, soft_wrap=True)
    console.print(
        f"Your browser then fails to open a page starting with {redirect_uri}/?state=... "
        "That is expected: copy that whole address from the address bar."
    )
    return str(typer.prompt("Paste the address here (input hidden)", hide_input=True))


async def _sign_in(
    console: Console,
    credentials: ClientCredentials,
    scopes: tuple[str, ...],
    port: int,
    *,
    no_browser: bool = False,
) -> tuple[TokenGrant, str]:
    """Run the browser sign-in. Returns the tokens and the redirect URI that was used."""
    state = secrets.token_urlsafe(32)
    pkce = new_pkce()
    if no_browser:
        redirect_uri = f"http://{LOOPBACK_HOST}:{port or NO_BROWSER_PORT}"
        url = authorization_url(credentials.client_id, redirect_uri, scopes, state, pkce.challenge)
        # Called directly, not in a thread: nothing else runs meanwhile, and a blocked
        # worker thread would make Ctrl+C hang until Enter.
        pasted = _paste_redirect(console, url, redirect_uri)
        code = code_from_redirect(pasted, state, redirect_uri)
        async with deps.google_http() as http:
            tokens = await exchange_code(
                http, credentials, code=code, verifier=pkce.verifier, redirect_uri=redirect_uri
            )
        return tokens, redirect_uri
    async with deps.google_http() as http:
        async with LoopbackReceiver(state, port=port) as receiver:
            url = authorization_url(
                credentials.client_id, receiver.redirect_uri, scopes, state, pkce.challenge
            )
            console.print("Sign in with Google in your browser. If it does not open, visit:")
            console.print(url, markup=False, highlight=False, soft_wrap=True)
            deps.open_browser(url)
            code = await receiver.wait()
        tokens = await exchange_code(
            http, credentials, code=code, verifier=pkce.verifier, redirect_uri=receiver.redirect_uri
        )
    return tokens, receiver.redirect_uri


async def _account(tokens: TokenGrant, gmail: GmailLevel) -> str:
    async with deps.google_http() as http:
        api = GoogleApi(_FixedToken(tokens.access.token), http)
        if gmail != "off":
            return await GmailClient(api).profile_email()
        return await CalendarClient(api).calendar_name()


async def _revoke(token: str) -> bool:
    async with deps.google_http() as http:
        return await revoke(http, token)


async def _connect(
    console: Console,
    credentials: ClientCredentials,
    gmail: GmailLevel,
    calendar: CalendarLevel,
    port: int,
    no_browser: bool = False,
) -> tuple[TokenGrant, Grant]:
    scopes = requested_scopes(gmail, calendar)
    tokens, _ = await _sign_in(console, credentials, scopes, port, no_browser=no_browser)
    granted = tokens.access.scopes
    grant_gmail = effective_gmail(gmail, granted)
    grant_calendar = effective_calendar(calendar, granted)
    try:
        if grant_gmail == "off" and grant_calendar == "off":
            raise OAuthError("Google granted none of the access Bastion asked for")
        account = await _account(tokens, grant_gmail) or "(your Google account)"
    except (OAuthError, GoogleApiError):
        await _revoke(tokens.refresh_token)  # never leave an unused token alive
        raise
    return tokens, Grant(account, grant_gmail, grant_calendar, granted)


def _store(console: Console, vault: Vault, token: str, grant: Grant, previous: str | None) -> None:
    """Save the new connection: the record first, then the token that makes it live.

    If the record cannot be saved, nothing has changed. If the token cannot be saved after the
    record was, the keyring would describe one connection and hold another, so everything is
    removed and both tokens are revoked: a clean "not connected" beats a confusing half-state.
    """
    try:
        save_grant(vault, grant)
    except VaultError as exc:
        asyncio.run(_revoke(token))
        raise _fail(console, f"Could not store the connection: {exc}") from exc
    try:
        vault.set(GOOGLE_REFRESH_TOKEN, token)
    except VaultError as exc:
        with contextlib.suppress(VaultError):
            clear_connection(vault)
        for stale in (token, previous):
            if stale is not None:
                asyncio.run(_revoke(stale))
        raise _fail(
            console, f"Could not store the connection ({exc}); it was removed. Connect again."
        ) from exc


def _report(console: Console, grant: Grant, gmail: GmailLevel, calendar: CalendarLevel) -> None:
    console.print(f"[green]Connected[/] to {escape(grant.account)}.")
    console.print(f"  Gmail: {grant.gmail} ({GMAIL_ACCESS[grant.gmail]})")
    console.print(f"  Calendar: {grant.calendar} ({CALENDAR_ACCESS[grant.calendar]})")
    if (grant.gmail, grant.calendar) != (gmail, calendar):
        console.print(
            "[yellow]Google granted less than requested[/] (boxes left unticked on the consent "
            "screen?). Run connect again to change it."
        )
    if grant.gmail == "draft":
        console.print(
            "Note: Google's permission for drafts also covers sending. Bastion offers no "
            "sending unless you connect with --gmail send."
        )
    console.print("If bastion daemon is running, restart it to use this connection.")


@google_app.command("connect")
def connect(
    gmail: Annotated[str, typer.Option(help="Gmail access: off, read, draft or send.")] = "draft",
    calendar: Annotated[str, typer.Option(help="Calendar access: off, read or write.")] = "write",
    port: Annotated[
        int,
        typer.Option(min=0, max=65535, help="Local port for the sign-in redirect (0: random)."),
    ] = 0,
    new_client: Annotated[
        bool, typer.Option("--new-client", help="Enter a different OAuth client.")
    ] = False,
    no_browser: Annotated[
        bool,
        typer.Option(
            "--no-browser",
            help="For servers and containers: sign in on another device, paste the address back.",
        ),
    ] = False,
) -> None:
    """Sign in with Google and choose what Bastion may do."""
    console = Console()
    gmail_level, calendar_level = _gmail_level(gmail), _calendar_level(calendar)
    if gmail_level == "off" and calendar_level == "off":
        raise typer.BadParameter("turn on at least one of --gmail and --calendar")
    with audit_session(console) as audit:
        vault = _vault()
        try:
            credentials = _client(console, vault, new_client)
            previous = vault.get(GOOGLE_REFRESH_TOKEN)
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        try:
            tokens, grant = asyncio.run(
                _connect(console, credentials, gmail_level, calendar_level, port, no_browser)
            )
        except (OAuthError, GoogleApiError) as exc:
            audit.append("google.connect_failed", {"error": str(exc)[:200]})
            raise _fail(console, f"Could not connect: {exc}") from exc
        except OSError as exc:
            raise _fail(console, f"Could not listen for the sign-in on port {port}.") from exc
        _store(console, vault, tokens.refresh_token, grant, previous)
        audit.append(
            "google.connected",
            {
                "gmail": grant.gmail,
                "calendar": grant.calendar,
                "scopes": sorted(grant.scopes),
                "replaced": previous is not None,
            },
            checkpoint=True,
        )
    stale = previous is not None and previous != tokens.refresh_token
    if stale and previous is not None and not asyncio.run(_revoke(previous)):
        console.print(f"Could not revoke the previous connection; check {REVOKE_PAGE}")
    _report(console, grant, gmail_level, calendar_level)


@google_app.command("status")
def status() -> None:
    """Show the Google connection and check that it still works."""
    console = Console()
    vault = _vault()
    try:
        grant, credentials = load_grant(vault), load_client(vault)
        token = vault.get(GOOGLE_REFRESH_TOKEN)
    except VaultError as exc:
        raise _fail(console, str(exc)) from exc
    if grant is None or credentials is None or token is None:
        console.print("Not connected. Run: bastion google connect")
        return
    console.print(f"Connected to {escape(grant.account)}.")
    console.print(f"  Gmail: {grant.gmail} ({GMAIL_ACCESS[grant.gmail]})")
    console.print(f"  Calendar: {grant.calendar} ({CALENDAR_ACCESS[grant.calendar]})")

    async def check() -> None:
        async with deps.google_http() as http:
            await refresh_access(http, credentials, token)

    try:
        asyncio.run(check())
    except AuthRevoked as exc:
        raise _fail(console, f"{exc}. Run: bastion google connect") from exc
    except OAuthError as exc:
        raise _fail(console, f"Could not check the connection: {exc}") from exc
    console.print("[green]Access works.[/]")


@google_app.command("disconnect")
def disconnect(
    forget_client: Annotated[
        bool, typer.Option("--forget-client", help="Also delete the stored OAuth client.")
    ] = False,
) -> None:
    """Revoke Bastion's Google access and delete it from this computer."""
    console = Console()
    with audit_session(console) as audit:
        vault = _vault()
        try:
            token = vault.get(GOOGLE_REFRESH_TOKEN)
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        revoked = asyncio.run(_revoke(token)) if token is not None else True
        try:
            clear_connection(vault, forget_client=forget_client)
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        audit.append(
            "google.disconnected",
            {"had_token": token is not None, "revoked": revoked, "forgot_client": forget_client},
            checkpoint=True,
        )
    if token is None:
        console.print("Bastion was not connected to Google.")
    elif revoked:
        console.print("Disconnected: Google revoked Bastion's access and it was deleted here.")
    else:
        console.print(
            "Deleted here, but Google could not be reached to revoke access. Remove Bastion at "
            f"{REVOKE_PAGE}"
        )
    console.print("A running bastion daemon loses Google access at its next use.")
