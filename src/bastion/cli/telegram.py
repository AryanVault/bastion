"""``bastion telegram``: connect a Telegram bot, pair the owner, and set up step-up codes.

The bot token is only read from a hidden prompt (never a command-line argument, which would leak
into shell history), and the authenticator secret is generated here. Both are kept in the OS
keyring.
"""

import asyncio
import contextlib

import typer
from rich.console import Console
from rich.markup import escape
from rich.text import Text

from bastion.cli import deps
from bastion.cli.admin import audit_session
from bastion.security.audit import AuditLog
from bastion.security.redact import Redactor
from bastion.security.totp import TotpVerifier, new_secret, provisioning_uri
from bastion.security.vault import TELEGRAM_TOKEN, TOTP_SECRET, Vault, VaultError
from bastion.telegram.api import TelegramApi, TelegramError, User, valid_token
from bastion.telegram.pairing import (
    PAIRING_TTL_SECONDS,
    Owner,
    PairingError,
    clear_owner,
    display_code,
    load_owner,
    new_code,
    save_owner,
    wait_for_pairing,
)
from bastion.text import reveal_invisible

telegram_app = typer.Typer(
    pretty_exceptions_show_locals=False,  # tracebacks must never print secrets
    help="Connect Bastion to a Telegram bot and pair your account.",
    no_args_is_help=True,
)

MAX_ENROLL_ATTEMPTS = 3
PAIRED_MESSAGE = (
    "Paired. Only you can use this bot now; messages from anyone else are ignored.\n\n"
    'Start Bastion on your computer with "bastion daemon", then send /help.'
)


def _vault() -> Vault:
    return Vault(deps.secret_store(), Redactor())


def _fail(console: Console, message: str) -> typer.Exit:
    console.print(f"[red]{escape(message)}[/]")
    return typer.Exit(1)


async def _get_me(api: TelegramApi) -> User:
    try:
        return await api.get_me()
    finally:
        await api.aclose()


@telegram_app.command("setup")
def setup_bot() -> None:
    """Store your bot's token (from @BotFather) in the OS keyring, after checking it."""
    console = Console()
    with audit_session(console) as audit:
        token = typer.prompt("Bot token from @BotFather (input hidden)", hide_input=True).strip()
        if not valid_token(token):
            raise _fail(console, "That does not look like a bot token (123456789:AA...).")
        try:
            me = asyncio.run(_get_me(deps.bot_api(token)))
        except TelegramError as exc:
            raise _fail(console, f"Telegram did not accept the token: {exc}") from exc
        if not me.is_bot:
            raise _fail(console, "That token does not belong to a bot.")
        try:
            _vault().set(TELEGRAM_TOKEN, token)
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        audit.append("telegram.setup", {"bot": me.username}, checkpoint=True)
    console.print(
        f"Stored the token for @{escape(me.username or me.first_name)} in the OS keyring."
    )
    console.print("Next: [bold]bastion telegram pair[/]")


async def _pair(
    api: TelegramApi, code: str, console: Console, audit: AuditLog, vault: Vault
) -> None:
    try:
        request = await wait_for_pairing(api, code)
        if request is None:
            raise _fail(console, "The code expired before it arrived. Run the command again.")
        # Names are chosen by whoever sent the code: show hidden characters, never obey them.
        console.print(Text(f"Pairing request from {reveal_invisible(request.user.label())}."))
        if not typer.confirm("Is this your Telegram account?", default=False):
            audit.append("telegram.pairing_rejected", {"user_id": request.user.id})
            raise _fail(console, "Not paired.")
        owner = Owner(request.user.id, request.chat.id)
        try:
            save_owner(vault, owner)
        except VaultError as exc:
            raise _fail(console, f"Could not save the pairing: {exc}") from exc
        audit.append("telegram.paired", {"user_id": owner.user_id}, checkpoint=True)
        # Pairing has already succeeded; the welcome message is a courtesy.
        with contextlib.suppress(TelegramError):
            await api.send_message(owner.chat_id, PAIRED_MESSAGE)
    finally:
        await api.aclose()


@telegram_app.command("pair")
def pair() -> None:
    """Pair your Telegram account: send the bot a one-time code, then confirm it here."""
    console = Console()
    with audit_session(console) as audit:
        vault = _vault()
        try:
            token = vault.get(TELEGRAM_TOKEN)
            paired = load_owner(vault) is not None
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        if token is None:
            raise _fail(console, "No bot token yet. Run: bastion telegram setup")
        if paired and not typer.confirm(
            "A Telegram account is already paired. Replace it?", default=False
        ):
            raise typer.Exit(1)
        code = new_code()
        console.print(
            f"In Telegram, open a private chat with your bot and send:\n\n"
            f"    [bold]/pair {display_code(code)}[/]\n\n"
            f"The code expires in {PAIRING_TTL_SECONDS // 60} minutes. Waiting..."
        )
        try:
            api = deps.bot_api(token)
        except ValueError as exc:
            raise _fail(
                console, "The stored bot token is malformed. Run: bastion telegram setup"
            ) from exc
        try:
            asyncio.run(_pair(api, code, console, audit, vault))
        except PairingError as exc:
            audit.append("telegram.pairing_failed", {"reason": str(exc)})
            raise _fail(console, f"Not paired: {exc}.") from exc
        except TelegramError as exc:
            raise _fail(console, f"Could not talk to Telegram: {exc}") from exc
    console.print(
        "[green]Paired.[/] Next: [bold]bastion telegram totp[/], then [bold]bastion daemon[/]"
    )


@telegram_app.command("unpair")
def unpair() -> None:
    """Forget the paired account: the bot then ignores everyone until you pair again."""
    console = Console()
    with audit_session(console) as audit:
        try:
            clear_owner(_vault())
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        audit.append("telegram.unpaired", {}, checkpoint=True)
    console.print("Unpaired. A running [bold]bastion daemon[/] stops at its next message.")


def _show_secret(console: Console, secret: str) -> None:
    grouped = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    console.print(
        "Add Bastion to your authenticator app (Google Authenticator, 1Password, Aegis, ...)."
    )
    console.print(Text(f"  Setup key: {grouped}", style="bold"))
    console.print(Text(f"  Or import: {provisioning_uri(secret)}"))
    console.print("Keep this key private: anyone with it can produce your approval codes.")


@telegram_app.command("totp")
def totp() -> None:
    """Set up an authenticator app: Telegram then asks for its code on high-risk actions."""
    console = Console()
    with audit_session(console) as audit:
        vault = _vault()
        try:
            enrolled = vault.get(TOTP_SECRET) is not None
        except VaultError as exc:
            raise _fail(console, str(exc)) from exc
        if enrolled and not typer.confirm(
            "An authenticator is already set up. Replace it?", default=False
        ):
            raise typer.Exit(1)
        secret = new_secret()
        _show_secret(console, secret)
        verifier = TotpVerifier(secret)
        for _ in range(MAX_ENROLL_ATTEMPTS):
            if verifier.verify(str(typer.prompt("Enter the 6-digit code your app shows"))):
                try:
                    vault.set(TOTP_SECRET, secret)
                except VaultError as exc:
                    raise _fail(console, f"Could not save the authenticator: {exc}") from exc
                audit.append("totp.enrolled", {}, checkpoint=True)
                console.print(
                    "[green]Authenticator set up.[/] A running [bold]bastion daemon[/] stops at "
                    "its next message; start it again to use the new authenticator."
                )
                return
            console.print(
                "[yellow]That code did not match.[/] Check the key, and that your phone's clock "
                "is set automatically."
            )
        raise _fail(console, "Not set up.")
