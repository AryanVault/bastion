"""``bastion daemon`` runs the always-on Telegram bot; ``bastion resume`` lifts ``/stop``."""

import asyncio

import typer
from rich.console import Console
from rich.markup import escape
from rich.text import Text

from bastion.cli import deps
from bastion.cli.admin import audit_session
from bastion.cli.chat import open_session_runtime
from bastion.config import bastion_home
from bastion.runtime import Runtime
from bastion.security.killswitch import KillSwitch
from bastion.security.totp import TotpError, TotpVerifier
from bastion.security.vault import TELEGRAM_TOKEN, TOTP_SECRET, VaultError
from bastion.telegram.api import TelegramApi, TelegramError
from bastion.telegram.approver import TelegramApprover
from bastion.telegram.bot import TelegramBot
from bastion.telegram.pairing import Owner, load_owner


def _fail(console: Console, message: str) -> typer.Exit:
    console.print(f"[red]{escape(message)}[/]")
    return typer.Exit(1)


def _telegram_config(runtime: Runtime, console: Console) -> tuple[str, Owner, TotpVerifier | None]:
    try:
        token = runtime.vault.get(TELEGRAM_TOKEN)
        owner = load_owner(runtime.vault)
        secret = runtime.vault.get(TOTP_SECRET)
        totp = TotpVerifier(secret) if secret else None
    except (VaultError, TotpError) as exc:
        raise _fail(console, f"Cannot start: {exc}") from exc
    if token is None:
        raise _fail(console, "No Telegram bot yet. Run: bastion telegram setup")
    if owner is None:
        raise _fail(console, "No Telegram account is paired. Run: bastion telegram pair")
    if totp is None:
        console.print(
            Text(
                "! No authenticator app is set up, so actions that need one will be refused. "
                "Run: bastion telegram totp",
                style="yellow",
            )
        )
    return token, owner, totp


async def _serve(
    runtime: Runtime,
    api: TelegramApi,
    owner: Owner,
    totp: TotpVerifier | None,
    console: Console,
) -> None:
    try:
        me = await api.get_me()
        approver = TelegramApprover(
            api, owner, audit=runtime.audit, totp=totp, redactor=runtime.redactor
        )
        bot = TelegramBot(
            api=api,
            owner=owner,
            agent=runtime.agent(approver),
            approver=approver,
            audit=runtime.audit,
            switch=KillSwitch(runtime.home),
            redactor=runtime.redactor,
            settings=runtime.settings.telegram,
            model_label=f"{runtime.provider.name} / {runtime.provider.model}",
            warn=lambda message: console.print(Text(f"! {message}", style="yellow")),
        )
        console.print(
            f"Bastion is online as @{escape(me.username or me.first_name)}. Ctrl+C stops it."
        )
        await bot.run()
    finally:
        await api.aclose()
        await runtime.aclose()


def daemon() -> None:
    """Run Bastion on Telegram, always on (long polling: no open ports). Ctrl+C stops it."""
    console = Console()
    runtime = open_session_runtime(console)
    try:
        token, owner, totp = _telegram_config(runtime, console)
        for notice in runtime.notices:
            console.print(Text(f"! {notice}", style="yellow"))
        asyncio.run(_serve(runtime, deps.bot_api(token), owner, totp, console))
    except KeyboardInterrupt:
        console.print("Stopped.")
    except TelegramError as exc:
        if exc.unauthorized:
            raise _fail(
                console, "Telegram rejected the bot token. Run: bastion telegram setup"
            ) from exc
        raise _fail(console, f"Telegram error: {exc}") from exc
    finally:
        runtime.close()


def resume() -> None:
    """Release the emergency stop (/stop) so the Telegram bot accepts requests again."""
    console = Console()
    switch = KillSwitch(bastion_home())
    if not switch.engaged():
        console.print("Bastion is not stopped.")
        return
    with audit_session(console) as audit:
        switch.release()
        audit.append("killswitch.released", {"via": "cli"}, checkpoint=True)
    console.print("[green]Resumed.[/] The Telegram bot accepts requests again.")
