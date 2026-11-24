"""``bastion daemon`` runs the always-on Telegram bot; ``bastion resume`` lifts ``/stop``."""

import asyncio
import contextlib
import signal
from collections.abc import Callable
from dataclasses import dataclass

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
from bastion.security.vault import TELEGRAM_TOKEN, TOTP_SECRET, Vault, VaultError
from bastion.telegram.api import TelegramApi, TelegramError, retry_transient
from bastion.telegram.approver import TelegramApprover
from bastion.telegram.bot import ConfigurationChanged, TelegramBot
from bastion.telegram.pairing import Owner, load_owner


@dataclass(frozen=True)
class _TelegramConfig:
    token: str
    owner: Owner
    totp_secret: str | None


def _fail(console: Console, message: str) -> typer.Exit:
    console.print(f"[red]{escape(message)}[/]")
    return typer.Exit(1)


def _read_config(vault: Vault) -> tuple[str | None, Owner | None, str | None]:
    return vault.get(TELEGRAM_TOKEN), load_owner(vault), vault.get(TOTP_SECRET)


def _telegram_config(runtime: Runtime, console: Console) -> _TelegramConfig:
    try:
        token, owner, secret = _read_config(runtime.vault)
    except VaultError as exc:
        raise _fail(console, f"Cannot start: {exc}") from exc
    if token is None:
        raise _fail(console, "No Telegram bot yet. Run: bastion telegram setup")
    if owner is None:
        raise _fail(console, "No Telegram account is paired. Run: bastion telegram pair")
    if secret is None:
        console.print(
            Text(
                "! No authenticator app is set up, so actions that need one will be refused. "
                "Run: bastion telegram totp",
                style="yellow",
            )
        )
    return _TelegramConfig(token, owner, secret)


def _unchanged(vault: Vault, config: _TelegramConfig) -> Callable[[], bool]:
    """Whether the owner and authenticator are still the ones the bot started with.

    Checked before every update, so `bastion telegram unpair` (say, after losing the phone)
    takes effect at once instead of at the next restart. Fails closed if the keyring is
    unreadable.
    """

    def check() -> bool:
        try:
            _, owner, secret = _read_config(vault)
        except VaultError:
            return False
        return owner == config.owner and secret == config.totp_secret

    return check


async def _serve(
    runtime: Runtime,
    api: TelegramApi,
    config: _TelegramConfig,
    totp: TotpVerifier | None,
    console: Console,
) -> None:
    def warn(message: str) -> None:
        console.print(Text(f"! {message}", style="yellow"))

    _stop_on_sigterm()
    try:
        me = await retry_transient(
            api.get_me,
            on_retry=lambda exc, wait: warn(
                f"Cannot reach Telegram ({exc}); retrying in {wait:.0f}s."
            ),
        )
        approver = TelegramApprover(
            api, config.owner, audit=runtime.audit, totp=totp, redactor=runtime.redactor
        )
        bot = TelegramBot(
            api=api,
            owner=config.owner,
            agent=runtime.agent(approver),
            approver=approver,
            audit=runtime.audit,
            switch=KillSwitch(runtime.home),
            redactor=runtime.redactor,
            settings=runtime.settings.telegram,
            model_label=f"{runtime.provider.name} / {runtime.provider.model}",
            still_valid=_unchanged(runtime.vault, config),
            warn=warn,
            tasks=runtime.task_runner() if runtime.settings.autonomy.enabled else None,
        )
        console.print(
            f"Bastion is online as @{escape(me.username or me.first_name)}. Ctrl+C stops it."
        )
        await bot.run()
    finally:
        try:
            await api.aclose()
        finally:
            await runtime.aclose()


def _stop_on_sigterm() -> None:
    """Treat SIGTERM (``docker stop``, ``systemctl stop``) like Ctrl+C: cancel the main task so
    the bot finishes cleanly and the audit chain is checkpointed, instead of dying mid-write."""
    if not hasattr(signal, "SIGTERM"):
        return
    loop = asyncio.get_running_loop()
    main = asyncio.current_task()
    if main is None:
        return
    with contextlib.suppress(NotImplementedError, RuntimeError):  # Windows has no such handlers
        loop.add_signal_handler(signal.SIGTERM, main.cancel)


def daemon() -> None:
    """Run Bastion on Telegram, always on (long polling: no open ports). Ctrl+C stops it."""
    console = Console()
    runtime = open_session_runtime(console)
    try:
        config = _telegram_config(runtime, console)
        try:
            totp = TotpVerifier(config.totp_secret) if config.totp_secret else None
            api = deps.bot_api(config.token)
        except (TotpError, ValueError) as exc:
            raise _fail(console, f"Cannot start: {exc}") from exc
        for notice in runtime.notices:
            console.print(Text(f"! {notice}", style="yellow"))
        asyncio.run(_serve(runtime, api, config, totp, console))
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("Stopped.")
    except ConfigurationChanged as exc:
        raise _fail(console, f"Stopped: {exc}. Start it again with: bastion daemon") from exc
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
