import asyncio
import sys
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pyotp
import pytest
from typer.testing import CliRunner, Result

from bastion.cli import app, deps
from bastion.cli import telegram as telegram_cli
from bastion.config import DATABASE_FILE
from bastion.security.audit import AuditLog
from bastion.security.killswitch import KillSwitch
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    TELEGRAM_OWNER,
    TELEGRAM_TOKEN,
    TOTP_SECRET,
    MemoryStore,
    Vault,
)
from bastion.storage.db import connect
from bastion.telegram.api import BotApi, TelegramApi, TelegramError, Update, User
from bastion.telegram.bot import HELP
from bastion.telegram.pairing import MAX_TOTAL_ATTEMPTS
from support.fakes import ScriptedProvider
from support.telegram import OWNER_ID, STRANGER_ID, FakeTelegramApi, message

TOKEN = "123456789:" + "B" * 35  # gitleaks:allow (dummy test token)
CODE = "ABCD2345"
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@dataclass
class Env:
    home: Path
    store: MemoryStore
    monkeypatch: pytest.MonkeyPatch
    api: FakeTelegramApi | None = None

    def use_api(self, api: FakeTelegramApi) -> FakeTelegramApi:
        self.api = api
        self.monkeypatch.setattr(deps, "bot_api", lambda token: api)
        return api

    def events(self) -> list[str]:
        vault = Vault(self.store, Redactor())
        with closing(connect(self.home / DATABASE_FILE)) as conn:
            log = AuditLog(conn, vault.key(AUDIT_KEY), Redactor())
            return [entry.event for entry in log.tail(200)]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    store = MemoryStore()
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(deps, "secret_store", lambda: store)
    monkeypatch.setattr(telegram_cli, "new_code", lambda: CODE)
    environment = Env(tmp_path / "home", store, monkeypatch)
    result = run(["init", "--provider", "ollama", "--model", "llama3"], stdin="\n")
    assert result.exit_code == 0, result.output
    yield environment


def run(args: list[str], stdin: str | None = None) -> Result:
    return CliRunner().invoke(app, args, input=stdin)


def flat(result: Result) -> str:
    return " ".join(result.output.split())


def paired(env: Env) -> None:
    env.store.set(TELEGRAM_TOKEN, TOKEN)
    env.store.set(TELEGRAM_OWNER, f"{OWNER_ID}:{OWNER_ID}")


# -------------------------------------------------------------------- setup


def test_setup_checks_the_token_and_stores_it_in_the_keyring(env: Env) -> None:
    api = env.use_api(FakeTelegramApi())

    result = run(["telegram", "setup"], stdin=f"{TOKEN}\n")

    assert result.exit_code == 0, result.output
    assert env.store.get(TELEGRAM_TOKEN) == TOKEN
    assert TOKEN not in result.output
    assert "@bastion_test_bot" in result.output
    assert api.closed
    assert "telegram.setup" in env.events()


def test_setup_rejects_something_that_is_not_a_token(env: Env) -> None:
    result = run(["telegram", "setup"], stdin="not-a-token\n")

    assert result.exit_code == 1
    assert "does not look like a bot token" in flat(result)
    assert env.store.get(TELEGRAM_TOKEN) is None


def test_setup_reports_a_token_telegram_rejects(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    class Rejecting(FakeTelegramApi):
        async def get_me(self) -> User:
            raise TelegramError("Telegram API 401: Unauthorized", status=401)

    env.use_api(Rejecting())

    result = run(["telegram", "setup"], stdin=f"{TOKEN}\n")

    assert result.exit_code == 1
    assert "did not accept the token" in flat(result)
    assert env.store.get(TELEGRAM_TOKEN) is None


def test_setup_refuses_a_user_account_token(env: Env) -> None:
    api = env.use_api(FakeTelegramApi())
    api.me = User(5, False, "Human")

    result = run(["telegram", "setup"], stdin=f"{TOKEN}\n")

    assert result.exit_code == 1
    assert "does not belong to a bot" in flat(result)


# --------------------------------------------------------------------- pair


def test_pairing_needs_the_code_and_the_owners_confirmation(env: Env) -> None:
    env.store.set(TELEGRAM_TOKEN, TOKEN)
    api = env.use_api(FakeTelegramApi([], [message(1, "/pair ABCD-2345")], block_when_idle=False))

    result = run(["telegram", "pair"], stdin="y\n")

    assert result.exit_code == 0, result.output
    assert "/pair ABCD-2345" in result.output
    assert f"Telegram user id {OWNER_ID}" in flat(result)
    assert env.store.get(TELEGRAM_OWNER) == f"{OWNER_ID}:{OWNER_ID}"
    assert api.texts[-1].startswith("Paired.")
    assert api.closed
    assert "telegram.paired" in env.events()


@pytest.mark.security
def test_pairing_is_refused_when_the_owner_does_not_recognise_the_sender(env: Env) -> None:
    env.store.set(TELEGRAM_TOKEN, TOKEN)
    env.use_api(
        FakeTelegramApi(
            [], [message(1, "/pair ABCD-2345", user_id=STRANGER_ID)], block_when_idle=False
        )
    )

    result = run(["telegram", "pair"], stdin="n\n")

    assert result.exit_code == 1
    assert env.store.get(TELEGRAM_OWNER) is None
    assert "telegram.pairing_rejected" in env.events()


@pytest.mark.security
def test_pairing_stops_after_a_flood_of_wrong_codes(env: Env) -> None:
    env.store.set(TELEGRAM_TOKEN, TOKEN)
    guesses = [
        message(i, "/pair GUESS999", user_id=20_000 + i) for i in range(1, MAX_TOTAL_ATTEMPTS + 1)
    ]
    env.use_api(FakeTelegramApi([], guesses, block_when_idle=False))

    result = run(["telegram", "pair"])

    assert result.exit_code == 1
    assert "too many wrong codes" in flat(result)
    assert env.store.get(TELEGRAM_OWNER) is None
    assert "telegram.pairing_failed" in env.events()


def test_a_malformed_stored_token_is_reported(env: Env) -> None:
    env.store.set(TELEGRAM_TOKEN, "not-a-token")
    env.monkeypatch.setattr(deps, "provider_override", lambda: ScriptedProvider())
    env.monkeypatch.setattr(deps, "bot_api", BotApi)

    pairing = run(["telegram", "pair"])
    env.store.set(TELEGRAM_OWNER, f"{OWNER_ID}:{OWNER_ID}")
    serving = run(["daemon"])

    assert pairing.exit_code == 1 and "malformed" in flat(pairing)
    assert serving.exit_code == 1 and "bot token" in flat(serving)


def test_pairing_reports_an_expired_code(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.store.set(TELEGRAM_TOKEN, TOKEN)
    env.use_api(FakeTelegramApi(block_when_idle=False))

    async def never(api: TelegramApi, code: str) -> None:
        return None

    monkeypatch.setattr(telegram_cli, "wait_for_pairing", never)

    result = run(["telegram", "pair"])

    assert result.exit_code == 1
    assert "expired" in flat(result)


def test_pairing_needs_a_bot_first(env: Env) -> None:
    result = run(["telegram", "pair"])

    assert result.exit_code == 1
    assert "bastion telegram setup" in flat(result)


def test_re_pairing_asks_before_replacing_the_owner(env: Env) -> None:
    paired(env)

    result = run(["telegram", "pair"], stdin="n\n")

    assert result.exit_code == 1
    assert env.store.get(TELEGRAM_OWNER) == f"{OWNER_ID}:{OWNER_ID}"


def test_unpair_forgets_the_owner(env: Env) -> None:
    paired(env)

    result = run(["telegram", "unpair"])

    assert result.exit_code == 0
    assert env.store.get(TELEGRAM_OWNER) is None
    assert "telegram.unpaired" in env.events()


# --------------------------------------------------------------------- totp


def test_totp_enrolment_needs_a_working_code(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(telegram_cli, "new_secret", lambda: SECRET)

    result = run(["telegram", "totp"], stdin=f"000000\n{pyotp.TOTP(SECRET).now()}\n")

    assert result.exit_code == 0, result.output
    assert env.store.get(TOTP_SECRET) == SECRET
    assert "did not match" in flat(result)
    assert "JBSW Y3DP" in result.output and "otpauth://totp/" in result.output
    assert "totp.enrolled" in env.events()


def test_totp_is_not_stored_without_a_working_code(env: Env) -> None:
    result = run(["telegram", "totp"], stdin="000000\n000000\n000000\n")

    assert result.exit_code == 1
    assert env.store.get(TOTP_SECRET) is None


def test_totp_asks_before_replacing_an_authenticator(env: Env) -> None:
    env.store.set(TOTP_SECRET, SECRET)

    result = run(["telegram", "totp"], stdin="n\n")

    assert result.exit_code == 1
    assert env.store.get(TOTP_SECRET) == SECRET


# ------------------------------------------------------------ daemon/resume


def test_daemon_needs_a_bot_and_an_owner(env: Env) -> None:
    env.monkeypatch.setattr(deps, "provider_override", lambda: ScriptedProvider())

    no_bot = run(["daemon"])
    env.store.set(TELEGRAM_TOKEN, TOKEN)
    no_owner = run(["daemon"])

    assert no_bot.exit_code == 1 and "bastion telegram setup" in flat(no_bot)
    assert no_owner.exit_code == 1 and "bastion telegram pair" in flat(no_owner)


def test_daemon_serves_the_owner_until_the_token_is_revoked(env: Env) -> None:
    paired(env)
    env.monkeypatch.setattr(deps, "provider_override", lambda: ScriptedProvider())
    api = env.use_api(
        FakeTelegramApi(
            [],
            [message(2, "/help")],
            TelegramError("Telegram API 401: Unauthorized", status=401),
        )
    )

    result = run(["daemon"])

    assert result.exit_code == 1
    assert "online as @bastion_test_bot" in flat(result)
    assert "No authenticator app is set up" in flat(result)
    assert "rejected the bot token" in flat(result)
    assert api.texts[0].startswith("Bastion is online")
    assert HELP in api.texts
    assert api.closed
    assert {"session.start", "session.end"} <= set(env.events())


def test_resume_releases_the_kill_switch(env: Env) -> None:
    from datetime import UTC, datetime

    KillSwitch(env.home).engage(via="telegram", at=datetime.now(UTC))

    result = run(["resume"])
    again = run(["resume"])

    assert result.exit_code == 0 and "Resumed" in result.output
    assert not KillSwitch(env.home).engaged()
    assert "not stopped" in again.output
    assert "killswitch.released" in env.events()


# -------------------------------------------------------------------- audit


def test_audit_verify_checks_a_recorded_checkpoint(env: Env) -> None:
    head = run(["audit", "verify"])
    mark = head.output.rsplit("Chain head: ", 1)[1].split()[0]

    good = run(["audit", "verify", "--checkpoint", mark])
    seq = mark.split(":")[0]
    forged = run(["audit", "verify", "--checkpoint", f"{seq}:{'0' * 16}"])
    future = run(["audit", "verify", "--checkpoint", f"{int(seq) + 50}:{'0' * 16}"])
    malformed = run(["audit", "verify", "--checkpoint", "nonsense"])

    assert good.exit_code == 0 and "1 recorded checkpoint(s) matched" in good.output
    assert forged.exit_code == 1 and "TAMPERED" in forged.output
    assert future.exit_code == 1 and "removed" in flat(future)
    assert malformed.exit_code == 2


def test_secrets_status_lists_the_telegram_entries(env: Env) -> None:
    result = run(["secrets", "status"])

    assert TELEGRAM_TOKEN in result.output and TOTP_SECRET in result.output


@pytest.mark.security
def test_unpairing_stops_a_running_daemon(env: Env) -> None:
    paired(env)
    env.monkeypatch.setattr(deps, "provider_override", lambda: ScriptedProvider())

    class UnpairedMidway(FakeTelegramApi):
        async def get_updates(self, offset: int | None, wait_seconds: int) -> list[Update]:
            if len(self.polls) == 1:  # after startup: the owner runs `bastion telegram unpair`
                env.store.delete(TELEGRAM_OWNER)
            return await super().get_updates(offset, wait_seconds)

    api = env.use_api(UnpairedMidway([], [message(2, "delete everything")]))

    result = run(["daemon"])

    assert result.exit_code == 1
    assert "account or the authenticator changed" in flat(result)
    assert len(api.texts) == 1 and api.texts[0].startswith("Bastion is online")
    assert api.closed


# --------------------------------------------------------------- stopping


def _forget_sigterm() -> None:
    import contextlib
    import signal

    with contextlib.suppress(NotImplementedError, RuntimeError, AttributeError):
        asyncio.get_running_loop().remove_signal_handler(signal.SIGTERM)


async def test_installing_the_stop_handler_never_fails() -> None:
    from bastion.cli.daemon import _stop_on_sigterm

    _stop_on_sigterm()  # a no-op where the platform has no such handlers (Windows)
    _forget_sigterm()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
async def test_sigterm_stops_the_daemon_like_ctrl_c() -> None:
    import os
    import signal

    from bastion.cli.daemon import _stop_on_sigterm

    async def serve() -> None:
        _stop_on_sigterm()
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(5)

    task = asyncio.create_task(serve())
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        _forget_sigterm()
