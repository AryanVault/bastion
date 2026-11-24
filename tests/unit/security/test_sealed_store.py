import base64
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from bastion.security.crypto import generate_key
from bastion.security.sealed_store import (
    MASTER_KEY_ENV,
    SEALED_FILE,
    STORE_ENV,
    SealedStore,
    UnavailableStore,
    describe_store,
    parse_master_key,
    read_master_key,
    store_from_environment,
    write_master_key,
)
from bastion.security.vault import KeyringStore, VaultError

SECRET = "sk-ant-api03-sandbox-value-0001"
KEY = generate_key()


def sealed(tmp_path: Path, key: bytes = KEY) -> SealedStore:
    return SealedStore(tmp_path / "home" / SEALED_FILE, lambda: key)


def test_secrets_round_trip(tmp_path: Path) -> None:
    store = sealed(tmp_path)

    store.set("llm.anthropic.api_key", SECRET)
    store.set("llm.anthropic.api_key", SECRET + "2")  # replaced, not duplicated

    assert store.get("llm.anthropic.api_key") == SECRET + "2"
    assert store.get("missing.name") is None
    store.delete("llm.anthropic.api_key")
    assert store.get("llm.anthropic.api_key") is None


@pytest.mark.security
def test_values_are_encrypted_at_rest(tmp_path: Path) -> None:
    store = sealed(tmp_path)
    store.set("llm.anthropic.api_key", SECRET)

    assert SECRET.encode() not in store.path.read_bytes()


@pytest.mark.security
def test_a_copy_of_the_data_folder_is_useless_without_the_master_key(tmp_path: Path) -> None:
    sealed(tmp_path).set("llm.anthropic.api_key", SECRET)

    with pytest.raises(VaultError, match="integrity check"):
        sealed(tmp_path, generate_key()).get("llm.anthropic.api_key")


@pytest.mark.security
def test_values_cannot_be_swapped_between_names(tmp_path: Path) -> None:
    store = sealed(tmp_path)
    store.set("telegram.owner", "111")
    store.set("auth.totp_secret", "JBSWY3DPEHPK3PXP")
    with closing(sqlite3.connect(store.path)) as conn, conn:
        totp = conn.execute("SELECT value FROM secrets WHERE name='auth.totp_secret'").fetchone()
        conn.execute("UPDATE secrets SET value = ? WHERE name = 'telegram.owner'", totp)

    with pytest.raises(VaultError):
        store.get("telegram.owner")


def test_two_writers_do_not_lose_each_others_secrets(tmp_path: Path) -> None:
    daemon, cli = sealed(tmp_path), sealed(tmp_path)

    daemon.set("audit.chain_head", "12:abc")
    cli.set("auth.totp_secret", "JBSWY3DPEHPK3PXP")

    assert cli.get("audit.chain_head") == "12:abc"
    assert daemon.get("auth.totp_secret") == "JBSWY3DPEHPK3PXP"


@pytest.mark.parametrize(
    "text",
    [KEY.hex(), base64.b64encode(KEY).decode(), base64.urlsafe_b64encode(KEY).decode().rstrip("=")],
)
def test_master_keys_can_be_hex_or_base64(text: str) -> None:
    assert parse_master_key(f"  {text}  ") == KEY


@pytest.mark.parametrize("text", ["", "short", base64.b64encode(b"x" * 16).decode(), "zz" * 32])
def test_bad_master_keys_are_refused(text: str) -> None:
    with pytest.raises(VaultError, match="32 bytes"):
        parse_master_key(text)


def test_a_new_master_key_file_is_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "master.key"

    write_master_key(path)

    assert len(read_master_key(path)) == 32
    with pytest.raises(FileExistsError):
        write_master_key(path)


def test_unreadable_or_oversized_key_files_are_vault_errors(tmp_path: Path) -> None:
    big = tmp_path / "big.key"
    big.write_text("a" * 1000, encoding="ascii")

    with pytest.raises(VaultError, match="cannot read"):
        read_master_key(tmp_path / "absent.key")
    with pytest.raises(VaultError, match="too large"):
        read_master_key(big)


def test_a_missing_master_key_shows_up_on_first_use(tmp_path: Path) -> None:
    store = SealedStore(tmp_path / SEALED_FILE, lambda: read_master_key(tmp_path / "absent"))

    with pytest.raises(VaultError, match="cannot read the master key"):
        store.get("llm.anthropic.api_key")
    assert not store.path.exists()


# --------------------------------------------------------------- choosing


def test_the_os_keyring_is_the_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STORE_ENV, raising=False)

    store = store_from_environment(tmp_path)

    assert isinstance(store, KeyringStore)
    assert describe_store(store) == "the OS keyring"


def test_the_file_store_uses_the_master_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "secrets" / "master.key"
    key.parent.mkdir()
    write_master_key(key)
    monkeypatch.setenv(STORE_ENV, "file")
    monkeypatch.setenv(MASTER_KEY_ENV, str(key))

    store = store_from_environment(tmp_path / "home")
    store.set("llm.anthropic.api_key", SECRET)

    assert isinstance(store, SealedStore)
    assert store.get("llm.anthropic.api_key") == SECRET
    assert "encrypted file" in describe_store(store)


@pytest.mark.parametrize(
    ("kind", "key_file", "reason"),
    [
        ("vault", None, "must be 'keyring' or 'file'"),
        ("file", None, MASTER_KEY_ENV),
        ("file", "home/master.key", "outside"),
    ],
)
def test_misconfigured_stores_explain_themselves_on_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, key_file: str | None, reason: str
) -> None:
    monkeypatch.setenv(STORE_ENV, kind)
    if key_file is None:
        monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(MASTER_KEY_ENV, str(tmp_path / key_file))

    store = store_from_environment(tmp_path / "home")

    assert isinstance(store, UnavailableStore)
    assert reason in describe_store(store)
    with pytest.raises(VaultError):
        store.get("a.b")
    with pytest.raises(VaultError):
        store.set("a.b", "v")
    with pytest.raises(VaultError):
        store.delete("a.b")
