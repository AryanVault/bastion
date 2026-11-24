"""Secrets on machines without an OS keyring: servers and containers (control C8, headless).

Set ``BASTION_SECRET_STORE=file`` and point ``BASTION_MASTER_KEY_FILE`` at a file holding a
32-byte master key (base64 or hex), kept *outside* Bastion's home: a Docker secret, or a file
only the service account can read. Each secret is then stored in ``secrets.db`` in Bastion's
home, sealed with AES-GCM under that key, with the secret's name bound in as associated data
so values cannot be swapped between names.

What this protects: a copy of the data directory (a backup, a stolen volume) reveals no
secret without the master key. What it does not: anyone who can read both, such as code
running as the service account, can read every secret, just as code running as the owner can
read the OS keyring. SQLite makes concurrent writers (the daemon and a CLI command) safe.
"""

import base64
import binascii
import contextlib
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from bastion.security.crypto import KEY_BYTES, DecryptionError, FieldCipher, generate_key
from bastion.security.vault import KeyringStore, SecretStore, VaultError

STORE_ENV = "BASTION_SECRET_STORE"
MASTER_KEY_ENV = "BASTION_MASTER_KEY_FILE"
SEALED_FILE = "secrets.db"
MAX_KEY_FILE_BYTES = 512
_BUSY_TIMEOUT_SECONDS = 10.0


def parse_master_key(text: str) -> bytes:
    """A master key from its text form: 64 hex digits, or base64 of 32 bytes."""
    value = text.strip()
    candidates: list[bytes] = []
    with contextlib.suppress(ValueError):
        candidates.append(bytes.fromhex(value))
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidates.append(decode(value + "=" * (-len(value) % 4)))
        except (binascii.Error, ValueError):
            continue
    for key in candidates:
        if len(key) == KEY_BYTES:
            return key
    raise VaultError(f"the master key must be {KEY_BYTES} bytes, written as base64 or hex")


def read_master_key(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_KEY_FILE_BYTES + 1)
    except OSError as exc:
        raise VaultError(f"cannot read the master key file {path} ({exc.strerror})") from exc
    if len(data) > MAX_KEY_FILE_BYTES:
        raise VaultError(f"{path} is too large to be a master key file")
    try:
        return parse_master_key(data.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise VaultError(f"{path} does not contain a master key") from exc


def new_master_key() -> str:
    """A fresh master key in its text form (base64)."""
    return base64.b64encode(generate_key()).decode("ascii")


def write_master_key(path: Path) -> None:
    """Create ``path`` holding a new master key, readable only by its owner. Never overwrites."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(new_master_key() + "\n")


class SealedStore:
    """Secrets sealed with a master key in an SQLite file. The key is read on first use, so a
    missing or wrong key surfaces as a ``VaultError`` exactly where keyring errors would."""

    def __init__(self, path: Path, master_key: Callable[[], bytes]) -> None:
        self._path = path
        self._master_key = master_key
        self._cipher: FieldCipher | None = None

    @property
    def path(self) -> Path:
        return self._path

    def _seal(self) -> FieldCipher:
        if self._cipher is None:
            self._cipher = FieldCipher(self._master_key())
        return self._cipher

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with closing(
                sqlite3.connect(self._path, timeout=_BUSY_TIMEOUT_SECONDS, isolation_level=None)
            ) as conn:
                if os.name == "posix":
                    self._path.chmod(0o600)
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS secrets "
                    "(name TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT"
                )
                yield conn
        except (sqlite3.Error, OSError) as exc:
            reason = f"the sealed secret store is unavailable ({type(exc).__name__})"
            raise VaultError(reason) from exc

    def get(self, name: str) -> str | None:
        cipher = self._seal()  # a bad master key fails here, before the file is touched
        with self._db() as conn:
            row = conn.execute("SELECT value FROM secrets WHERE name = ?", (name,)).fetchone()
        if row is None:
            return None
        try:
            return cipher.decrypt(row[0], context=_context(name))
        except DecryptionError as exc:
            raise VaultError(
                f"the stored secret {name} failed its integrity check (wrong master key, or "
                "the file was changed)"
            ) from exc

    def set(self, name: str, value: str) -> None:
        sealed = self._seal().encrypt(value, context=_context(name))
        with self._db() as conn:
            conn.execute(
                "INSERT INTO secrets (name, value) VALUES (?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                (name, sealed),
            )

    def delete(self, name: str) -> None:
        self._seal()
        with self._db() as conn:
            conn.execute("DELETE FROM secrets WHERE name = ?", (name,))


class UnavailableStore:
    """Stands in when the configured store cannot be used: every access explains why."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def get(self, name: str) -> str | None:
        raise VaultError(self.reason)

    def set(self, name: str, value: str) -> None:
        raise VaultError(self.reason)

    def delete(self, name: str) -> None:
        raise VaultError(self.reason)


def _context(name: str) -> str:
    return f"secret:{name}"


def store_from_environment(home: Path) -> SecretStore:
    """The secret store chosen by ``BASTION_SECRET_STORE``: the OS keyring (default) or the
    sealed file store. Problems are reported on first use, like keyring errors."""
    kind = os.environ.get(STORE_ENV, "keyring").strip().lower()
    if kind == "keyring":
        return KeyringStore()
    if kind != "file":
        return UnavailableStore(f"{STORE_ENV} must be 'keyring' or 'file', not {kind!r}")
    key_file = os.environ.get(MASTER_KEY_ENV, "").strip()
    if not key_file:
        return UnavailableStore(f"{STORE_ENV}=file needs {MASTER_KEY_ENV} (the master key file)")
    key_path = Path(key_file).expanduser()
    if key_path.resolve().is_relative_to(home.resolve()):
        return UnavailableStore(
            f"keep the master key outside {home}: a copy of that folder must not unlock it"
        )
    return SealedStore(home / SEALED_FILE, lambda: read_master_key(key_path))


def describe_store(store: SecretStore) -> str:
    if isinstance(store, SealedStore):
        return f"an encrypted file ({store.path}), sealed with the master key"
    if isinstance(store, UnavailableStore):
        return f"unavailable: {store.reason}"
    return "the OS keyring"
