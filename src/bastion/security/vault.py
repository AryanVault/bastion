"""Secrets vault (control C8).

Secrets (LLM and search API keys, OAuth tokens, the audit and storage keys) live only in the
operating system's credential store: Windows Credential Manager, macOS Keychain, or the Secret
Service on Linux. They never appear in config files, the model's context, or logs: every
value loaded through the vault is registered with the redactor.
"""

import base64
import binascii
import re
import secrets
from typing import Protocol

import keyring
import keyring.backend
import keyring.errors

from bastion.security.redact import Redactor

SERVICE = "bastion"
KEY_BYTES = 32

AUDIT_KEY = "audit.hmac_key"
STORAGE_KEY = "storage.encryption_key"
BRAVE_API_KEY = "search.brave.api_key"
AUDIT_HEAD = "audit.chain_head"
TELEGRAM_TOKEN = "telegram.bot_token"  # noqa: S105  # nosec B105: an entry name, not a value
# Kept in the keyring rather than the database: whoever is the owner can approve actions, so
# rewriting it must need more than write access to a file.
TELEGRAM_OWNER = "telegram.owner"
TOTP_SECRET = "auth.totp_secret"  # noqa: S105  # nosec B105: an entry name, not a value

_NAME = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*(?:\.[a-z0-9]+(?:_[a-z0-9]+)*)+$")
_INSECURE_BACKENDS = ("keyring.backends.fail", "keyring.backends.null", "keyrings.alt")


def _unavailable(exc: Exception) -> str:
    return f"the OS keyring is unavailable ({type(exc).__name__})"


def llm_api_key(provider: str) -> str:
    return f"llm.{provider}.api_key"


class VaultError(Exception):
    """A secret name or value is invalid, or a stored key is corrupt."""


class MissingSecretError(VaultError):
    """A required secret has not been set."""


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class KeyringStore:
    """Secrets in the OS credential store, namespaced under the ``bastion`` service."""

    def __init__(
        self, backend: keyring.backend.KeyringBackend | None = None, service: str = SERVICE
    ) -> None:
        self._backend_override = backend
        self._service = service

    def _backend(self) -> keyring.backend.KeyringBackend:
        if self._backend_override is not None:
            return self._backend_override
        backend = keyring.get_keyring()
        module = type(backend).__module__
        # A plaintext or no-op backend (e.g. selected via PYTHON_KEYRING_BACKEND) would quietly
        # turn "secrets in the OS keyring" into "secrets in a file" or "no secrets at all".
        if module.startswith(_INSECURE_BACKENDS):
            raise VaultError(f"refusing to use the insecure keyring backend {module}")
        return backend

    def get(self, name: str) -> str | None:
        try:
            return self._backend().get_password(self._service, name)
        except keyring.errors.KeyringError as exc:
            raise VaultError(_unavailable(exc)) from exc

    def set(self, name: str, value: str) -> None:
        try:
            self._backend().set_password(self._service, name, value)
        except keyring.errors.KeyringError as exc:
            raise VaultError(_unavailable(exc)) from exc

    def delete(self, name: str) -> None:
        try:
            self._backend().delete_password(self._service, name)
        except keyring.errors.PasswordDeleteError:
            return
        except keyring.errors.KeyringError as exc:
            raise VaultError(_unavailable(exc)) from exc


class MemoryStore:
    """Process-local store for tests and ephemeral runs. Never persists anything."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def set(self, name: str, value: str) -> None:
        self._values[name] = value

    def delete(self, name: str) -> None:
        self._values.pop(name, None)


def _check_name(name: str) -> None:
    if not _NAME.match(name):
        raise VaultError(f"invalid secret name {name!r} (expected dotted lowercase, e.g. a.b_c)")


class Vault:
    def __init__(self, store: SecretStore, redactor: Redactor) -> None:
        self._store = store
        self._redactor = redactor

    def get(self, name: str) -> str | None:
        _check_name(name)
        value = self._store.get(name)
        if not value:
            return None
        self._redactor.register_secret(value)
        return value

    def require(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise MissingSecretError(f"secret '{name}' is not set. Run: bastion secrets set {name}")
        return value

    def set(self, name: str, value: str) -> None:
        _check_name(name)
        if not value or value != value.strip() or "\n" in value or "\r" in value:
            raise VaultError("secret values must be non-empty single-line strings")
        self._store.set(name, value)
        self._redactor.register_secret(value)

    def delete(self, name: str) -> None:
        _check_name(name)
        self._store.delete(name)

    def key(self, name: str, *, create: bool = False) -> bytes:
        """A 32-byte symmetric key. Only ``bastion init`` should pass ``create=True``."""
        stored = self.get(name)
        if stored is None:
            if not create:
                raise MissingSecretError(f"key '{name}' is missing. Run: bastion init")
            new_key = secrets.token_bytes(KEY_BYTES)
            self.set(name, base64.urlsafe_b64encode(new_key).decode("ascii"))
            return new_key
        try:
            decoded = base64.b64decode(stored.encode("ascii"), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VaultError(f"stored key '{name}' is corrupt") from exc
        if len(decoded) != KEY_BYTES:
            raise VaultError(f"stored key '{name}' is corrupt (wrong length)")
        return decoded


class VaultAnchor:
    """Keeps the audit chain head in the OS keyring, outside the database it vouches for."""

    def __init__(self, vault: Vault, name: str = AUDIT_HEAD) -> None:
        self._vault = vault
        self._name = name

    def get(self) -> str | None:
        return self._vault.get(self._name)

    def set(self, value: str) -> None:
        self._vault.set(self._name, value)
