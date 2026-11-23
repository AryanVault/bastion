import base64

import keyring.backend
import keyring.errors
import pytest

from bastion.security.redact import REDACTED, Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    KeyringStore,
    MemoryStore,
    MissingSecretError,
    Vault,
    VaultError,
    llm_api_key,
)


class InMemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.data: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.data.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.data[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.data:
            raise keyring.errors.PasswordDeleteError("missing")
        del self.data[(service, username)]


@pytest.fixture
def redactor() -> Redactor:
    return Redactor()


@pytest.fixture
def vault(redactor: Redactor) -> Vault:
    return Vault(MemoryStore(), redactor)


def test_missing_secret_is_none(vault: Vault) -> None:
    assert vault.get("search.brave.api_key") is None


def test_set_then_get(vault: Vault) -> None:
    vault.set("search.brave.api_key", "BSA-test-value-123")

    assert vault.get("search.brave.api_key") == "BSA-test-value-123"


def test_loaded_secrets_are_registered_for_redaction(vault: Vault, redactor: Redactor) -> None:
    vault.set("search.brave.api_key", "BSA-test-value-123")

    assert redactor.redact("key=BSA-test-value-123") == f"key={REDACTED}"


def test_require_explains_how_to_fix_a_missing_secret(vault: Vault) -> None:
    with pytest.raises(MissingSecretError, match=r"bastion secrets set llm.anthropic.api_key"):
        vault.require(llm_api_key("anthropic"))


@pytest.mark.parametrize("name", ["", "UPPER.case", "no_dot", "a..b", "a.b c", "../etc", "a.b."])
def test_invalid_names_are_rejected(vault: Vault, name: str) -> None:
    with pytest.raises(VaultError):
        vault.get(name)


@pytest.mark.parametrize("value", ["", " padded ", "two\nlines"])
def test_malformed_values_are_rejected(vault: Vault, value: str) -> None:
    with pytest.raises(VaultError):
        vault.set("search.brave.api_key", value)


def test_key_is_created_once_and_then_reused(vault: Vault) -> None:
    created = vault.key(AUDIT_KEY, create=True)

    assert len(created) == 32
    assert vault.key(AUDIT_KEY) == created


def test_missing_key_is_an_error_unless_creation_is_requested(vault: Vault) -> None:
    with pytest.raises(MissingSecretError):
        vault.key(AUDIT_KEY)


@pytest.mark.parametrize(
    "stored", ["not-base64!!", base64.urlsafe_b64encode(b"short").decode("ascii")]
)
def test_corrupt_keys_are_rejected(stored: str, redactor: Redactor) -> None:
    store = MemoryStore()
    store.set(AUDIT_KEY, stored)

    with pytest.raises(VaultError, match="corrupt"):
        Vault(store, redactor).key(AUDIT_KEY)


def test_delete_removes_a_secret(vault: Vault) -> None:
    vault.set("search.brave.api_key", "BSA-test-value-123")
    vault.delete("search.brave.api_key")

    assert vault.get("search.brave.api_key") is None


def test_keyring_store_namespaces_secrets_under_the_service() -> None:
    backend = InMemoryKeyring()
    store = KeyringStore(backend=backend)

    store.set("audit.hmac_key", "value-1234567")
    store.delete("missing.secret")

    assert backend.data == {("bastion", "audit.hmac_key"): "value-1234567"}
    assert store.get("audit.hmac_key") == "value-1234567"


class LockedKeyring(InMemoryKeyring):
    def get_password(self, service: str, username: str) -> str | None:
        raise keyring.errors.KeyringLocked("locked")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise keyring.errors.KeyringLocked("locked")


def test_keyring_failures_become_vault_errors() -> None:
    store = KeyringStore(backend=LockedKeyring())

    with pytest.raises(VaultError, match="unavailable"):
        store.get("audit.hmac_key")
    with pytest.raises(VaultError, match="unavailable"):
        store.set("audit.hmac_key", "value-1234567")


@pytest.mark.security
def test_insecure_keyring_backends_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring.backends.fail

    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())

    with pytest.raises(VaultError, match="insecure"):
        KeyringStore().get("audit.hmac_key")


def test_vault_anchor_round_trips_through_the_vault(vault: Vault) -> None:
    from bastion.security.vault import VaultAnchor

    anchor = VaultAnchor(vault)
    anchor.set("7:" + "a" * 64)

    assert anchor.get() == "7:" + "a" * 64
