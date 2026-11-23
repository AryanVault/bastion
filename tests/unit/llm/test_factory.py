from typing import Any

import pytest

from bastion.config import LLMSettings
from bastion.llm.anthropic_provider import AnthropicProvider
from bastion.llm.factory import ProviderConfigError, build_provider, validate_base_url
from bastion.llm.openai_provider import OpenAICompatProvider
from bastion.security.redact import Redactor
from bastion.security.vault import MemoryStore, MissingSecretError, Vault


def vault_with(**secrets: str) -> Vault:
    vault = Vault(MemoryStore(), Redactor())
    for name, value in secrets.items():
        vault.set(name.replace("__", "."), value)
    return vault


def client_of(provider: Any) -> Any:
    return provider._client


def test_anthropic_uses_the_keyring_key_and_the_official_endpoint() -> None:
    provider = build_provider(
        LLMSettings(), vault_with(llm__anthropic__api_key="sk-ant-test-123456")
    )

    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-opus-5-5"
    assert "api.anthropic.com" in str(client_of(provider).base_url)


@pytest.mark.security
def test_environment_variables_cannot_redirect_the_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://evil.example")

    anthropic_provider = build_provider(
        LLMSettings(), vault_with(llm__anthropic__api_key="sk-ant-test-123456")
    )
    openai_provider = build_provider(
        LLMSettings(provider="openai", model="m", effort=None),
        vault_with(llm__openai__api_key="sk-test-1234567"),  # gitleaks:allow (dummy test key)
    )

    assert "evil.example" not in str(client_of(anthropic_provider).base_url)
    assert "evil.example" not in str(client_of(openai_provider).base_url)


def test_local_providers_need_no_key() -> None:
    provider = build_provider(
        LLMSettings(provider="ollama", model="llama3", effort=None), vault_with()
    )

    assert isinstance(provider, OpenAICompatProvider)
    assert provider.name == "ollama"


def test_a_missing_key_is_reported() -> None:
    with pytest.raises(MissingSecretError):
        build_provider(LLMSettings(), vault_with())


def test_unknown_providers_are_rejected() -> None:
    with pytest.raises(ProviderConfigError, match="unknown provider"):
        build_provider(LLMSettings(provider="mystery"), vault_with())


def test_the_custom_provider_needs_a_base_url() -> None:
    with pytest.raises(ProviderConfigError, match="base_url"):
        build_provider(LLMSettings(provider="custom", model="m", effort=None), vault_with())


@pytest.mark.parametrize(
    "url",
    [
        "http://llm.example.com/v1",
        "ftp://llm.example.com",
        "https://user:pw@llm.example.com/v1",
        "https://",
    ],
)
def test_insecure_base_urls_are_rejected(url: str) -> None:
    with pytest.raises(ProviderConfigError):
        validate_base_url(url)


@pytest.mark.parametrize(
    "url", ["https://llm.example.com/v1", "http://localhost:11434/v1", "http://127.0.0.1:8000"]
)
def test_secure_or_local_base_urls_are_accepted(url: str) -> None:
    assert validate_base_url(url) == url


def test_anthropic_output_limits_that_need_streaming_are_refused() -> None:
    with pytest.raises(ProviderConfigError, match="streaming"):
        build_provider(
            LLMSettings(max_output_tokens=32_000),
            vault_with(llm__anthropic__api_key="sk-ant-test-123456"),
        )


@pytest.mark.security
def test_llm_clients_ignore_proxies_and_never_follow_redirects() -> None:
    providers = [
        build_provider(LLMSettings(), vault_with(llm__anthropic__api_key="sk-ant-test-123456")),
        build_provider(LLMSettings(provider="ollama", model="m"), vault_with()),
    ]

    for provider in providers:
        http_client = client_of(provider)._client
        assert http_client.follow_redirects is False
        assert http_client.trust_env is False
