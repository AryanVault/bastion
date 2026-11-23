"""Build the configured LLM provider. Any supported provider works; security does not change.

Base URLs are always passed explicitly, so ``ANTHROPIC_BASE_URL`` / ``OPENAI_BASE_URL``
environment variables cannot silently redirect prompts (and API keys) to another server.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

import anthropic
import openai

from bastion.config import LLMSettings
from bastion.llm.anthropic_provider import AnthropicProvider
from bastion.llm.openai_provider import MaxTokensParam, OpenAICompatProvider
from bastion.llm.types import LLMProvider
from bastion.security.vault import Vault, llm_api_key

ANTHROPIC_BASE_URL = "https://api.anthropic.com"
# The Anthropic SDK refuses non-streaming requests that could run past 10 minutes
# (max_tokens above about 21,333); stay safely below that.
ANTHROPIC_MAX_OUTPUT_TOKENS = 21_000
OPENAI_BASE_URL = "https://api.openai.com/v1"
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class ProviderConfigError(Exception):
    """The LLM provider settings are invalid."""


@dataclass(frozen=True)
class ProviderPreset:
    kind: Literal["anthropic", "openai"]
    base_url: str | None
    needs_key: bool
    default_model: str | None = None
    max_tokens_param: MaxTokensParam = "max_tokens"


PRESETS: Mapping[str, ProviderPreset] = MappingProxyType(
    {
        "anthropic": ProviderPreset("anthropic", ANTHROPIC_BASE_URL, True, "claude-opus-5-5"),
        "openai": ProviderPreset("openai", OPENAI_BASE_URL, True, None, "max_completion_tokens"),
        "gemini": ProviderPreset(
            "openai", "https://generativelanguage.googleapis.com/v1beta/openai/", True
        ),
        # OpenRouter model IDs are "<vendor>/<model>", with dots in versions.
        "openrouter": ProviderPreset(
            "openai", "https://openrouter.ai/api/v1", True, "anthropic/claude-sonnet-5.5"
        ),
        "groq": ProviderPreset("openai", "https://api.groq.com/openai/v1", True),
        "mistral": ProviderPreset("openai", "https://api.mistral.ai/v1", True),
        "ollama": ProviderPreset("openai", "http://localhost:11434/v1", False),
        "custom": ProviderPreset("openai", None, True),
    }
)


def validate_base_url(url: str) -> str:
    """Prompts and API keys travel to this URL, so it must be HTTPS (plain HTTP only locally)."""
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise ProviderConfigError("the base URL must not contain credentials")
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS:
        return url
    raise ProviderConfigError(
        "the base URL must use https (plain http is allowed only for localhost)"
    )


def build_provider(settings: LLMSettings, vault: Vault) -> LLMProvider:
    preset = PRESETS.get(settings.provider)
    if preset is None:
        choices = ", ".join(PRESETS)
        raise ProviderConfigError(f"unknown provider '{settings.provider}' (choose: {choices})")
    base_url = settings.base_url or preset.base_url
    if base_url is None:
        raise ProviderConfigError(f"provider '{settings.provider}' needs base_url in config.toml")
    validate_base_url(base_url)
    if preset.kind == "anthropic":
        return _anthropic(settings, base_url, vault)
    api_key = vault.require(llm_api_key(settings.provider)) if preset.needs_key else "unused"
    # Ignore proxy/certificate environment variables, and never follow redirects: a redirect
    # could carry the API key (and every prompt) to another host.
    http_client = openai.DefaultAsyncHttpxClient(trust_env=False, follow_redirects=False)
    return OpenAICompatProvider(
        openai.AsyncOpenAI(api_key=api_key, base_url=base_url, http_client=http_client),
        settings.model,
        name=settings.provider,
        max_tokens_param=preset.max_tokens_param,
    )


def _anthropic(settings: LLMSettings, base_url: str, vault: Vault) -> AnthropicProvider:
    if settings.max_output_tokens > ANTHROPIC_MAX_OUTPUT_TOKENS:
        raise ProviderConfigError(
            f"max_output_tokens above {ANTHROPIC_MAX_OUTPUT_TOKENS} needs streaming, which "
            "Bastion does not use yet; lower it in config.toml"
        )
    # Same hardening as above. This matters doubly here: Anthropic authenticates with an
    # x-api-key header, which HTTP clients do not strip on cross-origin redirects.
    http_client = anthropic.DefaultAsyncHttpxClient(trust_env=False, follow_redirects=False)
    client = anthropic.AsyncAnthropic(
        api_key=vault.require(llm_api_key(settings.provider)),
        base_url=base_url,
        http_client=http_client,
    )
    return AnthropicProvider(client, settings.model, effort=settings.effort)
