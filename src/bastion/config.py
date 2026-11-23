"""Non-secret configuration, read from ``config.toml`` in the Bastion home directory.

The home directory is ``$BASTION_HOME`` or ``~/.bastion``. Secrets are never stored here:
API keys live in the OS keyring (see ``security/vault.py``).
"""

import json
import os
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

CONFIG_FILE = "config.toml"
POLICY_FILE = "policy.toml"
DATABASE_FILE = "bastion.db"

type Effort = Literal["low", "medium", "high", "xhigh", "max"]


class ConfigError(Exception):
    """Configuration is missing or invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LLMSettings(_Strict):
    provider: str = "anthropic"
    model: str = Field(default="claude-opus-5-5", min_length=1, max_length=200)
    base_url: str | None = None
    # Unset means "don't send it" (some models reject the parameter); `bastion init` writes
    # an explicit value for Anthropic models.
    effort: Effort | None = None
    max_output_tokens: int = Field(default=16_000, ge=256, le=128_000)


class SearchSettings(_Strict):
    provider: Literal["brave", "none"] = "brave"


class LimitSettings(_Strict):
    max_steps: int = Field(default=12, ge=1, le=100)
    max_tool_calls: int = Field(default=24, ge=1, le=500)
    max_turn_tokens: int = Field(default=500_000, ge=10_000, le=10_000_000)


class Settings(_Strict):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    search: SearchSettings = Field(default_factory=SearchSettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)


def bastion_home() -> Path:
    override = os.environ.get("BASTION_HOME")
    return Path(override).expanduser() if override else Path.home() / ".bastion"


def load_settings(home: Path) -> Settings:
    path = home / CONFIG_FILE
    if not path.exists():
        raise ConfigError(f"{path} not found. Run: bastion init")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ConfigError(f"invalid {path}: {details}") from exc


def render_config(settings: Settings) -> str:
    """TOML for ``config.toml``. Strings are JSON-escaped, which is valid TOML."""
    llm, limits = settings.llm, settings.limits
    lines = [
        "# Bastion configuration. Secrets are NOT stored here: they live in the OS keyring.",
        "# Manage them with: bastion secrets set <name>",
        "",
        "[llm]",
        f"provider = {json.dumps(llm.provider)}",
        f"model = {json.dumps(llm.model)}",
    ]
    if llm.base_url:
        lines.append(f"base_url = {json.dumps(llm.base_url)}")
    if llm.effort:
        lines.append(f"effort = {json.dumps(llm.effort)}  # Anthropic models only")
    lines += [
        f"max_output_tokens = {llm.max_output_tokens}",
        "",
        "[search]",
        f'provider = {json.dumps(settings.search.provider)}  # "brave" or "none"',
        "",
        "# Per-request budgets: a runaway or hijacked loop stops here.",
        "[limits]",
        f"max_steps = {limits.max_steps}",
        f"max_tool_calls = {limits.max_tool_calls}",
        f"max_turn_tokens = {limits.max_turn_tokens}",
    ]
    return "\n".join(lines) + "\n"
