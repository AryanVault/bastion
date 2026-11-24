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


class TelegramSettings(_Strict):
    # A long-idle conversation is replaced by a fresh one, which also clears its taint.
    idle_reset_minutes: int = Field(default=240, ge=5, le=10_080)
    # Requests the bot accepts from the owner: a burst, refilled at a steady hourly rate. This
    # bounds the cost of a hijacked Telegram account or a stuck client.
    message_burst: int = Field(default=10, ge=1, le=100)
    messages_per_hour: int = Field(default=60, ge=1, le=3_600)


class AutonomySettings(_Strict):
    # Scheduled tasks. Each run gets its own small budget, and each task a rolling 24-hour
    # token budget, so a task that loops or is hijacked stops on its own.
    enabled: bool = True
    max_tasks: int = Field(default=20, ge=1, le=100)
    max_steps: int = Field(default=8, ge=1, le=50)
    max_tool_calls: int = Field(default=16, ge=1, le=100)
    max_run_tokens: int = Field(default=200_000, ge=10_000, le=2_000_000)
    max_daily_tokens: int = Field(default=1_000_000, ge=10_000, le=20_000_000)
    max_consecutive_failures: int = Field(default=3, ge=1, le=20)


class Settings(_Strict):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    search: SearchSettings = Field(default_factory=SearchSettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)
    telegram: TelegramSettings = Field(default_factory=TelegramSettings)
    autonomy: AutonomySettings = Field(default_factory=AutonomySettings)


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
    llm, limits, telegram = settings.llm, settings.limits, settings.telegram
    autonomy = settings.autonomy
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
        "",
        "[telegram]",
        "# A conversation idle this long is replaced by a fresh one (which clears its taint).",
        f"idle_reset_minutes = {telegram.idle_reset_minutes}",
        "# Requests accepted from the owner: a burst, refilled at a steady hourly rate.",
        f"message_burst = {telegram.message_burst}",
        f"messages_per_hour = {telegram.messages_per_hour}",
        "",
        "# Scheduled tasks (bastion tasks). Budgets apply to every run and to each task's day.",
        "[autonomy]",
        f"enabled = {str(autonomy.enabled).lower()}",
        f"max_tasks = {autonomy.max_tasks}",
        f"max_steps = {autonomy.max_steps}",
        f"max_tool_calls = {autonomy.max_tool_calls}",
        f"max_run_tokens = {autonomy.max_run_tokens}",
        f"max_daily_tokens = {autonomy.max_daily_tokens}",
        "# This many failed runs in a row pause the task.",
        f"max_consecutive_failures = {autonomy.max_consecutive_failures}",
    ]
    return "\n".join(lines) + "\n"
