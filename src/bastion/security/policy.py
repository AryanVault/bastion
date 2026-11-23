"""Default-deny policy engine (control C1).

The model can only *propose* a tool call. This engine decides, from the tool's risk tier, the
conversation's taint state and the owner's policy file, whether the call runs, needs the
owner's approval, or is refused. Two floors are enforced in code and cannot be weakened by any
policy file or per-tool override:

* destructive actions always need approval (or are denied);
* send actions need approval whenever the conversation contains untrusted content.
"""

import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from bastion.core.conversation import TaintState
from bastion.tools.base import RiskTier


class PolicyError(Exception):
    """The policy file is invalid or would weaken a hard floor."""


class Verdict(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


_STRICTNESS = {Verdict.ALLOW: 0, Verdict.ASK: 1, Verdict.DENY: 2}

# (tier, tainted) -> the least strict verdict allowed.
_FLOORS: dict[tuple[RiskTier, bool], Verdict] = {
    (RiskTier.DESTRUCTIVE, False): Verdict.ASK,
    (RiskTier.DESTRUCTIVE, True): Verdict.ASK,
    (RiskTier.SEND, True): Verdict.ASK,
}


def _at_least(verdict: Verdict, floor: Verdict) -> Verdict:
    return verdict if _STRICTNESS[verdict] >= _STRICTNESS[floor] else floor


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TierRules(_Strict):
    read: Verdict
    write: Verdict
    send: Verdict
    destructive: Verdict

    def for_tier(self, tier: RiskTier) -> Verdict:
        rules = {
            RiskTier.READ: self.read,
            RiskTier.WRITE: self.write,
            RiskTier.SEND: self.send,
            RiskTier.DESTRUCTIVE: self.destructive,
        }
        return rules[tier]


class ToolRule(_Strict):
    clean: Verdict | None = None
    tainted: Verdict | None = None


class StepUpRules(_Strict):
    tiers: frozenset[RiskTier] = frozenset({RiskTier.DESTRUCTIVE})


class PolicyConfig(_Strict):
    clean: TierRules
    tainted: TierRules
    step_up: StepUpRules = StepUpRules()
    tools: dict[str, ToolRule] = {}

    @model_validator(mode="after")
    def _reject_weakened_floors(self) -> Self:
        if self.tainted.send is Verdict.ALLOW:
            raise ValueError(
                "tainted.send cannot be 'allow': untrusted content could trigger outbound actions"
            )
        for label, rules in (("clean", self.clean), ("tainted", self.tainted)):
            if rules.destructive is Verdict.ALLOW:
                raise ValueError(f"{label}.destructive cannot be 'allow'")
        return self


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    step_up: bool = False


DEFAULT_POLICY_TOML = """\
# Bastion policy. The model can only *propose* tool calls; these rules decide.
# Verdicts: "allow" (run it), "ask" (owner approval bound to the exact arguments), "deny".
#
# Floors enforced in code, which this file cannot weaken:
#   - destructive actions always need approval (or are denied)
#   - send actions always need approval once the conversation contains untrusted content

# The conversation contains only your own messages and trusted data.
[clean]
read = "allow"
write = "allow"
send = "ask"
destructive = "ask"

# The conversation contains untrusted content (web pages, emails, search results, ...).
[tainted]
read = "allow"
write = "ask"
send = "ask"
destructive = "deny"

# Tiers whose approvals also require a one-time code (TOTP).
[step_up]
tiers = ["destructive"]

# Per-tool overrides can tighten anything, but cannot go below the floors above.
[tools.memory_save]
tainted = "allow"  # safe: memories saved while tainted are stored and returned as untrusted
"""


def parse_policy(text: str) -> PolicyConfig:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy is not valid TOML: {exc}") from exc
    try:
        return PolicyConfig.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'policy'}: {err['msg']}"
            for err in exc.errors()
        )
        raise PolicyError(f"invalid policy: {details}") from exc


def load_policy(path: Path) -> PolicyConfig:
    return parse_policy(path.read_text(encoding="utf-8"))


def default_policy() -> PolicyConfig:
    return parse_policy(DEFAULT_POLICY_TOML)


class PolicyEngine:
    def __init__(self, config: PolicyConfig, known_tools: frozenset[str]) -> None:
        self._config = config
        self._known_tools = known_tools

    @property
    def config(self) -> PolicyConfig:
        return self._config

    def decide(self, tool: str, tier: RiskTier, taint: TaintState) -> Decision:
        if tool not in self._known_tools:
            return Decision(Verdict.DENY, f"unknown tool '{tool}' (default deny)")
        tainted = taint.tainted
        verdict = (self._config.tainted if tainted else self._config.clean).for_tier(tier)
        override = self._config.tools.get(tool)
        if override is not None:
            chosen = override.tainted if tainted else override.clean
            verdict = chosen if chosen is not None else verdict
        floor = _FLOORS.get((tier, tainted))
        if floor is not None:
            verdict = _at_least(verdict, floor)
        step_up = verdict is Verdict.ASK and tier in self._config.step_up.tiers
        return Decision(verdict, self._reason(tier, taint, verdict), step_up)

    @staticmethod
    def _reason(tier: RiskTier, taint: TaintState, verdict: Verdict) -> str:
        if taint.tainted:
            return (
                f"{tier.value} action ({verdict.value}) in a conversation containing "
                f"untrusted content from: {taint.describe()}"
            )
        return f"{tier.value} actions are '{verdict.value}' by policy"
