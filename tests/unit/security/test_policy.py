import pytest

from bastion.core.conversation import TaintState
from bastion.security.policy import (
    DEFAULT_POLICY_TOML,
    PolicyEngine,
    PolicyError,
    Verdict,
    default_policy,
    parse_policy,
)
from bastion.tools.base import RiskTier

CLEAN = TaintState()
TAINTED = TaintState(sources=("web_fetch:evil.example",))
TOOLS = frozenset({"web_search", "gmail_send", "memory_save", "files_delete"})


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(default_policy(), known_tools=TOOLS)


def _policy(extra: str = "", *, tainted_send: str = "ask", clean_destructive: str = "ask") -> str:
    return f"""
[clean]
read = "allow"
write = "allow"
send = "ask"
destructive = "{clean_destructive}"

[tainted]
read = "allow"
write = "ask"
send = "{tainted_send}"
destructive = "deny"

[step_up]
tiers = ["destructive"]
{extra}
"""


def test_unknown_tool_is_denied(engine: PolicyEngine) -> None:
    decision = engine.decide("delete_everything", RiskTier.READ, CLEAN)

    assert decision.verdict is Verdict.DENY


@pytest.mark.parametrize(
    ("tier", "expected"),
    [
        (RiskTier.READ, Verdict.ALLOW),
        (RiskTier.WRITE, Verdict.ALLOW),
        (RiskTier.SEND, Verdict.ASK),
        (RiskTier.DESTRUCTIVE, Verdict.ASK),
    ],
)
def test_clean_context_defaults(engine: PolicyEngine, tier: RiskTier, expected: Verdict) -> None:
    assert engine.decide("web_search", tier, CLEAN).verdict is expected


@pytest.mark.parametrize(
    ("tier", "expected"),
    [
        (RiskTier.READ, Verdict.ALLOW),
        (RiskTier.WRITE, Verdict.ASK),
        (RiskTier.SEND, Verdict.ASK),
        (RiskTier.DESTRUCTIVE, Verdict.DENY),
    ],
)
def test_tainted_context_defaults(engine: PolicyEngine, tier: RiskTier, expected: Verdict) -> None:
    assert engine.decide("web_search", tier, TAINTED).verdict is expected


def test_destructive_actions_require_step_up(engine: PolicyEngine) -> None:
    decision = engine.decide("files_delete", RiskTier.DESTRUCTIVE, CLEAN)

    assert decision.verdict is Verdict.ASK
    assert decision.step_up


def test_tainted_reason_names_the_untrusted_sources(engine: PolicyEngine) -> None:
    decision = engine.decide("gmail_send", RiskTier.SEND, TAINTED)

    assert "web_fetch:evil.example" in decision.reason


def test_config_cannot_allow_sends_in_a_tainted_context() -> None:
    with pytest.raises(PolicyError, match="send"):
        parse_policy(_policy(tainted_send="allow"))


def test_config_can_never_allow_destructive_actions() -> None:
    with pytest.raises(PolicyError, match="destructive"):
        parse_policy(_policy(clean_destructive="allow"))


def test_tool_override_cannot_bypass_the_tainted_send_floor() -> None:
    config = parse_policy(_policy('[tools.gmail_send]\ntainted = "allow"'))
    engine = PolicyEngine(config, known_tools=TOOLS)

    decision = engine.decide("gmail_send", RiskTier.SEND, TAINTED)

    assert decision.verdict is Verdict.ASK


def test_tool_override_cannot_allow_destructive_actions() -> None:
    config = parse_policy(_policy('[tools.files_delete]\nclean = "allow"'))
    engine = PolicyEngine(config, known_tools=TOOLS)

    assert engine.decide("files_delete", RiskTier.DESTRUCTIVE, CLEAN).verdict is Verdict.ASK


def test_tool_override_applies_within_the_floors() -> None:
    config = parse_policy(_policy('[tools.memory_save]\ntainted = "allow"'))
    engine = PolicyEngine(config, known_tools=TOOLS)

    assert engine.decide("memory_save", RiskTier.WRITE, TAINTED).verdict is Verdict.ALLOW


def test_tool_override_can_tighten() -> None:
    config = parse_policy(_policy('[tools.web_search]\nclean = "deny"'))
    engine = PolicyEngine(config, known_tools=TOOLS)

    assert engine.decide("web_search", RiskTier.READ, CLEAN).verdict is Verdict.DENY


def test_every_tier_must_be_explicit() -> None:
    text = _policy().replace('send = "ask"\n', "", 1)

    with pytest.raises(PolicyError):
        parse_policy(text)


def test_unknown_keys_are_rejected_to_catch_typos() -> None:
    with pytest.raises(PolicyError):
        parse_policy(_policy().replace('send = "ask"', 'sned = "ask"', 1))


def test_invalid_toml_is_reported_as_policy_error() -> None:
    with pytest.raises(PolicyError):
        parse_policy("[clean\nread = ")


def test_default_policy_matches_the_shipped_toml() -> None:
    assert parse_policy(DEFAULT_POLICY_TOML) == default_policy()
