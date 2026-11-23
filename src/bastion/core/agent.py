"""The agent loop: the model proposes, the security layer decides (ADR 0001).

For every tool call the model proposes, in order:

1. look the tool up (unknown tools are denied);
2. validate the arguments against the tool's strict schema;
3. ask the policy engine for allow / ask / deny, given the risk tier and the taint state;
4. on "ask", obtain the owner's approval, bound to the exact arguments;
5. run the tool with a timeout, containing any failure;
6. taint the conversation if the output is untrusted, and fence it before the model sees it;
7. audit every step.

The conversation history is append-only: nothing already sent to the model is edited.
"""

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import ValidationError

from bastion.common import utc_now
from bastion.core.conversation import Conversation
from bastion.core.prompts import SYSTEM_PROMPT, fence_untrusted
from bastion.llm.types import (
    Completion,
    LLMProvider,
    Message,
    ProviderError,
    Role,
    StopReason,
    ToolCall,
    ToolResult,
    Usage,
)
from bastion.security.approvals import ApprovalError, ApprovalRequest, ApprovalService
from bastion.security.audit import AuditLog
from bastion.security.egress import extract_urls
from bastion.security.policy import Decision, PolicyEngine, Verdict
from bastion.text import reveal_invisible, strip_invisible
from bastion.tools.base import (
    RiskTier,
    Tool,
    ToolArgs,
    ToolContext,
    ToolDenied,
    ToolError,
    ToolOutput,
    ToolRegistry,
    Trust,
)


class TurnStop(StrEnum):
    COMPLETED = "completed"
    REFUSED = "refused"
    MAX_TOKENS = "max_tokens"
    CONTEXT_EXCEEDED = "context_exceeded"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PROVIDER_ERROR = "provider_error"


@dataclass(frozen=True)
class AgentLimits:
    max_steps: int = 12
    max_tool_calls: int = 24
    max_output_tokens: int = 16_000
    max_turn_tokens: int = 500_000
    tool_timeout_seconds: float = 60.0


@dataclass(frozen=True)
class TurnResult:
    conversation: Conversation
    reply: str
    stop: TurnStop
    usage: Usage
    tool_calls: int


class Approver(Protocol):
    async def request_approval(self, request: ApprovalRequest) -> bool: ...


@dataclass
class _Turn:
    """Working state for one turn. Local to ``run_turn``; never shared."""

    conversation: Conversation
    usage: Usage = field(default_factory=Usage)
    tool_calls: int = 0


_STOPS = {
    StopReason.REFUSAL: TurnStop.REFUSED,
    StopReason.MAX_TOKENS: TurnStop.MAX_TOKENS,
    StopReason.CONTEXT_EXCEEDED: TurnStop.CONTEXT_EXCEEDED,
}
_BUDGET_NOTICE = "I stopped because this request exceeded its step or token budget."


def _sha256(text: str) -> str:
    # backslashreplace: model-supplied lone surrogates must never crash the audit trail.
    return hashlib.sha256(text.encode("utf-8", "backslashreplace")).hexdigest()


def _clip(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _error(call: ToolCall, message: str) -> ToolResult:
    return ToolResult(call.id, f"Error: {message}", is_error=True)


def _describe_validation(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or 'arguments'}: {err['msg']}"
        for err in exc.errors()[:5]
    )


def _reply_text(stop: TurnStop, completion: Completion) -> str:
    text = completion.message.text.strip()
    if stop is TurnStop.REFUSED:
        return text or "The model declined to respond to this request."
    if stop is TurnStop.CONTEXT_EXCEEDED:
        return "This conversation is too long for the model. Please start a new one."
    if stop is TurnStop.MAX_TOKENS:
        return f"{text}\n\n[The response was cut off at the output limit.]"
    return text or "(no response)"


class Agent:
    def __init__(
        self,
        *,
        provider: LLMProvider,
        tools: ToolRegistry,
        policy: PolicyEngine,
        approvals: ApprovalService,
        approver: Approver,
        audit: AuditLog,
        limits: AgentLimits | None = None,
        system_prompt: str = SYSTEM_PROMPT,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._provider = provider
        self._tools = tools
        self._policy = policy
        self._approvals = approvals
        self._approver = approver
        self._audit = audit
        self._limits = limits or AgentLimits()
        self._system_prompt = system_prompt
        self._clock = clock
        # Fixed for the agent's lifetime: a stable prefix keeps prompt caching effective.
        self._specs = tools.specs()

    async def run_turn(self, conversation: Conversation, user_text: str) -> TurnResult:
        turn = _Turn(self._start(conversation, user_text))
        for _ in range(self._limits.max_steps):
            try:
                completion = await self._provider.complete(
                    system=self._system_prompt,
                    messages=turn.conversation.messages,
                    tools=self._specs,
                    max_tokens=self._limits.max_output_tokens,
                )
            except ProviderError as exc:
                self._audit.append("llm.error", {"error": str(exc), "retryable": exc.retryable})
                return self._finish(turn, TurnStop.PROVIDER_ERROR, f"Model provider error: {exc}")
            self._record(turn, completion)
            calls = completion.message.tool_calls
            if calls and completion.stop_reason is StopReason.TOOL_USE:
                results = await self._run_tools(turn, calls)
                turn.conversation = turn.conversation.append(
                    Message(Role.USER, tool_results=results)
                )
                if (
                    turn.usage.input_tokens + turn.usage.output_tokens
                    > self._limits.max_turn_tokens
                ):
                    return self._finish(turn, TurnStop.BUDGET_EXHAUSTED, _BUDGET_NOTICE)
                continue
            if calls:  # proposed but not runnable (e.g. truncated): keep the transcript valid
                skipped = tuple(_error(c, "not executed: the response was cut off.") for c in calls)
                turn.conversation = turn.conversation.append(
                    Message(Role.USER, tool_results=skipped)
                )
            if completion.stop_reason is StopReason.PAUSE:
                continue
            stop = _STOPS.get(completion.stop_reason, TurnStop.COMPLETED)
            return self._finish(turn, stop, _reply_text(stop, completion))
        return self._finish(turn, TurnStop.BUDGET_EXHAUSTED, _BUDGET_NOTICE)

    # ------------------------------------------------------------- bookkeeping

    def _start(self, conversation: Conversation, user_text: str) -> Conversation:
        now = self._clock().astimezone()
        stamped = f"[{now:%a %Y-%m-%d %H:%M %z}] {user_text}"
        # The owner's words are private: audit their size and hash, not the text.
        self._audit.append(
            "turn.start",
            {
                "conversation": conversation.id,
                "chars": len(user_text),
                "sha256": _sha256(user_text),
            },
        )
        return conversation.with_urls(extract_urls(user_text)).append(
            Message(Role.USER, text=stamped)
        )

    def _record(self, turn: _Turn, completion: Completion) -> None:
        turn.usage = turn.usage + completion.usage
        message = completion.message
        if message.text or message.tool_calls:
            turn.conversation = turn.conversation.append(message)
        self._audit.append(
            "llm.call",
            {
                "model": completion.model,
                "stop": completion.stop_reason.value,
                "input_tokens": completion.usage.input_tokens,
                "output_tokens": completion.usage.output_tokens,
                "tool_calls": [c.name for c in message.tool_calls],
            },
        )

    def _finish(self, turn: _Turn, stop: TurnStop, reply: str) -> TurnResult:
        self._audit.append(
            "turn.end",
            {
                "conversation": turn.conversation.id,
                "stop": stop.value,
                "tool_calls": turn.tool_calls,
                "input_tokens": turn.usage.input_tokens,
                "output_tokens": turn.usage.output_tokens,
                "tainted_by": list(turn.conversation.taint.sources),
            },
            checkpoint=True,
        )
        return TurnResult(turn.conversation, reply, stop, turn.usage, turn.tool_calls)

    # ------------------------------------------------------------- tool calls

    async def _run_tools(self, turn: _Turn, calls: tuple[ToolCall, ...]) -> tuple[ToolResult, ...]:
        results: list[ToolResult] = []
        for tool_call in calls:
            if turn.tool_calls >= self._limits.max_tool_calls:
                results.append(
                    _error(tool_call, "not executed: the tool-call budget is exhausted.")
                )
                continue
            turn.tool_calls += 1
            results.append(await self._handle(turn, tool_call))
        return tuple(results)

    async def _handle(self, turn: _Turn, tool_call: ToolCall) -> ToolResult:
        tool = self._tools.get(tool_call.name)
        if tool is None:
            self._audit.append("tool.denied", {"tool": tool_call.name, "reason": "unknown tool"})
            return _error(tool_call, f"unknown tool '{reveal_invisible(tool_call.name)}'.")
        try:
            args = tool.parse_args(tool_call.arguments)
        except ValidationError as exc:
            self._audit.append(
                "tool.invalid_arguments", {"tool": tool.name, "errors": exc.error_count()}
            )
            return _error(
                tool_call, f"invalid arguments for {tool.name}: {_describe_validation(exc)}"
            )
        tier = tool.risk_for(args)
        decision = self._policy.decide(tool.name, tier, turn.conversation.taint)
        self._audit.append(
            "policy.decision",
            {
                "tool": tool.name,
                "tier": tier.value,
                "verdict": decision.verdict.value,
                "reason": decision.reason,
                # A summary, not the arguments: the log must not become a plaintext copy of
                # private data (memory contents, queries) that is encrypted everywhere else.
                "arguments": tool.audit_view(args),
            },
        )
        if decision.verdict is Verdict.DENY:
            return _error(
                tool_call, f"Denied by policy: {decision.reason}. Tell the owner; do not retry."
            )
        if decision.verdict is Verdict.ASK:
            refusal = await self._authorize(tool, args, tier, decision)
            if refusal is not None:
                return _error(tool_call, refusal)
        return await self._execute(turn, tool_call, tool, args)

    async def _authorize(
        self, tool: Tool[Any], args: ToolArgs, tier: RiskTier, decision: Decision
    ) -> str | None:
        """Ask the owner; return None if approved, otherwise the reason to give the model."""
        request = self._approvals.create(
            tool=tool.name,
            tier=tier,
            args=args,
            summary=tool.describe(args),
            reason=decision.reason,
            step_up=decision.step_up,
        )
        self._audit.append(
            "approval.requested",
            {
                "id": request.id,
                "tool": tool.name,
                "digest": request.digest,
                "step_up": request.step_up,
            },
        )
        try:
            approved = await self._approver.request_approval(request)
        except Exception as exc:  # fail closed: a broken approval channel means "no"
            self._audit.append(
                "approval.error", {"id": request.id, "error_type": type(exc).__name__}
            )
            approved = False
        try:
            self._approvals.record_decision(request.id, approved=approved)
            self._audit.append("approval.decision", {"id": request.id, "approved": approved})
            if not approved:
                return "The owner declined this action. Tell the owner; do not retry it."
            self._approvals.consume(request.id, tool.name, args)
        except ApprovalError as exc:
            self._audit.append("approval.rejected", {"id": request.id, "error": str(exc)})
            return f"approval check failed ({exc})."
        return None

    async def _execute(
        self, turn: _Turn, tool_call: ToolCall, tool: Tool[Any], args: ToolArgs
    ) -> ToolResult:
        ctx = ToolContext(
            provenance=turn.conversation.provenance, tainted=turn.conversation.taint.tainted
        )
        try:
            async with asyncio.timeout(self._limits.tool_timeout_seconds):
                output = await tool.run(args, ctx)
        except ToolError as exc:
            return self._tool_error(turn, tool_call, tool, exc)
        except TimeoutError:
            self._audit.append("tool.error", {"tool": tool.name, "error": "timeout"})
            return _error(tool_call, f"{tool.name} timed out.")
        except Exception as exc:  # contain tool bugs: never crash the agent or leak internals
            self._audit.append(
                "tool.crash",
                {"tool": tool.name, "error_type": type(exc).__name__, "error": _clip(str(exc))},
            )
            return _error(tool_call, f"{tool.name} failed unexpectedly.")
        return self._accept(turn, tool_call, tool, output)

    def _tool_error(
        self, turn: _Turn, tool_call: ToolCall, tool: Tool[Any], exc: ToolError
    ) -> ToolResult:
        self._audit.append(
            "tool.error",
            {
                "tool": tool.name,
                "error": _clip(str(exc)),
                "security_denial": isinstance(exc, ToolDenied),
                "untrusted_source": exc.untrusted_source,
            },
        )
        if exc.untrusted_source is None:
            return _error(tool_call, str(exc))
        # The failure happened after talking to an untrusted party: treat it like its output.
        turn.conversation = turn.conversation.tainted_by(exc.untrusted_source)
        fenced = fence_untrusted(strip_invisible(str(exc)), exc.untrusted_source)
        return _error(tool_call, fenced)

    def _accept(
        self, turn: _Turn, tool_call: ToolCall, tool: Tool[Any], output: ToolOutput
    ) -> ToolResult:
        untrusted = output.trust is Trust.UNTRUSTED
        if untrusted:
            turn.conversation = turn.conversation.tainted_by(output.source)
        if output.discovered_urls:
            turn.conversation = turn.conversation.with_urls(output.discovered_urls)
        self._audit.append(
            "tool.result",
            {
                "tool": tool.name,
                "trust": output.trust.value,
                "source": output.source,
                "chars": len(output.content),
                "sha256": _sha256(output.content),
            },
        )
        # Invisible characters (tag characters, zero-width, bidi) are how injections hide from
        # people while staying readable to models, so untrusted text loses them before fencing.
        content = (
            fence_untrusted(strip_invisible(output.content), output.source)
            if untrusted
            else output.content
        )
        return ToolResult(tool_call.id, content)
