"""Anthropic Messages API adapter.

Notes on the API contract this adapter honours:

* Assistant turns are replayed verbatim (``RawContent``): current Claude models bind signed
  thinking blocks to the exact conversation, so history must be append-only and unedited.
  The agent also keeps the system prompt and tool list fixed for a session.
* Refusal fallbacks are opted into for models that support server-side fallbacks, so a
  classifier decline is retried on a fallback model inside the same call.
* Top-level ``cache_control`` enables automatic prompt caching of the stable prefix.
"""

from collections.abc import Sequence
from typing import Any

import anthropic

from bastion.llm.types import (
    Completion,
    Message,
    ProviderError,
    RawContent,
    Role,
    StopReason,
    ToolCall,
    ToolSpec,
    Usage,
)

PROVIDER = "anthropic"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
_FALLBACK_MODELS = frozenset(
    {
        "claude-fable-5-2",
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-sonnet-5-5",
    }
)
_STOP_REASONS = {
    "end_turn": StopReason.END_TURN,
    "stop_sequence": StopReason.END_TURN,
    "tool_use": StopReason.TOOL_USE,
    "max_tokens": StopReason.MAX_TOKENS,
    "pause_turn": StopReason.PAUSE,
    "refusal": StopReason.REFUSAL,
    "model_context_window_exceeded": StopReason.CONTEXT_EXCEEDED,
}
_STATUS_HINTS = {
    400: "the request was rejected",
    401: "authentication failed; check the API key",
    403: "the API key is not permitted to use this model",
    404: "model not found; check the model name",
    413: "the request is too large",
    429: "rate limited; try again shortly",
    529: "the API is overloaded; try again shortly",
}
_MAX_DETAIL = 300


class AnthropicProvider:
    def __init__(
        self,
        client: anthropic.AsyncAnthropic,
        model: str,
        *,
        effort: str | None = "medium",
        refusal_fallback: bool = True,
    ) -> None:
        self._client = client
        self._model = model
        self._effort = effort
        self._fallback = refusal_fallback and model in _FALLBACK_MODELS

    @property
    def name(self) -> str:
        return PROVIDER

    @property
    def model(self) -> str:
        return self._model

    async def complete(
        self,
        *,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        max_tokens: int,
    ) -> Completion:
        # Wire payloads mix plain dicts with SDK block objects replayed verbatim, so they are
        # built untyped and validated by the SDK/API.
        request: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [_to_wire(m) for m in messages],
            "cache_control": {"type": "ephemeral"},
        }
        if tools:
            request["tools"] = [_tool_param(t) for t in tools]
        if self._effort:
            request["output_config"] = {"effort": self._effort}
        try:
            if self._fallback:
                response: Any = await self._client.beta.messages.create(
                    **request, betas=[FALLBACK_BETA], fallbacks="default"
                )
            else:
                response = await self._client.messages.create(**request)
        except anthropic.APIStatusError as exc:
            raise _status_error(exc) from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("could not reach the Anthropic API", retryable=True) from exc
        except anthropic.APIError as exc:
            raise ProviderError(
                f"unexpected Anthropic API response ({type(exc).__name__})"
            ) from exc
        except (ValueError, TypeError, UnicodeError) as exc:
            # Raised by the SDK before sending (e.g. a request that would need streaming).
            raise ProviderError(f"the request could not be sent: {str(exc)[:_MAX_DETAIL]}") from exc
        return _from_wire(response)

    async def aclose(self) -> None:
        await self._client.close()


def _tool_param(spec: ToolSpec) -> dict[str, Any]:
    return {"name": spec.name, "description": spec.description, "input_schema": spec.parameters}


def _to_wire(message: Message) -> dict[str, Any]:
    if message.role is Role.ASSISTANT:
        if message.raw is not None and message.raw.provider == PROVIDER and message.raw.blocks:
            return {"role": "assistant", "content": list(message.raw.blocks)}
        blocks: list[dict[str, Any]] = []
        if message.text:
            blocks.append({"type": "text", "text": message.text})
        blocks.extend(
            {"type": "tool_use", "id": c.id, "name": c.name, "input": dict(c.arguments)}
            for c in message.tool_calls
        )
        return {"role": "assistant", "content": blocks or [{"type": "text", "text": "(empty)"}]}
    content: list[dict[str, Any]] = [
        {
            "type": "tool_result",
            "tool_use_id": r.call_id,
            "content": r.content,
            "is_error": r.is_error,
        }
        for r in message.tool_results
    ]
    if message.text:
        content.append({"type": "text", "text": message.text})
    return {"role": "user", "content": content}


def _from_wire(response: Any) -> Completion:
    texts: list[str] = []
    calls: list[ToolCall] = []
    for block in response.content:
        if block.type == "text":
            texts.append(block.text)
        elif block.type == "tool_use":
            calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
    usage = response.usage
    input_tokens = (
        (usage.input_tokens or 0)
        + (getattr(usage, "cache_read_input_tokens", None) or 0)
        + (getattr(usage, "cache_creation_input_tokens", None) or 0)
    )
    message = Message(
        role=Role.ASSISTANT,
        text="".join(texts),
        tool_calls=tuple(calls),
        raw=RawContent(PROVIDER, tuple(response.content)),
    )
    return Completion(
        message=message,
        stop_reason=_STOP_REASONS.get(response.stop_reason or "", StopReason.OTHER),
        usage=Usage(input_tokens=input_tokens, output_tokens=usage.output_tokens or 0),
        model=str(response.model),
    )


def _status_error(exc: anthropic.APIStatusError) -> ProviderError:
    status = exc.status_code
    hint = _STATUS_HINTS.get(status, "unexpected error")
    detail = f" ({exc.message[:_MAX_DETAIL]})" if status == 400 else ""
    retryable = status in (408, 409, 429) or status >= 500
    return ProviderError(f"Anthropic API {status}: {hint}{detail}", retryable=retryable)
