"""Adapter for OpenAI and any OpenAI-compatible Chat Completions endpoint.

Covers OpenAI itself plus Gemini, OpenRouter, Groq, Mistral and local servers such as Ollama,
all through the same wire format.
"""

import json
from collections.abc import Sequence
from typing import Any

import openai

from bastion.llm.types import (
    Completion,
    MaxTokensParam,
    Message,
    ProviderError,
    Role,
    StopReason,
    ToolCall,
    ToolSpec,
    Usage,
)

_FINISH_REASONS = {
    "stop": StopReason.END_TURN,
    "tool_calls": StopReason.TOOL_USE,
    "function_call": StopReason.TOOL_USE,
    "length": StopReason.MAX_TOKENS,
    "content_filter": StopReason.REFUSAL,
}
_STATUS_HINTS = {
    400: "the request was rejected",
    401: "authentication failed; check the API key",
    403: "the API key is not permitted to use this model",
    404: "model not found; check the model name",
    429: "rate limited; try again shortly",
}
_MAX_DETAIL = 300


class OpenAICompatProvider:
    def __init__(
        self,
        client: openai.AsyncOpenAI,
        model: str,
        *,
        name: str = "openai",
        max_tokens_param: MaxTokensParam = "max_completion_tokens",
    ) -> None:
        self._client = client
        self._model = model
        self._name = name
        self._max_tokens_param = max_tokens_param

    @property
    def name(self) -> str:
        return self._name

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
        request: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "system", "content": system}, *_to_wire(messages)],
            self._max_tokens_param: max_tokens,
        }
        if tools:
            request["tools"] = [_tool_param(t) for t in tools]
        try:
            response: Any = await self._client.chat.completions.create(**request)
        except openai.APIStatusError as exc:
            raise self._status_error(exc) from exc
        except openai.APIConnectionError as exc:
            raise ProviderError(f"could not reach the {self._name} API", retryable=True) from exc
        except openai.APIError as exc:
            raise ProviderError(
                f"unexpected {self._name} API response ({type(exc).__name__})"
            ) from exc
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ProviderError(f"the request could not be sent: {str(exc)[:_MAX_DETAIL]}") from exc
        if not response.choices:
            raise ProviderError(f"{self._name} returned no choices")
        return self._from_wire(response)

    async def aclose(self) -> None:
        await self._client.close()

    def _from_wire(self, response: Any) -> Completion:
        choice = response.choices[0]
        calls = tuple(
            _parse_call(c)
            for c in (choice.message.tool_calls or ())
            if getattr(c, "type", "function") == "function"
        )
        stop = _FINISH_REASONS.get(choice.finish_reason or "", StopReason.OTHER)
        if calls and stop not in (StopReason.MAX_TOKENS, StopReason.REFUSAL):
            stop = StopReason.TOOL_USE
        usage = response.usage
        return Completion(
            message=Message(Role.ASSISTANT, text=choice.message.content or "", tool_calls=calls),
            stop_reason=stop,
            usage=Usage(usage.prompt_tokens or 0, usage.completion_tokens or 0)
            if usage
            else Usage(),
            model=str(response.model or self._model),
        )

    def _status_error(self, exc: openai.APIStatusError) -> ProviderError:
        status = exc.status_code
        hint = _STATUS_HINTS.get(status, "unexpected error")
        detail = f" ({exc.message[:_MAX_DETAIL]})" if status == 400 else ""
        retryable = status in (408, 409, 429) or status >= 500
        return ProviderError(f"{self._name} API {status}: {hint}{detail}", retryable=retryable)


def _tool_param(spec: ToolSpec) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        },
    }


def _parse_call(call: Any) -> ToolCall:
    try:
        arguments = json.loads(call.function.arguments or "{}")
    except json.JSONDecodeError:
        arguments = None
    if not isinstance(arguments, dict):
        # Never guess at malformed arguments; the agent's schema check will reject this.
        arguments = {"_unparseable_arguments": True}
    return ToolCall(id=str(call.id), name=str(call.function.name), arguments=arguments)


def _to_wire(messages: Sequence[Message]) -> list[dict[str, Any]]:
    wire: list[dict[str, Any]] = []
    for message in messages:
        if message.role is Role.ASSISTANT:
            entry: dict[str, Any] = {"role": "assistant", "content": message.text or None}
            if message.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(dict(c.arguments))},
                    }
                    for c in message.tool_calls
                ]
            wire.append(entry)
            continue
        wire.extend(
            {"role": "tool", "tool_call_id": r.call_id, "content": r.content}
            for r in message.tool_results
        )
        if message.text:
            wire.append({"role": "user", "content": message.text})
    return wire
