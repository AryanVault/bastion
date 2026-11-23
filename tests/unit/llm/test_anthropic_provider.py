import json
from typing import Any

import anthropic
import httpx2
import pytest

from bastion.llm.anthropic_provider import FALLBACK_BETA, AnthropicProvider
from bastion.llm.types import Message, ProviderError, Role, StopReason, ToolResult, ToolSpec

ECHO = ToolSpec(
    "echo", "Echo text.", {"type": "object", "properties": {"text": {"type": "string"}}}
)


def _message(
    content: list[dict[str, Any]], stop: str = "end_turn", model: str = "m"
) -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {"input_tokens": 11, "output_tokens": 7, "cache_read_input_tokens": 4},
    }


class FakeAnthropic:
    """Captures requests and replays canned API responses through the real SDK client."""

    def __init__(self, *responses: tuple[int, dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.requests: list[httpx2.Request] = []
        transport = httpx2.MockTransport(self._handle)
        self.client = anthropic.AsyncAnthropic(
            api_key="sk-ant-test-key",
            max_retries=0,
            http_client=anthropic.DefaultAsyncHttpxClient(transport=transport),
        )

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        status, body = self._responses.pop(0)
        return httpx2.Response(status, json=body)

    def body(self, index: int) -> dict[str, Any]:
        return dict(json.loads(self.requests[index].content))


async def _complete(provider: AnthropicProvider, messages: list[Message]) -> Any:
    return await provider.complete(system="sys", messages=messages, tools=[ECHO], max_tokens=1000)


async def test_text_reply_and_usage_are_normalized() -> None:
    fake = FakeAnthropic((200, _message([{"type": "text", "text": "Hello"}])))
    provider = AnthropicProvider(fake.client, "claude-haiku-5-5")

    completion = await _complete(provider, [Message(Role.USER, text="hi")])

    assert completion.message.text == "Hello"
    assert completion.stop_reason is StopReason.END_TURN
    assert completion.usage.input_tokens == 15
    assert completion.usage.output_tokens == 7


async def test_tool_use_becomes_tool_calls() -> None:
    content = [{"type": "tool_use", "id": "toolu_1", "name": "echo", "input": {"text": "hi"}}]
    fake = FakeAnthropic((200, _message(content, stop="tool_use")))

    completion = await _complete(AnthropicProvider(fake.client, "claude-haiku-5-5"), [])

    assert completion.stop_reason is StopReason.TOOL_USE
    assert completion.message.tool_calls[0].name == "echo"
    assert dict(completion.message.tool_calls[0].arguments) == {"text": "hi"}


async def test_request_shape() -> None:
    fake = FakeAnthropic((200, _message([{"type": "text", "text": "ok"}])))

    await _complete(AnthropicProvider(fake.client, "claude-haiku-5-5", effort="low"), [])

    body = fake.body(0)
    assert body["model"] == "claude-haiku-5-5"
    assert body["system"] == "sys"
    assert body["max_tokens"] == 1000
    assert body["tools"] == [
        {"name": "echo", "description": "Echo text.", "input_schema": ECHO.parameters}
    ]
    assert body["cache_control"] == {"type": "ephemeral"}
    assert body["output_config"] == {"effort": "low"}


async def test_empty_tool_list_is_omitted() -> None:
    fake = FakeAnthropic((200, _message([{"type": "text", "text": "ok"}])))
    provider = AnthropicProvider(fake.client, "claude-haiku-5-5", effort=None)

    await provider.complete(system="s", messages=[], tools=[], max_tokens=10)

    assert "tools" not in fake.body(0)
    assert "output_config" not in fake.body(0)


async def test_assistant_turns_are_replayed_verbatim() -> None:
    """Signed thinking blocks must round-trip unchanged for the API's history check."""
    first = [
        {"type": "thinking", "thinking": "", "signature": "sig-abc"},
        {"type": "tool_use", "id": "toolu_1", "name": "echo", "input": {"text": "hi"}},
    ]
    fake = FakeAnthropic(
        (200, _message(first, stop="tool_use")),
        (200, _message([{"type": "text", "text": "done"}])),
    )
    provider = AnthropicProvider(fake.client, "claude-haiku-5-5")
    user = Message(Role.USER, text="go")

    completion = await _complete(provider, [user])
    results = Message(Role.USER, tool_results=(ToolResult("toolu_1", "hi"),))
    await _complete(provider, [user, completion.message, results])

    replayed = fake.body(1)["messages"]
    assert replayed[1]["content"][0] == {"type": "thinking", "thinking": "", "signature": "sig-abc"}
    assert replayed[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "toolu_1", "content": "hi", "is_error": False}
    ]


async def test_refusal_fallback_is_enabled_for_supported_models() -> None:
    fake = FakeAnthropic((200, _message([{"type": "text", "text": "ok"}])))

    await _complete(AnthropicProvider(fake.client, "claude-opus-5-5"), [])

    assert FALLBACK_BETA in fake.requests[0].headers.get("anthropic-beta", "")
    assert fake.body(0)["fallbacks"] == "default"


async def test_refusal_fallback_is_not_sent_to_unsupported_models() -> None:
    fake = FakeAnthropic((200, _message([{"type": "text", "text": "ok"}])))

    await _complete(AnthropicProvider(fake.client, "claude-haiku-5-5"), [])

    assert "fallbacks" not in fake.body(0)


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        ("refusal", StopReason.REFUSAL),
        ("max_tokens", StopReason.MAX_TOKENS),
        ("model_context_window_exceeded", StopReason.CONTEXT_EXCEEDED),
        ("pause_turn", StopReason.PAUSE),
    ],
)
async def test_stop_reasons_are_mapped(wire: str, expected: StopReason) -> None:
    fake = FakeAnthropic((200, _message([], stop=wire)))

    completion = await _complete(AnthropicProvider(fake.client, "claude-haiku-5-5"), [])

    assert completion.stop_reason is expected


@pytest.mark.parametrize(("status", "retryable"), [(429, True), (529, True), (401, False)])
async def test_api_errors_become_provider_errors(status: int, retryable: bool) -> None:
    error = {"type": "error", "error": {"type": "api_error", "message": "nope"}}
    fake = FakeAnthropic((status, error))

    with pytest.raises(ProviderError) as raised:
        await _complete(AnthropicProvider(fake.client, "claude-haiku-5-5"), [])

    assert raised.value.retryable is retryable
    assert "sk-ant-test-key" not in str(raised.value)


async def test_requests_the_sdk_refuses_become_provider_errors() -> None:
    fake = FakeAnthropic()
    provider = AnthropicProvider(fake.client, "claude-haiku-5-5")

    with pytest.raises(ProviderError, match="could not be sent"):
        await provider.complete(system="s", messages=[], tools=[], max_tokens=64_000)

    assert fake.requests == []


async def test_aclose_releases_the_client() -> None:
    fake = FakeAnthropic()

    await AnthropicProvider(fake.client, "claude-haiku-5-5").aclose()

    assert fake.client.is_closed()
