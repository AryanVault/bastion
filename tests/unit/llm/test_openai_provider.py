import json
from typing import Any

import httpx2
import openai
import pytest

from bastion.llm.openai_provider import OpenAICompatProvider
from bastion.llm.types import (
    Message,
    ProviderError,
    Role,
    StopReason,
    ToolCall,
    ToolResult,
    ToolSpec,
)

ECHO = ToolSpec(
    "echo", "Echo text.", {"type": "object", "properties": {"text": {"type": "string"}}}
)


def _completion(message: dict[str, Any], finish: str = "stop") -> dict[str, Any]:
    return {
        "id": "c1",
        "object": "chat.completion",
        "created": 0,
        "model": "some-model",
        "choices": [
            {"index": 0, "message": {"role": "assistant", **message}, "finish_reason": finish}
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13},
    }


def _tool_call(arguments: str) -> dict[str, Any]:
    return {
        "id": "call_1",
        "type": "function",
        "function": {"name": "echo", "arguments": arguments},
    }


class FakeOpenAI:
    def __init__(self, *responses: tuple[int, dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.requests: list[httpx2.Request] = []
        self.client = openai.AsyncOpenAI(
            api_key="sk-test-openai-key",
            base_url="https://llm.example.test/v1",
            max_retries=0,
            http_client=openai.DefaultAsyncHttpxClient(
                transport=httpx2.MockTransport(self._handle)
            ),
        )

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        status, body = self._responses.pop(0)
        return httpx2.Response(status, json=body)

    def body(self, index: int = 0) -> dict[str, Any]:
        return dict(json.loads(self.requests[index].content))


async def _complete(provider: OpenAICompatProvider, messages: list[Message]) -> Any:
    return await provider.complete(system="sys", messages=messages, tools=[ECHO], max_tokens=500)


async def test_text_reply_and_usage() -> None:
    fake = FakeOpenAI((200, _completion({"content": "Hello"})))

    completion = await _complete(OpenAICompatProvider(fake.client, "some-model"), [])

    assert completion.message.text == "Hello"
    assert completion.stop_reason is StopReason.END_TURN
    assert (completion.usage.input_tokens, completion.usage.output_tokens) == (9, 4)


async def test_tool_calls_are_parsed() -> None:
    message = {"content": None, "tool_calls": [_tool_call('{"text": "hi"}')]}
    fake = FakeOpenAI((200, _completion(message, finish="tool_calls")))

    completion = await _complete(OpenAICompatProvider(fake.client, "some-model"), [])

    assert completion.stop_reason is StopReason.TOOL_USE
    assert completion.message.tool_calls == (ToolCall("call_1", "echo", {"text": "hi"}),)


async def test_tool_calls_win_over_a_misreported_finish_reason() -> None:
    message = {"content": None, "tool_calls": [_tool_call("{}")]}
    fake = FakeOpenAI((200, _completion(message, finish="stop")))

    completion = await _complete(OpenAICompatProvider(fake.client, "some-model"), [])

    assert completion.stop_reason is StopReason.TOOL_USE


async def test_unparseable_arguments_are_flagged_not_guessed() -> None:
    message = {"content": None, "tool_calls": [_tool_call("{not json")]}
    fake = FakeOpenAI((200, _completion(message, finish="tool_calls")))

    completion = await _complete(OpenAICompatProvider(fake.client, "some-model"), [])

    assert dict(completion.message.tool_calls[0].arguments) == {"_unparseable_arguments": True}


async def test_conversation_is_translated_to_chat_format() -> None:
    fake = FakeOpenAI((200, _completion({"content": "ok"})))
    history = [
        Message(Role.USER, text="hi"),
        Message(
            Role.ASSISTANT, text="checking", tool_calls=(ToolCall("call_1", "echo", {"text": "x"}),)
        ),
        Message(Role.USER, tool_results=(ToolResult("call_1", "x"),)),
    ]

    await _complete(
        OpenAICompatProvider(fake.client, "some-model", max_tokens_param="max_tokens"), history
    )

    body = fake.body()
    assert body["max_tokens"] == 500
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {
            "role": "assistant",
            "content": "checking",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "echo", "arguments": '{"text": "x"}'},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "x"},
    ]
    assert body["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "Echo text.",
                "parameters": ECHO.parameters,
            },
        }
    ]


@pytest.mark.parametrize(
    ("finish", "expected"),
    [("length", StopReason.MAX_TOKENS), ("content_filter", StopReason.REFUSAL)],
)
async def test_finish_reasons_are_mapped(finish: str, expected: StopReason) -> None:
    fake = FakeOpenAI((200, _completion({"content": "partial"}, finish=finish)))

    completion = await _complete(OpenAICompatProvider(fake.client, "some-model"), [])

    assert completion.stop_reason is expected


@pytest.mark.parametrize(("status", "retryable"), [(429, True), (503, True), (401, False)])
async def test_api_errors_become_provider_errors(status: int, retryable: bool) -> None:
    fake = FakeOpenAI((status, {"error": {"message": "nope", "type": "x"}}))

    with pytest.raises(ProviderError) as raised:
        await _complete(OpenAICompatProvider(fake.client, "some-model", name="groq"), [])

    assert raised.value.retryable is retryable
    assert "groq" in str(raised.value)
    assert "sk-test-openai-key" not in str(raised.value)


async def test_aclose_releases_the_client() -> None:
    fake = FakeOpenAI()

    await OpenAICompatProvider(fake.client, "some-model").aclose()

    assert fake.client.is_closed()
