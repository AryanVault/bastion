"""Normalized message and completion types shared by every provider adapter."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class Role(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"


class StopReason(StrEnum):
    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TOKENS = "max_tokens"
    REFUSAL = "refusal"
    CONTEXT_EXCEEDED = "context_exceeded"
    PAUSE = "pause"
    OTHER = "other"


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class RawContent:
    """Provider-native assistant content, replayed verbatim to the provider that produced it.

    Some providers bind hidden state (such as signed reasoning blocks) to the exact
    conversation, so assistant turns must round-trip unchanged rather than be rebuilt.
    """

    provider: str
    blocks: tuple[Any, ...]


@dataclass(frozen=True)
class Message:
    role: Role
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    raw: RawContent | None = None


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


@dataclass(frozen=True)
class Completion:
    message: Message
    stop_reason: StopReason
    usage: Usage
    model: str


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: Mapping[str, Any]


class ProviderError(Exception):
    """The LLM provider call failed. The message is safe to show to the owner."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class LLMProvider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    async def complete(
        self,
        *,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        max_tokens: int,
    ) -> Completion: ...

    async def aclose(self) -> None:
        """Release network resources (HTTP connection pools)."""
        ...
