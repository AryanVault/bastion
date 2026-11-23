"""Immutable conversation state, including taint (control C2) and URL provenance (C7)."""

import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from bastion.llm.types import Message
from bastion.security.egress import UrlProvenance

_MAX_TAINT_SOURCES = 20


@dataclass(frozen=True)
class TaintState:
    """Which untrusted sources have entered the conversation.

    Taint is sticky for the life of a conversation: once attacker-controllable text is in the
    model's context it stays there, so the conversation stays tainted until the owner starts
    a new one.
    """

    sources: tuple[str, ...] = ()

    @property
    def tainted(self) -> bool:
        return bool(self.sources)

    def with_source(self, source: str) -> "TaintState":
        if source in self.sources:
            return self
        return TaintState(sources=(*self.sources, source)[-_MAX_TAINT_SOURCES:])

    def describe(self) -> str:
        return ", ".join(self.sources) if self.sources else "none"


@dataclass(frozen=True)
class Conversation:
    id: str
    messages: tuple[Message, ...] = ()
    taint: TaintState = field(default_factory=TaintState)
    provenance: UrlProvenance = field(default_factory=UrlProvenance)

    @classmethod
    def new(cls) -> "Conversation":
        return cls(id=secrets.token_hex(8))

    def append(self, *messages: Message) -> "Conversation":
        return replace(self, messages=(*self.messages, *messages))

    def tainted_by(self, source: str) -> "Conversation":
        return replace(self, taint=self.taint.with_source(source))

    def with_urls(self, urls: Iterable[str]) -> "Conversation":
        return replace(self, provenance=self.provenance.add(urls))
