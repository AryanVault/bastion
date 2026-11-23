"""The tool contract.

A tool declares a risk tier (which the policy engine uses), a strict Pydantic argument model
(unknown fields are rejected), and whether its output is trusted. Tools never decide their own
permissions; the agent consults the policy engine before ``run`` is ever called.
"""

import hashlib
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, cast

from pydantic import BaseModel, ConfigDict

from bastion.common import canonical_json
from bastion.llm.types import ToolSpec
from bastion.security.egress import UrlProvenance

_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def fingerprint(text: str) -> str:
    """Short SHA-256 prefix for audit records (lone surrogates are escaped, never fatal)."""
    return hashlib.sha256(text.encode("utf-8", "backslashreplace")).hexdigest()[:16]


def _summarize(value: Any) -> Any:
    if isinstance(value, str):
        return {"chars": len(value), "sha256": fingerprint(value)}
    if isinstance(value, list | dict):
        encoded = canonical_json(value)
        return {"json_chars": len(encoded), "sha256": fingerprint(encoded)}
    return value


class RiskTier(StrEnum):
    READ = "read"  # observes data, no side effects
    WRITE = "write"  # changes the owner's own data, nothing leaves their account
    SEND = "send"  # has an effect on, or sends data to, someone other than the owner
    DESTRUCTIVE = "destructive"  # deletes or irreversibly changes data


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


@dataclass(frozen=True)
class ToolOutput:
    content: str
    trust: Trust
    source: str
    discovered_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolContext:
    provenance: UrlProvenance
    tainted: bool


class ToolError(Exception):
    """A tool failed; the message is safe to return to the model.

    Set ``untrusted_source`` when the failure happened after contacting an untrusted party
    (a web server, say). The agent then taints the conversation and fences the message, in
    case any detail of the failure was influenced by that party.
    """

    def __init__(self, message: str, *, untrusted_source: str | None = None) -> None:
        super().__init__(message)
        self.untrusted_source = untrusted_source


class ToolDenied(ToolError):
    """A tool refused an operation on security grounds."""


class Tool[A: ToolArgs](ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    args_model: ClassVar[type[ToolArgs]]
    risk: ClassVar[RiskTier]

    def risk_for(self, args: A) -> RiskTier:
        """Risk of this particular call. Tools may escalate based on arguments."""
        return self.risk

    def describe(self, args: A) -> str:
        """One-line human description of the call, shown in approval prompts."""
        return f"{self.name}({args.model_dump_json()})"

    def audit_view(self, args: A) -> dict[str, Any]:
        """What the audit log records about a call.

        Text becomes a length and a short hash: the log proves what ran without becoming a
        plaintext copy of private data. Tools override this to expose safe fields.
        """
        return {name: _summarize(value) for name, value in args.model_dump(mode="json").items()}

    def parse_args(self, raw: Mapping[str, Any]) -> A:
        return cast("A", self.args_model.model_validate(dict(raw)))

    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters=self.args_model.model_json_schema(),
        )

    @abstractmethod
    async def run(self, args: A, ctx: ToolContext) -> ToolOutput: ...


class ToolRegistry:
    """Immutable, name-sorted set of tools (stable order keeps prompt caching effective)."""

    def __init__(self, tools: Iterable[Tool[Any]]) -> None:
        by_name: dict[str, Tool[Any]] = {}
        for tool in tools:
            if not _TOOL_NAME.match(tool.name):
                raise ValueError(f"invalid tool name: {tool.name!r}")
            if tool.name in by_name:
                raise ValueError(f"duplicate tool name: {tool.name}")
            by_name[tool.name] = tool
        self._tools = MappingProxyType(dict(sorted(by_name.items())))

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def get(self, name: str) -> Tool[Any] | None:
        return self._tools.get(name)

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(tool.spec() for tool in self._tools.values())
