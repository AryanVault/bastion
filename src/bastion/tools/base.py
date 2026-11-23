"""The tool contract.

A tool declares a risk tier (which the policy engine uses), a strict Pydantic argument model
(unknown fields are rejected), and whether its output is trusted. Tools never decide their own
permissions; the agent consults the policy engine before ``run`` is ever called.
"""

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, cast

from pydantic import BaseModel, ConfigDict

from bastion.llm.types import ToolSpec
from bastion.security.egress import UrlProvenance

_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


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
    """A tool failed; the message is safe to return to the model."""


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
