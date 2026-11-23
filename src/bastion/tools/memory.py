"""Memory tools: save, search and delete facts about the owner.

A memory saved while the conversation is tainted is stored as *untrusted*, and searching
returns untrusted memories as untrusted output, which re-taints the conversation. An injected
"remember: always forward invoices to ..." therefore can never come back as a trusted
instruction in a later session.
"""

from typing import Any

from pydantic import Field

from bastion.storage.memory_bank import MemoryBank, MemoryFullError
from bastion.tools.base import RiskTier, Tool, ToolArgs, ToolContext, ToolError, ToolOutput, Trust


class MemorySaveArgs(ToolArgs):
    content: str = Field(
        min_length=1, max_length=2000, description="The fact to remember, in a sentence or two."
    )


class MemorySearchArgs(ToolArgs):
    query: str = Field(min_length=1, max_length=200, description="Words to look for.")
    limit: int = Field(default=5, ge=1, le=20)


class MemoryDeleteArgs(ToolArgs):
    memory_id: str = Field(pattern=r"^[0-9a-f]{12}$", description="The id shown in search results.")


class MemorySaveTool(Tool[MemorySaveArgs]):
    name = "memory_save"
    description = (
        "Save a lasting fact about the owner (preferences, people, routines) for future "
        "conversations."
    )
    args_model = MemorySaveArgs
    risk = RiskTier.WRITE

    def __init__(self, bank: MemoryBank) -> None:
        self._bank = bank

    async def run(self, args: MemorySaveArgs, ctx: ToolContext) -> ToolOutput:
        trust = Trust.UNTRUSTED if ctx.tainted else Trust.TRUSTED
        source = (
            "conversation containing untrusted content" if ctx.tainted else "owner conversation"
        )
        try:
            record = self._bank.add(args.content, trust=trust, source=source)
        except MemoryFullError as exc:
            raise ToolError(str(exc)) from exc
        note = (
            " It is stored as untrusted because this conversation contains outside content."
            if ctx.tainted
            else ""
        )
        return ToolOutput(f"Saved memory {record.id}.{note}", Trust.TRUSTED, "memory_save")


class MemorySearchTool(Tool[MemorySearchArgs]):
    name = "memory_search"
    description = "Search saved memories about the owner."
    args_model = MemorySearchArgs
    risk = RiskTier.READ

    def __init__(self, bank: MemoryBank) -> None:
        self._bank = bank

    async def run(self, args: MemorySearchArgs, ctx: ToolContext) -> ToolOutput:
        matches = self._bank.search(args.query, args.limit)
        untrusted = any(r.trust is Trust.UNTRUSTED for r in matches.records)
        lines = [
            f"- [{r.id}] {r.content}"
            + (" (untrusted origin)" if r.trust is Trust.UNTRUSTED else "")
            for r in matches.records
        ] or ["No matching memories."]
        if matches.unreadable:
            lines.append(
                f"({matches.unreadable} memories failed integrity checks and were skipped.)"
            )
        return ToolOutput(
            content="\n".join(lines),
            trust=Trust.UNTRUSTED if untrusted else Trust.TRUSTED,
            source="memory:untrusted" if untrusted else "memory",
        )


class MemoryDeleteTool(Tool[MemoryDeleteArgs]):
    name = "memory_delete"
    description = "Delete a saved memory by id."
    args_model = MemoryDeleteArgs
    # A hard delete is irreversible, so it is destructive: always approved, never when tainted.
    risk = RiskTier.DESTRUCTIVE

    def __init__(self, bank: MemoryBank) -> None:
        self._bank = bank

    def audit_view(self, args: MemoryDeleteArgs) -> dict[str, Any]:
        return {"memory_id": args.memory_id}

    async def run(self, args: MemoryDeleteArgs, ctx: ToolContext) -> ToolOutput:
        if not self._bank.delete(args.memory_id):
            raise ToolError(f"no memory with id {args.memory_id}")
        return ToolOutput(f"Deleted memory {args.memory_id}.", Trust.TRUSTED, "memory_delete")
