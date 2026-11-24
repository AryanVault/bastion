"""Wires configuration, secrets, storage, tools, policy and the LLM provider together.

Every channel (the CLI now, Telegram next) builds its agent from a ``Runtime``, so all of them
share one policy, one audit log and one set of security controls.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2

from bastion.autonomy.runner import TaskAgent, TaskRunner
from bastion.autonomy.tasks import Task, TaskStore
from bastion.config import DATABASE_FILE, POLICY_FILE, ConfigError, Settings, load_settings
from bastion.core.agent import Agent, AgentLimits, Approver
from bastion.core.prompts import task_system_prompt
from bastion.google.api import GoogleApi, google_client
from bastion.google.calendar import CalendarClient
from bastion.google.gmail import GmailClient
from bastion.google.grant import load_client, load_grant
from bastion.google.oauth import GoogleAuth
from bastion.llm.factory import build_provider
from bastion.llm.quarantine import QuarantinedReader
from bastion.llm.types import LLMProvider
from bastion.security.approvals import ApprovalService
from bastion.security.audit import AuditLog
from bastion.security.crypto import FieldCipher
from bastion.security.policy import PolicyEngine, load_policy
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    BRAVE_API_KEY,
    GOOGLE_REFRESH_TOKEN,
    STORAGE_KEY,
    SecretStore,
    Vault,
    VaultAnchor,
    VaultError,
)
from bastion.storage.db import connect
from bastion.storage.memory_bank import MemoryBank
from bastion.tools.base import Tool, ToolRegistry
from bastion.tools.calendar import (
    CalendarCreateTool,
    CalendarDeleteTool,
    CalendarListTool,
    CalendarUpdateTool,
)
from bastion.tools.gmail import GmailDraftTool, GmailReadTool, GmailSearchTool, GmailSendTool
from bastion.tools.memory import MemoryDeleteTool, MemorySaveTool, MemorySearchTool
from bastion.tools.tasks import TASK_TOOLS, TaskListTool, TaskRemoveTool, TaskScheduleTool
from bastion.tools.web_fetch import WebFetchTool
from bastion.tools.web_search import BraveSearch, WebSearchTool

GOOGLE_OFF_NOTICE = "Gmail and Calendar are off. Run: bastion google connect"


@dataclass
class Runtime:
    home: Path
    settings: Settings
    vault: Vault
    conn: sqlite3.Connection
    audit: AuditLog
    tools: ToolRegistry
    policy: PolicyEngine
    provider: LLMProvider
    notices: tuple[str, ...]
    # Knows every secret loaded through the vault: channels run outgoing text through it.
    redactor: Redactor
    tasks: TaskStore
    # HTTP clients the runtime owns besides the provider's (Google APIs), closed by `aclose`.
    clients: tuple[httpx2.AsyncClient, ...] = ()

    def agent(self, approver: Approver) -> Agent:
        limits = self.settings.limits
        return Agent(
            provider=self.provider,
            tools=self.tools,
            policy=self.policy,
            approvals=ApprovalService(),
            approver=approver,
            audit=self.audit,
            limits=AgentLimits(
                max_steps=limits.max_steps,
                max_tool_calls=limits.max_tool_calls,
                max_output_tokens=self.settings.llm.max_output_tokens,
                max_turn_tokens=limits.max_turn_tokens,
            ),
        )

    def task_agent(self, task: Task, approver: Approver) -> TaskAgent:
        """An agent for one run of ``task``: it sees only the tools the task was granted, under
        the policy's task mode, with the smaller per-run budgets of ``[autonomy]``."""
        granted = [name for name in task.spec.tools if name not in TASK_TOOLS]
        registry = ToolRegistry(
            [tool for name in granted if (tool := self.tools.get(name)) is not None]
        )
        autonomy = self.settings.autonomy
        agent = Agent(
            provider=self.provider,
            tools=registry,
            policy=self.policy.for_task(task.name, registry.names),
            approvals=ApprovalService(),
            approver=approver,
            audit=self.audit,
            limits=AgentLimits(
                max_steps=autonomy.max_steps,
                max_tool_calls=autonomy.max_tool_calls,
                max_output_tokens=self.settings.llm.max_output_tokens,
                max_turn_tokens=autonomy.max_run_tokens,
            ),
            system_prompt=task_system_prompt(task.name),
        )
        missing = tuple(name for name in granted if name not in registry.names)
        return TaskAgent(agent, tuple(sorted(registry.names)), missing)

    def task_runner(self) -> TaskRunner:
        return TaskRunner(self.tasks, self.settings.autonomy, self.audit, self.task_agent)

    async def aclose(self) -> None:
        """Release network resources (call inside the event loop)."""
        for client in self.clients:
            await client.aclose()
        await self.provider.aclose()

    def close(self) -> None:
        self.conn.close()


def open_audit_log(conn: sqlite3.Connection, vault: Vault, redactor: Redactor) -> AuditLog:
    """The audit log, with its chain head checkpointed in the OS keyring."""
    return AuditLog(conn, vault.key(AUDIT_KEY), redactor, anchor=VaultAnchor(vault))


@dataclass(frozen=True)
class GoogleTools:
    tools: tuple[Tool[Any], ...]
    notices: tuple[str, ...]
    client: httpx2.AsyncClient | None = None


def build_google_tools(
    vault: Vault, redactor: Redactor, provider: LLMProvider, audit: AuditLog
) -> GoogleTools:
    """Gmail and Calendar tools for exactly the access the owner granted (none if not connected).

    The access token comes from the refresh token in the keyring, which is re-checked before
    every use: `bastion google disconnect` (or a reconnect) stops a running daemon's access.
    """
    try:
        grant, credentials = load_grant(vault), load_client(vault)
        refresh_token = vault.get(GOOGLE_REFRESH_TOKEN)
    except VaultError as exc:
        return GoogleTools((), (f"Gmail and Calendar are off: {exc}",))
    if grant is None or credentials is None or refresh_token is None:
        return GoogleTools((), (GOOGLE_OFF_NOTICE,))

    def still_connected() -> bool:
        try:
            return vault.get(GOOGLE_REFRESH_TOKEN) == refresh_token
        except VaultError:
            return False  # fail closed: an unreadable keyring means no access

    client = google_client()
    auth = GoogleAuth(
        client, credentials, refresh_token, redactor=redactor, still_connected=still_connected
    )
    api = GoogleApi(auth, client)
    tools: list[Tool[Any]] = []
    if grant.gmail != "off":
        gmail = GmailClient(api)
        tools += [GmailSearchTool(gmail), GmailReadTool(gmail, QuarantinedReader(provider, audit))]
        if grant.gmail in ("draft", "send"):
            tools.append(GmailDraftTool(gmail))
        if grant.gmail == "send":
            tools.append(GmailSendTool(gmail))
    if grant.calendar != "off":
        calendar = CalendarClient(api)
        tools.append(CalendarListTool(calendar))
        if grant.calendar == "write":
            tools += [
                CalendarCreateTool(calendar),
                CalendarUpdateTool(calendar),
                CalendarDeleteTool(calendar),
            ]
    return GoogleTools(tuple(tools), (), client)


def core_tools(
    settings: Settings, vault: Vault, bank: MemoryBank
) -> tuple[list[Tool[Any]], tuple[str, ...]]:
    """The tools every runtime has: web, memory, and web search if a key is stored."""
    tools: list[Tool[Any]] = [
        WebFetchTool(),
        MemorySaveTool(bank),
        MemorySearchTool(bank),
        MemoryDeleteTool(bank),
    ]
    notices: list[str] = []
    if settings.search.provider == "brave":
        key = vault.get(BRAVE_API_KEY)
        if key:
            tools.append(WebSearchTool(BraveSearch(key)))
        else:
            notices.append(
                f"Web search is off (no Brave Search key). Run: bastion secrets set {BRAVE_API_KEY}"
            )
    return tools, tuple(notices)


def open_runtime(home: Path, store: SecretStore, *, provider: LLMProvider | None = None) -> Runtime:
    settings = load_settings(home)
    redactor = Redactor()
    vault = Vault(store, redactor)
    policy_path = home / POLICY_FILE
    if not policy_path.exists():
        raise ConfigError(f"{policy_path} not found. Run: bastion init")
    conn = connect(home / DATABASE_FILE)
    try:
        audit = open_audit_log(conn, vault, redactor)
        cipher = FieldCipher(vault.key(STORAGE_KEY))
        bank = MemoryBank(conn, cipher)
        tasks = TaskStore(conn, cipher)
        policy_config = load_policy(policy_path)
        llm = provider if provider is not None else build_provider(settings.llm, vault)
        base, notices = core_tools(settings, vault, bank)
        # Last: nothing after this can fail, so its HTTP client always reaches the Runtime
        # (whose `aclose` closes it) instead of leaking.
        google = build_google_tools(vault, redactor, llm, audit)
    except BaseException:
        conn.close()
        raise
    available: list[Tool[Any]] = [*base, *google.tools]
    if settings.autonomy.enabled:
        grantable = frozenset(tool.name for tool in available)
        available += [
            TaskScheduleTool(tasks, grantable, max_tasks=settings.autonomy.max_tasks),
            TaskListTool(tasks),
            TaskRemoveTool(tasks),
        ]
    tools = ToolRegistry(available)
    policy = PolicyEngine(policy_config, tools.names)
    clients = (google.client,) if google.client is not None else ()
    return Runtime(
        home=home,
        settings=settings,
        vault=vault,
        conn=conn,
        audit=audit,
        tools=tools,
        policy=policy,
        provider=llm,
        notices=(*notices, *google.notices),
        redactor=redactor,
        tasks=tasks,
        clients=clients,
    )
