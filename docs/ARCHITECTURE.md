# Bastion Architecture

## Overview

```
 owner ──> channel (CLI today, Telegram next)
              │
              ▼
         core/agent.py ──── llm/ (anthropic_provider, openai_provider) ──> model API
              │
              │  every proposed tool call
              ▼
   tools/base.py: lookup + strict schema
              ▼
   security/policy.py: allow | ask | deny   (risk tier + conversation taint)
              ▼
   security/approvals.py + channel approver: owner approves the exact arguments
              ▼
   tools/* run  ──> security/egress.py (web)  ·  storage/memory_bank.py (memory)
              ▼
   output: untrusted? -> taint conversation, fence content (core/prompts.py)
              ▼
   security/audit.py: HMAC-chained record of every step
```

`runtime.py` wires these together from configuration and secrets, so every channel shares one
policy, one audit log and one set of controls.

## The lifecycle of one request

1. The channel calls `Agent.run_turn(conversation, text)`. URLs in the owner's text are added to
   the conversation's provenance set (they may be fetched later). The text is timestamped and
   appended; only its length and SHA-256 go to the audit log.
2. The provider adapter sends the system prompt, the frozen tool list and the full history. The
   history is append-only, and assistant turns are replayed verbatim (`RawContent`), which keeps
   provider-side caching effective and satisfies providers that bind reasoning to the transcript.
3. For each proposed tool call: look up the tool, validate arguments (unknown fields rejected),
   compute the call's risk tier, and ask the policy engine. `deny` and owner refusals return an
   error result telling the model not to retry. Approvals are consumed against a digest of the
   exact arguments before the tool runs.
4. Tools run under a timeout. `ToolError` messages are safe to show the model; any other
   exception is contained and reported generically, with details only in the audit log.
5. Untrusted output (web pages, search results, untrusted memories) taints the conversation for
   good, loses invisible characters (tag characters, zero-width, bidi), and is wrapped in a fence
   whose closing tag carries a random boundary. A tool *failure* after contacting an untrusted
   party is treated the same way, and tool error messages never echo remote data.
6. Budgets (steps, tool calls, tokens) end runaway loops. Every step is audited.

## Module map

| Path | Responsibility |
|---|---|
| `core/agent.py` | The tool-use loop and its enforcement order |
| `core/conversation.py` | Immutable conversation: messages, taint, URL provenance |
| `core/prompts.py` | System prompt and the untrusted-content fence (defence in depth) |
| `llm/types.py` | Provider-neutral messages, tool calls, completions |
| `llm/anthropic_provider.py` | Claude via the Messages API (verbatim replay, refusal fallback) |
| `llm/openai_provider.py` | OpenAI and every OpenAI-compatible endpoint |
| `llm/factory.py` | Provider presets; explicit, HTTPS-only base URLs |
| `security/policy.py` | Policy file parsing, hard floors, decisions |
| `security/approvals.py` | Argument-bound, single-use, expiring approvals |
| `security/egress.py` | URL normalisation, IP checks, connect-time guard, provenance |
| `security/audit.py` | HMAC-chained audit log and verification |
| `security/vault.py` | OS keyring access; registers secrets for redaction |
| `security/redact.py` | Secret patterns and registered values |
| `security/crypto.py` | AES-256-GCM field encryption with context binding |
| `storage/db.py` | SQLite (WAL), migrations, append-only triggers |
| `storage/memory_bank.py` | Encrypted memories with provenance |
| `tools/*` | `web_search`, `web_fetch`, `memory_save/search/delete` |
| `text.py` | Invisible and control characters: strip (for the model and replies) or reveal (for approvals) |
| `cli/*` | `bastion` commands and the terminal approver |
| `config.py`, `runtime.py` | Configuration and wiring |

## Security controls in the code

| Control (threat model) | Implementation | Tests |
|---|---|---|
| C1 policy engine | `security/policy.py`, `core/agent.py::_handle` | `tests/unit/security/test_policy.py` |
| C2 taint tracking | `core/conversation.py::TaintState`, `core/agent.py::_accept` | `tests/unit/core/test_agent.py` |
| C4 argument-bound approvals | `security/approvals.py`, `cli/approver.py` | `test_approvals.py`, `test_approver.py` |
| C7 egress guard | `security/egress.py`, `tools/web_fetch.py` | `test_egress.py`, `test_web_fetch.py` |
| C8 vault and redaction | `security/vault.py`, `security/redact.py`, `llm/factory.py` | `test_vault.py`, `test_redact.py`, `test_factory.py` |
| C10 audit log | `security/audit.py`, `storage/db.py`, `security/vault.py::VaultAnchor` (checkpoint) | `test_audit.py`, `test_commands.py` |
| C11 budgets (per request) | `core/agent.py::AgentLimits` | `test_agent.py` |
| C12 memory provenance | `tools/memory.py`, `storage/memory_bank.py` | `tests/unit/tools/test_memory.py` |
| C13 encryption at rest | `security/crypto.py`, `storage/memory_bank.py` | `test_crypto.py`, `test_memory.py` |
| C14 supply chain | `uv.lock`, `.github/workflows/` | CI |
| C16 display safety | `text.py`, `core/agent.py::_accept`, `cli/approver.py`, `cli/chat.py` | `test_text.py`, `test_approver.py`, `test_agent.py` |

Tests that simulate an attack are marked `@pytest.mark.security` (`uv run pytest -m security`).

## Data at rest

| Where | What |
|---|---|
| `~/.bastion/config.toml` | Provider, model, budgets. No secrets. |
| `~/.bastion/policy.toml` | The owner's policy (cannot weaken the code-enforced floors) |
| `~/.bastion/bastion.db` | SQLite: `audit_log` (HMAC chain, append-only triggers), `memories` (AES-GCM) |
| OS keyring, service `bastion` | LLM and search API keys, `audit.hmac_key`, `storage.encryption_key` |

## Design decisions

- **No local server.** The CLI runs the agent in-process and the Telegram bot uses long
  polling, so Bastion opens no listening port (threat T16).
- **Append-only history.** Nothing already sent to the model is edited; taint labels and
  fences are applied when content is appended. This keeps prompt caching effective and is what
  providers with conversation-bound reasoning require.
- **Fewer dependencies.** Thin provider adapters instead of a multi-provider framework; the
  policy and config use TOML read by the standard library; HTML text extraction uses the
  standard library parser.
- **Taint is per conversation.** Untrusted text stays in the model's context once it is there,
  so the conversation stays tainted until the owner starts a new one.
- **Pinned interpreter.** Python 3.13.6+ is required (3.13.18 pinned for development and CI)
  because earlier 3.13 releases have a quadratic-time HTML parser (threat T20).
- **Synchronous SQLite.** Audit and memory writes are sub-millisecond and run on the event loop.
  That is fine for the single-user CLI; the always-on Telegram daemon (Phase 2) will move them
  off the loop.
