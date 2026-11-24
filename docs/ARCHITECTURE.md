# Bastion Architecture

## Overview

```
 owner ──> channel (CLI, or Telegram via `bastion daemon`)
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
                ──> google/ (Gmail, Calendar)  ·  llm/quarantine.py (reads email, no tools)
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
5. Untrusted output (web pages, search results, email, invitations, untrusted memories) taints the conversation for
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
| `tools/*` | `web_search`, `web_fetch`, `memory_save/search/delete`, `gmail_*`, `calendar_*` |
| `tools/gmail.py` | Search, read (quarantined digest by default), draft, and opt-in send |
| `tools/calendar.py` | List, create, change and delete events; identity checks against the live event |
| `llm/quarantine.py` | The quarantined reader: a tool-less model call with a strict JSON schema |
| `google/oauth.py` | Desktop sign-in (loopback, PKCE, state), token refresh and revocation |
| `google/api.py` | Authenticated REST calls: refresh on 401, size cap, safe error messages |
| `google/grant.py` | Access levels, the scopes they need, and what was granted |
| `google/gmail.py`, `google/calendar.py` | Thin Gmail and Calendar clients (ETags on changes) |
| `google/mail.py`, `google/events.py` | Pure helpers: addresses, MIME, bodies; event trust and times |
| `net.py` | Shared HTTP helpers (request logs silenced) |
| `security/totp.py` | Authenticator (TOTP) codes for step-up approvals, single use |
| `security/killswitch.py` | The `/stop` switch: a file only `bastion resume` removes |
| `security/ratelimit.py` | Token bucket for requests over always-on channels |
| `telegram/api.py` | Thin Bot API client (long polling); strict update parsing; token never logged |
| `telegram/pairing.py` | One-time-code pairing; the owner record in the OS keyring |
| `telegram/approver.py` | Inline-button approvals with opaque tokens; TOTP step-up |
| `telegram/bot.py` | The daemon: owner check, commands, kill switch, rate limit, one request at a time |
| `telegram/text.py` | Plain-text chunking and the approval prompt |
| `text.py` | Invisible and control characters: strip (for the model and replies) or reveal (for approvals) |
| `cli/*` | `bastion` commands, the terminal approver, `daemon`, `telegram`, `google`, `tasks`, `resume` |
| `autonomy/schedule.py` | The schedule grammar (`daily 08:00`, `every 4h`, ...) and next-run times |
| `autonomy/tasks.py` | Sealed task definitions, scheduling state, run history |
| `autonomy/runner.py` | Claiming due runs, budgets, failure pausing, run reports |
| `tools/tasks.py` | `task_schedule` (always asks, needs the code, clean conversations only), `task_list`, `task_remove` |
| `config.py`, `runtime.py` | Configuration and wiring (`Runtime.task_agent` builds a task's restricted agent) |

## Security controls in the code

| Control (threat model) | Implementation | Tests |
|---|---|---|
| C1 policy engine | `security/policy.py`, `core/agent.py::_handle` | `tests/unit/security/test_policy.py` |
| C2 taint tracking | `core/conversation.py::TaintState`, `core/agent.py::_accept` | `tests/unit/core/test_agent.py` |
| C2 taint: forwarded messages | `telegram/bot.py::_start_turn` | `tests/unit/telegram/test_bot.py` |
| C2 taint: email and invitations | `tools/gmail.py`, `google/events.py::Event.owner_written`, `tools/calendar.py` | `test_gmail.py`, `test_events.py`, `tools/test_calendar.py` |
| C3 quarantined reader | `llm/quarantine.py`, `tools/gmail.py::GmailReadTool` | `test_quarantine.py`, `test_gmail.py` |
| C4 argument-bound approvals | `security/approvals.py`, `cli/approver.py`, `telegram/approver.py` | `test_approvals.py`, `test_approver.py` (CLI and Telegram) |
| C4 approvals that name their target | `tools/calendar.py::_check_identity`, `google/calendar.py` (`If-Match`) | `tools/test_calendar.py`, `test_clients.py` |
| C5 TOTP step-up | `security/totp.py`, `telegram/approver.py`, `security/policy.py` (`always_step_up`), `tools/gmail.py::GmailSendTool.step_up` | `test_totp.py`, `telegram/test_approver.py`, `test_bot.py` |
| C6 Telegram lockdown | `telegram/pairing.py`, `telegram/bot.py::_on_message`, `telegram/api.py` | `test_pairing.py`, `test_bot.py`, `telegram/test_api.py` |
| C7 egress guard | `security/egress.py`, `tools/web_fetch.py` | `test_egress.py`, `test_web_fetch.py` |
| C8 vault and redaction | `security/vault.py`, `security/redact.py`, `llm/factory.py`, `google/oauth.py::GoogleAuth`, `google/api.py` | `test_vault.py`, `test_redact.py`, `test_factory.py`, `test_oauth.py`, `google/test_api.py` |
| C9 least-privilege OAuth | `google/grant.py`, `runtime.py::build_google_tools`, `cli/google.py`, `google/oauth.py::LoopbackReceiver` | `test_grant.py`, `test_runtime.py`, `test_google_commands.py`, `test_oauth.py` |
| C10 audit log | `security/audit.py`, `storage/db.py`, `security/vault.py::VaultAnchor` (checkpoint), `telegram/bot.py::_checkpoint` (off-machine copy) | `test_audit.py`, `test_commands.py`, `test_telegram_commands.py` |
| C11 budgets, rate limit, kill switch | `core/agent.py::AgentLimits`, `security/ratelimit.py`, `security/killswitch.py` | `test_agent.py`, `test_killswitch_ratelimit.py`, `test_bot.py` |
| C11 scheduled tasks: grants, task mode, budgets | `autonomy/`, `security/policy.py::PolicyEngine.for_task`, `runtime.py::Runtime.task_agent`, `tools/tasks.py` (`always_ask`, `clean_only`), `telegram/bot.py::check_schedule` | `tests/unit/autonomy/`, `test_policy.py`, `tools/test_tasks.py`, `test_runtime.py`, `test_bot.py`, `test_task_commands.py` |
| C12 memory provenance | `tools/memory.py`, `storage/memory_bank.py`; calendar origin marker in `tools/calendar.py` | `tests/unit/tools/test_memory.py`, `tools/test_calendar.py` |
| C13 encryption at rest | `security/crypto.py`, `storage/memory_bank.py`, `autonomy/tasks.py` | `test_crypto.py`, `test_memory.py`, `autonomy/test_tasks.py` |
| C14 supply chain | `uv.lock`, `.github/workflows/` | CI |
| C16 display safety | `text.py`, `core/agent.py::_accept`, `cli/approver.py`, `cli/chat.py`, `telegram/text.py`, `telegram/api.py` (no markup, no link previews), `google/mail.py` (bare ASCII addresses) | `test_text.py`, `test_approver.py`, `test_agent.py`, `telegram/test_text.py`, `telegram/test_api.py`, `test_mail.py` |

Tests that simulate an attack are marked `@pytest.mark.security` (`uv run pytest -m security`).

## Data at rest

| Where | What |
|---|---|
| `~/.bastion/config.toml` | Provider, model, budgets. No secrets. |
| `~/.bastion/policy.toml` | The owner's policy (cannot weaken the code-enforced floors) |
| `~/.bastion/bastion.db` | SQLite: `audit_log` (HMAC chain, append-only triggers), `memories` (AES-GCM), `tasks` (definitions sealed with AES-GCM; next run, paused and failure count in clear), `task_runs` (outcome, tokens, tool calls) |
| `~/.bastion/STOPPED` | Present while the kill switch is engaged (`/stop`); removed by `bastion resume` |
| OS keyring, service `bastion` | LLM and search API keys, `audit.hmac_key`, `storage.encryption_key`, `audit.chain_head`, `telegram.bot_token`, `telegram.owner`, `auth.totp_secret`, `google.client_id`, `google.client_secret`, `google.refresh_token`, `google.grant` (account and access levels) |
| Google Calendar | Events Bastion wrote from untrusted content carry `extendedProperties.private.bastion_origin = untrusted` |

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
- **Synchronous SQLite.** Audit and memory writes are sub-millisecond and run on the event loop,
  in the CLI and in the daemon alike. If `bastion chat` holds the write lock at the same moment,
  the daemon waits for it (up to the 10-second busy timeout); for one owner that is acceptable,
  and simpler than a thread hand-off for every audit entry.
- **A thin Telegram client.** Seven Bot API methods over the existing `httpx2` stack instead of a
  bot framework: one HTTP stack, no extra dependencies, and full control over what is logged
  (the token is part of every URL).
- **One request at a time.** The daemon runs a request as a background task so it can keep
  receiving approval taps, codes and `/stop`; a second request waits ("still working") rather
  than interleaving with the first.
- **Approvals live in the daemon.** Telegram approvals are resolved in memory by the process
  that asked; restarting abandons them (fail closed). Scheduled tasks did not need more: they
  run inside the daemon and use the same approver.
- **Tasks share the one request slot.** A due task starts only when the bot is idle and not
  stopped, so `/cancel`, `/stop` and the approval buttons cover it with no new machinery; the
  owner's messages wait ("running the scheduled task ...") until it finishes.
- **No scheduler dependency.** A fixed schedule grammar and a 30-second check in the daemon
  replace a cron library: every schedule is readable in an approval prompt, none can run more
  than hourly, and missed runs are skipped instead of replayed.
- **The model can propose a task, never grant one silently.** `task_schedule` always asks and
  always needs the authenticator code (`Tool.always_ask`, `Tool.step_up`), and is refused in a
  tainted conversation (`Tool.clean_only`); these are floors a policy file cannot lower.
- **Thin Google clients.** About ten Gmail and Calendar REST calls over the existing `httpx2`
  stack, instead of `google-api-python-client` and `google-auth` with their dozens of transitive
  packages. Phase 3 added no dependencies.
- **The owner's own OAuth client.** Bastion ships no Google client ID: each owner creates one, so
  no third party (not even Bastion's authors) can hold access to their account.
- **One short-lived listener.** Google allows only a loopback redirect for desktop apps with
  Gmail or Calendar access, so `bastion google connect` listens on 127.0.0.1 for one sign-in.
  Nothing listens at any other time.
- **Quarantined reading by default.** `gmail_read` returns the quarantined reader's digest; the
  exact text is one argument away (`full=true`) when the owner needs it. Either way it is
  untrusted.
- **Approvals name their target.** Changing or deleting an event takes its title and start, not
  just an id, so the approval prompt says what will happen; code verifies them against the
  live event, and the ETag guards the gap between that check and the write.
- **Sending mail always needs the code.** Tools can demand step-up regardless of the policy's
  step-up tiers (`Tool.step_up`); `gmail_send` does, because mail sent as the owner is the
  costliest thing a hijacked chat account could do.
