# Bastion

**A secure, always-on personal AI agent. The system, not the model, decides what the agent may do.**

Bastion is a personal agent you talk to from Telegram or the terminal. It searches and reads the
web, remembers things for you, reads and drafts your email, and manages your calendar; scheduled
tasks are next. Unlike most agents, it is built on the assumption that the language model **will** be
prompt-injected at some point: a web page or email will eventually try to make it leak your data
or act against you. Bastion's security controls live *outside* the model, in ordinary code, so a
hijacked model still cannot do damage.

> Status: pre-alpha, under active development. See the [roadmap](#roadmap).

## How it works

The model can only *propose* tool calls. Every proposal goes through deterministic checks:

```
model proposes a tool call
  -> unknown tool?                         deny
  -> arguments fail the strict schema?     reject
  -> policy engine (risk tier + taint)     allow | ask the owner | deny
  -> owner approval, bound to the exact arguments (single use, expiring)
  -> tool runs with a timeout; failures are contained
  -> untrusted output taints the conversation and is fenced before the model sees it
  -> every step is written to an HMAC-chained audit log
```

Once a web page, search result or email enters a conversation, the conversation is *tainted*:
anything that sends data out or affects other people now needs your explicit approval, and
destructive actions are refused outright. No prompt can change that, because the model never
decides permissions.

## Security controls

| Control | Defends against | Status |
|---|---|---|
| Default-deny policy engine with risk-tiered tools and code-enforced floors | The model deciding its own permissions | Built |
| Taint tracking of untrusted content | Prompt injection escalating into actions | Built |
| Argument-bound, single-use, expiring approvals | Approve one thing, execute another | Built |
| URL provenance + SSRF guard checked at connect time (DNS-rebinding safe) | Exfiltration via crafted URLs, internal network access | Built |
| Secrets only in the OS keyring, plus redaction | Credential theft from disk, logs or model context | Built |
| HMAC-chained, append-only audit log | Silent tampering with the record of what happened | Built |
| Encrypted memory with provenance bound into the ciphertext | Injected "remember this" instructions coming back as trusted | Built |
| Step, tool-call and token budgets per request | Runaway or hijacked loops | Built |
| Display safety (escape codes, bidi tricks, disguised links) | Misleading the owner on screen | Built |
| Telegram pairing and owner lockdown, no open ports | Strangers commanding the bot | Built |
| Authenticator-code (TOTP) step-up; a `/stop` kill switch only the computer can release | A hijacked Telegram account | Built |
| Forwarded messages treated as untrusted; no link previews or markup | Injection via forwards, exfiltration via link previews | Built |
| Daily audit checkpoint sent off the machine | Rewriting or truncating the audit log | Built |
| Least-privilege Google access: your own OAuth client, an access level you choose, sending opt-in | Over-broad account access | Built |
| Quarantined email reader: a model with no tools summarises email for the planner | Attacker text steering the planner | Built |
| Invitations untrusted; calendar changes checked against the live event before they run | Injection via invites, misdirected approvals | Built |
| Capability grants for scheduled tasks | Autonomous tasks drifting beyond their purpose | Phase 4 |
| Red-team prompt-injection eval suite | Regressions in any of the above | Phase 5 |

Read the [threat model](docs/THREAT_MODEL.md) for the attackers, threats and accepted risks, and
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for where each control lives in the code.

## Quick start

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/AryanVault/bastion.git && cd bastion
uv sync
uv run bastion init      # choose a model provider; keys go to the OS keyring
uv run bastion chat
```

Configuration lives in `~/.bastion` (override with `BASTION_HOME`). API keys are never written
to disk by Bastion: they are stored in Windows Credential Manager, the macOS Keychain or the
Linux Secret Service, and are only ever entered at hidden prompts.

### Model providers

Use whichever model you like; the security guarantees do not depend on it.

| `provider` | Notes |
|---|---|
| `anthropic` | Claude models (default `claude-opus-5-5`) |
| `openai` | OpenAI models |
| `openrouter` | Hundreds of models; IDs look like `anthropic/claude-sonnet-5.5` (the default) |
| `gemini`, `groq`, `mistral` | Through their OpenAI-compatible APIs |
| `ollama` | Fully local; no API key, nothing leaves your machine |
| `custom` | Any OpenAI-compatible endpoint (HTTPS required) |

Web search uses the [Brave Search API](https://brave.com/search/api/) if you add a key
(`bastion secrets set search.brave.api_key`).

### Telegram (always on)

1. In Telegram, talk to [@BotFather](https://t.me/BotFather), send `/newbot`, and copy the token.
2. `uv run bastion telegram setup`: paste the token (hidden; stored in the OS keyring).
3. `uv run bastion telegram pair`: send the bot the one-time code it shows, then confirm in the
   terminal that the request came from you. From then on the bot ignores everyone else.
4. `uv run bastion telegram totp`: add Bastion to an authenticator app. High-risk actions (such
   as deleting) then need its 6-digit code as well as a tap on Approve.
5. `uv run bastion daemon`: Bastion is online. It only makes outbound requests to Telegram; no
   port is opened.

In the chat: `/new` starts fresh, `/status` shows the safety state, `/cancel` abandons a request,
and `/stop` is the emergency stop: Bastion refuses all work until you run `bastion resume` on
the computer. A hijacked Telegram account can stop Bastion, but never restart it.

### Gmail and Google Calendar

Bastion signs in with **your own** Google OAuth client, so no third party ever holds access to
your account. One-time setup in the [Google Cloud console](https://console.cloud.google.com):

1. Create a project, and enable the **Gmail API** and the **Google Calendar API**.
2. Under *Google Auth Platform > Audience*, choose **Personal** if it is offered (sign-ins then
   never expire and there is no "unverified app" screen). Otherwise choose *External* and add
   your own address as a test user; Google then asks you to sign in again every 7 days.
3. Under *Clients*, create a client of type **Desktop app** and keep its ID and secret handy.
4. `uv run bastion google connect`: paste the client ID and secret (the secret is hidden), then
   sign in in the browser window that opens.

Choose how much Bastion may do; the default is `--gmail draft --calendar write`:

| Option | Bastion can |
|---|---|
| `--gmail read` | search and read email |
| `--gmail draft` | ...and save drafts for you to review and send yourself |
| `--gmail send` | ...and send email (each email needs your approval and your authenticator code) |
| `--calendar read` | list events |
| `--calendar write` | ...and create, change and delete single events (deleting needs your approval and authenticator code) |

Emails and invitations from other people are treated as untrusted, like web pages. When
Bastion reads an email, the planning model sees a summary written by a separate model that has
no tools, unless you ask for the exact text. `bastion google status` checks the connection;
`bastion google disconnect` revokes it at Google and deletes it from your computer.

### Commands

| Command | What it does |
|---|---|
| `bastion init` | Set up the provider, keys, config and default policy |
| `bastion chat` | Talk to Bastion in the terminal (`/status`, `/new`, `/exit`) |
| `bastion daemon` | Run Bastion on Telegram, always on |
| `bastion telegram setup \| pair \| unpair \| totp` | Connect the bot, pair your account, set up step-up codes |
| `bastion google connect \| status \| disconnect` | Connect Gmail and Calendar, check the connection, revoke it |
| `bastion resume` | Release the `/stop` kill switch |
| `bastion policy show` | Show what is allowed, asked about or denied |
| `bastion audit verify` | Check the audit log for tampering (`--checkpoint` checks it against a checkpoint the bot sent you) |
| `bastion audit tail` | Show recent audit entries |
| `bastion secrets status` | Show which secrets are set (never their values) |
| `bastion secrets set <name>` | Store a secret from a hidden prompt |

## Roadmap

- [x] Phase 0: foundation, CI security pipeline, threat model
- [x] Phase 1: secure core, multi-provider LLM layer, CLI, web search and fetch, memory
- [x] Phase 2: Telegram channel with approvals and step-up auth
- [x] Phase 3: Gmail and Google Calendar
- [ ] Phase 4: autonomous scheduled tasks
- [ ] Phase 5: red-team eval suite, hardened Docker image, signed release

## Development

```sh
uv sync
uv run pytest --cov                  # tests, 80% coverage gate
uv run pytest -m security            # just the attack-scenario tests
uv run ruff check . && uv run ruff format --check .
uv run mypy                          # strict
uv run bandit -c pyproject.toml -r src
uv export --frozen --no-emit-project --format requirements.txt -o requirements-audit.txt
uv run pip-audit --strict --disable-pip --require-hashes -r requirements-audit.txt
```

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
