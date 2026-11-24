# Bastion

**Your personal, open-source AI assistant. It runs on your computer, answers you on Telegram, and
its security doesn't depend on the AI behaving.**

[![CI](https://github.com/AryanVault/bastion/actions/workflows/ci.yml/badge.svg)](https://github.com/AryanVault/bastion/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)
[![Red team: 0 of 24 attacks succeed](https://img.shields.io/badge/red%20team-0%20of%2024%20attacks%20succeed-brightgreen.svg)](docs/RED_TEAM.md)

**Open source** · **Runs on your computer** · **Personal: paired to you alone** · **Any AI model,
local ones too**

Bastion is a personal assistant you run yourself, on your own computer or home server, and
message from your phone (Telegram) or your terminal. It reads and drafts your email, manages your
calendar, researches the web, remembers things for you, and runs jobs on a schedule, such as a
briefing every morning. There is no Bastion account and no Bastion server: it's yours.

Giving an AI your inbox is risky: one malicious email or web page can try to talk it into
forwarding your data or deleting things. Bastion is built on the assumption that this **will**
happen. The AI only *proposes* actions; ordinary code decides what is allowed, and anything that
reaches other people or cannot be undone waits for your approval and your authenticator code.

> **Status:** early release (0.1). Everything below works; expect rough edges, and please
> [report problems](../../issues).

**Contents:** [What it does](#what-it-does) · [Open source, local and personal](#open-source-local-and-personal) ·
[Why Bastion](#why-bastion-and-not-another-assistant) · [Why you can trust it](#why-you-can-trust-it) ·
[Get started](#get-started) · [Everyday use](#everyday-use) ·
[Troubleshooting](#troubleshooting) · [How it works](#how-it-works) ·
[Development](#development)

## What it does

| | You can say... |
|---|---|
| **Email** (Gmail) | "Anything important in my inbox today?" · "Summarise the thread with Priya" · "Draft a reply saying I'll send it Friday" |
| **Calendar** (Google Calendar) | "What's on this week?" · "Move my dentist appointment to 4pm" · "Book 30 minutes with Sam tomorrow morning" |
| **Web research** | "Find three reviews of the Framework 13 and summarise them" · "What changed in Python 3.13?" |
| **Memory** | "Remember that my passport expires in March" · "What do you know about my travel plans?" |
| **Scheduled tasks** | "Every weekday at 8, brief me on my calendar and unread email" |

## Open source, local and personal

- **Open source.** Apache-2.0. Every line of code, the [threat model](docs/THREAT_MODEL.md) and
  the [attack suite](docs/RED_TEAM.md) are in this repository, so you can check every claim here.
- **Runs on your computer.** Windows, macOS, Linux, a home server or a Raspberry Pi. Your keys,
  memories and scheduled tasks stay on your own disk, encrypted, next to a tamper-evident
  audit log.
- **Personal.** It pairs with exactly one Telegram account, yours, and ignores everyone else.
  No app to install and no ports to open on your network.
- **Any AI model.** Claude, GPT, Gemini, OpenRouter's hundreds of models, Groq, Mistral, any
  OpenAI-compatible endpoint, or a model that runs on your own machine through Ollama.

**What leaves your computer:** what you ask, and the emails and pages it reads for you, go to the
AI provider you choose, and your Telegram messages pass through Telegram. With a local model
(Ollama), the AI part stays on your machine too.

## Why Bastion, and not another assistant

An assistant that reads your email can be talked into things by the email itself (prompt
injection), and no model is immune to it. Most assistants ask the model to be careful. Bastion
assumes the model **will** be fooled and puts the rules in code that no message can reach.

- **Hosted assistants** run on someone else's servers with their model, and mostly rely on the
  model noticing an attack. Bastion runs on your machine, with the model you choose.
- **DIY agent setups** run locally too, but often keep keys in plain config files and act on
  whatever the model decides. Bastion keeps keys in your keychain, and anything sent in your
  name needs your tap and your authenticator code, even if your chat account is stolen.
- **It shows its work:** 24 attacks run against the real safeguards on every change, and the
  [results](docs/RED_TEAM.md) are published.

It's not the right pick if you want zero setup (a hosted assistant is easier), need it to browse
websites or run code (deliberately out of scope for now), or want a shared assistant for a team.

## Why you can trust it

- **Nothing leaves in your name without you.** Sending an email, inviting someone or deleting
  anything shows you the exact action and needs your tap **and** a 6-digit code from your
  authenticator app. Someone who steals your Telegram account still can't do it.
- **Reading something can't make it act.** Once an email, web page or search result is in the
  conversation, anything outward-facing needs approval and destructive actions are refused
  outright, whatever the text says.
- **It can't be steered to arbitrary websites.** It only opens links you sent it or that came
  from a search, and never reaches your home network or cloud metadata services.
- **Your keys stay locked up.** API keys and tokens live in your operating system's keychain
  (or an encrypted file on servers), never in plain text, logs or the AI's context.
- **You have a kill switch.** Send `/stop` and Bastion refuses all work until you release it
  on your computer.
- **Everything is on the record.** A tamper-evident log records every action and decision.
- **It's tested like an attacker would.** `bastion redteam` throws 24 attacks at it with an AI
  that obeys the attacker completely: **none succeed** ([results](docs/RED_TEAM.md)).

## Get started

About 10 minutes for the basics; each later step is optional.

### 1. What you need

- A computer running Windows, macOS or Linux (or a server; see [step 9](#9-keep-it-running)).
- An API key from a model provider, such as [Anthropic](https://console.anthropic.com),
  [OpenAI](https://platform.openai.com/api-keys) or [OpenRouter](https://openrouter.ai/keys).
  Or [Ollama](https://ollama.com) for a model that runs entirely on your machine (no key).
- Optional: Telegram (to use it from your phone), a Google account (email and calendar), and an
  authenticator app such as Google Authenticator, 1Password or Aegis.

### 2. Install

Bastion installs with [uv](https://docs.astral.sh/uv/), which also fetches the right Python
for you.

```sh
# macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Open a new terminal, then:

```sh
uv tool install git+https://github.com/AryanVault/bastion
bastion --version
```

### 3. Set it up

```sh
bastion init
```

It asks which provider you use (`anthropic`, `openai`, `gemini`, `openrouter`, `groq`,
`mistral`, `ollama` or `custom`), which model (with a sensible default), and your API key.
Keys are typed at hidden prompts and go straight into your system's keychain. Press Enter to
skip the web-search key for now ([step 7](#7-turn-on-web-search)).

| Provider | Notes |
|---|---|
| `anthropic` | Claude models (default `claude-opus-5-5`) |
| `openai` | OpenAI models |
| `openrouter` | Hundreds of models; IDs look like `anthropic/claude-sonnet-5.5` (the default) |
| `gemini`, `groq`, `mistral` | Through their OpenAI-compatible APIs |
| `ollama` | The model runs on your own machine; no API key |
| `custom` | Any OpenAI-compatible endpoint (HTTPS required) |

### 4. Say hello

```sh
bastion chat
```

Ask it anything. When it wants to do something that needs your say-so, it shows you exactly
what and asks first. Type `/status` to see its safety state, `/new` to start over and `/exit`
to leave.

### 5. Put it on your phone (Telegram)

1. In Telegram, open [@BotFather](https://t.me/BotFather), send `/newbot`, follow the prompts
   and copy the token it gives you.
2. Run `bastion telegram setup` and paste the token (it stays hidden).
3. Run `bastion telegram pair`. It shows a one-time code: send `/pair <code>` to your new bot,
   then confirm in the terminal that it was you. From now on the bot ignores everyone else.
4. Run `bastion telegram totp`. Add the setup key it shows to your authenticator app, and type
   the code the app shows to confirm. Sending and deleting will need these codes.
5. Run `bastion daemon`. Bastion is online: message your bot!

When an action needs approval you'll get a message showing exactly what will happen, with
**Approve** and **Deny** buttons. For sending or deleting, tap Approve and then send the
6-digit code from your authenticator app as a normal message.

### 6. Connect Gmail and Google Calendar (optional)

Bastion signs in with **your own** Google app, so no third party ever holds access to your
account. One-time setup in the [Google Cloud console](https://console.cloud.google.com):

1. Create a project, and enable the **Gmail API** and the **Google Calendar API**.
2. Under *Google Auth Platform > Audience*, choose **Personal** if it is offered (sign-ins then
   never expire and there is no "unverified app" screen). Otherwise choose *External* and add
   your own address as a test user; Google then asks you to sign in again every 7 days.
3. Under *Clients*, create a client of type **Desktop app** and keep its ID and secret handy.
4. Run `bastion google connect`: paste the client ID and secret (the secret stays hidden), then
   sign in in the browser window that opens. On a server with no browser, add `--no-browser`.

Choose how much Bastion may do (the default is `--gmail draft --calendar write`):

| Option | Bastion can |
|---|---|
| `--gmail read` | search and read email |
| `--gmail draft` | ...and save drafts for you to review and send yourself |
| `--gmail send` | ...and send email (each one needs your approval and authenticator code) |
| `--calendar read` | list events |
| `--calendar write` | ...and create, change and delete events (inviting people or deleting needs your approval and authenticator code) |

When Bastion reads an email, a separate AI with no abilities summarises it first, so the
assistant never acts on the sender's words directly. `bastion google status` checks the
connection; `bastion google disconnect` revokes it at Google and removes it from your computer.

### 7. Turn on web search

Web search uses the [Brave Search API](https://brave.com/search/api/). Get a key there, then:

```sh
bastion secrets set search.brave.api_key
```

### 8. Schedule tasks

Ask on Telegram ("every weekday at 8, brief me on my calendar and unread email") and approve
with your code, or add one on your computer:

```sh
bastion tasks add --name "Morning brief" --schedule "weekdays 08:00" \
  --tools gmail_search,gmail_read,calendar_list_events \
  --instructions "Summarise today's calendar and any important new email."
```

Schedules look like `daily 08:00`, `weekdays 08:00`, `weekends 10:30`, `mon,wed,fri 18:30` or
`every 4h`, in your computer's local time. Each run starts fresh, can use only the tools you
gave it, has a token budget, and sends you a report on Telegram. A task can never send or
invite without asking you, and three failed runs in a row pause it. `bastion tasks list`
shows your tasks; `bastion tasks run <id>` runs one now.

### 9. Keep it running

Telegram and scheduled tasks need `bastion daemon` running. To start it automatically, follow
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): a hardened Docker setup for a server, VPS or
Raspberry Pi, a systemd service, or start-at-sign-in on Windows and macOS.

## Everyday use

**On Telegram**

| Command | What it does |
|---|---|
| `/new` | Start a fresh conversation (also clears the "untrusted content" state) |
| `/status` | Show the model, the conversation's safety state and your tasks |
| `/tasks` | List scheduled tasks |
| `/cancel` | Abandon the current request |
| `/stop` | Emergency stop: Bastion refuses everything until you run `bastion resume` on your computer |

Forwarded messages are treated like web pages: Bastion reads them, but they can't make it act.
After it reads outside content, it tells you that sending and deleting now need your approval;
send `/new` when you move on to something else.

**On your computer**

| Command | What it does |
|---|---|
| `bastion init` | Set up the model, keys and default policy |
| `bastion chat` | Talk to Bastion in the terminal |
| `bastion daemon` | Run Bastion on Telegram and run scheduled tasks |
| `bastion resume` | Release the `/stop` emergency stop |
| `bastion telegram setup \| pair \| unpair \| totp` | Connect the bot, pair your account, set up codes |
| `bastion google connect \| status \| disconnect` | Connect Gmail and Calendar, check, revoke |
| `bastion tasks list \| show \| add \| pause \| resume \| remove \| run` | Manage scheduled tasks |
| `bastion secrets status \| set <name>` | See which secrets are stored (never their values), store one |
| `bastion secrets master-key <file>` | Create the key for the encrypted secret file (servers only) |
| `bastion policy show` | See what is allowed, asked about or refused |
| `bastion audit verify \| tail` | Check the activity log for tampering, show recent entries |
| `bastion redteam` | Attack Bastion in a sandbox and show what held |

Your settings live in `~/.bastion` (change it with `BASTION_HOME`). Spending limits per request
and per scheduled task are in `~/.bastion/config.toml` under `[limits]` and `[autonomy]`.

## Troubleshooting

**"The OS keyring is unavailable" (Linux).** Bastion stores keys in the Secret Service. On a
desktop, make sure GNOME Keyring or KWallet is running; on a server or in a container, use the
encrypted file store instead ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

**The bot doesn't answer.** Check that `bastion daemon` is running and that you are messaging
from the account you paired. If you changed phones or accounts, run `bastion telegram pair`
again. Only one daemon can run per bot.

**"No authenticator is set up" when sending or inviting.** Run `bastion telegram totp`, then
restart `bastion daemon`.

**Google says "Access blocked" or "This app isn't verified".** Add your address as a test user
under *Audience* (or choose *Personal*). Being asked to sign in again every 7 days means your
app is in *Testing* mode; *Personal* avoids it.

**It refused something I wanted.** Read the reason it gives. Usually the conversation contains
outside content (send `/new` and ask again), or the action needs your approval. `bastion policy
show` lists the rules.

**Bastion is stopped.** Someone (hopefully you) sent `/stop`. Run `bastion resume` on the
computer.

**Uninstall.** Run `bastion google disconnect` and `bastion telegram unpair`, then
`uv tool uninstall bastion` and delete `~/.bastion`. Any remaining keychain entries (service
name `bastion`, listed by `bastion secrets status`) can be removed in your system's keychain app.

## How it works

The AI model can only *propose* actions. Every proposal goes through checks in ordinary code:

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

| Control | Defends against |
|---|---|
| Default-deny policy engine with risk-tiered tools and code-enforced floors | The model deciding its own permissions |
| Taint tracking of untrusted content | Prompt injection escalating into actions |
| Argument-bound, single-use, expiring approvals | Approve one thing, execute another |
| Authenticator-code step-up for anything sent in your name or destructive; `/stop` only the computer can release | A hijacked Telegram account |
| URL provenance + SSRF guard checked at connect time (DNS-rebinding safe) | Exfiltration via crafted URLs, internal network access |
| Quarantined email reader: a model with no tools summarises email for the planner | Attacker text steering the planner |
| Invitations untrusted; calendar changes checked against the live event | Injection via invites, misdirected approvals |
| Encrypted memory with provenance bound into the ciphertext | Injected "remember this" instructions coming back as trusted |
| Scheduled tasks with fixed tool grants, budgets and sealed definitions | Tasks drifting, looping, or being planted by injected text |
| Secrets in the OS keyring (servers: a sealed file whose key lives elsewhere), plus redaction | Credential theft from disk, backups, logs or model context |
| HMAC-chained audit log with off-machine checkpoints | Silent tampering with the record |
| Step, tool-call and token budgets | Runaway or hijacked loops |
| Telegram pairing, owner lockdown, no open ports, no link previews | Strangers commanding the bot, exfiltration via previews |
| Display safety (escape codes, bidi tricks, disguised links) | Misleading you on screen |
| Least-privilege Google access through your own OAuth client | Over-broad account access |
| Hardened container; releases with an SBOM and signed provenance | Escalation after a compromise; tampered downloads |
| [Red-team suite](docs/RED_TEAM.md): 24 attacks against the real controls, in CI | Regressions in any of the above |

Read the [threat model](docs/THREAT_MODEL.md) for the attackers, threats and accepted risks,
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for where each control lives in the code, and
[SECURITY.md](SECURITY.md) to report a vulnerability or verify a release.

## Development

```sh
git clone https://github.com/AryanVault/bastion.git && cd bastion
uv sync
uv run pytest --cov                  # tests, 80% coverage gate
uv run pytest -m security            # just the attack-scenario tests
uv run bastion redteam               # the red-team suite
uv run ruff check . && uv run ruff format --check .
uv run mypy                          # strict
uv run bandit -c pyproject.toml -r src
uv export --frozen --no-emit-project --format requirements.txt -o requirements-audit.txt
uv run pip-audit --strict --disable-pip --require-hashes -r requirements-audit.txt
docker build -t bastion .            # the hardened image (CI also smoke-tests it)
```

The landing page lives in [`site/`](site/): plain HTML, CSS and JavaScript with no build step
and nothing loaded from other hosts. A test keeps its attack list in step with the suite.

Contributions are welcome. For anything security-related, please read
[SECURITY.md](SECURITY.md) first.

## License

[Apache-2.0](LICENSE)
