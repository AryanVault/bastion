# Warden

**A secure, always-on personal AI agent. The system, not the model, decides what the agent may do.**

Warden is a personal agent you talk to over Telegram or the CLI. It can read your Gmail and
Calendar, search the web, and run tasks on a schedule. Unlike most agents, it is designed on the
assumption that the language model **will** be prompt-injected at some point: a malicious email or
web page will eventually try to make it leak your data or act against you. Warden's security
controls live outside the model, so a hijacked model still cannot do damage.

> Status: pre-alpha, under active development. See the [roadmap](#roadmap).

## Security model at a glance

| Control | Defends against |
|---|---|
| Default-deny policy engine with risk-tiered tools | Model deciding its own permissions |
| Taint tracking of untrusted content (email, web) | Prompt injection escalating to actions |
| Quarantined reader (dual-LLM pattern) | Attacker text reaching the privileged model |
| Argument-bound, single-use, expiring approvals | Approve-one-thing, execute-another (TOCTOU) |
| TOTP step-up for high-risk actions | Hijacked Telegram account |
| Telegram owner allowlist, long polling only | Strangers commanding the bot, exposed webhooks |
| URL-provenance egress guard and SSRF protection | Data exfiltration through URLs, internal network access |
| OS keyring secret storage and log redaction | Credential theft from disk, logs, or model context |
| Least-privilege OAuth scopes | Over-broad access to your Google account |
| Hash-chained, tamper-evident audit log | Silent tampering with the record of what happened |
| Capability grants and budgets for scheduled tasks | Runaway autonomy |
| Red-team prompt-injection eval suite | Regressions: every control is tested against attacks |

The full analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Roadmap

- [x] Phase 0: foundation, CI security pipeline, threat model
- [ ] Phase 1: secure core, multi-provider LLM layer, CLI, web search
- [ ] Phase 2: Telegram channel with approvals and step-up auth
- [ ] Phase 3: Gmail and Google Calendar
- [ ] Phase 4: autonomous scheduled tasks
- [ ] Phase 5: red-team eval suite, hardened Docker image, signed release

## Development

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run pytest --cov
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run bandit -c pyproject.toml -r src
uv run pip-audit
```

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
