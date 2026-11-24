# Security Policy

Security is the point of this project, so reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately through
GitHub's [private vulnerability reporting](../../security/advisories/new) for this repository.

Include what you can of:
- the affected component (policy engine, taint tracking, egress guard, approvals, a tool, a channel)
- steps to reproduce, or a proof-of-concept prompt / email / web page
- the impact (what an attacker gains)

Expect an acknowledgement within 7 days. Fixes for confirmed issues are released as soon as
practical, and reporters are credited in the advisory unless they prefer otherwise.

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.

## Verifying a release

Every release is built by [`release.yml`](.github/workflows/release.yml) from a tagged
commit, and every artefact (wheel, sdist, CycloneDX SBOM, container image) carries a
Sigstore-signed build-provenance attestation tied to this repository and that workflow.
Check one before you install or run it (needs the [GitHub CLI](https://cli.github.com)):

```sh
gh attestation verify bastion-0.1.0-py3-none-any.whl --repo AryanVault/bastion
gh attestation verify oci://ghcr.io/aryanvault/bastion:0.1.0 --repo AryanVault/bastion
```

A passing check proves the file was built by this repository's release workflow from the
tagged commit, not that the commit is free of bugs. The SBOM
(`bastion-<version>.cdx.json`) lists every dependency with its exact version and hashes.

## What counts as a vulnerability

Bastion assumes the language model can be manipulated, so "I made the model say something odd" is
not a vulnerability by itself. These are:

- Any way to make Bastion perform a `send` or `destructive` action **without** the owner's approval
- Any way to exfiltrate private data (emails, calendar, memory, secrets) to a third party
- Bypassing the approval binding (approving one action and having a different one executed)
- Bypassing the Telegram owner allowlist or TOTP step-up
- SSRF or URL-provenance bypasses in `web_fetch`
- Secrets appearing in logs, the audit log, or model context
- Reading secrets from the sealed file store without its master key
- Escaping the container's restrictions (non-root, read-only, no capabilities)
- Undetected tampering with the audit log
- A scheduled task exceeding its capability grant or budget

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full model, including the risks we
explicitly accept.
