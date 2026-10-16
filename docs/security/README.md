# Keyorix Security Documentation

> **Positioning.** This is the index into every security document this
> repository maintains. Every claim in every linked document cites the
> code, test, ADR, or live CI/GitHub-API evidence behind it — this page
> does not restate those claims, only points to where they live. See
> [`../../SECURITY.md`](../../SECURITY.md) for the vulnerability
> disclosure policy (the document GitHub's Security tab surfaces) and
> [`../compliance/README.md`](../compliance/README.md) for the
> regulatory-framework control mappings built on top of everything here.

## Contents

| Document | Covers |
|---|---|
| [`SECURITY-MODEL.md`](SECURITY-MODEL.md) | One-page public summary in the Vault/OpenBao/Infisical format: goals, in scope, explicit out-of-scope list, trust assumptions. Start here. |
| [`threat-model.md`](threat-model.md) | System-wide threat model: assets, trust boundaries, STRIDE per boundary, residual risks — the longest-standing, most-reviewed source; per-component documents below narrow this, never override it. |
| [`threat-models/`](threat-models/README.md) | Twelve per-component threat models (server API, authentication, authorization/RBAC, audit chain, secret storage + key hierarchy, backup/restore, update bundles, connectors, Kubernetes operator, web UI, HA consistency, MCP server), each with a data-flow diagram and a VSO-style threat table (ID/STRIDE/Description/Mitigation/Evidence link/Residual-or-GAP). |
| [`architecture.md`](architecture.md) | How encryption, authentication, authorization, transport, process hardening, and air-gap operation actually work, with code/ADR citations for each mechanism. |
| [`production-hardening-matrix.md`](production-hardening-matrix.md) | What each network listener (REST/web, gRPC, k8s-sync probe) enforces — timeouts, request limits, rate limits, response headers, TLS — with the setting, the default and the test behind every row (rows that name a missing test fail CI). |
| [`hardening-guide.md`](hardening-guide.md) | A production configuration checklist with the exact config keys, verified against `internal/config`. |
| [`SDLC.md`](SDLC.md) | Secure development policy: branch protection (read live via `gh api`), DCO, review flow, CI gates, fuzzing, dependency policy, release signing/SBOM/SLSA, remediation SLA, merge queue — each item marked in place (with evidence) or planned. |
| [`SECURE-CODING.md`](SECURE-CODING.md) | Ten coding rules this codebase actually enforces, each with the real finding that motivated it and the guard/test that keeps it true. |
| [`testing.md`](testing.md) | CI gates in depth, the fuzzing programme, differential/property testing, and the machine-checked coverage ledgers. |
| [`BSI-APP.bd.6-mapping.md`](BSI-APP.bd.6-mapping.md) | One row per requirement of Germany's BSI IT-Grundschutz module APP.bd.6 ("Secrets Management with Hashicorp Vault") — status (met/partly/not met/not applicable), evidence link, gap issue if any. |

## Related, one level up

| Document | Covers |
|---|---|
| [`../../SECURITY.md`](../../SECURITY.md) | Vulnerability disclosure: how to report, response targets, safe harbor, remediation SLA, release-verification commands. |
| [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) | What CI checks and what's required to contribute (overlaps `SDLC.md`'s branch-protection section; `SDLC.md` is the more detailed, evidence-linked version). |
| [`../compliance/README.md`](../compliance/README.md) | NIS2/DORA/ISO 27001/ENS/SOC 2 control mappings built on the controls documented here. |

## For buyers: control → evidence

One page, no prose — each row is a claim a vendor-security-review
questionnaire typically asks about, and the exact artifact that proves
it. If a link 404s or a cited test doesn't exist, that's a bug in this
table — file an issue; don't take the row on faith.

| Control | Evidence |
|---|---|
| Encryption at rest (AES-256-GCM, envelope encryption) | [`architecture.md`](architecture.md) §1, [`threat-models/secret-storage-key-hierarchy.md`](threat-models/secret-storage-key-hierarchy.md) |
| Key management (file/env/exec/Shamir/TPM/KMS, no plaintext KEK on disk) | [`architecture.md`](architecture.md) §1, ADR-038/041 |
| Key rotation with completeness guarantee | [`architecture.md`](architecture.md) §2, `internal/encryption/sweep_completeness_test.go` |
| Audit trail: tamper-evidence, not just logging | [ADR-029](../adr-029-audit-log-tamper-evidence.md), [`threat-models/audit-chain.md`](threat-models/audit-chain.md), [`../compliance/AUDIT-LOG-PROVISIONS.md`](../compliance/AUDIT-LOG-PROVISIONS.md) |
| Independent, offline audit verification (don't trust the vendor's running server) | [`../compliance/OFFLINE-AUDIT-VERIFICATION.md`](../compliance/OFFLINE-AUDIT-VERIFICATION.md) |
| Authentication: sessions, PAT, machine identity, MFA, WebAuthn, OIDC, SAML SSO | [`threat-models/authentication.md`](threat-models/authentication.md), [`architecture.md`](architecture.md) §4 |
| Authorization: scoped RBAC, no role-rename self-escalation | [`threat-models/authorization-rbac.md`](threat-models/authorization-rbac.md), [ADR-084](../adr-084-admin-bypass-structural-marker.md) |
| Anti-enumeration (no existence leak via differential errors) | [ADR-096](../adr-096-anti-enumeration-403-for-both.md) |
| SSRF protection on outbound connector/rotation-target calls | [`threat-models/connectors.md`](threat-models/connectors.md), `internal/netutil` |
| TLS enforcement, cipher-suite hardening, HSTS/CSP | [`architecture.md`](architecture.md) §6 |
| Process hardening (core-dump suppression) | [`architecture.md`](architecture.md) §7, [ADR-098](../adr-098-process-memory-hardening.md) |
| Air-gapped operation: no phone-home, signed offline update bundles, offline licensing | [`threat-models/update-bundles-airgap.md`](threat-models/update-bundles-airgap.md), [`architecture.md`](architecture.md) §8 |
| Backup/restore with integrity + audit-chain-verified restore | [`threat-models/backup-restore.md`](threat-models/backup-restore.md) |
| Release signing (cosign keyless), SLSA build provenance, SBOM | [`../../SECURITY.md`](../../SECURITY.md) § Verifying a Release, [`SDLC.md`](SDLC.md) § Release signing |
| CI security gates (static analysis, vuln scanning, secret scanning, race-detector tests) | [`testing.md`](testing.md) §1, [`SDLC.md`](SDLC.md) § Branch protection |
| Continuous fuzzing programme | [`testing.md`](testing.md) §2 |
| Dependency policy (Dependabot, govulncheck, OSV-Scanner, license allowlist) | [`SDLC.md`](SDLC.md) § Dependency policy |
| Vulnerability disclosure process + remediation SLA | [`../../SECURITY.md`](../../SECURITY.md), [ADR-104](../adr-104-security-remediation-sla.md) |
| Branch protection — **honestly scoped, not overstated; one gap found and resolved same-day** | [`SDLC.md`](SDLC.md) § Branch protection — found an org-admin bypass actor earlier documents had incorrectly claimed didn't exist; resolved 2026-10-05 by narrowing it to a pull-request-only break-glass path rather than removing it; also added no-force-push/no-deletion rules on `main` the same day |
| Required code-owner review on security-sensitive paths — **currently a designation, not a GitHub-enforced gate** | [`../compliance/SECURITY-VERIFICATION.md`](../compliance/SECURITY-VERIFICATION.md#process-controls) |
| K8s delivery (operator/sync-agent/ESO): least-privilege RBAC, confused-deputy guard | [`threat-models/kubernetes-operator.md`](threat-models/kubernetes-operator.md) |
| Web UI: session-cookie-only auth (no token in `localStorage`), CSRF, CSP | [`threat-models/web-ui.md`](threat-models/web-ui.md) |
| HA / cross-replica consistency — a threat class not published by any competitor surveyed | [`threat-models/ha-consistency.md`](threat-models/ha-consistency.md), `docs/specs/check-then-act-inventory.md` |
| AI-agent (MCP server) access: least-privilege, read-only, audited, prompt-injection modeled explicitly | [`threat-models/mcp-server.md`](threat-models/mcp-server.md), [`../mcp.md`](../mcp.md) |
| Regulatory control mappings (NIS2, DORA, ISO 27001, ENS, SOC 2) | [`../compliance/README.md`](../compliance/README.md) |
| BSI IT-Grundschutz APP.bd.6 mapping (Vault-specific module, walked against Keyorix) | [`BSI-APP.bd.6-mapping.md`](BSI-APP.bd.6-mapping.md) |

Two rows above are deliberately phrased as "honestly scoped" rather than
"in place" — a prior version of several documents in this repository
overstated branch-protection and code-owner-review enforcement, found
while writing this evidence pack (2026-10-05). The branch-protection gap
was resolved the same day (narrowed, not removed, per Andrei's decision —
see `SDLC.md`); the code-owner-review gap is still open. Both rows stay
here rather than being quietly rewritten to "in place" without a trace,
consistent with this repository's own stated engineering principle: a
claim with no mechanism that fails when it stops being true is a comment,
however carefully written.
