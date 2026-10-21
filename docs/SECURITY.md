# Security documentation

Keyorix is a self-hosted secrets manager: encryption at rest, authentication
(sessions, PAT, machine identities, OIDC, SAML SSO, TOTP MFA, WebAuthn/passkeys),
scoped RBAC, and a tamper-evident audit trail, deployed entirely inside your own
infrastructure. This page is the index into the security documentation. For what
is implemented and how, follow the links below; this page is deliberately short.

## Reporting a vulnerability

The vulnerability disclosure policy is maintained in one place:
**[`/SECURITY.md`](../SECURITY.md)**. It covers the reporting channel, response
targets, remediation timelines, scope, safe harbour, supported versions, and how
advisories and patch releases are announced. Nothing on this page overrides it.

Do not open a public GitHub issue for a suspected vulnerability.

## Security documentation

| Document | Covers |
|---|---|
| [`security/threat-model.md`](security/threat-model.md) | Assets, trust boundaries, STRIDE analysis, and stated residual risks — including open items, not only mitigated ones. |
| [`security/architecture.md`](security/architecture.md) | How encryption, authentication, authorization, transport, process hardening, and air-gap operation actually work, with citations. |
| [`security/hardening-guide.md`](security/hardening-guide.md) | A production configuration checklist with the exact config keys, verified against `internal/config`. |
| [`security/testing.md`](security/testing.md) | CI gates, the fuzzing program, differential/property testing, and the machine-checked coverage ledgers. |
| [`security/incident-response-plan.md`](security/incident-response-plan.md) | Roles, severity scale, first-hour checklist, notification, evidence preservation, and secrets-platform cases. |
| [`security/tabletop-1.md`](security/tabletop-1.md) | The first incident-response tabletop exercise: scenario script, injects, and outcomes table. |
| [`security/security-txt.md`](security/security-txt.md) | Source, hosting and renewal of the RFC 9116 `security.txt`. |
| [`compliance/README.md`](compliance/README.md) | Regulatory control mappings (NIS2, DORA, ISO 27001, ENS, SOC 2) built on top of the above. |
| [`compliance/SECURITY-FAQ.md`](compliance/SECURITY-FAQ.md) | The questions a buyer's security team typically asks during a vendor review. |
| [`compliance/SECURITY-VERIFICATION.md`](compliance/SECURITY-VERIFICATION.md) | The security audits performed to date, issues found and fixed, and the standing CI gates. |
| [`compliance/AUDIT-LOG-PROVISIONS.md`](compliance/AUDIT-LOG-PROVISIONS.md) / [`compliance/OFFLINE-AUDIT-VERIFICATION.md`](compliance/OFFLINE-AUDIT-VERIFICATION.md) | What's logged, how, and how to independently verify the audit tamper-evidence chain without trusting the running server. |

## Repository-level protections

GitHub-native secret scanning and push protection, Dependabot security
updates, and private vulnerability reporting are all enabled on this
repository. Branch protection is a GitHub ruleset requiring 18 status-check
contexts (static analysis, `govulncheck`, fuzz coverage, license compliance,
DCO, and more — see [`security/testing.md`](security/testing.md) and
[`security/SDLC.md`](security/SDLC.md) for the full ruleset detail), merged
only through a squash-only merge queue; force-pushing or deleting `main` is
blocked outright. **Correction (2026-10-05):** this previously said "no
bypass, including for maintainers" — the live ruleset carried a standing
`OrganizationAdmin`/`always` bypass actor, which was real, not a
hypothetical. Resolved the same day: kept as a deliberate, narrowed
break-glass path (`bypass_mode: pull_request`, visible on the PR) rather
than removed — see `security/SDLC.md` for the full detail.
