# Keyorix Controls Mapping — SOC 2 (Trust Services Criteria)

This document maps Keyorix's **implemented** technical controls onto the AICPA
Trust Services Criteria (TSC), 2017 revision — the Common Criteria (CC1–CC9,
the Security category, mandatory in every SOC 2 report) plus the
Confidentiality and Availability categories most relevant to a secrets
manager. It is the SOC2-oriented companion to the
[NIS2 · DORA · ISO 27001 controls statement](./NIS2-DORA-ISO-CONTROLS.md); all
three describe the same shipped capabilities through different frameworks.

> **Positioning — read this first, it matters more here than in the other
> mappings.** Keyorix is **not** SOC 2 audited, and **cannot be**, in the sense
> a customer's own auditor usually means: a SOC 2 report is an opinion on an
> **organization's** controls over a period of time (a Type II report),
> examined by a licensed CPA firm, covering things no self-hosted product can
> supply on a customer's behalf — the customer's own personnel/HR controls,
> vendor-management program, business-continuity plan, and change-management
> process for *their* environment. What Keyorix *can* provide is the technical
> control evidence a customer's auditor will ask for under **CC6 (logical
> access)**, **CC7 (system operations)**, and parts of **CC8/CC9** — the
> categories where a specific product's implementation is directly relevant
> evidence. CC1–CC5 are, for a self-hosted deployment, substantially the
> **operator's own** organizational controls, not something Keyorix ships.
> This document says so explicitly per criterion below, rather than mapping
> every CC row to a product feature regardless of fit. See
> [`README.md`](./README.md) for the shared disclaimer and Q3 2026 note.

## How to read the mapping

Each Common Criteria series gets one row group. **Applicability** states
whether the criterion is substantially product-supportable, substantially
operator-owned, or split. **Status** follows the other compliance docs'
convention: `Shipped`, `Operator-configured`, `Operator-owned` (not a product
capability at all — an honest, not evasive, answer), or `Roadmap`.

## CC1 — Control Environment

**Expected:** Organizational integrity, board/management oversight, HR
policies, accountability structures.

**Applicability:** Operator-owned. This is about the operating organization,
not the software it runs. Keyorix's own contribution is limited to supporting
evidence that access decisions are enforceable and attributable once an
organizational policy exists to enforce (scoped RBAC, §CC6) — it cannot
substitute for the policy itself.

**Status:** Operator-owned.

## CC2 — Communication and Information

**Expected:** Internal/external communication of security policies and
responsibilities; information supporting the functioning of internal control.

**Applicability:** Split. Keyorix ships the technical *audit trail* an
operator's own security communications program can point to as evidence
records are complete and attributable; it does not ship the communications
program itself.

**Keyorix provides:**
- A complete, attributable activity log (see CC7 below and
  [`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md)) that an operator can
  cite as evidence their own information-sharing controls are backed by real
  records, not just policy documents.

**Status:** Shipped (the audit-trail evidence half); Operator-owned (the
communications program itself).

## CC3 — Risk Assessment

**Expected:** Objectives are specified clearly enough to identify and assess
risk; fraud risk is considered; changes that could impact controls are
identified.

**Applicability:** Operator-owned — a customer's own risk assessment process.
Keyorix's contribution is the raw material (what's actually enforced, and
what's an explicit residual risk) that a risk assessment can be built from
rather than guessed at — see
[`../security/threat-model.md`](../security/threat-model.md), which states
Keyorix's own residual risks plainly rather than only what's mitigated.

**Status:** Operator-owned.

## CC4 — Monitoring Activities

**Expected:** Ongoing and/or separate evaluations to ascertain whether
controls are present and functioning.

**Keyorix provides:**
- **Built-in anomaly detection** — brute-force / unusual-access alerts,
  deduplicated within a detection window.
- **Independent, offline audit-chain verification**
  (`keyorix-server admin verify-audit`, [`OFFLINE-AUDIT-VERIFICATION.md`](./OFFLINE-AUDIT-VERIFICATION.md))
  — lets an operator's own monitoring function verify control operation
  without trusting the running server process, which is closer to what a
  SOC 2 Type II examiner actually wants ("show me you checked this yourself
  over the period," not "the vendor says it's fine").
- **A live, machine-readable compliance-control matrix**
  (`GET /api/v1/compliance/controls`, ADR-051) surfacing pass/gap/
  not-configured status per control, across frameworks — an operator's own
  continuous-monitoring evidence, generated from the deployment's actual
  posture rather than a point-in-time attestation.

**Status:** Shipped.

## CC5 — Control Activities

**Expected:** Controls that mitigate risk to acceptable levels are selected,
developed, and deployed; policies and procedures put controls into action.

**Applicability:** Split. Keyorix ships the control mechanisms; deploying and
operationalizing them into the organization's own control activities is the
operator's task.

**Keyorix provides:** the full technical control set described in
[`../security/architecture.md`](../security/architecture.md) — encryption,
RBAC, audit, MFA, TLS — as controls available to select and deploy. It does
not, and cannot, decide which of them a given organization's risk posture
requires; `hardening-guide.md` states the production-recommended
configuration.

**Status:** Shipped (mechanisms); Operator-owned (selection and deployment
into a documented control activity).

## CC6 — Logical and Physical Access Controls

**Expected:** Logical access is restricted to authorized users through
credentialing, authentication, and authorization; access is removed when no
longer needed; physical access to facilities is restricted.

This is the criterion series where Keyorix's technical controls are the most
directly relevant evidence — the same access-control surface described in
full in [`NIS2-DORA-ISO-CONTROLS.md`](./NIS2-DORA-ISO-CONTROLS.md) §1 and §4:

**Keyorix provides:**
- **Authentication** — TOTP MFA and WebAuthn/passkeys (ADR-034, ADR-036),
  configurable password policy, short-lived sessions with a hard absolute
  lifetime ceiling, OIDC and SAML 2.0 federation for enterprise identity
  providers.
- **Authorization** — scoped RBAC (system/project/environment), least-
  privilege defaults, a 5-state project-membership lifecycle, PAT tokens
  scopeable below their owner's full authority (ADR-042).
- **Access removal** — session revocation (individual or, on suspension,
  immediate), account suspend/reactivate, membership revocation immediately
  removing access.
- **Physical access** — out of scope by construction: Keyorix runs on
  infrastructure the operator controls, so physical facility access controls
  are the operator's (or their cloud/co-location provider's) responsibility
  entirely, not a Keyorix concern.

**Status:** Shipped (logical access); Operator-owned (physical access to the
hosting infrastructure).

## CC7 — System Operations

**Expected:** Detection and monitoring of anomalies and security events;
evaluation of security events to determine whether they represent an
incident; incident response.

**Keyorix provides:**
- **Complete audit trail** of every security-relevant event — secret
  lifecycle, sharing, authentication, RBAC changes, membership transitions,
  impersonation — each with actor identity, `actor_type`, timestamp, and
  outcome ([`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md)).
- **Tamper-evidence** — a SHA-256 hash chain over audit events (ADR-029)
  detects after-the-fact modification, deletion, insertion, or reordering,
  supporting the integrity of the evidence an incident investigation would
  rely on.
- **SIEM forwarding** — Splunk HEC, Datadog, generic webhook push connectors,
  plus a cursor-paginated pull export, so an operator's own detection tooling
  receives events in near-real-time rather than relying on Keyorix's own UI.
- **A published, timed remediation commitment for vulnerabilities Keyorix
  itself introduces** — acknowledge within 48 hours, initial assessment within
  7 days, a fix within 90 days for all severities, with a 1-week advance
  notice and a same-day advisory for High/Critical findings (ADR-104; see
  [`../SECURITY.md`](../SECURITY.md) once updated to carry this table).

**Status:** Shipped.

## CC8 — Change Management

**Expected:** Changes to infrastructure, data, and software are authorized,
designed, developed, tested, approved, and implemented in a controlled
manner.

**Applicability:** Split. Keyorix's own development process (this repository's
CI gates) is evidence of *the vendor's* change-management discipline, which a
customer's auditor may ask about as vendor due diligence, but does not
substitute for the *customer's own* change-management process for how they
deploy and upgrade Keyorix in their environment.

**Keyorix provides (as vendor-side evidence):**
- 11 required CI status checks gating every merge — `govulncheck`, `gosec`,
  `golangci-lint`, `go test -race`, `go vet`, `gitleaks`, `CodeQL`, `checkov`,
  `go-licenses`, fuzz-target-staleness, DCO sign-off (full list and hardening
  log: [`SECURITY-VERIFICATION.md`](./SECURITY-VERIFICATION.md)).
- **CODEOWNERS** designates the required reviewer for cryptography,
  auth/authz/RBAC core, HTTP/gRPC middleware, database migrations, and the
  CI/CD pipeline itself. **Not currently enforced as a GitHub branch-
  protection gate** — verified via `gh api` that `main`'s ruleset has no
  required-reviewer rule; see
  [`SECURITY-VERIFICATION.md`](./SECURITY-VERIFICATION.md#process-controls)
  and [`../security/SDLC.md`](../security/SDLC.md#branch-protection).
- **Schema-epoch downgrade guard** (ADR-097) — a binary older than the
  database it's pointed at refuses to start rather than silently running
  against unknown schema state, turning a class of unauthorized/unintended
  change into a loud startup failure.

**Status:** Shipped (vendor-side); Operator-owned (the customer's own change
process for deploying/upgrading Keyorix).

## CC9 — Risk Mitigation

**Expected:** Risk from business disruptions and vendor/business-partner
relationships is identified and mitigated.

**Keyorix provides:**
- **No third-party ICT dependency for core operation** — no Keyorix-operated
  cloud sits in the secret-resolution path; air-gapped deployment is
  supported, which materially reduces the vendor-risk surface a customer's own
  vendor-management program has to track for the secrets-management function
  specifically (see [`README.md`](./README.md) "Why on-premise matters").
- **A published, timed vulnerability-remediation commitment** (CC7, above,
  ADR-104) is itself risk-mitigation evidence for the vendor relationship: it
  gives an auditor a concrete, checkable SLA rather than an unstated
  best-effort.
- **Documented, honest residual risk** — [`../security/threat-model.md`](../security/threat-model.md)
  §6 states open items plainly (transient in-process secret exposure, an
  in-progress API wire-hygiene finding; the CLI local-mode gap is closed by ADR-108) rather than presenting a clean bill of health that
  wouldn't survive a real audit.

**Status:** Shipped (the product's own vendor-risk profile); Operator-owned
(the customer's broader vendor-management program, of which Keyorix is one
line item).

## Summary matrix

| Criterion | Applicability | Status |
|---|---|---|
| CC1 — Control Environment | Operator-owned | Operator-owned |
| CC2 — Communication and Information | Split | Shipped (evidence) / Operator-owned (program) |
| CC3 — Risk Assessment | Operator-owned | Operator-owned |
| CC4 — Monitoring Activities | Product-supportable | Shipped |
| CC5 — Control Activities | Split | Shipped (mechanisms) / Operator-owned (selection) |
| CC6 — Logical and Physical Access Controls | Product-supportable (logical) | Shipped (logical) / Operator-owned (physical) |
| CC7 — System Operations | Product-supportable | Shipped |
| CC8 — Change Management | Split | Shipped (vendor) / Operator-owned (customer process) |
| CC9 — Risk Mitigation | Split | Shipped (product risk profile) / Operator-owned (program) |

*This matrix is an informational mapping to support a customer's own SOC 2
program — it is not a SOC 2 report, an attestation, or a substitute for one.
See the disclaimer in [`README.md`](./README.md) and the positioning note
above.*
