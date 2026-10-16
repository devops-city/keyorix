# Keyorix Controls Statement — NIS2 · DORA · ISO/IEC 27001

This document maps Keyorix's **implemented** technical controls onto the control
themes of the EU NIS2 Directive (Directive (EU) 2022/2555), the Digital
Operational Resilience Act (DORA, Regulation (EU) 2022/2554), and ISO/IEC
27001:2022 Annex A.

> See [`README.md`](./README.md) for the positioning disclaimer. Keyorix is not
> certified against these frameworks; this is an informational mapping of shipped
> capabilities. Article numbers are provided for orientation — confirm exact
> applicability with your legal counsel.

## How to read the mapping

Each control theme below lists:
- **What the regulation expects** (paraphrased, for orientation).
- **What Keyorix provides** — the concrete, shipping capability.
- **Status** — `Shipped` (in product today), `Operator-configured` (a shipped
  capability the operator must enable/configure), or `Roadmap`.

---

## 1. Access control & authorisation

**Expected** — NIS2 Art. 21(2)(i) access-control policies; DORA ICT protection &
prevention (access management); ISO 27001 Annex A 5.15–5.18 (access control,
identity, authentication, access rights).

**Keyorix provides:**
- **Role-based access control (RBAC)** with a two-tier scoped model: roles are
  granted at **system**, **project**, or **environment** scope (sentinel model —
  `project_id = 0` = system scope). Built-in roles: `system_admin` /
  `system_auditor` / `system_viewer` and `project_admin` / `project_developer` /
  `project_viewer` / `project_auditor`. Authorisation is enforced server-side on
  every API path (`core.Authorize(user, permission, scope)`), with the same
  enforcement on both the HTTP and gRPC surfaces.
- **Least-privilege defaults** — new users default to `system_viewer`; users
  cannot grant permissions they do not themselves hold.
- **Project membership lifecycle** — a 5-state membership machine
  (`invited → identity_verified → provisioned → active`, `revoked` terminal);
  access is granted only on `active` and removed on `revoke`.
- **Machine identities** — service/CI/Kubernetes principals modelled separately
  from human users, with their own lifecycle (`pending → active → suspended ⇄
  active`, `revoked` terminal).

**Status:** Shipped.

---

## 2. Cryptography & protection of data

**Expected** — NIS2 Art. 21(2)(h) cryptography and encryption policies; DORA
protection of data at rest/in transit; ISO 27001 Annex A 8.24 (use of
cryptography).

**Keyorix provides:**
- **Encryption at rest** — every secret value is encrypted with **AES-256-GCM**
  using **envelope encryption**: a Data Encryption Key (DEK) wrapped by a
  passphrase-derived Key Encryption Key (KEK). Additional Authenticated Data
  (AAD) binds each ciphertext to its project context, preventing
  cross-context ciphertext substitution.
- **Key rotation** — operator-driven DEK rotation with a full re-encryption sweep
  (`keyorix-server admin encryption rotate`), covering all DEK-encrypted tables, with
  promote-to-disk and restart-survival verified by an end-to-end integration
  test (ADR-010).
- **Encryption in transit** — TLS terminated either by the bundled, opt-in Caddy
  auto-HTTPS profile (`docker compose --profile tls up`, which auto-provisions a
  publicly-trusted certificate for a real domain) or at the server itself for the
  single-binary deployment. HSTS and a strict Content-Security-Policy
  (`script-src 'self'`) are shipped.
- **No plaintext in logs** — audited across every sink: no secret values,
  passphrases, key bytes, or raw tokens are ever logged. Tokens are SHA-256
  hashed before use; API keys are masked.

**Status:** Shipped (in-transit TLS is Operator-configured — enable the profile
or provide certs).

---

## 3. Logging, monitoring & audit trail

**Expected** — NIS2 Art. 21(2) logging in support of incident detection &
handling; DORA detection and record-keeping of ICT activity; ISO 27001 Annex A
8.15 (logging), 8.16 (monitoring activities).

**Keyorix provides** (see [`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md)
for the full treatment):
- A complete, append-style **audit trail** of every security-relevant event —
  secret create/read/update/delete, sharing changes, authentication
  success/failure, RBAC role/permission/group changes, membership transitions,
  and impersonation start/end — each carrying actor identity, timestamp, and
  outcome.
- **Actor attribution** — `actor_type` (user / machine_identity / system) and,
  for delegated actions, `impersonated_by` / `acting_as` resolved to
  human-readable identities; every action under an impersonation session is
  tagged.
- **Change diffs without leakage** — `secret.updated` records a metadata
  before/after diff (max_reads, expiration) and a `{"value":{"changed":true}}`
  marker — **never the plaintext value**.
- **SIEM integration** — async push connectors for Splunk HEC, Datadog, and a
  generic webhook, plus a cursor-paginated pull export
  (`GET /api/v1/audit/export`).
- **Anomaly detection** — built-in alerts (e.g. brute-force / unusual access),
  deduplicated within a detection window.

**Status:** Shipped (SIEM forwarding is Operator-configured).

---

## 4. Authentication & session security

**Expected** — NIS2 Art. 21(2)(j) use of MFA/strong authentication where
appropriate; ISO 27001 Annex A 5.17 (authentication information), 8.5 (secure
authentication).

**Keyorix provides:**
- **Short-lived session tokens** with a configurable access TTL and a hard
  **absolute lifetime ceiling** that refresh cannot extend; `/auth/refresh`
  rotates the token and refuses past the ceiling. Active sessions are listable
  and individually revocable.
- **Password policy** — configurable minimum length, character-class complexity,
  reject-personal-info, reject-common-passwords (offline denylist), password
  history (no-reuse), and max-age expiry.
- **Account state machine** — `active` / `pending_first_login` /
  `password_reset_required` / `suspended`; a first-login gate forces a password
  change before any other action; suspended accounts cannot authenticate.
- **Credential delivery** — single-use, hashed-at-rest setup links (24h TTL) or a
  one-time generated password for out-of-band relay; no reusable credential is
  ever emailed.
- **MFA / TOTP + WebAuthn** — **Shipped** (ADR-034, ADR-036): per-user opt-in
  second factors with a two-step login (a short-lived single-use challenge gates
  session issuance) — TOTP with single-use recovery codes (secret encrypted at
  rest), and **phishing-resistant WebAuthn / passkeys** (origin-bound public-key
  assertions, no exportable shared secret, FIDO clone detection). Either factor
  satisfies a `security.require_mfa` mandate (interactive sessions without a second
  factor are confined to enrolment; PAT / machine / OIDC are exempt). The mandate
  is enforceable **deployment-wide or per-project** (ADR-037: a sensitive project
  can require MFA even when the global policy is off), giving risk-proportionate
  step-up.

**Status:** Shipped.

---

## 5. ICT third-party risk & operational continuity

**Expected** — DORA ICT third-party-risk management and continuity of critical
functions; NIS2 supply-chain security (Art. 21(2)(d)); ISO 27001 Annex A 5.19–5.23
(supplier relationships, cloud services).

**Keyorix provides:**
- **On-premise / air-gapped deployment** — no Keyorix-operated cloud in the
  secret-resolution path; the single static binary can serve the API and the web
  UI with no external dependency. This materially reduces the ICT-third-party
  surface for the secret-management function.
- **PostgreSQL-backed durability** — the operator owns the database; standard
  PostgreSQL backup/restore applies. The self-hosting runbook documents backup &
  restore of **both** the database and the key material (wrapped DEK + KEK salt).
- **No hidden defaults** — the deployment refuses to start without
  operator-supplied secrets (`${VAR:?}`), so there are no baked-in default
  passwords.

**Status:** Shipped.

---

## 6. Data retention & disposal

**Expected** — NIS2 durable record-keeping in support of incident handling; ISO
27001 Annex A 8.10 (information deletion), 5.33 (protection of records).

**Keyorix provides:**
- **Operator-controlled, uncapped retention** — audit history lives in your
  PostgreSQL; Keyorix imposes no retention limit and no retention paywall.
- **Soft delete + restore** — users (and projects/environments) are soft-deleted
  and restorable, preserving audit and ownership history rather than hard-erasing
  it.

**Status:** Shipped. (Automated purge schedulers for soft-deleted records are
config-present but not yet wired — Roadmap.)

---

## Summary matrix

| Control theme | NIS2 (Art. 21) | DORA | ISO 27001:2022 | Keyorix status |
|---|---|---|---|---|
| Access control & authorisation | 21(2)(i) | ICT protection | A.5.15–5.18 | Shipped |
| Cryptography | 21(2)(h) | data protection | A.8.24 | Shipped |
| Logging & audit | 21(2) | detection/records | A.8.15–8.16 | Shipped |
| Authentication & sessions | 21(2)(j) | — | A.5.17, 8.5 | Shipped (incl. TOTP MFA + WebAuthn/passkeys) |
| ICT third-party / continuity | 21(2)(d) | third-party risk | A.5.19–5.23 | Shipped |
| Retention & disposal | 21(2) | record-keeping | A.8.10, 5.33 | Shipped (purge roadmap) |

*This matrix is an informational mapping, not a certification. See the disclaimer
in [`README.md`](./README.md).*
