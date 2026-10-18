# Keyorix Threat Model

> **Positioning.** This is an engineering threat model, not a certification or an
> audit report. It states what Keyorix defends against, how, and what is
> deliberately out of scope or still open — with a code, test, or ADR citation for
> every claim. See [`../compliance/README.md`](../compliance/README.md) for the
> regulatory-framework mappings this threat model underpins.

## 1. Scope and method

Keyorix is a self-hosted secrets manager: an operator runs the server (and,
optionally, the CLI, gRPC clients, the web UI, and Kubernetes delivery agents)
entirely inside their own infrastructure. There is no Keyorix-operated cloud in
the secret-resolution path. This document covers the product as shipped on
`main` as of 2026-09-25, and is organized the way
[`../security-review-2026-09.md`](../security-review-2026-09.md) — the primary
evidence source behind §4 — was itself organized: by trust boundary, then by
STRIDE category, with an explicit mitigation and an explicit residual risk for
every entry. Nothing below is invented for this document; every mitigation cites
the code, ADR, or test that implements or proves it.

**What this document does not do:** it does not re-derive findings that
`security-review-2026-09.md` already investigated and closed — it cites that
review's conclusions and adds the trust-boundary structure the review itself
didn't organize around. It also does not treat `docs/findings/*.md` (a live,
in-progress internal audit campaign, most recently touched 2026-09-25) as
settled evidence — those are cited only where explicitly marked "in progress,"
never as closed.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| **Secret values** (plaintext) | Transient: process heap, between decryption and response/wipe | The product's core promise: only an authorized, authenticated caller ever sees one. |
| **Secret ciphertext** | `secret_nodes` and related tables, AES-256-GCM under the current DEK | Confidentiality rests on the DEK never leaking and AAD binding preventing ciphertext substitution. |
| **DEK (Data Encryption Key)** | Wrapped by the KEK, stored alongside the encrypted data | Compromise = compromise of every secret value in the install. |
| **KEK (Key Encryption Key)** | File, KMS/HSM, or TPM-backed (`internal/config/config.go` `KeyProvider`) | Compromise of the KEK, plus the wrapped DEK, is total compromise. Where the KEK IS the threat boundary is exactly where "host root" stops mattering — see §5.1. |
| **Audit chain hash-chain key material** (checkpoint HMAC key) | HKDF-derived from the KEK, held only in server process memory (ADR-029, `#502` correction) | Lets a DB-only actor tamper with history undetectably; never persisted to the database itself. |
| **Recovery key** | SHA-256 verifier only, `internal/recoverykey`, `internal/storage/store/local_recovery_key.go` | The one credential that can restore admin access when every admin account is locked out — see §5.1. |
| **Session / PAT / machine / setup / reset tokens** | SHA-256-hashed at rest (session tokens are 256-bit random opaque values looked up directly — `SECURITY-VERIFICATION.md` "Known, accepted residual risks") | Each is a distinct blast radius: session (time-bounded), PAT (until revoked, now scopeable per ADR-042), machine identity (service-to-service), setup/reset (single-use, short-TTL). |
| **Audit log content** | `audit_events`, hash-chained (ADR-029) | The record a regulator or an incident responder relies on; must be complete, attributable, and itself tamper-evident. |
| **TLS/OIDC signing material** | Operator-supplied certs; issuer JWKS fetched over HTTPS only | Protects the transport and the machine-identity federation trust boundary. |

## 3. Trust boundaries

| # | Boundary | What crosses it | Enforcement chokepoint |
|---|---|---|---|
| B1 | **CLI → server (remote mode)** | HTTP requests carrying a session/PAT/machine token | Same HTTP middleware + `core.Authorize` as any browser/API client |
| B2 | ~~CLI → local SQLite (local mode)~~ **Removed** | The CLI has no local mode: `cli/` is its own Go module, imports no server internals or database driver, and only speaks HTTP | Closed by ADR-108 Decision A — see §5.2 |
| B3 | **REST API** | Every human- and machine-facing HTTP request | `core.Authorize(user, permission, scope)` at every handler |
| B4 | **gRPC API** | A partial (86-RPC), data-plane-only subset of the REST surface | The *same* `core.Authorize` call, reached from `server/grpc/services/*` (ADR-105) |
| B5 | **Web UI ↔ server** | Session cookie (`kx_session`, HttpOnly+Secure+SameSite=Lax) + CSRF double-submit token | `server/middleware/session_cookie.go`; verified in `security-review-2026-09.md`'s frontend token-storage check |
| B6 | **k8s-sync / operator / ESO ↔ server** | Machine-identity token, by-reference secret reads (`GET /api/v1/secrets/value?ref=…`, ADR-059) | Same `core.Authorize` chokepoint; least-privilege namespace-scoped RBAC on the Kubernetes side (ADR-076) |
| B7 | **Server ↔ external connectors/KMS/rotation targets** (AWS/Azure/GCP SDKs, Vault, Postgres/MySQL rotation targets) | Outbound calls carrying operator-configured credentials | Per-connector `allowed_refs` allowlist + project/environment scoping (ADR-082); SSRF/link-local guards (`internal/netutil`, `internal/core/dynamic_secrets_ssrf_test.go`) |
| B8 | **Admin host access** (`keyorix-server admin …`) | Direct DB + key-file access, no network hop, by design | Host access IS the authority (ADR-108 decision B) — see §5.1 |
| B9 | **Backups** | `keyorix-server admin backup`/`admin restore` (SQLite and PostgreSQL; ADR-108 §B3, `docs/SELF_HOSTING.md` §5) | Neither half alone is useful — see §5.3 |
| B10 | **Supply chain** (CI, dependencies, release artifacts) | Third-party code entering the build; the build entering a customer's environment | CI gates enumerated in `SECURITY-VERIFICATION.md` — see §5.4 |

## 4. STRIDE per trust boundary

Each row: **Threat → Mitigation → Evidence → Residual risk.**

### B3/B4 — REST and gRPC API (the primary attack surface)

- **Spoofing** (forged identity) → Tokens minted from `crypto/rand` (256-bit),
  reusable tokens SHA-256-hashed and looked up by hash, never compared in
  plaintext → `SECURITY-VERIFICATION.md` "Token handling" → Residual: a leaked
  raw token is valid until revoked/expired; mitigated by short session TTLs and
  an absolute lifetime ceiling refresh cannot extend.
- **Tampering** (unauthorized data modification) → Every write path funnels
  through `core.Authorize`/`core.AuthorizePrincipal` before mutation; PAT
  restrictions apply *before* role resolution and the admin bypass (ADR-042) →
  `internal/core/authz.go` → Residual: none identified beyond ordinary
  authenticated-actor-does-authorized-thing (see B2 for the one bypass path
  that exists today).
- **Repudiation** (denying an action happened) → Every security-relevant
  action is audited with actor identity, `actor_type`, and outcome, including
  impersonation attribution → `AUDIT-LOG-PROVISIONS.md` → Residual: an action
  that predates the reader's retention window is only as durable as the
  operator's own PostgreSQL retention (Keyorix imposes no cap — this is a
  documented operator responsibility, not a gap).
- **Information disclosure** → No plaintext secret values, key bytes,
  passphrases, or raw tokens in logs (regression-tested); scoped RBAC limits
  read access → `SECURITY-VERIFICATION.md` §"No plaintext in logs" →
  **Residual, open and in progress**: an active internal audit
  (`docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md`) found ~26
  REST routes serializing raw, untagged Go structs, including two routes
  (`SearchAuditLogs`, `AccessHistory`) that leak `IPAddress` (PII) where a
  sibling route already redacts it. This is a real, currently-open gap, not a
  hypothetical — it is not yet closed as of this document's writing, and this
  threat model does not claim it is.
- **Denial of service** → Rate limiting, payload/timeout bounds, pagination,
  bulk-op batch caps, and a bounded-BFS fix for `transitiveDependents`
  (matching its sibling `blastBFS`'s node/depth cap) → `security-review-2026-09.md`
  "Availability and denial-of-service resistance" → Residual: none identified
  in the review beyond ordinary capacity planning.
- **Elevation of privilege** → Scoped RBAC (system/project/environment),
  least-privilege defaults (`system_viewer`), cross-project isolation
  enforced at every nested-resource route, gRPC authorized identically to
  HTTP (no flat-vs-scoped gap) → `SECURITY-VERIFICATION.md` "Access control &
  authorisation" hardening log → Residual: none identified after the
  cross-transport parity fix; the admin-bypass marker itself is now a
  structural, non-freeform field (ADR-084) rather than a name-matched role,
  closing the prior self-escalation-via-role-rename risk class.

### B1/B2 — CLI (remote vs. local mode)

- **Elevation of privilege via local mode** → **Closed.** The CLI used to
  open the SQLite database directly in a "local" mode, a second server that
  bypassed the API's authorization, audit and rate limiting (ADR-108 Context).
  ADR-108 Decision A (status Implemented) removed it: the CLI (`cli/`, its own
  Go module) is a thin client that talks to a server over HTTP only, has no
  database driver and no import of server internals, and `cli/internal/depguard`
  guards the imports. What remains of the old path is host access, which is the
  authority by design (B8, ADR-108 decision B).
- **CLI** → Same authorization/audit/rate-limit coverage as any other HTTP
  client (B3). The `/system` storage-proxy tier (`RemoteStorage`) that the old
  remote mode used, and whose per-route authorization re-implementation was the
  class of bug the 2026-09 raw-storage-bypass sweep found, has been deleted
  with it (`docs/ARCHITECTURE.md`, "Deleted: the old three-mode CLI").

### B5 — Web UI

- **Spoofing / session theft (XSS)** → Session token delivered exclusively via
  an `HttpOnly`, `Secure`, `SameSite=Lax` cookie — never readable by JS, never
  in `localStorage` → `security-review-2026-09.md` "Frontend session-token
  storage checked" (verified 2026-09-02, a deliberate migration away from an
  earlier localStorage-token design) → Residual: the accepted CSP
  `style-src unsafe-inline` finding (`#1273`/`#1302`), investigated and
  accepted as a documented tradeoff, not a regression.
- **CSRF** → A JS-readable double-submit `csrf_token` cookie, correct by
  design for that pattern (carries no authority on its own) →
  `RequireCSRF`/`csrf.go` → Residual: none identified.
- **Tampering with client-side state** → `zustand` `persist` in `localStorage`
  holds only non-credential bookkeeping (profile, expiry timestamps for UX) →
  verified by reading `web/src/store/authStore.ts` directly → Residual: none
  identified; the rest of the frontend beyond CSP and token storage is
  explicitly out of scope for the 2026-09 review and scheduled as its own
  future pass.

### B6 — Kubernetes delivery (sync agent / operator / ESO)

- **Elevation of privilege via over-broad RBAC** → The operator defaults to a
  single-namespace `Role`/`RoleBinding`, least-privilege by default; broader
  scopes are explicit opt-ins resolved from one shared helper so they can
  never disagree (ADR-076) → `docs/k8s-operator.md` → Residual: an operator
  who opts into cluster-wide watch accepts a correspondingly larger RBAC
  surface — a documented, deliberate tradeoff, not a silent default.
- **Tampering / partial writes** → A fetch failure never writes a partial
  Secret; it records `Ready=False`/`SyncError` and backs off → `docs/k8s-operator.md`
  "How it works" → Residual: none identified.
- **Information disclosure** → All three delivery mechanisms (operator, sync
  agent, ESO) read over the same authorized API, honoring `max_reads`,
  suspension, and audit, and never log values → `docs/k8s-operator.md` →
  Residual: none identified.

### B7 — External connectors, rotation targets, KMS

- **Server-side request forgery (SSRF)** → Link-local/NAT64 address guards on
  outbound connector/dynamic-secret calls → `internal/netutil`,
  `internal/core/dynamic_secrets_ssrf_test.go`, `internal/core/admin_dsn_ssrf_fuzz_test.go`
  → Residual: none identified in the reviewed surfaces; this is an
  actively-fuzzed boundary (`FuzzAzureGenerateUpstreamRef`, `FuzzPostgresQuoting`,
  `FuzzMySQLQuoteString` — the exact class that already produced one real,
  shipped, fixed path-traversal vulnerability in `rotation_ref` handling,
  now additionally denylist-validated at configuration time).
- **Cross-tenant leakage via Connect** → Connectors are scoped to
  `(scope, project, environment)`, with ownership enforcement and
  `ListConnectors` filtering by the caller's authorized scope, plus a
  dedicated `connect.platform.use` permission gated as a **terminal deny**
  with no delegation fallback (ADR-082, all four implementation branches
  shipped) → Residual: none identified after ADR-082's three rounds of
  revision; the ADR's own "Out of scope" section names what is deliberately
  deferred to later implementation work — see that document directly for the
  exact boundary.
- **Signing-key MITM (OIDC/federation)** → `jwks_uri` must be `https` (loopback
  exempted for local development only); asymmetric-only algorithm allowlist
  (`HS*`/`none` rejected); issuer allowlist checked *before* key retrieval →
  `SECURITY-VERIFICATION.md` "ICT third-party risk / federation trust
  boundary" → Residual: none identified.

### B8 — Admin host access

Covered in depth in §5.1 (insider / host-root) below — the short version:
host access to `keyorix-server admin …` **is** the authority these commands
grant, by design (ADR-108 decision B: "these need shell access on the server
host plus the DB and key files; owning the host is the authority"). The
threat-modeling question is not "can host root do damage" (yes, always,
everywhere) but "does anything on this boundary silently grant *more* than
host access already implies" — traced in §5.1 and found: no, with one
explicit, accepted exception (the keyless recovery mode, opt-in only).

### B9 — Backups

Covered in §5.3.

### B10 — Supply chain

Covered in §5.4.

## 5. Cross-cutting scenarios

### 5.1 Insider threat and host-root

The load-bearing distinction Keyorix draws, consistently, is **where the KEK
lives**:

- **KEK as a local file** (`key_provider.type: file`) — host root already has
  everything: the ciphertext, the wrapped DEK, and the KEK-derivation
  material. No control at the application layer changes this; it is stated
  plainly rather than implied
  (`docs/design-b2-recover-admin.md` §1: *"this recovery key does not protect
  your secrets from root — it protects your admin account from anyone who is
  not you"*).
- **KEK in a KMS/HSM/TPM** (`aws-kms`/`gcp-kms`/`azure-kms`/`tpm`) — host root
  can read ciphertext but cannot unwrap secrets without also compromising the
  external KMS/HSM boundary. Here, application-layer controls (the recovery
  key, MFA, session revocation) are doing real, additional work against a
  host-compromise actor, not just against a stolen-credential actor.

**Break-glass admin recovery** (`keyorix-server admin recover-admin`,
`internal/recoverykey`, `server/admin/recover_admin.go`) is the concrete
mechanism this boundary runs through:

| Actor | Outcome | Why |
|---|---|---|
| Host root, no recovery key, default (required) mode | Cannot recover | The stored value is a one-way SHA-256 verifier (`internal/storage/store/local_recovery_key.go`) — root can overwrite it, not derive the key from it. |
| Recovery key holder, no host access | Cannot recover | `recover-admin` is a local subcommand, never a network endpoint (ADR-108 B) — a key with no shell on the host is inert. |
| Host root **and** the recovery key | Can recover | This is the accepted ceiling for a local break-glass tool, not a gap: two independent factors is the strongest practical bar. The residual control is *detectability* — every use is written to the audit chain and triggers an admin notification, making the act visible and attributable even though it can't be prevented. |
| Keyless mode explicitly enabled | Host root alone recovers | An opt-in-only labs/demo escape hatch that deliberately collapses "host access" and "admin access" into one boundary — cannot be enabled remotely, and its reachability is itself guarded by a dedicated test (`internal/config/keyless_mode_reachability_test.go`). |

This mirrors ADR-108's broader design choice: admin-recovery, offline backup/
restore, and version-skipping upgrades are all `keyorix-server admin`
subcommands rather than network endpoints, specifically because a network path
to any of them would be a built-in authentication bypass.

### 5.2 The CLI local-mode gap (closed)

Earlier versions of this document listed CLI local mode as the largest open
item: a second, unaudited, unrate-limited path into the database the API
protects. ADR-108 Decision A removed it and the CLI no longer contains it (§4,
B1/B2). The remaining non-API path into the database is host access
(`keyorix-server admin …`, direct database and key-file access), which is the
authority by design (B8): grant shell access on the server, and database
access, only to people who may also read every secret.

### 5.3 Stolen backup

`keyorix-server admin backup`/`admin restore` (ADR-108 §B3) is the supported
mechanism on both SQLite and PostgreSQL, alongside an offline audit checkpoint
export for drills and real disaster recovery
([`../AIRGAP_RUNBOOK.md`](../AIRGAP_RUNBOOK.md)). It writes the database and the
key material in one archive; the PostgreSQL procedure, including a live backup
next to a running server, is in [`../SELF_HOSTING.md`](../SELF_HOSTING.md) §5.
A manual `pg_dump` plus a copy of the key-material volume remains possible but
is not required. Either way, the
threat-model consequence is the same, stated plainly rather than left
implicit:

- **A stolen database (dump or `admin backup` archive) alone** is encrypted
  ciphertext under a DEK that is itself wrapped by the KEK — unreadable
  without the key material.
- **A stolen key-material volume alone** is useless without the database it
  wraps keys for.
- **Both together, plus `KEYORIX_MASTER_PASSWORD`** (or the file/fd/stdin
  passphrase source, ADR-099) — for a file-KEK install, this is a complete
  offline compromise, equivalent to host root (§5.1). For a KMS/HSM-backed
  install, the attacker still needs the external KMS boundary, so a stolen
  backup pair alone is *not* sufficient.

`admin backup`'s archive is checksum-verified (SHA-256 per file) at restore
time, which proves the archive wasn't **corrupted** — it does not prove the
archive wasn't **tampered with**, since anyone who can edit the archive can
recompute a matching checksum. That's a job for the audit hash chain instead:
`admin restore` runs `admin verify-audit` automatically and fails closed
(non-zero exit) if the chain reports BROKEN, and a checkpoint anchor exported
separately (`admin audit export-checkpoint`) and held outside the host is the
one check that constrains even a host admin who holds both the database and
its checkpoint signing key — see `../AIRGAP_RUNBOOK.md` "Exporting an
audit-chain anchor" and `docs/design-b4-offline-audit-verify.md` §2. No
comparable *encryption*-format guarantee exists for the archive itself beyond
what the wrapped DEK already provides — a stolen archive's confidentiality
still reduces to the bullet points above, unchanged by `admin backup`
shipping.

### 5.4 Rollback and downgrade

A binary older than the database it's pointed at could, before ADR-097,
silently run against schema state it doesn't understand — for example, an
older binary unaware of `roles.bypasses_permission_checks` writing a new row
without it, or unaware of `audit_events.prev_hash`/`entry_hash` breaking the
tamper-evidence chain. ADR-097's `checkSchemaEpoch`/`recordSchemaEpoch`
(`internal/storage/factory.go`) makes this a **loud startup refusal** rather
than a silent behavioral gap — tracing every security-relevant column added to
date confirmed each one defaults in the safe direction for an old binary, and
the schema-epoch guard now makes that hold structurally rather than by each
migration author's individual discipline (`security-review-2026-09.md`
"Update, 2026-09-02" §"Migration downgrade paths").

### 5.5 Supply chain

A GitHub ruleset gates every merge to `main` behind 18 required CI
status-check contexts routed through a squash-only merge queue, and blocks
force-pushing or deleting `main` outright. **Correction (2026-10-05):**
earlier revisions of this section said "no bypass" — the live ruleset
carried a standing `OrganizationAdmin`/`always` bypass actor, found and
resolved the same day: kept as a deliberate break-glass path, narrowed to
`bypass_mode: pull_request` (every use visible on the PR) rather than
removed. See [`testing.md`](testing.md) and
[`SDLC.md`](SDLC.md#branch-protection) for the full detail. The checks
themselves: `govulncheck` (known-vulnerability gate, checked on every PR), `gosec` +
`golangci-lint` (static analysis), `go test -race` (the full suite including
security regressions), `go vet`, `gitleaks` (PR-scoped secret history scan),
`CodeQL` (cross-function taint tracking, both Go modules), `checkov` (Helm
chart security-policy scanning), `go-licenses` (dependency license
compliance — the allowlist was derived from the actual dependency tree and
verified to genuinely fail on an injected AGPL test dependency), fuzz-target
staleness (bidirectional: a target that exists but isn't declared would
otherwise silently never run), and DCO sign-off. Full detail and the hardening
log behind each gate: [`../compliance/SECURITY-VERIFICATION.md`](../compliance/SECURITY-VERIFICATION.md).
Release artifacts (the `keyorix-server` image and the `charts/keyorix` OCI
chart) publish to `ghcr.io` via `.github/workflows/release.yml` and
`docker-publish.yml`; verify a specific published artifact with `helm pull`
against the OCI reference directly, not the GitHub packages API (the latter
does not reliably enumerate OCI-chart artifacts).

## 6. Residual risks, stated honestly

Carried forward from `security-review-2026-09.md` rather than re-litigated:

- **Transient in-process secret-value exposure.** Every secret-VALUE plaintext
  accumulates at least three unwiped heap copies between decryption and the
  wire (the `gcm.Open` output, a `string()` conversion, and a JSON/protobuf
  serialization buffer) — structural to Go strings' immutability and
  `encoding/json`'s API, not a missed call site. Closing it would mean
  threading `[]byte`-only plaintext through the entire read path. **Not
  fixed; recorded as an open design gap**, not a code defect.
- **`KEYORIX_MASTER_PASSWORD` cannot be wiped** — string-shaped from
  `os.Getenv` onward, and Go strings cannot be zeroed once created. The
  *sourcing* half is fixed (ADR-099: `--passphrase-fd`/`--passphrase-file`/
  `--passphrase-stdin` all yield a wipeable `[]byte`; the env var is the
  documented weakest, last-resort fallback). The wiping gap for
  `PasswordKeyProvider`'s own long-lived string stays open **by design** — it
  can legitimately be asked for the KEK a second time during in-process
  rotation, so wiping after the first call would break the second.
- **Authentication cache window (~30s), narrowed.** Every cache hit
  re-checks the credential's revocation state live (session row, account
  state, PAT, machine token, federated machine identity), so a revocation is
  honoured on the next request on every replica. Since CACHE-FAILCLOSED-1
  (2026-10-17) a re-check that cannot read the database refuses the request
  (503 / `Unavailable`) instead of serving the cached login, so an outage no
  longer hides a revocation; the cost is that a brief database outage rejects
  cached credentials. Still held for up to the cache TTL: an impersonation
  session's admin-ceiling re-check (slow path only, behind its own
  60s cache). A federated JWT's own `exp` is no longer held past expiry
  (OIDC-EXPIRY-CAP-1): its cache entry ends at `exp` and a token within 5s of
  expiring is not cached. See `threat-models/authentication.md` AUTH-1 and AUTH-11.
- **CLI local mode** — removed (ADR-108 Decision A, §5.2); no longer an open item.
- **API response wire-hygiene** — an open, in-progress internal finding
  (§4, B3/B4 information-disclosure row) covering PascalCase/snake_case
  inconsistency and, more seriously, PII (`IPAddress`) leaking via two
  specific audit/access-log routes where a sibling route already redacts it.
  Not yet closed as of this writing.
- **No dedicated backup-artifact *encryption* mechanism beyond what the
  wrapped DEK already provides** (§5.3) — `admin backup` (local/SQLite) adds
  checksum integrity and an audit-chain-verified restore path, but a stolen
  archive's confidentiality still reduces to the same KEK-custody analysis as
  before the command shipped. Postgres-backed deployments still use an
  operator-driven `pg_dump` + key-volume copy, with no Keyorix-native
  artifact at all.
- **On-box audit-chain enforcement can be neutralized by a DB-level actor who
  can also write `audit_checkpoints`** — deleting or overwriting the latest
  checkpoint row forces `verify` to fail closed (report invalid) until the
  next scheduler re-baseline; within that window a truncation could be
  re-blessed. What such an actor can never do is *forge* a checkpoint that
  makes a truncated chain verify as valid (the HMAC key is never in the
  database) — detection in that scenario reverts to an off-box external
  anchor (ADR-029, "Residual (honest scope)").

## 7. Governing ADRs

ADR-029 (audit tamper-evidence), ADR-034/036/037 (TOTP/WebAuthn/per-project MFA),
ADR-041 (KMS key provider), ADR-042 (PAT scoping), ADR-044/045 (RBAC
reconciliation, per-reference grants), ADR-049 (CLI storage via factory),
ADR-057/076 (k8s orphan cleanup, operator RBAC scope), ADR-059 (secret value
by reference), ADR-082 (Connect tenant scoping), ADR-084 (admin-bypass
structural marker), ADR-087/088 (RemoteStorage deletion, system proxy layer),
ADR-091/092 (machine actor attribution), ADR-094 (time handling / wall-clock
distrust), ADR-095 (database path resolution), ADR-096 (anti-enumeration,
403-for-both), ADR-097 (schema-epoch downgrade guard), ADR-098/ADR-100 (process
memory hardening; mlockall removal), ADR-099 (master passphrase sourcing),
ADR-104 (security remediation SLA), ADR-105 (gRPC scope and parity), ADR-108
(CLI/server split), ADR-109 (core depends on interfaces).
