# Keyorix Security FAQ

The questions a customer's security team typically asks during a vendor review.
Answers describe **shipped** behaviour; see [`../SECURITY.md`](../SECURITY.md) for
the full security guide and [`NIS2-DORA-ISO-CONTROLS.md`](./NIS2-DORA-ISO-CONTROLS.md)
for the regulatory mapping.

> See [`README.md`](./README.md) for the positioning disclaimer. Keyorix is not
> independently certified; this FAQ describes implemented capabilities.

## Deployment & data residency

**Where does our data live?**
Entirely on infrastructure you control. Keyorix deploys as a Docker Compose stack
(server + web + PostgreSQL) or as a single static binary that serves both the API
and the web UI. There is no Keyorix-operated cloud in the secret-resolution path.
Air-gapped deployment is supported.

**Do you (the vendor) ever see our secrets?**
No. We operate nothing in your secret path. We have no telemetry that exfiltrates
secret material, and the product runs without any outbound dependency for core
operation.

**Is there a SaaS option?**
Not currently — Keyorix is on-premise / self-hosted by design. (A SaaS offering is
gated behind on-prem traction and is not on the near-term roadmap.)

## Encryption

**How are secrets encrypted at rest?**
AES-256-GCM with envelope encryption: each secret is encrypted under a Data
Encryption Key (DEK), and the DEK is wrapped by a passphrase-derived Key
Encryption Key (KEK). Ciphertexts are bound to their project context via AEAD
Additional Authenticated Data (AAD).

**How is data protected in transit?**
TLS — either via the bundled opt-in Caddy auto-HTTPS profile (auto-provisions a
publicly-trusted certificate for a real domain; internal CA for localhost) or
terminated at the server for the single-binary deployment. HSTS and a strict CSP
(`script-src 'self'`) ship by default.

**Can we rotate encryption keys?**
Yes. `keyorix-server admin encryption rotate` performs a full re-encryption sweep across all
DEK-encrypted tables, promotes the new key to disk, and survives restart — covered
by an end-to-end integration test (ADR-010).

**What happens if we lose the master password or key material?**
Secrets become unrecoverable by design — there is no vendor backdoor. The
self-hosting runbook documents backing up **both** the database and the key
material (wrapped DEK + KEK salt); losing the key volume or changing the master
password without the original makes every secret unreadable.

## Access control

**What authorisation model do you use?**
Role-based access control with scoping at system, project, and environment level.
Built-in system roles (`system_admin` / `system_auditor` / `system_viewer`) and
project roles (`project_admin` / `project_developer` / `project_viewer` /
`project_auditor`). Authorisation is enforced server-side on every request, on
both the HTTP and gRPC surfaces; new users default to least privilege
(`system_viewer`).

**How do machine/service workloads authenticate?**
Service, CI, and Kubernetes principals are modelled as **machine identities**,
separate from human users, with their own lifecycle. (OIDC service-account auth —
e.g. Kubernetes projected tokens — is a roadmap item.)

**Do you support MFA?**
Yes — per-user opt-in **TOTP** (RFC 6238, ADR-034) and **phishing-resistant
WebAuthn/passkeys** (ADR-036), each with a two-step login and single-use TOTP
recovery codes; the TOTP secret is encrypted at rest. A deployment can mandate
either factor for interactive login (`security.require_mfa`), and the mandate
can be scoped to a single sensitive project even when the global policy is off
(ADR-037). Password policy, short-lived sessions with an absolute lifetime
ceiling, and first-login password-change enforcement are also shipped.

**Can an admin act as another user, and is that visible?**
Yes — impersonation issues a separate short-lived session (the admin's own session
is untouched), and **every** action under it is tagged in the audit log with
`impersonated_by` / `acting_as`, plus discrete `impersonation.start` /
`impersonation.end` events with duration and action count.

## Authentication & sessions

**How long do sessions last?**
Configurable. Access tokens have a short TTL and a hard **absolute lifetime
ceiling** that token refresh cannot extend; the default is a 24h access window with
an uncapped ceiling (short-lived is opt-in). Active sessions are listable and
individually revocable.

**What is your password policy?**
Configurable: minimum length, character-class complexity, reject-personal-info,
reject-common-passwords (offline denylist), no-reuse password history, and max-age
expiry. Conservative defaults (16-char minimum + full complexity) ship out of the
box.

**How are credentials delivered to new users?**
Via single-use, hashed-at-rest setup links (24h TTL) or a one-time generated
password for out-of-band relay. No reusable credential is ever emailed; accounts
are created in a restricted state that forces a password change at first login.

## Audit & monitoring

**What is logged?**
Every security-relevant event — secret access/changes, sharing, authentication
(incl. failures), RBAC changes, membership transitions, account lifecycle, machine
identities, and impersonation — each with actor identity, `actor_type`, timestamp,
and outcome. See [`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md).

**Are secret values ever written to logs?**
No. Records reference secrets by id/name only; no plaintext values, key bytes, or
raw tokens are logged (regression-tested). Secret-update diffs record changed
metadata plus a `value changed` marker, never the value.

**Can we forward audit logs to our SIEM?**
Yes — async push connectors for Splunk HEC, Datadog, and a generic webhook, plus a
cursor-paginated pull export and (when gRPC is enabled) a live stream.

**How long are logs retained?**
As long as you choose — audit history lives in your PostgreSQL with no Keyorix
retention cap or paywall.

## Vulnerability management & reporting

**How do you handle security scanning?**
The codebase is gated in CI with `gosec`, `golangci-lint`, and `govulncheck`
(reported at zero issues/vulnerabilities at last sweep). The frontend ships a
strict CSP and passes `pnpm audit`.

**How do we report a vulnerability?**
Email `security@keyorix.com`. We acknowledge a report within 48 hours and give
an initial assessment within 7 days; fixes ship within 90 days of a validated
report, with one week's advance notice for High and Critical. See [`../SECURITY.md`](../SECURITY.md) for details.

## Known gaps (stated honestly)

We would rather tell you these up front than have you find them:

- **Audit-log tamper-evidence** — a SHA-256 hash chain over audit events
  (ADR-029) is shipped, detecting after-the-fact modification, deletion,
  insertion, or reordering (`GET /api/v1/audit/verify`, and independently via
  `keyorix-server admin verify-audit` — see
  [`OFFLINE-AUDIT-VERIFICATION.md`](./OFFLINE-AUDIT-VERIFICATION.md)). This is
  tamper-*evidence*, not WORM prevention: a database-level actor can still
  alter rows, but cannot do so undetectably. Physical write-once-read-many
  storage remains operator-owned infrastructure, outside the application.
- **Automated purge of soft-deleted records is opt-in.** The retention purge
  scheduler (ADR-032) is wired and runs only when `purge.enabled: true`
  (default off); it hard-deletes soft-deleted records past
  `soft_delete.retention_days` and skips a tick while a legal hold applies. With
  it off, soft-deleted records are kept until you purge them.
- *(Not a gap)* **PAT per-token permission scoping** is shipped (ADR-042): a
  personal access token can be minted with a restricted permission/scope subset
  of its owner's, rather than always inheriting the owner's full authority.
- **No independent certification yet** — NIS2/DORA/ISO mappings are informational;
  detailed reviewed reports are targeted for Q3 2026.
- **`keyorix run`'s injected secrets are readable via OS process-environment
  introspection** — for the lifetime of the child process, any process able to
  read this OS user's process environment (e.g. another local process, or an
  operator with shell access to the host) can read an injected secret value.
  This is inherent to how OS environment variables work, not unique to
  Keyorix (direnv/dotenv share it), and not fixable at the application layer
  — `--clean-env` isolates the child from the invoking shell's leftover
  variables, not from external process-environment readers.
