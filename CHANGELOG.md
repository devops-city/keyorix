# Changelog

All notable changes to Keyorix are documented here. This project follows
[Semantic Versioning](https://semver.org/).

**Unreleased entries now live in `changelog.d/`** (one fragment file per PR; see
`changelog.d/README.md`) and are assembled into this file at release time by
`scripts/changelog-assemble.sh`. Do not add new entries to "Unreleased" below;
that section is the text written before the switch.

## Unreleased

### Security
- **A database fault during login no longer reveals that the password, TOTP
  code or passkey was correct.** Every login path (password, TOTP, WebAuthn
  second factor, passwordless, re-authentication, MFA step-up) already answered
  a storage failure *after* the credential matched with the same response a
  wrong credential gets. The account's **lockout state** now matches too: the
  failed-attempt counter is cleared only once the login has actually been
  delivered, and a post-match failure counts as an attempt. Previously the
  counter was reset on the way to the failure, so an attacker at one attempt
  short of the lockout threshold could tell a correct password from a wrong one
  by whether the account locked. Audit logging distinguishes the two for
  operators — `auth.login_error` (the credential was right; a storage fault
  denied the login) versus `auth.login_failed` (a wrong credential) — and
  `/auth/mfa/verify` now writes `auth.login_error` for this case instead of
  nothing at all. Visible effects: a login denied by a transient storage fault
  now counts toward the per-account lockout, so a sustained database problem can
  lock accounts whose owners typed the right password; and the counter is reset a
  few milliseconds later in the request than before. A fault reading the
  account's roles after the password matched now also answers `401 Invalid
  credentials` instead of a distinguishable `500`. (#2894, #2888)
- **The bundled Caddy (`tls` compose profile) no longer runs as root.** It runs as
  uid:gid 65532 with only `NET_BIND_SERVICE`. A one-shot `caddy-init` service
  chowns the existing `caddy_data` / `caddy_config` volumes first, so upgrading
  an install whose Caddy volumes are root-owned needs no manual step and keeps
  its certificates. `caddy-init` runs with `CHOWN` + `DAC_READ_SEARCH` so a
  second run (Caddy's storage directories are `0700`) and an interrupted first
  run succeed; it touches only the two Caddy volumes and only entries not already
  owned by 65532. See `docs/SELF_HOSTING.md` §7.
- **Every `tmpfs` (compose) and `emptyDir` (Helm) now has an explicit size limit**
  (`size=` / `sizeLimit`), so a runaway writer cannot exhaust host memory or node
  ephemeral storage. The backend's `/tmp` (64 MiB) also stages `admin restore`.
- **The bundled PostgreSQL runs as the image's own uid, 70, in both compose and
  the Helm chart** (`postgres:15-alpine`; the Debian-based images use 999). Compose
  volumes were already owned by 70. **Helm upgrade note:** charts since v0.87.0 ran
  the pod as 999 even on the alpine image, so an existing chart-created volume is
  owned by 999 and the pod will not start (Postgres refuses a data directory it
  does not own). Either `--set postgresql.runAsUser=999` to keep the old owner, or
  `--set postgresql.migrateOwnership=true` for a one-time chown to 70 (opt-in: it
  adds a root init container with only `CHOWN` + `DAC_READ_SEARCH`, which a Pod
  Security "restricted" namespace rejects). Guarded by `deploy/hardening`, which
  ties compose user, chart securityContext and image flavour together. See
  `docs/UPGRADING.md` §5.
- **The shipped compose stack and Helm chart run with
  `security.enable_file_permission_check` on** (ADR-112 default): key material and
  the `*_FILE` secret files are checked strictly; the orchestrator-mounted config
  file only warns. Both configs omit the key on purpose, because an explicit `true`
  would also audit that root/host-owned file strictly. A `*_FILE` secret that is not
  key material follows the same upgrade grace period as the key files. Guarded by
  `deploy/hardening` `TestShipped{Compose,Helm}Config_FilePermissionCheckIsOn`.
- **Every secret the server reads from the environment now also accepts
  `<NAME>_FILE`** (Docker secrets, Kubernetes Secret volumes): the master
  password, DB password, bootstrap token, SMTP/SIEM/SCIM/webhook/SSO secrets and
  the operator-named KEK, Shamir-share, rotation-DSN and Vault-token variables.
  Setting both `X` and `X_FILE`, or pointing `X_FILE` at an unreadable or empty
  file, stops the server at startup; the value and the file contents are never
  logged. File permissions: the master password, KEK and Shamir-share files are
  **always refused** unless `0600`/`0400` (the key-material rule) -- the one
  exception is a group-readable file the running user does not own whose group the
  process holds (a Kubernetes Secret volume with `fsGroup`, a Docker secret with
  `group_add`); every other secret file follows
  `security.enable_file_permission_check` (refuse) / warn, and during the ADR-112
  upgrade grace period they only warn. The container
  entrypoint (`KEYORIX_ADMIN_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE`) and
  `keyorix system init` resolve `_FILE` too, so a `_FILE`-only deployment
  auto-bootstraps; the entrypoint never exports a value read from a file (the
  server gets the `_FILE` path) and sends the bootstrap token in the request body,
  not on wget's command line. A file value has one trailing `\n`, then one `\r`,
  stripped (same bytes as `--passphrase-file`); the plain `KEYORIX_MASTER_PASSWORD` variable keeps
  its whitespace trim. See `docs/CONFIGURATION.md`.
- **New `server.http/grpc.tls_mode: strict` setting** (ADR-112, secure-by-default
  baseline, item 3) switches a listener to TLS 1.3 only, with no fallback to
  1.2. The existing default (TLS 1.2 floor, restricted to forward-secret AEAD
  cipher suites — unchanged by this release) remains compliant, not a
  downgrade to warn about: NIST SP 800-52 Rev. 2 requires servers to support
  both 1.2 and 1.3, and OT/legacy clients often still need 1.2. `tls_mode` is
  the opt-in upgrade for a deployment that can require 1.3-only clients.
  `tls.allowed_ciphers` has no effect under strict mode (TLS 1.3 negotiates
  its own suite set) and now warns if both are set.
- **Every break-glass activation must now be reviewed after the fact**
  (ADR-112, secure-by-default baseline, break-glass review item 5):
  `POST /api/v1/projects/{id}/break-glass/{activationId}/review` records who
  reviewed an activation, when, and a note — exactly once (a second attempt
  is refused, not a silent overwrite). The reviewer must be **someone other
  than the user who activated it**, and must be an attributable human (a
  machine identity cannot review), and the activation must have **concluded**
  first — a still-active grant has to be revoked or allowed to expire before
  it can be reviewed, since a reviewer cannot assess access that is still in
  use. Activation itself remains single-person, by design (an emergency path
  that needs a second person fails exactly when it's needed) — review is the
  separate, after-the-fact check that makes that safe, not a second approver.

  `break_glass.review_window` (default 72h) is how long an activation may go
  unreviewed before it is reported. Past that, it is counted as a deviation
  in the compliance posture report (`emergency_access.unreviewed_activations`,
  with the age of the worst outstanding one), and a recurring check logs a
  `SECURITY:` warning and writes a `break_glass.review_overdue` audit event
  — on startup and every 6h. That visibility is the whole of the
  enforcement: nothing is locked out, no grant is cut short, and no user is
  blocked, because an emergency path that can be disabled by unfiled
  paperwork fails exactly when it is needed.

  **Upgrade note:** break-glass activations recorded before this release have
  no review on file (`reviewed_at` is NULL), so immediately after upgrading
  every one of them older than `break_glass.review_window` is counted as
  unreviewed — the posture report's `emergency_access.unreviewed_activations`
  will jump, the "emergency-access" control will show a Gap, and the 6-hourly
  reminder will log and audit them until each one is reviewed. Retention will
  not clear the backlog for you — an unreviewed activation is never purged, no
  matter how old, deliberately, so retention cannot silently erase the
  deviation. They are also NOT backfilled as "pre-review-era": a synthetic
  review record would assert a second pair of eyes that never looked, which is
  exactly the claim this change exists to make true. Review the pre-upgrade
  activations (any user other than the activator with `roles.assign` at the
  project can) to clear the report. (#2461)
- **The server now refuses to start on an incomplete key-file set** (ADR-112,
  follow-up from #2400). #2400 made a single restore operation atomic (every
  file in a key-material set is either all written or none are); this adds the
  boot-time check for what that cannot cover — a set assembled across multiple
  operations. The encryption key files (salt, wrapped DEK, and any KMS/TPM
  wrapped-key blob or Shamir share files) must either all be present or all be
  absent. A partial set — the salt restored but not the wrapped DEK, say —
  refuses to start, naming every present and missing file.
  A second, **best-effort** check compares ages within each group of files one
  operation writes together (a Shamir provider's share set, in practice) and
  refuses when they differ by more than 24h. It is deliberately *not* presented
  as a mixed-generation guarantee, because mtimes cannot provide one: `cp`,
  `install`, `docker cp` and `kubectl cp` all stamp the destination with the
  current time, so a set hand-assembled from two different backups by the most
  common means shows no gap at all, and mtime is writable by anyone who can
  write the file. Issue #2900 tracks the real fix — a key-set manifest
  (generation id plus per-file hash) written atomically with the keys and
  verified at boot, which also covers the `.pending` rotation-staging files.
  The wrapped DEK is exempt from the timing check (routine DEK rotation
  legitimately rewraps it on its own schedule), and so is any comparison
  *across* groups: `rotate-kek` rewrites only the salt and DEK, so a deployment
  with a KMS/TPM/Shamir fallback keeps that provider's blob at its original
  age, which must not become a refusal to boot after an ordinary rotation.
- **`security.enable_file_permission_check` and `security.require_mfa` now
  default to the secure state** (ADR-112, secure-by-default baseline, item 1).
  A fresh install enforces file-permission/DEK-salt-size/database-reachability
  startup checks and admin MFA from its very first start, with no config
  changes needed; the first admin login asks for MFA enrolment. On the
  default, the encryption key material and database file are checked strictly;
  the config file and TLS cert/key (usually orchestrator-mounted) get a warning
  naming the file and the fix, and an explicit `true` makes those strict too.
  **Upgrade note:** an existing deployment (its database already has users)
  that never set `enable_file_permission_check` keeps booting during a grace
  period: a real file-permission or startup-validation problem logs a loud
  `ADR-112` warning naming the setting and how to comply, instead of refusing
  to start. The grace period ends for good at the first boot whose checks pass
  (or when the key is set explicitly). `require_mfa` on such a deployment is
  also in a grace period: not enforced yet, with a loud start-up warning on
  every boot until the key is set explicitly. On a fresh install a
  session-authenticated user without MFA is confined to the enrolment
  endpoints until they enrol (non-interactive PAT/machine credentials are
  unaffected). An explicit
  `enable_file_permission_check: true` keeps its exact pre-upgrade behavior,
  including refusing to start when the key material is missing.
- **`keyorix mfa enroll` / `keyorix mfa activate`**: the CLI can now enrol a
  TOTP factor (secret + otpauth URI, then confirm with a code and the account
  password; prints one-time recovery codes). With `require_mfa` on, this is
  how a CLI-only operator gets past the first-login enrolment confinement;
  `keyorix login --mfa-code` completes later logins.
- **16 security-weakening settings renamed to an `insecure_` prefix** (ADR-112,
  secure-by-default baseline, item 2, part 3) —
  `security.allow_unsafe_file_permissions`, `security.login_lockout.disabled`,
  `security.recover_admin.keyless_mode`,
  `audit.siem.allow_private_network_target`/`allow_insecure_transport`,
  `evidence_delivery.webhook.allow_private_network_target`/`allow_insecure_transport`,
  `notifications.webhook.allow_private_network_target`/`allow_insecure_transport`,
  `dynamic_secrets.allow_private_network_targets`/`allow_insecure_transport`,
  `storage.encryption.key_provider.kms_allow_context_fallback`/`allow_weaker_fallback`,
  `sso.providers[].trust_asserted_email`,
  `sso.providers[].saml.allow_idp_initiated` and `audit_checkpoints.disabled`.
  **Upgrade note: every old name still works exactly as before.** It is a
  deprecated alias, not a removal — the raw YAML is rewritten before the strict
  decode, so nothing changes except that using an old name now logs a start-up
  warning naming its replacement. Setting both names is not ambiguous: the new
  one wins and a "both set" warning fires. The two key-provider settings are
  also aliased **inside the `fallbacks:` chain**, where a config file using the
  old name previously hit the strict decode's unknown-field check and the
  server refused to start instead of warning.
  Not renamed: the fourteen settings tracked in #2895, each of which needs a
  polarity inversion or a non-boolean field restructured first.
- **Every security-weakening setting is now registered, warned about and
  audited** (ADR-112, secure-by-default baseline, item 2 — the opt-out rule).
  `internal/config.InsecureSettingsRegistry` is the single enumeration of all
  33 of them (32 plus the fast-audit opt-out from ADR-112 Amendment 1); three things read it, so nothing has to be wired up per setting:
  a start-up **warning** for every one currently in effect, a start-to-start
  **settings diff** that writes an audit event (old value → new value) for any
  of them that changed between two starts of the same deployment, and the
  posture report. Nothing is renamed yet and no behaviour changes for an
  existing config file: each entry records the `insecure_`-prefixed name it is
  *heading for* alongside the real key it reads today, and the literal YAML
  renames land as their own small follow-ups, each keeping the old key working
  as a warning-logging deprecated alias.
  A **sweep of the whole config surface** (`insecure_settings_sweep_test.go`)
  is what keeps the registry honest: a setting whose name reads as an opt-out
  and that no entry covers fails CI by name, and a set ratchet over every
  leaf setting fails on *any* config addition, removal or rename — because seven of the registered
  weakenings (`membership.validation_mode`, `storage.database.ssl_mode`,
  `credential_delivery.mode`, the SMTP/email `tls` enums, `metrics_token`,
  `max_request_body_bytes`) have names no pattern list can recognise. Thirteen settings that cannot be renamed
  mechanically — each needing a polarity inversion of a load-bearing flag, or
  a non-boolean field restructured into a real boolean — are recorded as known
  exceptions with an owning tracking issue, and are covered by the warning,
  the audit diff and the posture report under their current names meanwhile.
- **New `keyorix-server admin validate --posture` command** (ADR-112,
  secure-by-default baseline, item 4) reports every secure-baseline deviation
  in one place and exits non-zero if any is found. **Every security-weakening
  setting in effect counts**, whatever stage its `insecure_` naming is at:
  encryption-at-rest disabled, database TLS disabled, unauthenticated
  `/metrics`, log-delivered setup links and the rest are deviations because of
  what they do, not because of what they are called. The report also covers
  `security.enable_file_permission_check` disabled outright, a real
  file-permission / encryption / database problem, an incomplete key-file set
  (item 6), an enabled listener with no TLS while
  `security.require_transport_tls` is set, and an admin-tier holder with
  neither TOTP MFA nor a passkey enrolled. `security.require_mfa: false` is a
  deviation, and so is an upgraded deployment still in `require_mfa`'s ADR-112
  grace period (the server does not enforce MFA there yet, even with every
  admin enrolled). A grace-period setting (item 1)
  still enforcing only via its new secure-by-default value, with the underlying
  condition it covers still non-compliant, is reported as its own deviation
  referencing the detail above it. Each deviation is labelled with whether it
  comes from a **shipped default** or an **explicit** config choice (whether
  the config file literally writes the key), so an
  operator can tell "this install has not been hardened yet" from "someone
  turned this off" — but both count toward the exit code. Only genuinely
  non-judgemental facts are informational: TLS mode, and the KEK salt file's
  age (no rotation-age threshold is defined anywhere in this codebase, so a
  number here would be a guess).

## v0.95.3 — 2026-10-01

### Security
- **Last-admin guard on group deletion is now race-free.** Deleting a group
  concurrently with deleting a user could remove the last administrator; both
  operations now serialize on the same lock (an advisory lock on Postgres, an
  in-process lock on SQLite). Under heavy contention a deletion can now fail
  with a lock timeout instead of racing. (#2348)
- **Deleting an environment can no longer orphan a secret created at the
  same moment.** Secret creation, folder creation and secret restore now take
  the same per-environment lock as environment deletion and re-check that the
  environment still exists. A create against an environment that was just
  deleted returns "not found" (not a server error). (#2353)
- **Machine identity revoke/suspend always takes effect immediately.** If the
  post-revoke cache eviction fails, every machine token in the auth cache is
  now flushed instead of the revoked one staying cached for up to 30s, and
  the call reports success (the revoke had already committed). The flush no
  longer locks out unrelated machine identities. (#2349)
- **`POST /auth/logout` on an already-invalidated session returns 401, not
  500.** (#2337)
- **More operations write audit events:** alert-escalation-policy changes,
  every on-demand admin job (including runs that find nothing to do),
  compliance evidence verification and posture snapshots, and 13 further
  operations found by the audit-completeness fuzzer, including bulk secret
  owner reassignment and bulk rotation. (#2249, #2252)

### Added
- **`keyorix-server admin recovery-key rotate --recipient <age1… key | ssh-ed25519 public
  key file>`** prints (or, with `--output <file>`, writes) the new recovery
  key only encrypted to that recipient; the plaintext key is never shown. The
  recipient is validated before the key is generated. (#2257)
- **New `alerts.write` permission and `alert_operator` built-in role** (ADR-110
  follow-up): notification-channel/escalation-policy management and 5 of the 11
  `/admin/jobs` on-demand triggers (the ones that only emit/dispatch a
  notification AND carry no compliance/audit-derived data — rotation/expiry/
  token-expiry reminders, role-expiry-check, check-read-quotas) moved off
  `system.write` onto this narrower permission. `system.write` remains a
  strict superset: existing holders keep access via a one-time backfill on
  upgrade. `record-hygiene-snapshot`, `suspend-inactive-users`, and
  `purge-audit-logs` stayed on `system.write` (they mutate account/data state,
  not just send a notification); `anomaly-alerts`, `compliance-digest`, and
  `run-alert-escalation` also stayed on `system.write` despite being
  notification-only, because they all dispatch anomaly/compliance-derived
  data and an `alert_operator` could point a notification channel at a URL
  they control to exfiltrate it (an SSRF path from air-gapped hosts too). See
  `docs/adr-110-system-write-scope.md`'s Decision section for the full
  per-route table. (#2244)

### Fixed
- **Deleting a custom role now also removes its user, group and machine
  role assignments, its permissions and its connector ref grants**, in the
  same transaction. Previously these rows were left behind. They granted
  nothing (authorization always checks the live role), but they cluttered
  exports and listings. Break-glass and access-review history keep their
  references by design. (#2357)

### Testing
- End-to-end customer-journey suite (application reads a secret, access
  control, audit trail, Vault/OpenBao migration, Keycloak SSO, disaster
  recovery) runs against the real server and CLI binaries: the fast tier in
  the merge queue, the container tier nightly. (#2338, #2339, #2341–#2344,
  #2355, #2358)

## v0.95.2 — 2026-09-30

### Added
- **`admin backup`/`admin restore` now support Postgres, in addition to
  SQLite** — the same commands, same archive format, on either backend.
  Backup reads through a single `REPEATABLE READ` snapshot transaction by
  default on Postgres (`--exclusive` opts into the same host-level lock a
  SQLite backup always holds). The archive itself is a new backend-neutral
  logical format: a streaming, table-by-table snapshot with an
  HMAC-signed manifest (KEK-derived key), rather than a raw database-file
  copy — checksums catch corruption, the signature catches tampering a
  checksum alone can't. Restore still reads an archive from the previous
  (SQLite-only, physical-copy) format, with a deprecation notice, until
  Keyorix 1.0. Moving a deployment from SQLite to Postgres, and restoring a
  backup taken on a much older release, are both just this same restore
  command pointed at a different target — no new subcommand, no separate
  migration tool. See `docs/SELF_HOSTING.md` §5.
  (#2261, #2263, #2270, #2280, #2284, #2288, #2291, #2293)

### Security
- **`admin restore` now refuses to restore a backup that is behind this host's
  own audit trail, by default.** Restoring an older backup than the host has
  already progressed past could silently undo any revocation recorded since
  (a suspended account, a deleted machine credential, a rotated role grant) —
  the restored database simply doesn't know it happened, and `verify-audit`
  reported the restored (shorter, self-consistent) chain as `VALID` either
  way. Restore now compares the archive's own certified audit-trail progress
  against a host-local witness file before writing anything to disk, and
  refuses if the archive is behind; pass `--allow-rollback` for a genuine
  disaster-recovery restore of an intentionally older backup, which writes an
  explicit audit event recording the override. See `docs/SELF_HOSTING.md` §5.
- **Removed the dead `verify-credentials`/`verify-mfa`/`mfa-challenge` HTTP
  endpoints.** These existed only to serve `storage.type: remote`, removed
  entirely in ADR-108 Phase 6 — the routes had no remaining legitimate caller
  but stayed live, gated only by `users.write`. (`c8bcf9dd`)

### Fixed
- **Seven tables with live handler code were never migrated on any
  install** (secret version comments, notification channels, alert
  escalation policies, secret templates, MFA step-up tokens, hygiene-trend
  snapshots, compliance-posture snapshots) — every fresh install 500'd on
  first use of any of them. Fixed for fresh and upgraded installs alike.
  (`0b6bb65a`)


### Changed
- **The air-gapped build profile ships, and the published air-gapped image
  is renamed** `keyorix-server-lean` → `keyorix-server-airgap`. Operators
  pulling the air-gapped image must update their image reference. (`2bc79ce2`,
  `ddadf47c`)

### Added
- `keyorix-migrate vault scan` — a free, strictly read-only health check for an existing Vault
  (or OpenBao) install: version/EOL, seal configuration, audit devices, auth methods, policy
  sprawl, TTL hygiene, secrets-engine inventory, TLS listener config, and a "migration readiness"
  summary. Ships in the same `keyorix-migrate` binary. See `docs/vault-health-scan.md`.

## v0.95.1 — 2026-09-27

### Security
- **Admin-rank ceiling now fails closed on a storage error.** A transient DB error while
  resolving a target's or actor's roles during a privileged user mutation (delete,
  update, suspend, revoke sessions — over REST and gRPC) used to be treated as
  permission-granted; it now refuses the action. High severity: this let a
  lower-privileged actor act on a higher-privileged user's account during the error
  window. Found by `FuzzStorageFaultOperations`. (#2201)
- **Dynamic-secret lease renewal/sweep now enforces an anti-rollback watermark** against
  clock jumps (NTP correction, VM pause/resume, manual clock changes), closing a window
  where a backwards time step could let an expired lease be renewed or an active lease
  swept early. (#2186)
- **Login-throttle budget is now reserved by `ConsumeSetup` and
  `BeginWebAuthnPasswordlessLogin`**, closing two authentication paths that could be
  hammered without counting against the same per-account throttle every other login path
  already respects. (#2190)
- **SSRF guards now validate every host in a multi-host PostgreSQL admin DSN**, and decode
  6to4/Teredo/NAT64-local-use IPv6 encodings of an embedded IPv4 address (extending the
  existing NAT64/IPv4-compatible decoding already used by the SIEM forwarder and
  notification-channel webhook guards). Previously, a bracket-quoted IPv6 host anywhere in
  a comma-separated failover DSN skipped SSRF validation entirely, even though the
  Postgres driver would still dial it. (#2197)
- **Auth-cache negative tombstones are no longer written on a benign account-state
  transition** (e.g. reactivating a suspended user). Previously, any state transition
  evicted every one of the account's session/PAT hashes from the auth cache via a
  short-lived negative tombstone — including on reactivation, where a credential created
  while suspended (never cached before) could be spuriously rejected as "invalid or
  expired" for up to the tombstone TTL after the account came back. (#2206)
- **Removed the dead `verify-credentials`/`verify-mfa`/`mfa-challenge` HTTP endpoints.**
  These existed only to serve `storage.type: remote`, which was removed entirely in
  ADR-108 Phase 6 — the routes had no remaining legitimate caller but were still live and
  gated only by `users.write`, making them an unnecessary credential/MFA-testing oracle
  for any holder of that permission. (#2212)
- **Installs bootstrapped before v0.95.0's ordering fix now self-repair on first upgrade.**
  See "Fresh-Postgres bootstrap" below (#2188) — that fix only prevents the bug on *new*
  installs. A one-time startup reconcile now grants the missing `system_viewer` baseline
  role to any existing user who never got it, on every backend, the first time a
  pre-v0.95.1 install starts up after upgrading. It runs exactly once (a
  `system_metadata` completion marker prevents any later run), and skips a user whose
  audit trail shows an admin deliberately removed the role, or who was JIT-provisioned via
  SSO with a different configured baseline role — it repairs the ordering bug only, never
  overrides a deliberate choice made since. **Known limitation:** if audit-log retention
  has already purged an admin's `role.removed` event for a given user before this reconcile
  runs, that removal history is no longer visible to it, and the user is re-granted
  `system_viewer` once on this one upgrade despite having been deliberately removed —
  re-remove it if this applies to your install. (#2195)

### Fixed
- **Fresh-Postgres bootstrap no longer logs `"user 1 (admin) created without its baseline
  system_viewer role: Role not found"`.** The bootstrap admin user was created before the
  baseline RBAC role catalog was seeded — on every backend, not just Postgres — so the
  admin silently never got the `system_viewer` grant. Roles are now seeded first. (#2188)

### Added
- **Published `keyorix-server`/`keyorix-web` Docker images now include a `linux/arm64`
  manifest** alongside `linux/amd64`. `docker compose up` previously failed outright on
  Apple Silicon and arm64 servers (e.g. AWS Graviton) with "no matching manifest for
  linux/arm64/v8". (#2187)
- **`keyorix-migrate` is now a published release binary** (linux/darwin × amd64/arm64,
  each with its own SBOM and a `keyorix-migrate version` command), instead of requiring a
  source build to run the Vault/OpenBao migration tool. (#2189, #2200)
- **A CI job dry-runs the full release process** — `make release` plus a no-push
  multi-arch Docker build — on every PR touching release-relevant files, and weekly, so a
  release-day failure like the ones fixed above is caught before tagging. (#2185)

### Documentation
- **`.env.example` and `docs/SELF_HOSTING.md` now document `KEYORIX_BOOTSTRAP_TOKEN`**,
  required alongside `KEYORIX_ADMIN_PASSWORD` for the first-boot admin auto-bootstrap —
  previously, omitting it silently skipped admin creation with no visible error.
  `server/entrypoint.sh` now logs a clear `WARN` when this happens. (#2184)

## v0.95.0 — 2026-09-27

### Added
- **`keyorix machine grant-role` / `revoke-role` / `roles`** — grant, revoke,
  and list a machine identity's project-scoped role grants. The REST
  endpoints (`POST`/`DELETE .../machine-identities/{id}/roles`, and a new
  `GET` for listing) already existed (ADR-030); previously the only way to
  give a machine identity access to anything was a hand-crafted authenticated
  HTTP call. See [`QUICK_START.md`](QUICK_START.md#giving-a-machine-ciapp-access)
  and [`docs/operator/demo.md`](docs/operator/demo.md) step 5.
- **`keyorix change-password`** — self-service password change
  (`POST /auth/change-password`), so the documented lost-admin recovery flow
  (`docs/operator/j5-lost-admin.md`) needs no raw `curl` call to finish
  setting a real password after logging in with `recover-admin`'s printed
  one-time password.

### Changed
- **BREAKING: `keyorix` is now the new, thin, REST-only CLI (ADR-108 Phase 5).**
  The old, thick CLI's **local/embedded mode — opening the database directly,
  with no server involved — is gone from the released `keyorix` binary.**
  Every command now talks to a running `keyorix-server` over the network;
  `keyorix login` replaces `keyorix connect`. Host-side operations that used to
  be `keyorix system init` / `keyorix system audit` / `keyorix system validate`
  / `keyorix encryption ...` are now `keyorix-server admin init` / `admin
  audit` / `admin validate` / `admin encryption ...` — see
  [`docs/cli-migration.md`](docs/cli-migration.md) for the full old-command ->
  new-command table. **The old CLI's source (`internal/cli`, `make
  keyorix-legacy`) is now removed entirely (ADR-108 Phase 6)** — rollback to
  the old CLI means checking out a commit before this removal, not a build
  flag.
- **BREAKING (opt-out available): the `keyorix`, `keyorix-k8s-sync`, and
  `keyorix-operator` Helm charts now default to a deny-by-default egress
  `NetworkPolicy`** on top of the existing ingress restrictions
  (`networkPolicy.egress.enabled`, default `true`). Pods can now only reach
  DNS and their known peers (bundled Postgres, the Kubernetes API server, the
  configured Keyorix server) — a server-side integration that dials out on
  another port (SMTP, syslog/SIEM forwarding, LDAP, a checkpoint notary/TSA,
  a secret-rotation backend, a webhook sink, a non-default external Postgres)
  needs a `networkPolicy.egress.extraRules` entry added *before* upgrading, or
  it silently stops working — a NetworkPolicy drop is a connection timeout,
  not an error. Set `networkPolicy.egress.enabled: false` to opt out. See
  each chart's README "Upgrading: egress NetworkPolicy" section. (#2102)
- **BREAKING: several REST endpoints now return `snake_case` field names**
  instead of the Go struct's raw `PascalCase`, matching the documented wire
  convention. Secrets (`GetSecret`, `ListSecrets`, secret sharing, and the
  rest of the `SecretNode` family) are fixed in this wave (#2098); projects,
  roles, shares, and machine identities are the same class of fix and follow
  in subsequent PRs before this reaches a release. A client reading the old
  PascalCase keys (`ID`, `ProjectID`, `IsShared`, ...) off any of these
  routes needs to switch to the snake_case equivalents.

- **`keyorix-server-lean` is replaced by `keyorix-server-airgap`** (ADR-109
  step 6). The new AIR-GAPPED release variant (`-tags noaws,noazure,nogcp`)
  excludes every AWS/Azure/GCP SDK package (0 remaining, enforced by
  `scripts/airgap-dependency-guard.sh`) — Vault and Kubernetes stay, since
  on-prem Vault read-through and on-prem k8s are legitimate air-gapped uses.
  The old `lean` variant only ever excluded the AWS IAM rotation backend and
  the S3-compatible evidence sink (131 cloud SDK packages remained) — a
  narrower, different exclusion this release replaces rather than aliases. A
  `<ver>-airgap` image tag is also now published alongside the full
  `keyorix-server` image.

### Removed
- **The `/system` server-to-server proxy route tier is gone (ADR-108 Phase 6
  step 14c).** These 151 `...Proxy`-suffixed routes existed only to let a
  downstream Keyorix server booted with `storage.type: remote` (ADR-049)
  proxy requests to this server's real storage backend — with `RemoteStorage`
  and the old CLI's embedded mode both already removed, nothing could reach
  them. A misconfigured `storage.type: remote` now fails loudly at startup
  instead of silently doing nothing. The 5 routes actually used by the web
  dashboard and first-boot setup (`/system/info`, `/system/metrics`,
  `/system/auth-config`, `/system/encryption-config`, `/system/init`) are
  untouched — they were never part of this tier.

### Known gaps
- **Sharing a secret requires both the owner and the recipient to already hold
  an explicit role in the secret's project** — holding the global `admin` role
  from bootstrap is not enough, and `share create` fails with a bare `HTTP 403`
  and no explanation if either grant is missing. Documented in
  [`QUICK_START.md`](QUICK_START.md#sharing) and exercised by
  `scripts/smoke.sh`; not yet fixed at the API layer.

## v0.94.0 — 2026-09-17

### Security
- Bumped `digitorus/pkcs7`/`digitorus/timestamp` off a pinned 2023 commit
  carrying two BER-parser defects found by fuzzing and disclosed to the
  maintainer: a memory-exhaustion amplification (~130B input → ~1.8GB
  allocation) and an unrecovered index-out-of-range panic. Both are fixed
  upstream as of 2026-09-14. The strict-DER framing guard added in v0.92.1
  (#1848) already shielded both timestamp-parsing paths and stays in place
  as defence-in-depth; this removes the remaining reliance on that single
  mitigation by dropping the vulnerable dependency itself. (#1895)
- **A crash during DEK rotation could make every re-encrypted secret
  permanently undecryptable.** `RotateDEKWithSweep`'s re-encryption sweep
  commits the database under the new DEK, then renames the new key into
  place on disk; a crash (power loss, SIGKILL, OOM) in the window between
  that commit and the rename left the database encrypted under a key that
  existed only as a "pending" file, which startup's cleanup unconditionally
  deleted — total, unrecoverable loss of every secret touched by the
  rotation. Found by a new crash-consistency fuzzer
  (`FuzzDEKSweepCrashConsistency`) that interrupts the real rotation at
  each durability checkpoint. Fixed with a write-ahead redo marker plus
  recovery-on-startup (ADR-010 addendum): the marker becomes durable
  atomically with the re-encrypted rows, and startup promotes the pending
  key before initializing whenever the marker is present. (#1918)

### Fixed
- The login page threw `crypto.randomUUID is not a function` and blocked
  sign-in entirely over plain HTTP — `crypto.randomUUID()` is only defined
  in a secure context (HTTPS or localhost), which plain `http://<LAN-IP>`
  is not. Added a `crypto.getRandomValues()`-based UUIDv4 fallback, used by
  every caller. (#1882)
- The admin Users page rendered seven org-wide compliance sections (stale
  accounts, token hygiene, secret-hygiene debt, and more) above the actual
  user list on a page titled "User Management." The user list now sits
  directly under the header. (#1885)
- The dashboard's Security Alerts panel rendered every open anomaly inline
  — routinely hundreds — breaking the page layout. Capped to the 5 most
  recent, with a link to the full paginated view. (#1883)
- Creating a group could fail with a generic error that hid the real
  cause: untrimmed whitespace in the name tripped the server's identifier
  validator, and the modal never surfaced the server's actual message.
  Separately, the groups list read the wrong field from the API response
  and always rendered empty even when the group existed. Both fixed. (#1886)
- The Projects page's "Recent" section was based on last-*updated* time,
  not actual access — with a small project count this put most projects
  under "Recent" and the rest under "All Projects," backwards from what
  the sections imply. "Recent" is now based on the projects a user has
  actually opened. (#1887)

### Added
- Edit/rename a project's name and description from the projects list or
  the project page, without opening Settings. (#1884)
- Audit page: the RBAC Events tab now matches the real role/group/
  permission event types (it previously matched a non-existent prefix) and
  resolves actor/target ids to names at display time. The Projects list
  gained an explicit sort control; Service Accounts now shows an honest
  "under construction" state instead of an error, since the standalone
  backend isn't built yet; the roadmap page reflects current shipped
  state. (#1888)

### Changed
- Migrated the MongoDB dynamic-secrets engine and rotation executor off
  the deprecated `mongo-driver` v1 to v2. No behavior change; the existing
  SRV/dialer egress guards (G48) are preserved under the new driver. (#1881)

## v0.93.0 — 2026-09-14

### Security
- **Human SSO logins now use PKCE (RFC 7636, S256).** The OIDC
  authorization-code flow generates a per-login code verifier, sends its S256
  challenge on the authorization request, and replays the verifier on token
  exchange — defense-in-depth against authorization-code interception, on top
  of the existing confidential-client and single-use login-state protections.
  A login already in flight when you upgrade completes normally. (#1875)
- **SSO/OIDC/WebAuthn trust-seam hardening.** OIDC JWKS and discovery fetches
  are now guarded against resolving to link-local addresses (e.g. cloud
  instance-metadata endpoints); `allow_idp_initiated` is rejected at config
  validation, since Keyorix has no SAML replay cache to make it safe; a
  human-SSO provider's client ID can no longer double as a machine-federation
  audience on the same issuer; and WebAuthn relying-party origins are
  validated at startup. No auth bypass was found in the affected code — this
  closes narrow defense-in-depth gaps from an adversarial review. (#1874)
- **IdP-driven role auto-grants (SSO group mapping, SCIM) are now gated on the
  granted role's actual permissions, not its name.** The SSO and SCIM paths
  previously checked for an admin role by name or bypass flag; a custom role
  bundling the role-assignment permission under a non-canonical name could
  turn a self-service IdP group into an unchecked privilege path. Both paths
  now derive the ceiling from the role's real permission tier. (#1876)
- **The KEK-derivation PBKDF2 iteration count is now a single source of
  truth.** It previously lived as two independent `600000` literals with
  asymmetric guards; raising one without the other would have made
  `rotate-kek` fail closed with a confusing "old passphrase incorrect" error.
  No data-loss or exposure risk existed, but the two values can no longer
  drift apart. (#1877)
- **A session's positive auth-cache entry can no longer outlive the session
  itself.** The cache TTL was a flat 30 seconds regardless of the session's
  own expiry, so a session that expired server-side could keep authenticating
  on cache hits for up to 30 seconds afterward (revoke/logout/suspend were
  already immediate). The cache entry is now clamped to the session's own
  expiry. (#1878)
- DAST/security-header fixes: added the missing
  `X-Permitted-Cross-Domain-Policies: none` header and scoped the DAST scan to
  the web app instead of the CI runner host (#1860); normalized nuclei's SARIF
  `executionSuccessful` field so a clean scan no longer reports as a tool
  error in GitHub Code Scanning (#1862); and excluded the HSTS matcher from
  the plaintext DAST scan, since Keyorix correctly omits HSTS when TLS isn't
  terminated (#1863).

### Changed
- **New `lean` build tag drops the AWS IAM/S3 SDK footprint (~14% smaller
  binary) for installs that don't use the `aws-iam` rotation backend or the
  S3-compatible evidence sink.** Both features fail loudly, rather than
  silently, if a lean binary is deployed against a config that still names
  them. (#1865)
- **Release binaries and container images are now built with `-s -w`
  (stripped symbols/DWARF), shrinking `keyorix-server` from ~92MB to ~62MB.**
  Version/commit metadata injected via ldflags is unaffected; local
  `make build-*`/`make dev` builds keep full symbols for debugging. (#1864)

## v0.92.1 — 2026-09-12

### Security
- **RFC 3161 timestamp tokens are now validated as strict DER before decoding.**
  A malformed timestamp token (or TSA response) could previously drive the
  CMS/BER decoding path into excessive memory allocation on the notary verify
  path (audit-checkpoint anchoring and receipt verification). Keyorix now
  rejects any token that is not well-formed, definite-length DER — with bounded
  nesting depth and node count — before it reaches the decoder, closing that
  denial-of-service vector while still accepting every spec-compliant token
  (RFC 3161 §2.4.2 requires DER). (#1848)

### Fixed
- **Keyorix v0.92.0 could not start against an existing PostgreSQL database.**
  A migrations/audit startup ordering problem prevented boot against a
  pre-existing Postgres schema; upgrades against an existing database now boot
  cleanly. (#1850)
- Dependency updates: Go module patch group (#1855), npm patch group (#1858),
  and `sigs.k8s.io/controller-runtime` 0.24.1 → 0.25.0 (#1853).

## v0.92.0 — 2026-09-10

> **Scope note.** `v0.88.0` through `v0.91.0` were tagged without changelog
> entries, so everything below covers the whole range since `v0.87.4`
> (2026-07-07), not just the last tag. The full commit list is at
> https://github.com/keyorixhq/keyorix/compare/v0.87.4...v0.92.0 — this section
> is the curated subset an operator upgrading needs to read.

### Changed
- **gRPC is now labelled, in the product itself, as a partial data-plane
  interface — not an HTTP-equivalent API.** It exposes 13 services / 86 RPCs
  against 151 HTTP handler files, and the governance surface (classification,
  descriptions, access reviews, legal hold, SoD, anomaly configuration) is
  HTTP-only today. Nothing about the runtime changed: enforcement was already
  transport-agnostic, and the real risk was never a bypass but *silent
  under-configuration* — an object created over gRPC lands in the
  least-governed state, and until now nothing said so. `configs/keyorix.yaml.tpl`
  carries the notice, and `docs/adr-105-grpc-scope-and-parity.md` is the record.
  Field numbers 11–20 on `CreateSecretRequest` are reserved for the planned
  governance fields, so a future addition cannot collide with a number already
  spent.
- **API definitions become proto-first
  (`docs/adr-106-proto-first-api-definition.md`, supersedes ADR-074 decision 1).**
  Where two transports must agree, the agreement is generated rather than
  maintained by hand. Nothing is regenerated by this release; it sets the
  direction for the next transport change.
- **`storage.type: remote` (CLI-against-server) is documented as
  work-in-progress**, with a per-area coverage table derived from the source
  rather than hand-counted, and a test that fails when the documentation drifts
  from the code (`docs/REMOTE_CLI_SETUP.md`). Local/embedded mode — the default,
  and the single-machine and air-gapped story — is unaffected.
- **`QUICK_START.md` rewritten.** The previous version documented four commands
  that could not work, including `share create --recipient <email>` (the flag is
  `--recipient-id`, and it takes a numeric id) and a `docker-compose` file that
  does not exist in the repository; it also omitted `KEYORIX_MASTER_PASSWORD`,
  without which the default passphrase provider hard-fails, and never mentioned
  `keyorix system init`, which is the actual first step. Every command in it is
  now checked against the real cobra command tree by
  `internal/cli/quickstart_commands_test.go`, and the documented flow is
  *executed* end to end by `make smoke`.
- **BREAKING: `keyorix run` no longer injects secrets by default (#1816)** —
  every invocation must now pass `--var NAME=secret-ref` (recommended,
  repeatable — you choose the env var name for each secret) or the deprecated
  `--derive-names` (restores the old behavior: every secret in the project +
  environment is injected, with the env var name auto-derived from the
  secret's own name). Previously, whoever could **name** a project secret
  also controlled which env var it became in the launched process — including
  reserved ones like `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES` — not just its
  value; see #1813 for the live PoC this was found with. If you have scripts,
  CI jobs, or Dockerfiles that call `keyorix run` with no `--var`/`--derive-names`
  flag, they will now fail fast with a clear error naming both options —
  update them to `--var` (preferred) or add `--derive-names` to keep the old
  behavior for now. Collision precedence also changed for the deprecated
  `--derive-names` path only: a derived secret name no longer overrides a
  value already present in the inherited environment (the inherited value
  wins instead) — a second, independent guard alongside the existing
  reserved-name filter (#1813). `--var`'s explicit names still override the
  inherited environment on collision, since that's the operator's expressed
  intent. See `keyorix run --help` and
  https://github.com/keyorixhq/keyorix/issues/1816 for the full reasoning.
- **BREAKING: `keyorix status` and `keyorix ping` now exit non-zero when the
  configured target is unhealthy or unreachable** — previously both commands
  always exited 0 regardless of what they found, reporting failure only via
  printed text ("❌ Unhealthy" / "❌ Failed"), so a script checking `$?` after
  either command could never detect an outage without parsing stdout. If you
  have automation that runs `keyorix status` or `keyorix ping` and previously
  ignored their exit code, verify it doesn't need to accommodate the new
  non-zero results. Full exit code contract below.
- **BREAKING: `keyorix status`/`keyorix ping` no longer construct or create
  anything when nothing is configured.** With no `keyorix.yaml`, no
  `KEYORIX_CONFIG_PATH`, and no `keyorix connect`/env-var remote target,
  `status` used to silently build an in-memory `storage.type: local` config
  on the spot and initialize storage against it — which, for a fresh
  `./secrets.db` path, **created the file**, then reported "Healthy" for a
  database the command had just created a moment earlier. That was a
  false-success pattern, not a graceful default. "Not configured" is now a
  first-class state distinct from "unhealthy": nothing is constructed,
  nothing is created, and the command exits 2 (usage/config error) — a
  script chaining `keyorix status && deploy` will no longer proceed on an
  unconfigured machine. An explicit `storage.type: local` config whose
  database file doesn't exist yet is now also reported as unhealthy (exit 1)
  rather than silently provisioned — `status` verifies an existing store, it
  doesn't create one. `status`/`ping` exit codes: 0 healthy, 1
  unhealthy/unreachable, 2 usage/config error (no config, or `ping` without
  remote storage configured).
- **BREAKING (targeting v0.92.0): every Keyorix Connect connector must declare
  `scope: project` or `scope: platform` (ADR-082)** — an existing deployment with
  `connect.enabled: true` and one or more configured connectors **will fail to boot**
  after upgrading unless every connector in `connect.connectors` gains an explicit
  `scope:` (and `project:` when `scope: project`). **There is no escape hatch and no
  deployment-wide bypass** — adding `scope:` to an existing connector takes minutes,
  and an unscoped connector would deny every read anyway once ownership enforcement
  evaluates it (see below), so a bypass would only defer the failure from boot time
  to read time, not restore access. Connector ownership is enforced on the read path
  as of this same change: a caller must be a member of the connector's owning
  project (or hold a matching `ConnectRefGrant`) to read through it — see
  `docs/adr-082-connect-connector-tenant-scoping.md`.
- **BREAKING (targeting v0.92.0): every `gcp-secret-manager` Keyorix Connect
  connector must set `project_id` (#431)** — an existing deployment with
  `connect.enabled: true` and one or more `gcp-secret-manager` connectors **will
  fail to boot** after upgrading unless every such connector gains an explicit
  `project_id`. Previously, an unset `project_id` only logged a startup warning and
  let the connector boot unpinned — since a GCP Secret Manager ref embeds its own
  project ID (unlike Vault's `address` or Azure Key Vault's `address` vault URL,
  which each already pin the connector to one backend), an unpinned connector could
  read a secret from **any** GCP project the ambient ADC identity can reach,
  regardless of which Keyorix project/scope (ADR-082) the connector itself is bound
  to — a confused-deputy gap. **There is no escape hatch**: add `project_id: <your
  GCP project>` to every `gcp-secret-manager` connector before upgrading (see
  `docs/CONFIGURATION.md`'s Keyorix Connect section for the exact field). The
  project-pin is now enforced twice — once at config-load time
  (`validateConnectGCPProjectID`) and again at read time inside
  `GCPSecretManagerConnector.GetSecret` (defense in depth; a ref naming a different
  project, or a connector somehow left unpinned despite the boot check, is refused
  before ever reaching the backend) — see `docs/adr-082-connect-connector-tenant-scoping.md`'s
  "Out of scope" section for how this closes a gap that ADR explicitly deferred.
- **BREAKING (targeting v0.92.0): a Keyorix Connect connector with an unrecognized
  `type` now fails boot instead of booting with that connector silently skipped
  (#1476)** — previously, `server/main.go`'s Connect-wiring loop logged a warning
  and continued for any `connect.connectors` entry whose `type` didn't match one
  of the four recognized backends (`aws-secrets-manager`, `gcp-secret-manager`,
  `azure-key-vault`, `vault`), so a typo'd or removed connector type produced a
  deployment that looked healthy but silently had one fewer working connector
  than configured. `type` is now validated at config-load time, before boot
  reaches the connector-wiring loop, and aggregates every offending connector
  into one error. **If you have a connector with a misspelled or unsupported
  `type`, fix it before upgrading** — this is the same fail-open shape ADR-082
  closed for a missing/invalid connector `scope` above.
- **BREAKING (targeting v0.92.0): `storage.type: remote` combined with
  `server.http.enabled` or `server.grpc.enabled` no longer boots (ADR-083)** —
  `storage.type: remote` is a CLI/client mode only; RemoteStorage never
  implemented the RBAC primitives a server needs to check ANY permission for
  ANY caller (`GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, `RoleSetHasPermission`
  are all unconditional "not supported" stubs), so a server booted this way
  could never actually serve a permission-gated request — every request to
  every RBAC-gated route failed closed. If you were relying on this
  combination to run a "downstream Keyorix server" against `storage.type:
  remote`, it never functioned for ordinary API traffic; switch that
  deployment to `storage.type: local` or `storage.type: postgres`. The CLI's
  own client mode (`keyorix connect <server>`, or `storage.type: remote` in
  `~/.keyorix/cli.yaml` with no server enabled) is unaffected — see
  `docs/adr-083-remote-storage-cli-only.md`.
- **BREAKING (targeting v0.92.0): GCP KMS `kms_encryption_context` AAD wire format
  changed (crypto-gcpkms-01)** — `encContextAAD`'s canonicalisation of
  `kms_encryption_context` switched from an unescaped `"key=value\n"` join (where
  adversarial `=`/`\n` content in a key or value could let two structurally
  different context maps serialise to identical AdditionalAuthenticatedData,
  undermining the cross-install isolation the feature exists to provide) to a
  length-prefixed encoding that cannot collide. **Only installs configuring
  `kms_encryption_context` with a GCP KMS key provider are affected** — a KEK
  wrapped under the old AAD bytes will fail to decrypt after upgrading, since the
  new AAD no longer matches what it was wrapped under. To re-wrap: temporarily set
  `kms_allow_context_fallback: true`, run `keyorix encryption migrate-provider
  --to-kms-encryption-context=...` to re-wrap the KEK under the new AAD encoding,
  then **disable `kms_allow_context_fallback` again** (leaving it enabled makes
  the AAD binding advisory rather than enforced).
- **BREAKING: keyorix-operator default RBAC/watch scope narrowed to own-namespace-only
  (ADR-076)** — an unmodified `helm install deploy/helm/keyorix-operator` now binds a
  namespace-scoped `RoleBinding` in its own release namespace and watches only that
  namespace, instead of the previous default of a cluster-wide `ClusterRoleBinding`
  granting full CRUD on every Secret in the cluster. **Relied on the old default (set
  neither value)? Add `--set rbac.clusterScoped=true` to your `helm upgrade`** to preserve
  current behavior — without it, the operator stops reconciling `KeyorixSecret` CRs outside
  its own release namespace after the upgrade. **Already set `watchNamespaces`?**
  `rbac.clusterScoped` defaulted to `true` before this release, and a plain `helm upgrade`
  (without `--reset-values`) carries forward a release's previously-recorded values by
  default — so your install is very likely already in the now-rejected combination
  (`rbac.clusterScoped=true` + `watchNamespaces` set), and the upgrade will refuse to
  render at all: `rbac.clusterScoped=true and watchNamespaces=[...] are both set -- these
  are mutually exclusive (ADR-076)`. **Add `--set rbac.clusterScoped=false` explicitly to
  your `helm upgrade`** (or the equivalent in your values file) to clear it — this is a
  hard block on the upgrade, not a permissions change, until you do. Two opt-in modes cover
  broader deployments: `watchNamespaces: [ns, ...]` for a bounded multi-namespace instance,
  or `rbac.clusterScoped: true` for the original cluster-wide behavior — see the [operator
  docs](docs/k8s-operator.md#choosing-a-namespace-scope-adr-076) for detail. See ADR-076
  for the full rationale, including why this is the third attempt at this narrowing and
  what's different this time.
- **Frontend monorepo consolidation (ADR-070)** — `keyorix-web` (the dashboard)
  is folded into this repository at `web/`, full commit history preserved via
  `git subtree`. One `vX.Y.Z` tag now triggers both the server and web image
  builds in `docker-publish.yml`, closing the version-drift bug where the
  `docker-compose.yml`/Helm chart image pins assumed the two tracked the same
  tag when nothing enforced that. See ADR-070 for the full rationale and the
  CI/CD consolidation decisions (CodeQL, Sonar, SBOM, dependency review).

### Removed
- **`keyorix ping`** — removed as dead code: it was never registered as a
  runnable subcommand (only `keyorix status` was wired into the root command),
  so invoking `keyorix ping` has always produced "unknown command," regardless
  of this change. `keyorix status` already covers the same connectivity/
  response-time check, with a real exit-code contract (`0` healthy, `1`
  unhealthy/unreachable, `2` not configured) `ping` never had. Documentation
  that referenced `keyorix ping` has been updated to point to `status`.

### Added
- **`make smoke` — an executing first-run test.** `scripts/smoke.sh` runs the
  documented flow end to end in an isolated temp directory with its own `HOME`:
  `system init`, `project create`, `secret create`, `secret list`, `secret get`
  with a value round-trip, asserting embedded mode throughout (no server is
  started anywhere in it). It exists because the pre-existing
  `quickstart_commands_test.go` verifies that documented commands and flags
  *exist* and does not run them — which is precisely how a broken `system init`
  reached the documented first-run path with a green test suite. The two
  mechanisms now point at each other in their own headers.
- **FinOps billing report** — `GET /api/v1/admin/billing/report?from=&to=[&project_id=]`
  and `keyorix billing report --from --to [--project-id] [--format table|json]`.
  Per-project breakdown of secret counts, reads, writes, rotations, unique human users,
  and machine reads for a bounded date range. Gated behind the new `FeatureBilling =
  "billing"` license feature. Zero-activity projects are excluded from the output.
  ([#1227])
- **Dashboard stat-card trends** — the `DeploymentStatsSnapshot` GORM model is
  extended with four previously-missing metrics: `AuditLogins30d`,
  `AuditSecretReads30d`, `FailedAuthAttempts24h`, and `InactiveUsers`.
  `DashboardStats` gains prev+trend fields for all six deployment metrics;
  `saveDeploymentSnapshot` computes trends via `computeTrend`. GORM AutoMigrate
  handles the schema update with no migration file required. ([#1226])
- **Secret type update via CLI** — `keyorix secret update --type <new-type>` now
  actually changes a secret's type; the field is wired through
  `UpdateSecretRequest.Type` → core → HTTP handler → audit diff
  (`before`/`after`). Previously the flag was accepted but silently ignored.
  ([#1225])

### Fixed
- **`keyorix system init` could never generate a config, on any clean install.**
  ([#1839]) It read its template with `SafeReadFile(".", "keyorix_template.yaml")`
  — a file that does not exist anywhere in the repository (the shipped template
  is `configs/keyorix.yaml.tpl`), resolved against **the caller's working
  directory**. So the very first command a new user runs failed with
  `failed to read template file: no such file or directory`, and everything
  downstream failed with it: no config, so the server refused to boot. This was
  not a quirk of one machine — a binary on `$PATH` has no reason to be run from
  a directory containing repository files. The template is now embedded into the
  binary with `go:embed`, so `system init` is self-contained and
  cwd-independent. Found by a clean-checkout dress rehearsal, and now covered by
  `make smoke`.
- **Client mode (`storage.type: remote`) decoded several server responses
  incorrectly, returning empty results instead of data.** ([#1831], [#1832],
  [#1835], [#1836]) `ListRoles`, `GetRole`, `UpdateRole`, `GetUserRoles`,
  `GetGroupRoles`, `GetUserPermissions`, `ListSecretVersions`,
  `ListSharesBySecret`, `ListSharesByGroup` and `GetAuditLogs` each expected a
  bare array or a differently-named field where the server sends a wrapped
  envelope, and several request bodies were sent with the wrong casing. Machine-
  caller attribution (`#1573`) was also dropped across the wire on six fields.
  Two guards now hold this shut: one asserts client and server wire structs
  agree on every JSON key, the other that attribution fields survive the round
  trip. Both found real gaps on their first run, including one the guard's own
  author had just introduced.
- **Absolute `dek_path` / `salt_path` are bootable again.** ([#1827])
- **keyorix-operator `rbac.clusterScoped: false` never actually worked (ADR-076)** — this
  opt-out (added in [#1224]) bound namespace-scoped RBAC without ever telling the manager
  to narrow its own watch scope correspondingly, so it silently attempted a cluster-wide
  watch against namespace-scoped RBAC — in practice, repeated `Forbidden` errors on every
  namespace outside the release namespace, likely fatal to controller startup. Never
  worked correctly; fixed as part of ADR-076's broader scope-resolution rework before its
  first tagged release — `git tag --contains` confirms no released version ever shipped
  it (it landed three days after `v0.88.0`, the most recent tag at the time), so no
  affected versions to name.
- **SQLite RBAC grant-expiry timezone mismatch** — GORM formats `time.Time` using
  the process `Location`; mixed UTC/local `ExpiresAt` values broke SQLite string
  comparisons so grants appeared expired or perpetual depending on the host
  timezone. Fixed via `BeforeSave` hooks that normalise all `ExpiresAt` fields to
  UTC before write, and explicit UTC WHERE clauses for expiry queries. ([#1218])
- **DAST-identified security gaps** — CSP `frame-ancestors 'self'` on all HTML
  responses (closes clickjacking), `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Embedder-Policy: require-corp`, and a `Permissions-Policy` header
  removing access to camera/microphone/geolocation. ([#1217])
- **GitHub crash-report notifications on vCD fuzzing VMs** — GH token env-var
  lookup and `notified-*` marker cleanup so the fuzzing service correctly fires
  crash notifications on fleet VMs. ([#1222])

### Security
- **Optional `account_id` pin for `aws-secrets-manager` Keyorix Connect connectors**
  — the AWS sibling of the `gcp-secret-manager` `project_id` pin above, but with a
  narrower risk shape: a bare secret-name ref (the common case) is always resolved
  within the ambient credential's own AWS account by the Secrets Manager API itself,
  so it never carries a confused-deputy gap; only a full-ARN ref naming a DIFFERENT
  account is at risk, and only if that target account's own resource policy has
  separately granted cross-account access (a double opt-in, unlike GCP's
  single-opt-in ambient-reach gap). Because of that, `account_id` is **optional, not
  mandatory** — no existing deployment is broken by this change. When set,
  `validateConnectAWSAccountID` (`internal/config/config.go`) fails boot if it is
  not exactly 12 digits (the AWS account ID format), and
  `AWSSecretsManagerConnector.GetSecret` independently refuses any ARN-shaped ref
  naming a different account (defense in depth). When unset, `server/main.go` logs
  a startup recommendation rather than failing boot. See
  `docs/CONFIGURATION.md`'s Keyorix Connect section for the exact field and its
  documented scope boundary (a bare-name ref is never checked, by construction).
- **PAT scope enforcement, WebAuthn identity binding, template injection, K8s sync
  RBAC, TOTP anti-replay on proxy, operator Helm `clusterScoped`** — five
  security hardening items from the DAST/SAST backlog (PAT-SCOPE-002, WAUN-001,
  TMPL-002, K8SSYNC-007, and TOTP anti-replay on the remote-storage proxy path)
  closed in one bundle. ([#1224])

[#1827]: https://github.com/keyorixhq/keyorix/pull/1827
[#1831]: https://github.com/keyorixhq/keyorix/pull/1831
[#1832]: https://github.com/keyorixhq/keyorix/pull/1832
[#1835]: https://github.com/keyorixhq/keyorix/pull/1835
[#1836]: https://github.com/keyorixhq/keyorix/pull/1836
[#1839]: https://github.com/keyorixhq/keyorix/pull/1839
[#1217]: https://github.com/keyorixhq/keyorix/pull/1217
[#1218]: https://github.com/keyorixhq/keyorix/pull/1218
[#1222]: https://github.com/keyorixhq/keyorix/pull/1222
[#1224]: https://github.com/keyorixhq/keyorix/pull/1224
[#1225]: https://github.com/keyorixhq/keyorix/pull/1225
[#1226]: https://github.com/keyorixhq/keyorix/pull/1226
[#1227]: https://github.com/keyorixhq/keyorix/pull/1227

## v0.87.4 — 2026-07-07

CI-only patch release: pins the release workflow's cosign binary so signed release
artifacts publish again.

### Internal
- **cosign pinned to v2.5.2 for legacy `sign-blob` flags** — v0.87.3's fix traded one
  cosign v3.1.1 breakage for another: `sign-blob` started demanding
  `--signing-config`/`--use-signing-config` alongside `--new-bundle-format=false`, so the
  v0.87.3 release run failed at the same signing step and shipped without a GitHub
  Release (Docker images and the Helm chart still published fine both times). Rather than
  keep chasing v3.1.1's shifting flag requirements, `cosign-installer`'s `cosign-release`
  input is now pinned to `v2.5.2` — the last version that supported
  `--output-signature`/`--output-certificate` natively. ([#873])

[#873]: https://github.com/keyorixhq/keyorix/pull/873

## v0.87.3 — 2026-07-07

CI-only patch release: pins cosign's signing format so release artifacts publish again.

### Internal
- **cosign `sign-blob` pinned to the legacy bundle format** — the v0.87.2 release run
  failed at "Sign checksums.txt (keyless)": cosign now defaults to
  `--new-bundle-format=true` and silently drops `--output-signature`/`--output-certificate`,
  so no GitHub Release was created for that tag (Docker images and the Helm chart still
  published). `SECURITY.md` documents verification via the separate
  `checksums.txt.sig`/`.pem` files, so the workflow now pins
  `--new-bundle-format=false` to keep that verification flow working. (Superseded by
  [#873] once cosign v3.1.1 introduced a further flag requirement.) ([#872])

[#872]: https://github.com/keyorixhq/keyorix/pull/872
[#873]: https://github.com/keyorixhq/keyorix/pull/873

## v0.87.2 — 2026-07-07

A round-119 completeness audit closes 55 confirmed gaps where `storage.type: remote`
silently no-op'd or fully broke login/SSO/2FA/RBAC/compliance/dynamic-secrets flows,
plus a broad hardening bundle across degrade-on-error, TOCTOU, and access-control
paths, and new CodeQL/fuzzing/license-compliance CI gates.

### Fixed
- **Remote-storage completeness campaign: ~50 previously-stubbed `RemoteStorage` methods
  now proxy correctly under `storage.type: remote`** — a round-119 census traced every
  `RemoteStorage` method's real callers and found 55 confirmed, currently-reachable gaps
  that had silently accumulated across ~10 rounds of piecemeal fixing: SSO login
  (OIDC+SAML) was 100% broken, WebAuthn-as-2FA login was 100% broken, self-service
  access-requests were 100% broken, and most of RBAC/permission-catalog/Connect
  federated reads/project&environment management/dynamic-secrets/MFA
  enrollment/scheduler-lock/login-lockout accounting either failed open or errored out
  entirely when running against a remote storage backend. Each is now individually
  proxied and covered by a regression test. ([#793], [#802], [#810], [#811], [#812],
  [#823], [#827], [#828], [#830], [#831], [#835], [#836], [#837], [#838], [#839],
  [#840], [#841], [#842], [#846], [#847], [#848], [#849], [#850], [#851], [#852],
  [#853], [#854], [#860], [#861], [#862], [#863], [#864], [#865], [#866], [#867],
  [#868], [#869], [#870], [#871])
- **A completeness guard now pins every `RemoteStorage` stub to a reasoned
  classification** — `TestRemoteUnsupportedStubsAreAllowlisted` exact-matches every
  `remoteUnsupported(...)` call site against a fully-reasoned allowlist, classifying each
  as verified-permanent (with a citation) or a confirmed, backlog-tracked gap. A PR that
  adds a new unclassified stub, or fixes a listed gap without removing its entry, now
  fails CI immediately — closing the blind spot that let this round's 55 gaps
  accumulate unnoticed in the first place. ([#856])
- **`storage.type: remote` was fully broken for every proxied write** — the shared
  remote-storage response helper was missing the `"success"` key `sendSuccess` writes,
  so every successful proxied call was misread as a failure by the caller. ([#794])
- **Systemic fail-open across `GetCompliancePosture` closed** — a transient sub-query
  failure (legal hold, risk exceptions, SoD violations, dormant grants, and others)
  previously left the field at its "all clear" zero value instead of surfacing as
  degraded; every control now defers to an explicit unknown/degraded status instead of a
  false pass when its underlying query errors. ([#712], [#728], [#737], [#755], [#756],
  [#757], [#758], [#763], [#764], [#770], [#775], [#779], [#784], [#785], [#801], [#809])
- **Several long-running TOCTOU and race-condition fixes**: Shamir-reconstructed KEK
  verified against a real HMAC commitment ([#722]); rotation no-op detection stops
  spurious `LastRotatedAt` bumps ([#727]); pre-existing duplicate rows deduped before
  adding new unique indexes, closing an upgrade-time migration failure ([#761], [#766]);
  admin bootstrap password no longer leaks via `wget` argv ([#720]); evidence-pack
  generation is now one atomic snapshot ([#748]); reminder/notification dedup races
  closed ([#751], [#760]).
- **Validation and error-handling correctness**: CSV-formula-injection in audit export
  ([#749]); control-character/ANSI-escape injection in imported secret keys/values
  ([#742]); internal errors sanitized before reaching classify/rotate/restore/copy
  handlers ([#745]); user-creation and other handler validation errors now correctly
  return 400 instead of a generic 500 ([#858], [#859]); the audit high-water mark no
  longer embeds NUL bytes that corrupted persistence ([#857]).
- **`docker-compose` requires `KEYORIX_BOOTSTRAP_TOKEN` for auto-bootstrap**, closing an
  unauthenticated first-admin-seizure window in the bundled compose deployment path.
  ([#844])

### Security
- **RBAC / access-control hardening bundle**: `RequireRole` now unconditionally rejects
  machine/OIDC principals from human-only role checks ([#817]); a grant-time
  separation-of-duties preventive gate on role assignment ([#804]); `roles.read` now
  required to view a group's role grants ([#743]); dormant-role-grant detection counts
  write-tier activity and narrows masking between distinct admin-tier grants ([#732],
  [#770], [#801], [#809]); dead, scope-blind `CheckPermission` code path removed
  ([#741]).
- **Crypto / key-handling hardening**: evidence-signing key and audit-checkpoint key now
  derive from the KEK rather than the DEK ([#800], [#808]); local CLI key operations
  join the exclusive-DEK-lock coordination ([#783]); `rotate --dry-run` plus full
  sweep-result reporting ([#787]).
- **Supply-chain and CI hardening**: CodeQL analysis added for both Go modules
  ([#796]); native Go fuzz targets for Shamir, JWT, and rotation-ref parsing plus
  self-hosted continuous fuzzing ([#795], [#805]); `CONTRIBUTING.md` with enforced DCO
  sign-off ([#813]); a `checkov` IaC security-policy scan for the three Helm charts
  ([#814]); a `go-licenses` dependency license-compliance gate ([#822]); gitleaks scope
  narrowed to the checked-out branch ([#806]).
- **gRPC hardening**: outbound response size capped to match the inbound cap ([#788]);
  `ConnectService.ReadSecret` rejects an empty ref ([#776]); the unary interceptor chain
  reordered so metrics wraps auth correctly ([#778]); server-side keepalive reclaims
  idle connections ([#768]).
- **`TLSConfig.AllowedCiphers` now actually wired into HTTP + gRPC cipher suites** —
  the configured allowlist was previously validated but not enforced. ([#782])

### Internal
- Routine dependency bumps (AWS/Azure SDKs, `k8s.io/api`/`client-go`, `cobra`,
  `go-chi/chi`, and several GitHub Actions).
- Documentation refresh for `SECURITY.md`/`CONTRIBUTING.md`/`SECURITY-VERIFICATION.md`
  and several stale in-code comments closed out following this hardening pass ([#843],
  [#736], [#820], [#821], [#826]).

[#712]: https://github.com/keyorixhq/keyorix/pull/712
[#720]: https://github.com/keyorixhq/keyorix/pull/720
[#722]: https://github.com/keyorixhq/keyorix/pull/722
[#727]: https://github.com/keyorixhq/keyorix/pull/727
[#728]: https://github.com/keyorixhq/keyorix/pull/728
[#732]: https://github.com/keyorixhq/keyorix/pull/732
[#736]: https://github.com/keyorixhq/keyorix/pull/736
[#737]: https://github.com/keyorixhq/keyorix/pull/737
[#741]: https://github.com/keyorixhq/keyorix/pull/741
[#742]: https://github.com/keyorixhq/keyorix/pull/742
[#743]: https://github.com/keyorixhq/keyorix/pull/743
[#745]: https://github.com/keyorixhq/keyorix/pull/745
[#748]: https://github.com/keyorixhq/keyorix/pull/748
[#749]: https://github.com/keyorixhq/keyorix/pull/749
[#751]: https://github.com/keyorixhq/keyorix/pull/751
[#755]: https://github.com/keyorixhq/keyorix/pull/755
[#756]: https://github.com/keyorixhq/keyorix/pull/756
[#757]: https://github.com/keyorixhq/keyorix/pull/757
[#758]: https://github.com/keyorixhq/keyorix/pull/758
[#760]: https://github.com/keyorixhq/keyorix/pull/760
[#761]: https://github.com/keyorixhq/keyorix/pull/761
[#763]: https://github.com/keyorixhq/keyorix/pull/763
[#764]: https://github.com/keyorixhq/keyorix/pull/764
[#766]: https://github.com/keyorixhq/keyorix/pull/766
[#768]: https://github.com/keyorixhq/keyorix/pull/768
[#770]: https://github.com/keyorixhq/keyorix/pull/770
[#775]: https://github.com/keyorixhq/keyorix/pull/775
[#776]: https://github.com/keyorixhq/keyorix/pull/776
[#778]: https://github.com/keyorixhq/keyorix/pull/778
[#779]: https://github.com/keyorixhq/keyorix/pull/779
[#782]: https://github.com/keyorixhq/keyorix/pull/782
[#783]: https://github.com/keyorixhq/keyorix/pull/783
[#784]: https://github.com/keyorixhq/keyorix/pull/784
[#785]: https://github.com/keyorixhq/keyorix/pull/785
[#787]: https://github.com/keyorixhq/keyorix/pull/787
[#788]: https://github.com/keyorixhq/keyorix/pull/788
[#793]: https://github.com/keyorixhq/keyorix/pull/793
[#794]: https://github.com/keyorixhq/keyorix/pull/794
[#795]: https://github.com/keyorixhq/keyorix/pull/795
[#796]: https://github.com/keyorixhq/keyorix/pull/796
[#800]: https://github.com/keyorixhq/keyorix/pull/800
[#801]: https://github.com/keyorixhq/keyorix/pull/801
[#802]: https://github.com/keyorixhq/keyorix/pull/802
[#804]: https://github.com/keyorixhq/keyorix/pull/804
[#805]: https://github.com/keyorixhq/keyorix/pull/805
[#806]: https://github.com/keyorixhq/keyorix/pull/806
[#808]: https://github.com/keyorixhq/keyorix/pull/808
[#809]: https://github.com/keyorixhq/keyorix/pull/809
[#810]: https://github.com/keyorixhq/keyorix/pull/810
[#811]: https://github.com/keyorixhq/keyorix/pull/811
[#812]: https://github.com/keyorixhq/keyorix/pull/812
[#813]: https://github.com/keyorixhq/keyorix/pull/813
[#814]: https://github.com/keyorixhq/keyorix/pull/814
[#817]: https://github.com/keyorixhq/keyorix/pull/817
[#820]: https://github.com/keyorixhq/keyorix/pull/820
[#821]: https://github.com/keyorixhq/keyorix/pull/821
[#822]: https://github.com/keyorixhq/keyorix/pull/822
[#823]: https://github.com/keyorixhq/keyorix/pull/823
[#826]: https://github.com/keyorixhq/keyorix/pull/826
[#827]: https://github.com/keyorixhq/keyorix/pull/827
[#828]: https://github.com/keyorixhq/keyorix/pull/828
[#830]: https://github.com/keyorixhq/keyorix/pull/830
[#831]: https://github.com/keyorixhq/keyorix/pull/831
[#835]: https://github.com/keyorixhq/keyorix/pull/835
[#836]: https://github.com/keyorixhq/keyorix/pull/836
[#837]: https://github.com/keyorixhq/keyorix/pull/837
[#838]: https://github.com/keyorixhq/keyorix/pull/838
[#839]: https://github.com/keyorixhq/keyorix/pull/839
[#840]: https://github.com/keyorixhq/keyorix/pull/840
[#841]: https://github.com/keyorixhq/keyorix/pull/841
[#842]: https://github.com/keyorixhq/keyorix/pull/842
[#843]: https://github.com/keyorixhq/keyorix/pull/843
[#844]: https://github.com/keyorixhq/keyorix/pull/844
[#846]: https://github.com/keyorixhq/keyorix/pull/846
[#847]: https://github.com/keyorixhq/keyorix/pull/847
[#848]: https://github.com/keyorixhq/keyorix/pull/848
[#849]: https://github.com/keyorixhq/keyorix/pull/849
[#850]: https://github.com/keyorixhq/keyorix/pull/850
[#851]: https://github.com/keyorixhq/keyorix/pull/851
[#852]: https://github.com/keyorixhq/keyorix/pull/852
[#853]: https://github.com/keyorixhq/keyorix/pull/853
[#854]: https://github.com/keyorixhq/keyorix/pull/854
[#856]: https://github.com/keyorixhq/keyorix/pull/856
[#857]: https://github.com/keyorixhq/keyorix/pull/857
[#858]: https://github.com/keyorixhq/keyorix/pull/858
[#859]: https://github.com/keyorixhq/keyorix/pull/859
[#860]: https://github.com/keyorixhq/keyorix/pull/860
[#861]: https://github.com/keyorixhq/keyorix/pull/861
[#862]: https://github.com/keyorixhq/keyorix/pull/862
[#863]: https://github.com/keyorixhq/keyorix/pull/863
[#864]: https://github.com/keyorixhq/keyorix/pull/864
[#865]: https://github.com/keyorixhq/keyorix/pull/865
[#866]: https://github.com/keyorixhq/keyorix/pull/866
[#867]: https://github.com/keyorixhq/keyorix/pull/867
[#868]: https://github.com/keyorixhq/keyorix/pull/868
[#869]: https://github.com/keyorixhq/keyorix/pull/869
[#870]: https://github.com/keyorixhq/keyorix/pull/870
[#871]: https://github.com/keyorixhq/keyorix/pull/871
[#872]: https://github.com/keyorixhq/keyorix/pull/872

## v0.87.1 — 2026-07-04

CI-only patch release: fixes broken chart-signing authentication in the release
workflow.

### Internal
- **`release.yml` now authenticates to GHCR before cosign chart signing** — `publish-chart`
  failed on v0.87.0: all three Helm chart pushes succeeded, but the first cosign sign
  call failed with `UNAUTHORIZED` because `helm registry login` only populates Helm's
  own credential store, not the Docker config cosign reads registry auth from. A
  `docker/login-action` step now runs before the push+sign block, mirroring the
  already-working pattern `docker-publish.yml` uses for image signing. (v0.87.0's three
  charts remain live but unsigned in GHCR — not retroactively fixable without mutating
  an already-published tag.) ([#698])

[#698]: https://github.com/keyorixhq/keyorix/pull/698

## v0.87.0 — 2026-07-04

A large security-hardening campaign closes several CRITICAL/HIGH authorization and
account-takeover gaps (SSO JIT-provisioning takeover, repeated admin-rank-ceiling
bypasses, systemic compliance-posture fail-open), migrates session auth to httpOnly
cookies with CSRF protection, and fixes dozens of TOCTOU races and validation gaps
across RBAC, SCIM, SSO, dynamic secrets, and the operator.

### Added
- **Session auth migrates to an httpOnly cookie (`kx_session`) with double-submit
  CSRF** — session tokens no longer need to live in client-held storage, closing the
  XSS blast-radius on session theft; a `csrf_token` cookie plus `X-CSRF-Token` header
  protects state-changing requests now that auth is ambient. Admin impersonation was
  redesigned to swap sessions purely via cookies (`kx_admin_session`) without the
  server ever needing to recall a plaintext token from storage. Bearer-token auth
  keeps working alongside cookies during a bake-in period; removing the fallback is a
  deliberately deferred follow-up. ([#679])

### Security
- **SSO JIT-provisioning account takeover (CRITICAL)** — the existing-account lookup
  in SSO login had been hardened to require a verified email match, but the
  just-in-time provisioning branch reused an unguarded lookup and returned an existing
  account regardless of verification. With `auto_provision` enabled and an IdP that
  omits `email_verified` (e.g. Entra), an attacker asserting a victim's email with a
  fresh subject could be logged in as the victim, including admins, across identity
  providers. Provisioning now routes through the same verified-email guard as the
  existing-account path. ([#657])
- **Three more admin-rank-ceiling gaps closed (all HIGH)**: group restore reinstated
  role grants — including admin-tier roles — with no check on the restoring actor's
  own authority ([#568], part of #147); project/environment restore had the same gap,
  plus a query that never joined against the project's/environment's own
  soft-delete state, so a directly-bound role kept authorizing after the scope was
  deleted (#161); admin impersonation only checked a target's literal global-admin
  flag, missing a project-scoped or group-inherited admin (#165). All three now
  enforce a scope-aware authority ceiling before the elevated action proceeds.
  ([#588], [#616])
- **Systemic compliance-posture fail-open closed (HIGH)** — `GetCompliancePosture`'s
  `if err == nil { set }` pattern silently left a sub-query failure (legal hold, risk
  exceptions, SoD violations, and others) at its "all clear" zero value instead of
  surfacing as degraded; empirically proven to flip a real adverse state back to
  false on a dropped table mid-query. Every control now surfaces an explicit
  unknown/degraded status instead of a false pass. ([#610])
- **Startup/schema validation now actually runs on boot (HIGH)** — `ValidateStartup`
  and `Config.Validate()` were documented as running automatically but were never
  wired into `server/main.go`; an operator relying on
  `enable_file_permission_check: true` to catch a world-readable DEK/salt file got no
  warning at all. Also fixes a hardcoded config path (spurious failures under
  `KEYORIX_CONFIG_PATH`) and a startup check that unconditionally required a SQLite
  path even for postgres/remote deployments. ([#612])
- **DB-level email uniqueness closes a concurrent account-collision race (HIGH)** — a
  missing unique index on `users.email` meant concurrent signup/invite-accept calls
  with the same email could all succeed, leaving lookups to resolve to an arbitrary
  row; SCIM's email-uniqueness and last-admin-deactivation guards are also switched
  from fail-open to fail-closed on a transient lookup error. ([#614])
- **RBAC bundling and role-grant CRITICAL/HIGH fixes**: the actor must already hold a
  permission before bundling it into a role they grant ([#557]); every
  privilege-grant path now routes through one audited RBAC choke point ([#588]);
  `GetMachineRoleIDsAt` closed a soft-deleted-role gap ([#589]); SCIM Update/
  Deprovision/List restricted to SCIM-managed accounts ([#523]).
- **CI/supply-chain hardening across workflows, images, and the release pipeline**
  ([#543]), plus pinned/checksum-verified GitHub Action installs ([#668]).
- **`golang.org/x/net` bumped to v0.55.0 in the operator module**, closing 5
  published HIGH-severity CVEs (CVE-2026-25681, CVE-2026-27136, CVE-2026-33814,
  CVE-2026-39821, CVE-2026-42502) caught by the new Trivy image-scan CI gate.
  ([#696], [#697])

### Fixed
- Broad TOCTOU-race closures across invitation/access-request accept-vs-revoke
  ([#677]), project/user purge-vs-restore ([#678], [#680]), legal hold placement
  ([#593]), access-review decisions and campaign close ([#595], [#622]), break-glass
  revoke ([#596]), audit-checkpoint writes ([#601]), invite/delete-project races
  ([#599]), WebAuthn sign-counter updates ([#600]), and DEK rotation coordination
  with a live server ([#526], [#651]).
- SSO/SAML hardening: SAML/OIDC type-confusion panic and login-state TOCTOU fixed
  ([#606]); SSO identity scoped to its asserting provider, closing cross-provider
  takeover ([#517]); SAML email-fallback linking gated behind a per-provider opt-in
  ([#659]).
- Dynamic-secrets hardening: install-wide max-TTL ceiling with honest lease expiry
  ([#541]); admin authority required to bind a backend ([#524], [#551]); configs
  disabled and leases revoked on project deletion ([#646]).
- Session-refresh reuse-detection and WebAuthn clone-detection ([#656]); MFA/WebAuthn
  credential changes now require re-authentication ([#664]).
- httpOnly-cookie migration's Go toolchain bump (1.26.4 minimum) and Dependabot gomod
  coverage. ([#683], [#684])

### Internal
- CI supply-chain and container hardening: Trivy vulnerability scanning for
  published images ([#694]), a buildx-driver fix for broken image publishing
  ([#695]).

[#517]: https://github.com/keyorixhq/keyorix/pull/517
[#523]: https://github.com/keyorixhq/keyorix/pull/523
[#524]: https://github.com/keyorixhq/keyorix/pull/524
[#526]: https://github.com/keyorixhq/keyorix/pull/526
[#541]: https://github.com/keyorixhq/keyorix/pull/541
[#543]: https://github.com/keyorixhq/keyorix/pull/543
[#551]: https://github.com/keyorixhq/keyorix/pull/551
[#557]: https://github.com/keyorixhq/keyorix/pull/557
[#568]: https://github.com/keyorixhq/keyorix/pull/568
[#588]: https://github.com/keyorixhq/keyorix/pull/588
[#589]: https://github.com/keyorixhq/keyorix/pull/589
[#593]: https://github.com/keyorixhq/keyorix/pull/593
[#595]: https://github.com/keyorixhq/keyorix/pull/595
[#596]: https://github.com/keyorixhq/keyorix/pull/596
[#599]: https://github.com/keyorixhq/keyorix/pull/599
[#600]: https://github.com/keyorixhq/keyorix/pull/600
[#601]: https://github.com/keyorixhq/keyorix/pull/601
[#606]: https://github.com/keyorixhq/keyorix/pull/606
[#610]: https://github.com/keyorixhq/keyorix/pull/610
[#612]: https://github.com/keyorixhq/keyorix/pull/612
[#614]: https://github.com/keyorixhq/keyorix/pull/614
[#616]: https://github.com/keyorixhq/keyorix/pull/616
[#622]: https://github.com/keyorixhq/keyorix/pull/622
[#646]: https://github.com/keyorixhq/keyorix/pull/646
[#651]: https://github.com/keyorixhq/keyorix/pull/651
[#656]: https://github.com/keyorixhq/keyorix/pull/656
[#657]: https://github.com/keyorixhq/keyorix/pull/657
[#659]: https://github.com/keyorixhq/keyorix/pull/659
[#664]: https://github.com/keyorixhq/keyorix/pull/664
[#668]: https://github.com/keyorixhq/keyorix/pull/668
[#677]: https://github.com/keyorixhq/keyorix/pull/677
[#678]: https://github.com/keyorixhq/keyorix/pull/678
[#679]: https://github.com/keyorixhq/keyorix/pull/679
[#680]: https://github.com/keyorixhq/keyorix/pull/680
[#683]: https://github.com/keyorixhq/keyorix/pull/683
[#684]: https://github.com/keyorixhq/keyorix/pull/684
[#694]: https://github.com/keyorixhq/keyorix/pull/694
[#695]: https://github.com/keyorixhq/keyorix/pull/695
[#696]: https://github.com/keyorixhq/keyorix/pull/696
[#697]: https://github.com/keyorixhq/keyorix/pull/697

## v0.86.0 — 2026-06-27

Deployment-wide rotation planning lands (ADR-053), personal access tokens gain a
network allowlist (ADR-066), and a consolidated hardening batch closes an
unauthenticated-bootstrap seizure gap plus several transport-parity and
secrets-at-rest issues.

### Added
- **Deployment-wide rotation planning (ADR-053)** — `keyorix rotation plan
  --all-projects` rolls up the rotation plan across every project in one view;
  auto-rotation is now ordered by the secret dependency graph so dependents rotate
  after what they depend on, and secret soft-delete/restore/purge cascades through
  that same dependency graph. ([#503], [#505], [#507], [#508])
- **Network (IP/CIDR) allowlist for personal access tokens (ADR-066)** — a PAT can now
  be scoped to a set of source IPs/CIDRs; enforcement is closed over both HTTP and
  gRPC so a restricted PAT can't bypass the allowlist through the transport that
  doesn't check it. ([#502], [#504])
- **Cached certificate expiry refreshes on rotation (ADR-056)** — a rotated
  certificate's cached expiry no longer lags the real one. ([#509])
- **Configurable timezone and off-hours band for anomaly detection** — the
  `off_hours` anomaly rule now accounts for install timezone instead of assuming
  UTC, and the live detection window is excluded from its own statistical/ML
  baseline so a burst of activity can't suppress its own detection. ([#510], [#511])
- **Supply-chain-integrity control in the compliance posture/matrix (ADR-062 §7)**.
  ([#500])

### Security
- **Unauthenticated bootstrap seizure closed (HIGH)** — `POST /system/init` was
  gated only by a "no users yet" check, so any network-reachable fresh instance
  could be seized by whoever called it first. It now requires a bootstrap token
  (constant-time compare; auto-generated and logged on first boot, or set via
  `KEYORIX_BOOTSTRAP_TOKEN`), and enforces the password policy on the seeded admin.
  ([#518])
- **gRPC transport-parity gaps closed**: `ShareService.ListUserShares`/
  `ListSharedSecrets` ignored a PAT's scope restriction over gRPC (enforced on the
  equivalent HTTP routes); a PAT's IP allowlist is now enforced over gRPC as well,
  closing a transport bypass. ([#504], [#506])
- **KMS encryption-context binding for the wrapped KEK (AWS `EncryptionContext` /
  GCP AAD)**, opt-in and default-equivalent, so installs sharing one CMK can't
  unwrap each other's KEK (Azure unsupported — RSA-OAEP has no AAD). ([#516])
- **Session tokens and service-account credentials now hashed at rest** instead of
  stored in plaintext, alongside gating MFA/WebAuthn second-factor login on account
  state and revoking impersonation sessions when the impersonating admin is
  blocked. ([#516])
- **Durable, opt-in on-disk SIEM spool with replay** — a sustained SIEM outage no
  longer silently drops the off-box audit copy; `emitAudit` no longer swallows a
  persist error, and forwarded SIEM payloads carry `entry_hash`/`prev_hash` for
  downstream gap/forgery detection. ([#516])
- **Break-glass grants are always bounded, even when `MaxTTL` is unconfigured**, and
  the granted role is now locked under multi-party (M-of-K) approval so a second
  approver can't race a change to what's being approved. ([#513], [#512])

[#500]: https://github.com/keyorixhq/keyorix/pull/500
[#502]: https://github.com/keyorixhq/keyorix/pull/502
[#503]: https://github.com/keyorixhq/keyorix/pull/503
[#504]: https://github.com/keyorixhq/keyorix/pull/504
[#505]: https://github.com/keyorixhq/keyorix/pull/505
[#506]: https://github.com/keyorixhq/keyorix/pull/506
[#507]: https://github.com/keyorixhq/keyorix/pull/507
[#508]: https://github.com/keyorixhq/keyorix/pull/508
[#509]: https://github.com/keyorixhq/keyorix/pull/509
[#510]: https://github.com/keyorixhq/keyorix/pull/510
[#511]: https://github.com/keyorixhq/keyorix/pull/511
[#512]: https://github.com/keyorixhq/keyorix/pull/512
[#513]: https://github.com/keyorixhq/keyorix/pull/513
[#516]: https://github.com/keyorixhq/keyorix/pull/516
[#518]: https://github.com/keyorixhq/keyorix/pull/518

## v0.85.0 — 2026-06-24

A proactive license-expiry reminder, plus break-glass and federated-auth boundary tests.

### Added
- **Background license-expiry reminder** — an opt-in scheduler (`license_expiry`) that
  notifies install-wide admins when the offline commercial license is within its lead window
  of expiry or has already expired, so a silent lapse (which degrades commercial features to
  the community baseline) doesn't go unnoticed. It targets install-wide admins only
  (`super_admin` / `admin` / `system_admin`, not project-scoped admins), is deduped so it
  doesn't repeat on every tick, and is single-replica-gated in HA (ADR-039). The fail-safe
  gate and `GET /api/v1/license/status` are unaffected. (ADR-065 Phase 2c) ([#496])

### Internal
- Security-boundary tests: an expired break-glass emergency grant denies authorization end
  to end ([#494]), and federated machine-identity auth keeps cross-issuer bindings isolated
  (a token from one issuer can't satisfy a binding for another) ([#495], ADR-031).

[#494]: https://github.com/keyorixhq/keyorix/pull/494
[#495]: https://github.com/keyorixhq/keyorix/pull/495
[#496]: https://github.com/keyorixhq/keyorix/pull/496

## v0.84.0 — 2026-06-24

The first commercial-licensed feature, plus session-lifetime hardening.

### Added
- **`bundle import` is the first license-gated commercial feature (`airgap_updates`)** —
  staging an air-gap update bundle for rollout now requires a valid offline license carrying
  the `airgap_updates` feature; `bundle verify` stays free. The gate is fail-safe: a
  missing/expired/invalid license simply means the feature is off and import is refused with
  an actionable message — it never affects a running deployment. Gating strips nothing from
  community builds: import already requires the embedded update-signing key that only release
  builds carry. (ADR-065 Phase 2c, ADR-062) ([#491])

### Security
- **The absolute session-lifetime ceiling is enforced at validation** — a session is now
  rejected once it passes its absolute lifetime cap even if the access token itself has not
  expired, closing a window where a long-lived refresh chain could outlive the configured
  ceiling. ([#489])
- **A suspended account can no longer authenticate via a personal access token** — `SuspendUser`
  changes the account state and terminates the user's sessions but intentionally leaves
  `is_active` set, so a suspended user's existing PATs continued to authenticate. PAT validation
  now also rejects a blocked account state (mirroring session validation), so suspension
  immediately revokes access through every credential type, not only sessions. ([#492])

### Internal
- A regression test pinning that the SIEM-pull audit export carries the ADR-029 hash-chain
  links (so an external SIEM can independently verify tamper-evidence). ([#490])

[#489]: https://github.com/keyorixhq/keyorix/pull/489
[#490]: https://github.com/keyorixhq/keyorix/pull/490
[#491]: https://github.com/keyorixhq/keyorix/pull/491
[#492]: https://github.com/keyorixhq/keyorix/pull/492

## v0.83.0 — 2026-06-24

Offline commercial-license validation — the second air-gap mechanism, fail-safe by design —
plus secret-encryption chunk-ordering hardening.

### Added
- **Offline license validation (`keyorix license issue` / `install` / `status` + server
  enforcement)** — a paid air-gap tier needs entitlement that validates **with no
  phone-home**. A license is a compact `ed25519`-signed token (licensee, plan, features,
  expiry, optional deployment binding) verified locally against a public key embedded at
  build time. Enforcement is the deliberate **inverse of update bundles**: bundles are
  fail-closed, a license is **fail-safe** — a missing, expired, or invalid license degrades
  to the AGPL community baseline (no commercial features) with an admin warning and an audit
  event; it never denies access to existing secrets or stops the server, because
  availability is itself a security property for a secrets manager. The server loads the
  configured license at startup (a bad file never blocks boot), evaluates it freshly on
  every check, records the state as a startup audit event, and serves `GET
  /api/v1/license/status`. No shipped feature is gated on it — the gate is ready for future
  commercial-only capabilities. (ADR-065, ADR-062 Phase 2) ([#485], [#487])

### Security
- **Chunk position is authenticated in secret-value encryption** — chunked secret values now
  bind each chunk's position into its AEAD additional data, so a stored ciphertext can't be
  reordered, spliced, or truncated without detection. ([#484])

### Internal
- A regression test that DEK rotation preserves the AAD transplant binding (a rewrapped
  value stays bound to its identity). ([#486])

[#484]: https://github.com/keyorixhq/keyorix/pull/484
[#485]: https://github.com/keyorixhq/keyorix/pull/485
[#486]: https://github.com/keyorixhq/keyorix/pull/486
[#487]: https://github.com/keyorixhq/keyorix/pull/487

## v0.82.0 — 2026-06-24

Air-gapped, cryptographically-verifiable update bundles — the first build-on of the Phase 0
trust foundation — plus a security-test sweep over per-reference RBAC and secret-encryption
tamper-resistance.

### Added
- **Air-gap update bundles (`keyorix bundle build` / `verify` / `import`)** — a single,
  signed, offline-verifiable artifact for carrying a Keyorix release into an air-gapped or
  regulated environment (defence, finance, government; NIS2/DORA supply-chain integrity). A
  bundle is a gzip-tar whose `manifest.json` pins every component (images, charts, CRDs,
  binaries, migrations) by sha256, with a detached `ed25519` `manifest.sig`. `build` signs
  with an offline key; `verify` and `import` check the signature **offline** against the
  public key embedded in the binary at build time — trust follows a pinned chain, never a
  key shipped inside the bundle — then verify every component's digest. `import`
  additionally enforces **no-downgrade / `min_upgrade_from`** before staging the verified
  artifacts atomically, and prints the operator-controlled rollout steps (loading images
  into the internal registry and the Helm upgrade stay the operator's own steps). Everything
  **fails closed**: a plain (non-release) build embeds no keys, so verification refuses.
  Reads are size-bounded (decompression-bomb guard). Builds on the Phase 0 trust registry
  (`internal/trust`). (ADR-064, ADR-062 Phase 1) ([#479], [#482])

### Internal
- Security-boundary test sweep: Keyorix Connect per-reference RBAC has no admin bypass and
  no bare-prefix segment-boundary footgun ([#477], [#478], ADR-045); and the secret-
  encryption AEAD is tamper- and transplant-resistant, with no legacy-AAD downgrade bypass
  of the transplant binding ([#480], [#481]).

[#477]: https://github.com/keyorixhq/keyorix/pull/477
[#478]: https://github.com/keyorixhq/keyorix/pull/478
[#479]: https://github.com/keyorixhq/keyorix/pull/479
[#480]: https://github.com/keyorixhq/keyorix/pull/480
[#481]: https://github.com/keyorixhq/keyorix/pull/481
[#482]: https://github.com/keyorixhq/keyorix/pull/482

## v0.81.0 — 2026-06-23

A security-hardening release: the HTTP edge gets global security headers, a request
body-size cap, no panic-internals leakage, and the debug route removed from production;
per-account login lockout is now atomic under concurrency; and share self-removal works
end-to-end.

### Added
- **Share self-removal works end-to-end** — a recipient can now remove themselves from a
  secret share via `DELETE /api/v1/secrets/{id}/self-share` and the corresponding CLI
  command. The CLI command previously shipped as a non-functional placeholder; it is now a
  registered remote-only command backed by a real route, and the operation only removes the
  caller's own direct share (never a group share, never someone else's). ([#458])

### Security
- **Global security-headers middleware** — every response now carries `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and HSTS when TLS is
  enabled. ([#455])
- **Request body-size cap (DoS mitigation)** — requests are bounded by
  `http.MaxBytesReader` (10 MiB default, configurable), so an oversized or slow body can't
  exhaust server memory. ([#456])
- **Panic internals never reach the client** — the recovery middleware no longer has a
  development branch that could return the panic value or stack trace in the response; it
  always responds with a generic 500. ([#453])
- **Debug `/test-route` removed from the production router** — a leftover debug route is no
  longer registered. ([#460])

### Fixed
- **Per-account login lockout is atomic under concurrency** — failed-login counting now uses
  an atomic update, so concurrent attempts can't race past the lockout threshold. ([#474])

### Internal
- Group-inherited grant lifecycle boundary tests — expiry and membership transitions for
  permissions inherited through group shares. ([#475])

[#453]: https://github.com/keyorixhq/keyorix/pull/453
[#455]: https://github.com/keyorixhq/keyorix/pull/455
[#456]: https://github.com/keyorixhq/keyorix/pull/456
[#458]: https://github.com/keyorixhq/keyorix/pull/458
[#460]: https://github.com/keyorixhq/keyorix/pull/460
[#474]: https://github.com/keyorixhq/keyorix/pull/474
[#475]: https://github.com/keyorixhq/keyorix/pull/475

## v0.80.0 — 2026-06-23

SAML 2.0 single sign-on (Service Provider) lands as a working login path, three more
subsystems reach gRPC parity (audit-chain verify, break-glass, group management), SCIM
deprovisioning becomes atomic, and the HTTP surface gets response-cache and method
hardening — over a broad authorization- and concurrency-boundary test sweep.

### Added
- **SAML 2.0 single sign-on (Service Provider)** — Keyorix can now authenticate users
  against a SAML IdP, alongside the existing OIDC SSO. The SP is built on the vetted
  `crewjam/saml` + `goxmldsig` stack (no hand-rolled XML-DSig); the
  `/auth/saml/{provider}/{metadata,login,acs}` routes mirror the OIDC ones, and a SAML
  assertion maps to a user through the same identity-source-agnostic provisioning,
  group/role reconcile, and session path as OIDC. Opt-in and config-gated — no behaviour
  change without a SAML provider configured. (ADR-063; design [#446], SP core [#447],
  login flow + routes [#461])
- **Audit-chain verify, checkpoint & retention over gRPC** — the tamper-evident audit
  log's verify / checkpoint / retention operations are now first-class gRPC RPCs, matching
  the HTTP surface for programmatic compliance tooling. ([#443])
- **Break-glass emergency access over gRPC** — the break-glass request / approve / use flow
  is now available over gRPC. ([#445])
- **Group management over gRPC** — group CRUD and membership management reach gRPC parity.
  ([#448])
- **`WithTransaction` storage primitive; atomic SCIM deprovision** — a transaction
  primitive in the storage layer, used to make SCIM deprovisioning atomic so a partial
  failure can no longer leave a user half-removed. ([#454])

### Fixed
- **Expired time-bound shares no longer grant access** — `ListUserPermissions` now excludes
  time-bound shares past their expiry, closing a window where an expired share could still
  be enumerated as a live permission. ([#449])
- **Auth cache evicts the old token on refresh** — refreshing a token now evicts the prior
  entry from the auth cache, so a rotated token can't linger as a cached credential. ([#451])

### Security
- **`Cache-Control: no-store` on all API and SCIM responses** — secret material and
  directory data are never written to shared or intermediary caches. ([#469])
- **Web-UI static assets and the SPA fallback are GET/HEAD only** — mutating methods against
  static paths no longer fall through to the SPA handler. ([#470])

### Internal
- A broad authorization- and concurrency-boundary test sweep: cross-tenant and
  permission-granularity authorization ([#457], [#459]), HTTP↔gRPC authorization parity for
  secrets and sharing ([#462], [#463]), machine-identity no-admin-bypass ([#464]), and
  `-race` invariants for max-reads burn-after-read, the audit hash-chain, and the login
  rate-limiter ([#465], [#466], [#472]) — plus by-reference cross-project scope denial
  ([#471]), the group-share self-removal guard ([#467]), and a fix for two long-standing
  local-only `server/http` test flakes ([#468]).

[#443]: https://github.com/keyorixhq/keyorix/pull/443
[#445]: https://github.com/keyorixhq/keyorix/pull/445
[#446]: https://github.com/keyorixhq/keyorix/pull/446
[#447]: https://github.com/keyorixhq/keyorix/pull/447
[#448]: https://github.com/keyorixhq/keyorix/pull/448
[#449]: https://github.com/keyorixhq/keyorix/pull/449
[#451]: https://github.com/keyorixhq/keyorix/pull/451
[#454]: https://github.com/keyorixhq/keyorix/pull/454
[#457]: https://github.com/keyorixhq/keyorix/pull/457
[#459]: https://github.com/keyorixhq/keyorix/pull/459
[#461]: https://github.com/keyorixhq/keyorix/pull/461
[#462]: https://github.com/keyorixhq/keyorix/pull/462
[#463]: https://github.com/keyorixhq/keyorix/pull/463
[#464]: https://github.com/keyorixhq/keyorix/pull/464
[#465]: https://github.com/keyorixhq/keyorix/pull/465
[#466]: https://github.com/keyorixhq/keyorix/pull/466
[#467]: https://github.com/keyorixhq/keyorix/pull/467
[#468]: https://github.com/keyorixhq/keyorix/pull/468
[#469]: https://github.com/keyorixhq/keyorix/pull/469
[#470]: https://github.com/keyorixhq/keyorix/pull/470
[#471]: https://github.com/keyorixhq/keyorix/pull/471
[#472]: https://github.com/keyorixhq/keyorix/pull/472

## v0.79.0 — 2026-06-23

CLI ergonomics (machine-identity OIDC bindings, by-reference secret reads, richer
token listing), more reliable compliance-evidence delivery, and the cryptographic
foundation for air-gapped signing.

### Added
- **Machine-identity OIDC federation bindings in the CLI** — manage the bindings that
  map an external `(issuer, subject)` to a machine identity (ADR-031), so a workload can
  authenticate with a platform-issued JWT (e.g. a Kubernetes projected SA token) instead
  of a stored credential. The binding existed over HTTP and gRPC but had no CLI; operators
  can now wire it from the terminal. ([#438])
- **Read a secret by reference from the CLI** — `keyorix secret get --ref
  project/environment/name` reads a secret's value by a human-readable reference (ADR-059),
  completing CLI parity with the HTTP endpoint. Handy for scripts and automation; the read
  is scoped, counts toward `max_reads`, and is audited like any value read. ([#442])
- **`keyorix pat list` shows created / last-used / expiry** — the token list now surfaces
  `created_at`, `last_used_at`, and `expires_at`, so "which of my tokens are stale or about
  to expire?" is answerable from the CLI instead of the web UI or raw API. ([#440])
- **Air-gap signing trust foundation** — `internal/trust`, a verify-only, purpose-scoped
  `ed25519` public-key registry (fails closed) with trusted keys embedded at build time,
  plus `keyorix trust keygen` to mint a keypair and print the embed snippet. The base for
  air-gapped update bundles and offline licenses (ADR-062 Phase 0). No behaviour change —
  no callers yet, and a non-release build trusts no keys. ([#441])

### Fixed
- **Compliance evidence-pack delivery retries transient failures** — the daily
  evidence-pack webhook (ISO 27001 / SOC 2 continuous evidence) previously POSTed once and
  lost the pack on a brief receiver outage; it now retries transient failures, closing a
  gap in the continuous-evidence guarantee. ([#439])

[#438]: https://github.com/keyorixhq/keyorix/pull/438
[#439]: https://github.com/keyorixhq/keyorix/pull/439
[#440]: https://github.com/keyorixhq/keyorix/pull/440
[#441]: https://github.com/keyorixhq/keyorix/pull/441
[#442]: https://github.com/keyorixhq/keyorix/pull/442

## v0.78.0 — 2026-06-23

A read-only **MCP server** so AI agents can use Keyorix secrets safely, reliable
delivery for all operational-alert channels, CLI CSV export for auditors, and a design
for air-gapped updates + offline licensing.

### Added
- **MCP server for AI agents** — `keyorix-mcp`, a read-only Model Context Protocol server
  (stdio JSON-RPC 2.0) that lets an AI agent (Claude Desktop/Code, etc.) read Keyorix
  secrets through a least-privilege machine token. Tools: `keyorix_get_secret(ref)` (value
  by `project/environment/name`, via the by-reference endpoint) and
  `keyorix_list_secrets(environment?)` (references only, no values). No write tools, no
  network surface; every read goes through the usual scoped `secrets.read` / `max_reads` /
  suspension / audit, and values are never logged. Ships a Docker image and a configuration
  guide. (ADR-061) ([#433])
- **Reliable notification delivery for every channel** — the webhook, chat (Slack/Teams),
  and email (SMTP) operational-alert sinks (anomalies, break-glass, rotation/recert
  reminders — ISO 27001 A.5.5) now run on a shared delivery engine that **retries
  transient failures with exponential backoff** (permanent `4xx` not retried), is
  shutdown-aware, and exports Prometheus metrics so drops/failures are alertable. Replaces
  the previous fire-and-forget that silently lost an alert on a brief endpoint blip or a
  full queue. ([#432], [#434])
- **Compliance & inventory CSV export in the CLI** — `keyorix compliance controls --csv`
  (the control matrix) and `keyorix compliance inventory [--project <id>]` (the secret
  asset inventory, metadata only — no values) give auditors CLI parity with the dashboard
  for an air-gapped hand-off, instead of falling back to the raw HTTP API. ([#430])

### Design
- **Air-gapped updates & offline license validation** — a design (no behaviour change) for
  cryptographically-verifiable offline update bundles and fail-safe offline license
  validation (both `ed25519` with embedded pinned public keys), ready to build on the first
  air-gap prospect. (ADR-062) ([#435])

[#430]: https://github.com/keyorixhq/keyorix/pull/430
[#432]: https://github.com/keyorixhq/keyorix/pull/432
[#433]: https://github.com/keyorixhq/keyorix/pull/433
[#434]: https://github.com/keyorixhq/keyorix/pull/434
[#435]: https://github.com/keyorixhq/keyorix/pull/435

## v0.77.0 — 2026-06-23

A Kubernetes release: the secret-sync workstreams (orphan cleanup, an External Secrets
Operator integration, Kubernetes dynamic secrets, a by-reference read endpoint) and a
native CRD-based **operator** — plus time-bound secret shares and correct version
stamping in the published images.

### Added
- **Kubernetes sync orphan cleanup** — the `keyorix-k8s-sync` agent can now reap the
  Secrets it created once their mapping is removed, instead of leaving stale values
  behind forever. Opt-in (`cleanup: true` / `-cleanup`, **off by default**); ownership is
  recorded on-cluster via an `app.kubernetes.io/managed-by=keyorix-sync` label, so cleanup
  only ever lists/deletes Secrets the agent created and only in namespaces still in the
  config. A still-desired target survives a fetch failure, so a transient upstream error
  can't delete a live Secret. Adds a `deleted` outcome to the log line, `/status`, and the
  metrics; chart RBAC gains `list`/`delete`. (ADR-057) ([#426])
- **External Secrets Operator integration** — read Keyorix secrets into native Kubernetes
  Secrets through ESO's generic **Webhook** provider — no custom controller. Ships
  `deploy/eso/` manifests (`ClusterSecretStore`, `ExternalSecret`, token template) and a
  `docs/k8s-eso.md` guide. Reads go through Keyorix's scoped `secrets.read`, `max_reads`,
  suspension, and audit. ([#426])
- **Kubernetes dynamic secrets** — a `kubernetes` dynamic-secret backend that mints
  short-lived ServiceAccount tokens via the TokenRequest API (dependency-free `net/http`;
  in-cluster or explicit `api_server` config). Ephemeral like AWS STS / GCP — native
  expiry, `Revoke` is a no-op, `Renew` refused. (ADR-058) ([#426])
- **By-reference secret read** — `GET /api/v1/secrets/value?ref=project/environment/name`
  returns a secret's value by a human-readable reference (used by ESO and the operator),
  reusing the exact by-id read path: a scope resolver feeds the standard scoped
  `secrets.read` gate and the value is read through the same `max_reads` / suspension /
  audit machinery. The three-level reference is unambiguous (project names are globally
  unique). (ADR-059) ([#426])
- **Kubernetes operator (KeyorixSecret CRD)** — a `controller-runtime` operator that
  reconciles `KeyorixSecret` resources (`secrets.keyorix.io/v1alpha1`) into native
  Kubernetes Secrets and keeps them current — the native, `kubectl apply`-able delivery
  model alongside the sync agent and ESO. The target Secret is owned by the CR, so
  deleting it garbage-collects the Secret. Lives in its own Go module (`operator/`) so
  `controller-runtime`/`client-go` stay out of the server/CLI build; ships a Helm chart
  (`deploy/helm/keyorix-operator`) and a distroless image. (ADR-060) ([#429])
- **Time-bound secret shares** — a share can be given an expiry so access auto-lapses
  without manual revocation. ([#428])

### Fixed
- **Real version in container images** — the published images now embed the actual
  release version and commit (`VERSION`/`GIT_COMMIT` build args), so `keyorix --version`
  reports the tag from inside an image rather than `dev`. ([#427])

[#426]: https://github.com/keyorixhq/keyorix/pull/426
[#427]: https://github.com/keyorixhq/keyorix/pull/427
[#428]: https://github.com/keyorixhq/keyorix/pull/428
[#429]: https://github.com/keyorixhq/keyorix/pull/429

## v0.76.0 — 2026-06-23

Certificate lifecycle hardening — expiry monitoring and a hygiene control in the
compliance posture — rotation-plan parity across CLI and gRPC, and per-scheduler
health metrics for the background jobs.

### Added
- **Certificate-expiry monitoring** — an opt-in background scan (`certificate_expiry`)
  that parses certificate-typed secrets and notifies project admins of certificates
  **expired or expiring** within the lead window, using the certificate's *real*
  `notAfter` (ADR-054 parser) rather than the manual `expiration` field. Prevents the
  classic silent cert lapse / outage. One de-duplicated standing reminder per project,
  single-replica-gated. The scan reads cert values to extract only the expiry — never
  the value or private key, skips suspended secrets, doesn't count against `max_reads`.
  Default off. (ADR-055) ([#419])
- **CLI for the rotation plan** — `keyorix rotation plan <project-id>` prints a
  project's automated rotation plan (ADR-053) in the terminal: overdue/due-soon secrets
  batched into dependency-safe waves, most urgent first, each annotated with why it's
  due and what it must rotate after. Thin REST client over the existing endpoint.
  ([#420])
- **Certificate hygiene in the compliance posture** — the control matrix gains a
  **Certificate expiry hygiene** control (a gap when any certificate is expired; mapped
  to ISO 27001 / SOC 2 / NIS2 / ENS `op.exp.11`) plus a `certificates` posture figure
  (expired / expiring-soon / total / not-yet-evaluated). Fed by a cached cert `notAfter`
  (`SecretNode.cert_not_after`) populated as a side-effect of certificate inspection and
  the expiry scan — so the posture reports hygiene without decrypting on the dashboard
  path and without touching the create/rotate path. (ADR-056) ([#421])
- **gRPC for the rotation plan** — `ProjectService.GetProjectRotationPlan` exposes the
  automated rotation plan (ADR-053) over gRPC (read-only, scoped `secrets.read`),
  completing its surface parity with HTTP / CLI / web. ([#422])
- **Per-scheduler health metrics** — the ~14 background schedulers (anomaly detection,
  retention purge, auto-rotation, certificate-expiry scan, audit checkpoints, …) each
  export their outcome to Prometheus: `keyorix_scheduler_runs_total{scheduler,outcome}`
  (success / failure / **skipped**), a run-duration histogram, and last-run /
  last-success timestamp gauges, on the same `/metrics` endpoint. `skipped` (an HA
  follower not holding the single-writer lock, or a legal-hold stand-down) is tracked
  distinctly from `failure` so a follower replica never reads as broken — alert on
  `time() - keyorix_scheduler_last_success_timestamp_seconds{...}`. ([#423])

[#419]: https://github.com/keyorixhq/keyorix/pull/419
[#420]: https://github.com/keyorixhq/keyorix/pull/420
[#421]: https://github.com/keyorixhq/keyorix/pull/421
[#422]: https://github.com/keyorixhq/keyorix/pull/422
[#423]: https://github.com/keyorixhq/keyorix/pull/423

## v0.75.0 — 2026-06-23

A large security release: anomaly-detection ML, ENS compliance mapping, the full
secret dependency graph (tracking, impact, rotation order) across HTTP/CLI/gRPC/UI,
automated rotation planning, certificate inspection, plus observability and CLI parity.

### Added
- **Automated rotation planning** — `GET /api/v1/projects/{id}/rotation-plan` composes
  rotation status, secret risk, and the dependency graph (ADR-052) into an ordered,
  dependency-respecting **plan**: the project's overdue/due-soon secrets, batched into
  parallel-safe **waves** (each secret rotates after anything it depends on) and
  prioritised by **urgency** within a wave (overdue beats due-soon; more days past due +
  higher risk rank higher). Each entry carries human-readable reasons ("30 days
  overdue", "high risk", "rotate after db-password"). Deterministic and explainable —
  appropriate for an air-gapped security operation; an LLM advisor can later sit on top
  of the structured plan. (ADR-053) ([#413])
- **CLI for the secret dependency graph** — `keyorix secret deps list|add|rm|impact`
  and `keyorix rotation order <project-id>` bring the ADR-052 dependency graph to the
  terminal: declare/list/remove edges, see a secret's rotation blast radius, and print
  a project's safe rotation order. Thin REST clients over the existing endpoints,
  scoped server-side. ([#414])
- **gRPC surface for the secret dependency graph** — `SecretService.ListSecretDependencies`
  / `GetSecretImpact` and `ProjectService.GetProjectRotationOrder` expose the ADR-052
  dependency graph over gRPC (read-only), mirroring the HTTP/CLI surfaces with the same
  scoped `secrets.read` authorization. ([#415])
- **Certificate inspection** — `GET /api/v1/secrets/{id}/certificate` and
  `keyorix secret cert <id>` parse a certificate-valued secret's leaf X.509 cert and
  return its **public** metadata (subject, issuer, real `notAfter`/expiry, SANs, is-CA,
  self-signed, algorithms) for PKI hygiene. Never returns the value or any private key
  (only `CERTIFICATE` blocks are parsed), does **not** count against `max_reads`,
  respects suspension, and is audited (`secret.certificate_inspected`). Scoped
  `secrets.read`. (ADR-054) ([#416])
- **ML anomaly detection (Isolation Forest)** — an opt-in machine-learning pass that
  complements the existing rule-based access-anomaly detection. Each scan trains a
  per-secret Isolation Forest on the secret's 30-day access baseline and flags
  accesses whose joint pattern (hour, IP rarity, user rarity) is a multivariate
  outlier — catching what the binary rules miss: a **known-but-rare** actor or IP, and
  **combinations** that are unremarkable signal-by-signal. Pure-Go, no new
  dependencies; metadata only (no secret value is examined); deterministic (seeded).
  Flagged accesses emit an `ml_outlier` alert through the existing alert pipeline.
  Config-gated under `anomaly_alerts.ml` (default off). (ADR-050) ([#410])
- **ENS in the compliance control matrix** — every control in the live control matrix
  (`GET /api/v1/compliance/controls`, gRPC, and the `compliance-controls.csv` auditor
  export) now carries an `ens` reference to its Spanish *Esquema Nacional de Seguridad*
  (RD 311/2022) measure (`op.acc.*` / `op.exp.*` / `mp.info.*` / …) alongside ISO 27001
  / SOC 2 / NIS2 / DORA, with the same live pass/gap/not-configured status. Lets an ENS
  auditor pull the secret-management control set mapped to RD 311/2022 with its current
  state. Mappings are consistent with `docs/compliance/ENS-CONTROLS.md`. (ADR-051) ([#411])
- **Secret dependency tracking** — declare that one secret depends on another (e.g. an
  app token derived from a DB password, or a cert chain) and Keyorix maintains the
  per-project dependency graph. Answers two questions before a rotation: **impact /
  blast radius** (`GET /api/v1/secrets/{id}/impact` — the transitive dependents that
  break if you rotate it) and **rotation order** (`GET /api/v1/projects/{id}/rotation-order`
  — a safe sequence where each secret precedes anything depending on it). Manage edges
  via `GET/POST /secrets/{id}/dependencies` + `DELETE /secrets/{id}/dependencies/{depId}`,
  gated by scoped `secrets.read`/`secrets.write` and audited. Edges are confined to a
  single project + environment (matching Keyorix's environment-granular authorization)
  and the graph is kept acyclic (self-edges, duplicates, cross-project/-environment, and
  cycles are rejected). Metadata only — no secret value is read. This is the
  prerequisite for automated rotation planning; the topological order is the
  deterministic core of that. (ADR-052) ([#412])
- **gRPC metrics on `/metrics`** — gRPC request volume, outcomes, and cumulative
  handler time are now exported to Prometheus (`keyorix_grpc_requests_total{status}`
  and `keyorix_grpc_request_duration_seconds_total`) on the same endpoint as the
  HTTP metrics, instead of being reachable only via an authenticated RPC. ([#407])
- **CLI for dynamic-secret config classification and inspection** —
  `keyorix dynamic-secret get-config <id>` shows a single config (backend, TTLs,
  classification) and `keyorix dynamic-secret classify <id> --level <level>` sets
  its classification, matching the HTTP/gRPC surfaces. ([#408])

[#407]: https://github.com/keyorixhq/keyorix/pull/407
[#408]: https://github.com/keyorixhq/keyorix/pull/408
[#410]: https://github.com/keyorixhq/keyorix/pull/410
[#411]: https://github.com/keyorixhq/keyorix/pull/411
[#412]: https://github.com/keyorixhq/keyorix/pull/412
[#413]: https://github.com/keyorixhq/keyorix/pull/413
[#414]: https://github.com/keyorixhq/keyorix/pull/414
[#415]: https://github.com/keyorixhq/keyorix/pull/415
[#416]: https://github.com/keyorixhq/keyorix/pull/416

## v0.74.0 — 2026-06-22

Group lifecycle, audit completeness, and a few correctness fixes.

### Added
- **Groups can be soft-deleted and restored** — `DELETE /api/v1/groups/{id}` now
  soft-deletes (reversible) and `POST /api/v1/groups/{id}/restore` brings the
  group back with its prior role grants and memberships. A soft-deleted group
  authorizes nothing (role inheritance and group shares both exclude it), and its
  name is freed for reuse via a partial unique index. Audited as `group.deleted` /
  `group.restored`. ([#405])
- **Restore operations are audited** — restoring a secret, project, or environment
  now records `secret.restored` / `project.restored` / `environment.restored`, the
  inverse of the delete events. ([#402])

### Fixed
- **A secret's share list excludes expired shares** — `ListSecretShares` returned
  expired time-bound shares that no longer authorized, disagreeing with
  enforcement; it now filters them like every authorization path. ([#403])
- **Description length is bounded** — project, group, and rotation-policy
  descriptions are now capped (like secret descriptions) at the create/update
  choke points. ([#404])

[#402]: https://github.com/keyorixhq/keyorix/pull/402
[#403]: https://github.com/keyorixhq/keyorix/pull/403
[#404]: https://github.com/keyorixhq/keyorix/pull/404
[#405]: https://github.com/keyorixhq/keyorix/pull/405

## v0.73.1 — 2026-06-22

Security fix.

### Fixed
- **max_reads is now enforced atomically** — a limited-use secret could be read
  more than its `max_reads` cap under concurrent requests (a check-then-act race),
  and a storage error on the read-counter update failed open. Reads are now gated
  by a single atomic conditional update and fail closed, so concurrent reads can
  never collectively exceed the cap. ([#400])

[#400]: https://github.com/keyorixhq/keyorix/pull/400

## v0.73.0 — 2026-06-21

Complete audit coverage for governance mutations.

### Added
- **Role-definition changes are audited** — creating, updating, or deleting a role
  now records `role.created` / `role.updated` / `role.deleted` in the RBAC audit
  log, closing a gap where role definitions (which control what privileges exist)
  changed without a trace, even though role assignments were already audited.
  ([#396])
- **Group changes are audited** — `group.created` / `group.updated` /
  `group.deleted` on the API/CLI path, matching the SCIM provisioning path which
  already audited. ([#397])
- **Rotation-policy changes are audited** — `rotation_policy.created` /
  `.updated` / `.deleted`, so changes to a policy's rotation/compliance posture
  for its covered secrets are traceable. ([#398])

[#396]: https://github.com/keyorixhq/keyorix/pull/396
[#397]: https://github.com/keyorixhq/keyorix/pull/397
[#398]: https://github.com/keyorixhq/keyorix/pull/398

## v0.72.0 — 2026-06-21

Access visibility and operator controls over HTTP.

### Added
- **Group access visibility** — `GET /api/v1/groups/{id}/shared-secrets` lists the
  live secrets a group can reach via shares (skipping expired time-bound shares),
  the group counterpart to the per-user permissions view. ([#392])
- **User→machine migration over HTTP** —
  `POST /api/v1/projects/{id}/machine-identities/migrate-from-user` converts a
  service-account-shaped human user into a project machine identity and (unless
  `keep_user` is set) suspends the source user, so the conversion can be driven
  from automation or the dashboard, not just the CLI. Requires `roles.assign`
  (project) and `users.write`. ([#393])
- **On-demand job triggers** — a new `/api/v1/admin/jobs` group (`system.write`)
  dispatches the scheduled notification/alert jobs immediately instead of waiting
  for the next tick: `anomaly-alerts`, `rotation-reminders`,
  `expiry-reminders?lead_days=N`, and `compliance-digest`. ([#394])

[#392]: https://github.com/keyorixhq/keyorix/pull/392
[#393]: https://github.com/keyorixhq/keyorix/pull/393
[#394]: https://github.com/keyorixhq/keyorix/pull/394

## v0.71.0 — 2026-06-21

Just-in-time access, RBAC visibility, and naming-policy remediation.

### Added
- **Time-bound (JIT) role grants** — assigning a role now accepts an optional
  `expires_at`, so a grant can expire automatically instead of becoming standing
  privilege (emergency / contractor / on-call access). Works for users
  (`POST /api/v1/user-roles`) and groups (`POST /api/v1/groups/{id}/roles`); a
  set expiry must be in the future, persists on the grant, and is swept and
  audited by the existing JIT scheduler. CLI: `keyorix rbac assign-role --ttl 4h`.
  The group-roles response now carries each grant's expiry so clients can show
  remaining time. ([#387], [#388])
- **Bulk rename toward naming-policy conformance** —
  `POST /api/v1/projects/{id}/secrets/bulk-rename` renames policy-violating
  secrets in one call (the remediation for the name-conformance report). Each new
  name must satisfy the policy and not collide; a dry run reports what would
  change without touching anything; every rename is audited and never reveals a
  value. CLI: `keyorix secret bulk-rename` (dry-run by default; `--apply` to
  rename). ([#386])
- **User effective permissions** — `GET /api/v1/users/{id}/permissions` returns
  the de-duplicated permission set across a user's roles (excluding expired
  time-bound grants) — the "what can this user do" view for dashboards and access
  reviews. ([#389])
- **Custom environments on project create** — `POST /api/v1/projects` accepts an
  optional `environments` list to seed exactly those instead of the default
  development/staging/production set, for one-call infrastructure-as-code
  provisioning. ([#390])

### Fixed
- **CLI `project create --envs` honored in remote mode** — the flag posted a
  field the server ignored, so against a server the custom environments were
  silently dropped and the project got the default set. The CLI now sends the
  field the handler reads. ([#390])

[#386]: https://github.com/keyorixhq/keyorix/pull/386
[#387]: https://github.com/keyorixhq/keyorix/pull/387
[#388]: https://github.com/keyorixhq/keyorix/pull/388
[#389]: https://github.com/keyorixhq/keyorix/pull/389
[#390]: https://github.com/keyorixhq/keyorix/pull/390

## v0.70.0 — 2026-06-21

Per-secret usage visibility, and CLI commands that finally honor the configured
storage backend.

### Added
- **Per-secret read statistics** — `GET /api/v1/secrets/{id}/stats?days=N`
  returns a focused per-secret usage view: the durable lifetime read total and
  version count, plus a configurable recent window (reads, unique readers, last
  read time). Answers "is this secret actually used, and by whom lately?" in one
  scoped (`secrets.read`) call, beside `/{id}/access-log` and `/{id}/risk`, and
  never reveals the value. ([#382])

### Fixed
- **CLI commands honor `storage.type`** — ~17 `rbac`, `secret`, `share`, and
  `encryption` subcommands opened the database directly and hardwired SQLite, so
  against a Postgres deployment they silently operated on a stray local
  `secrets.db` instead of the real store. They now obtain storage through the
  factory (or a `*gorm.DB` helper that honors `storage.type`), so every command
  talks to the configured backend; SQLite stays supported for embedded/air-gapped
  use. ([#383])

[#382]: https://github.com/keyorixhq/keyorix/pull/382
[#383]: https://github.com/keyorixhq/keyorix/pull/383

## v0.69.0 — 2026-06-21

Operability: a real readiness probe and honest build identity.

### Added
- **Readiness probe** — `GET /readyz` verifies the database is reachable (200
  ready / 503 not-ready), so Kubernetes stops routing to a replica whose database
  is down and restores it on recovery. The Helm chart's readiness probe now
  targets `/readyz`; the liveness probe stays on `/health` (liveness must not
  depend on the database). ([#378])
- **`keyorix system info`** — a CLI command that shows the connected server's
  version, commit, runtime, uptime, and feature/security configuration. ([#380])

### Changed
- **Honest build identity** — `/health` and `/system/info` now report the real
  build version and commit (injected at build time) instead of hardcoded
  placeholders, and `/health` is a lightweight liveness signal that no longer
  fabricates dependency-health claims. ([#379])

[#378]: https://github.com/keyorixhq/keyorix/pull/378
[#379]: https://github.com/keyorixhq/keyorix/pull/379
[#380]: https://github.com/keyorixhq/keyorix/pull/380

## v0.68.0 — 2026-06-20

Compliance read surface: an on-demand digest and a control-matrix export.

### Added
- **On-demand compliance digest** — `GET /compliance/digest` returns the
  human-readable compliance summary (controls pass/gap, overdue recertifications,
  rotation gaps, unclassified secrets, open anomalies, risk exceptions, legal
  hold) that is otherwise broadcast to the notification channels on a schedule,
  so an admin can pull a point-in-time report; shown with a copy button on the
  Compliance page. ([#375])
- **Control-matrix CSV export** — `GET /compliance/controls.csv` downloads the
  control matrix (each control mapped to ISO 27001 / SOC 2 / NIS2 / DORA clauses
  with its live pass/gap status) for an auditor's spreadsheet, with a download
  button on the Compliance page. Completes the compliance-export family beside
  the audit-log, asset-inventory, and access-recertification CSVs. ([#376])

[#375]: https://github.com/keyorixhq/keyorix/pull/375
[#376]: https://github.com/keyorixhq/keyorix/pull/376

## v0.67.0 — 2026-06-20

Secret-name governance and an access-recertification export.

### Added
- **Secret naming-policy conformance** — the optional naming policy is enforced
  only at create time, so this surfaces existing secrets whose names violate the
  current policy (e.g. after it's added or tightened), per project
  (`GET /projects/{id}/secrets/name-conformance`, `keyorix secret
  name-conformance --project <id>`) and deployment-wide
  (`GET /secrets/name-conformance`, the same CLI command with `--project`
  omitted), with web panels on Project Settings and the Admin page. Each
  violation carries the exact reason create-time enforcement would give.
  ([#371], [#372])
- **Access-review campaign CSV export** — download a recertification campaign
  (ISO 27001 A.5.18) as a CSV record of every reviewed grant and its
  attest/revoke decision, for an auditor to archive
  (`GET /projects/{id}/access-review/campaigns/{campaignId}/export.csv`).
  Extends the compliance-export family beside the audit-log and asset-inventory
  CSVs. ([#373])

[#371]: https://github.com/keyorixhq/keyorix/pull/371
[#372]: https://github.com/keyorixhq/keyorix/pull/372
[#373]: https://github.com/keyorixhq/keyorix/pull/373

## v0.66.0 — 2026-06-20

Bulk environment promotion, deployment-wide hygiene, and a secret asset register.

### Added
- **Bulk environment promotion** — copy all of an environment's secrets into
  another environment in one call
  (`POST /projects/{id}/environments/{envId}/copy-secrets` and
  `keyorix secret copy-environment`), instead of promoting each secret by hand.
  ([#363], [#364])
- **Deployment-wide secret-hygiene rollup** — `GET /hygiene` (and
  `keyorix hygiene`) aggregate every project's hygiene posture
  (orphaned / recycle-bin / expiring / rotation-overdue counts) into a single
  deployment-wide view for admins. ([#365], [#366])
- **Secret asset inventory (CSV)** — a metadata-only asset register for auditors
  (ISO 27001 A.5.9): `GET /projects/{id}/secrets/inventory.csv` per project and
  `GET /secrets/inventory.csv` org-wide, exported from the web UI. Lists every
  live secret's metadata (name, environment, type, classification, owner,
  timestamps) and never reads or returns a value. ([#367], [#369])
- **Bulk-renew expiring secrets** — `POST /projects/{id}/secrets/extend-expiring`
  pushes the expiration of all soon-to-expire secrets out to a new window
  (default 90 days), surfaced as an "Extend all" button on the project's
  expiring-secrets panel. Only ever extends, never shortens. ([#368])

[#363]: https://github.com/keyorixhq/keyorix/pull/363
[#364]: https://github.com/keyorixhq/keyorix/pull/364
[#365]: https://github.com/keyorixhq/keyorix/pull/365
[#366]: https://github.com/keyorixhq/keyorix/pull/366
[#367]: https://github.com/keyorixhq/keyorix/pull/367
[#368]: https://github.com/keyorixhq/keyorix/pull/368
[#369]: https://github.com/keyorixhq/keyorix/pull/369

## v0.65.0 — 2026-06-19

Secret naming governance, machine-token hygiene, and richer search.

### Added
- **Secret naming policy** — an optional, operator-configured naming convention
  (regex + max length) enforced at create, plus `GET /secrets/policy` so clients
  can show the convention and pre-validate (surfaced as a hint in the web create
  form). Off by default. ([#357], [#358])
- **Machine-token hygiene** — `GET /machine-token-hygiene` (and
  `keyorix machine token-hygiene`) surface deployment-wide machine credentials
  that are expired-but-active or stale, with an admin web panel — completing
  credential hygiene across PATs, sessions, and machine tokens. ([#359], [#360])
- **Rotation-overdue in the project hygiene summary** — secrets past their
  rotation policy's interval are now counted in `GET /projects/{id}/hygiene`
  (and the CLI / web posture card). ([#356])
- **Richer secret search** — the secret list `?search=` now matches a secret's
  description and tags, not just its name. ([#361])

[#356]: https://github.com/keyorixhq/keyorix/pull/356
[#357]: https://github.com/keyorixhq/keyorix/pull/357
[#358]: https://github.com/keyorixhq/keyorix/pull/358
[#359]: https://github.com/keyorixhq/keyorix/pull/359
[#360]: https://github.com/keyorixhq/keyorix/pull/360
[#361]: https://github.com/keyorixhq/keyorix/pull/361

## v0.64.0 — 2026-06-19

Audit CSV export, access-change notifications, and secret promote/copy.

### Added
- **Audit log CSV export** — `GET /audit/export.csv` (and `keyorix audit export --csv`)
  download audit events as CSV for compliance hand-off, distinct from the JSON
  SIEM feed. ([#345], [#346])
- **Access-change notifications** — the affected user is now notified when a secret
  is shared with them, when ownership is transferred to them (with a single summary
  for bulk reassignment), and when their share is revoked — fanned out to group
  members for group shares. ([#347], [#348], [#349], [#350])
- **Copy a secret to another environment** — `POST /secrets/{id}/copy` (and
  `keyorix secret copy`) promote a secret's value and metadata into another
  environment of the same project (e.g. staging → production), with two-sided
  authorization. ([#353], [#354])
- **`keyorix secret expiring`** — list a project's expiring/expired secrets for
  renewal triage. ([#351])
- **`keyorix secret info`** — one-shot secret metadata summary (no value). ([#352])

[#345]: https://github.com/keyorixhq/keyorix/pull/345
[#346]: https://github.com/keyorixhq/keyorix/pull/346
[#347]: https://github.com/keyorixhq/keyorix/pull/347
[#348]: https://github.com/keyorixhq/keyorix/pull/348
[#349]: https://github.com/keyorixhq/keyorix/pull/349
[#350]: https://github.com/keyorixhq/keyorix/pull/350
[#351]: https://github.com/keyorixhq/keyorix/pull/351
[#352]: https://github.com/keyorixhq/keyorix/pull/352
[#353]: https://github.com/keyorixhq/keyorix/pull/353
[#354]: https://github.com/keyorixhq/keyorix/pull/354

## v0.63.0 — 2026-06-19

Secret descriptions and hygiene triage.

### Added
- **Secret description** — a free-text note on a secret (what it's for, its
  upstream, who to contact): settable at creation and via
  `PATCH /secrets/{id}/description`, plus `keyorix secret create --description`,
  `keyorix secret description`, and a description editor on the web detail view. ([#341], [#342])
- **List a project's expiring secrets** — `GET /projects/{id}/secrets/expiring?days=N`
  lists secrets expiring (or already expired) within the window, soonest-first,
  making the hygiene summary's expiring count actionable for renewal triage. ([#343])
- **CLI `project hygiene`** — `keyorix project hygiene <id>` prints a project's
  cleanup counts (orphaned / unused / expiring secrets, stale machine identities). ([#340])

[#340]: https://github.com/keyorixhq/keyorix/pull/340
[#341]: https://github.com/keyorixhq/keyorix/pull/341
[#342]: https://github.com/keyorixhq/keyorix/pull/342
[#343]: https://github.com/keyorixhq/keyorix/pull/343

## v0.62.0 — 2026-06-19

Secret tags and a project hygiene summary.

### Added
- **Secret tags** — free-form labels on a secret: `GET`/`PUT /secrets/{id}/tags`
  (normalized: trimmed, lowercased, de-duplicated, ≤20 tags, ≤50 chars), plus
  `keyorix secret tags --id N [--set a,b]` and a tag editor on the web secret
  detail view. ([#335], [#337])
- **Filter secrets by tag** — `GET /secrets?tag=prod&tag=tier1` (or
  `?tag=prod,tier1`) returns only secrets carrying every requested tag (AND). ([#336])
- **Project hygiene summary** — `GET /projects/{id}/hygiene` returns one-call
  counts of the project's outstanding cleanup signals (orphaned, unused, and
  expiring secrets; stale machine identities) for an at-a-glance posture. ([#338])

[#335]: https://github.com/keyorixhq/keyorix/pull/335
[#336]: https://github.com/keyorixhq/keyorix/pull/336
[#337]: https://github.com/keyorixhq/keyorix/pull/337
[#338]: https://github.com/keyorixhq/keyorix/pull/338

## v0.61.0 — 2026-06-18

Offboarding & incident response: cut off a departing or compromised user across
all three credential types they hold — owned secrets, personal access tokens, and
live sessions.

### Added
- **Orphaned-secret detection** — `GET /projects/{id}/secrets/orphaned` lists a
  project's secrets whose owner is no longer a live user (offboarding), plus
  `keyorix secret orphaned` and a project-settings alert in the web UI. ([#326], [#327])
- **Bulk owner reassignment** — `POST /projects/{id}/secrets/reassign-owner`
  re-homes every secret a departed user owned to a new owner in one call (each
  re-authorized and audited individually), plus `keyorix secret reassign-owner`
  and a per-former-owner "Reassign all" web action. ([#328], [#329])
- **Personal-access-token hygiene** — `GET /pat-hygiene?days=N` surfaces the
  deployment-wide non-revoked tokens that are expired-but-active or stale (token
  sprawl), plus `keyorix pat hygiene` and an admin web panel. ([#330], [#331])
- **Admin force-logout** — `POST /users/{id}/revoke-sessions` terminates all of a
  user's active sessions without changing their account state (suspected session/
  token theft), plus `keyorix user revoke-sessions` and a "Force log out" action
  on the user detail page. ([#332], [#333])

[#326]: https://github.com/keyorixhq/keyorix/pull/326
[#327]: https://github.com/keyorixhq/keyorix/pull/327
[#328]: https://github.com/keyorixhq/keyorix/pull/328
[#329]: https://github.com/keyorixhq/keyorix/pull/329
[#330]: https://github.com/keyorixhq/keyorix/pull/330
[#331]: https://github.com/keyorixhq/keyorix/pull/331
[#332]: https://github.com/keyorixhq/keyorix/pull/332
[#333]: https://github.com/keyorixhq/keyorix/pull/333

## v0.60.0 — 2026-06-18

Secret audit trail and a recycle bin for deleted secrets.

### Added
- **Per-secret audit trail** — `GET /secrets/{id}/audit?limit=N` lists a secret's
  lifecycle events (created, rotated, rolled-back, suspended/resumed, shared,
  owner-transferred, reclassified) newest-first, completing the investigation triad
  alongside the access inspector and access history. Metadata only — never a value. ([#321])
- **CLI `secret audit`** — `keyorix secret audit --id <id> [--limit N]` prints a
  secret's lifecycle events. ([#322])
- **Recycle bin** — `GET /projects/{id}/secrets/deleted?limit=N` lists a project's
  soft-deleted (restorable) secrets, newest-deleted first, so an operator can find
  what to restore (the existing restore route needs the secret's ID). ([#323])
- **CLI `secret trash` / `secret restore`** — `keyorix secret trash --project <id>`
  lists restorable secrets and `keyorix secret restore --id <id>` brings one back. ([#324])

[#321]: https://github.com/keyorixhq/keyorix/pull/321
[#322]: https://github.com/keyorixhq/keyorix/pull/322
[#323]: https://github.com/keyorixhq/keyorix/pull/323
[#324]: https://github.com/keyorixhq/keyorix/pull/324

## v0.59.0 — 2026-06-18

Secret investigation, project-wide incident response, and machine-identity hygiene.

### Added
- **Per-secret access history** — `GET /secrets/{id}/access-log?days=N` lists who has
  read a secret recently (accessor, IP, time), complementing the access inspector. ([#316])
- **Project-wide suspend / resume** — `POST /projects/{id}/secrets/suspend-all` and
  `/resume-all` freeze or restore value reads of every secret in a project (breach
  response). ([#317])
- **CLI investigation commands** — `keyorix secret access` (who can read) and
  `keyorix secret access-log` (who has read). ([#318])
- **Stale machine-identity detection** — `GET /projects/{id}/machine-identities/stale?days=N`
  surfaces active machine identities not authenticated within the window — abandoned
  credentials to revoke. ([#319])

[#316]: https://github.com/keyorixhq/keyorix/pull/316
[#317]: https://github.com/keyorixhq/keyorix/pull/317
[#318]: https://github.com/keyorixhq/keyorix/pull/318
[#319]: https://github.com/keyorixhq/keyorix/pull/319

## v0.58.0 — 2026-06-18

Incident response: suspend/resume a secret.

### Added
- **Suspend / resume a secret** — freeze value reads of a suspected-compromised
  secret without deleting it (versions, shares, and audit trail are preserved);
  reversible. A suspended secret refuses reads on every value path, even for the
  owner, while metadata/listing/management stay available. `POST /secrets/{id}/suspend`
  (optional reason) and `/resume` (scoped `secrets.write`, audited
  `secret.suspended` / `secret.resumed`), plus `keyorix secret suspend|resume`. ([#313], [#314])

### Fixed
- The secret-value quality policy is now enforced on `UpdateSecret` too, not just
  create and rotate — closing a path where a weak value could be set via update. ([#312])

[#312]: https://github.com/keyorixhq/keyorix/pull/312
[#313]: https://github.com/keyorixhq/keyorix/pull/313
[#314]: https://github.com/keyorixhq/keyorix/pull/314

## v0.57.0 — 2026-06-18

Secret governance: ownership transfer, value policy, access inspector, HTTP render.

### Added
- **Secret ownership transfer** — hand a secret to another user (recover orphaned
  secrets when an owner leaves). The current owner can transfer; an authorized caller
  can recover a secret whose owner is gone (the lookup fails closed on a transient
  error, so an active owner's secret can't be taken). `POST /secrets/{id}/transfer-ownership`,
  audited `secret.owner_transferred`. ([#307])
- **Secret-value quality policy** — an opt-in (off-by-default) gate that rejects weak/
  placeholder values (`changeme`, too-short, a configurable denylist) at create and
  rotate. The rejection reason never echoes the value. ([#309])
- **"Who can access" inspector** — `GET /secrets/{id}/access` lists every user who can
  read a secret (owner + direct + group shares, members expanded; expired shares
  excluded), for least-privilege review. ([#310])
- **HTTP template render** — `POST /projects/{id}/secrets/render` expands
  `${secret:<environment>/<name>}` references within a project, resolving only the
  caller's readable secrets. ([#306])

### Fixed
- Corrected an integration test's assertion against the paginated `/shares` response
  shape introduced in v0.54.0. ([#308])

[#306]: https://github.com/keyorixhq/keyorix/pull/306
[#307]: https://github.com/keyorixhq/keyorix/pull/307
[#308]: https://github.com/keyorixhq/keyorix/pull/308
[#309]: https://github.com/keyorixhq/keyorix/pull/309
[#310]: https://github.com/keyorixhq/keyorix/pull/310

## v0.56.0 — 2026-06-17

Secret templating: render config/`.env` files from live secrets.

### Added
- **Secret-reference templating** — a template can embed `${secret:<environment>/<name>}`
  placeholders that expand to a secret's current value (`$$` escapes a literal `$`).
  `keyorix secret render <template>` renders a file (or stdin) to stdout or `--output`,
  resolving only the secrets the caller can read and failing without partial output on a
  missing/forbidden reference — handy for generating a `.env` or config file. ([#303], [#304])

[#303]: https://github.com/keyorixhq/keyorix/pull/303
[#304]: https://github.com/keyorixhq/keyorix/pull/304

## v0.55.0 — 2026-06-17

Kubernetes sync agent: observability + distribution.

### Added
- **Prometheus metrics** — the sync agent serves `/metrics` (reconcile passes,
  per-outcome Secret counts, last-run timestamp, last-failed gauge); the Helm chart
  adds `prometheus.io/scrape` pod annotations. ([#301])
- **Agent Helm chart published to GHCR** — `keyorix-k8s-sync` is now pushed to
  `oci://ghcr.io/keyorixhq/charts/keyorix-k8s-sync` on release, so it can be installed
  with `helm install … oci://…` rather than only from a repo checkout. ([#300])

[#300]: https://github.com/keyorixhq/keyorix/pull/300
[#301]: https://github.com/keyorixhq/keyorix/pull/301

## v0.54.0 — 2026-06-17

Kubernetes integration: sync Keyorix secrets into native Kubernetes Secrets.

### Added
- **Kubernetes sync agent** (`keyorix-k8s-sync`) — a small in-cluster agent that
  materialises selected Keyorix secrets into native Kubernetes Secrets and refreshes
  them as the upstream values rotate. It authenticates to Keyorix with a
  machine-identity token and writes Secrets via the Kubernetes API (Server-Side Apply)
  using its service-account credentials — **no `client-go` dependency**. A reconcile
  creates/updates a target Secret only when its data changes and never writes a Secret
  partially if any value fails to fetch. ([#291], [#292], [#293], [#294])
- **Agent container image** — published to `ghcr.io/keyorixhq/keyorix-k8s-sync`
  alongside the server image. ([#295])
- **Helm chart** (`deploy/helm/keyorix-k8s-sync`) — deploys the agent with
  least-privilege RBAC (a `RoleBinding` to a `secrets` `get`/`create`/`patch`
  `ClusterRole` per target namespace), config, and the token sourced from an existing
  Secret. ([#296])
- **Health & probes** — the agent serves `/healthz`, `/readyz` (gated on the first
  successful reconcile), and `/status`; the chart wires liveness/readiness probes. ([#297])
- **`-once` and `-dry-run` modes** — run a single reconcile (a CI gate / Kubernetes
  `Job`; non-zero exit on failure) and preview what would change without writing. ([#298])

[#291]: https://github.com/keyorixhq/keyorix/pull/291
[#292]: https://github.com/keyorixhq/keyorix/pull/292
[#293]: https://github.com/keyorixhq/keyorix/pull/293
[#294]: https://github.com/keyorixhq/keyorix/pull/294
[#295]: https://github.com/keyorixhq/keyorix/pull/295
[#296]: https://github.com/keyorixhq/keyorix/pull/296
[#297]: https://github.com/keyorixhq/keyorix/pull/297
[#298]: https://github.com/keyorixhq/keyorix/pull/298

## v0.53.0 — 2026-06-17

Access-anomaly detection and secret-sharing lifecycle improvements.

### Added
- **Anomaly frequency-spike detection** — the access-anomaly detector now emits a
  `frequency_spike` alert when a secret's read count in the detection window clears an
  absolute floor and exceeds a multiple of its learned hourly baseline (activating the
  previously-computed-but-unused baseline). ([#286])
- **Anomaly alert filtering** — `GET /anomalies` accepts `?severity` and `?alertType`
  filters (AND-combined); the web alerts table gains an alert-type filter and renders
  humanized type labels. ([#289])
- **Editable share expiry** — `PUT /shares/{id}` accepts `expires_at` / `clear_expiry`
  so a time-bound share can be extended, shortened, or made permanent after creation;
  omitting both preserves the current expiry. ([#287])

### Fixed
- **`GET /shares` returns a proper paginated DTO** — the endpoint now returns shares
  with resolved recipient/creator names, the expiry, and `{data, total, page, pageSize,
  totalPages}` (with `?secretId` / `?recipientType` filters), instead of raw models —
  repairing the Sharing Management page, which rendered empty against a real backend. ([#288])

[#286]: https://github.com/keyorixhq/keyorix/pull/286
[#287]: https://github.com/keyorixhq/keyorix/pull/287
[#288]: https://github.com/keyorixhq/keyorix/pull/288
[#289]: https://github.com/keyorixhq/keyorix/pull/289

## v0.52.0 — 2026-06-17

Secret lifecycle: rollback, expiry reminders, and time-bound (JIT) shares.

### Added
- **Time-bound (expiring) secret shares** — a share can now carry an optional expiry
  (just-in-time access), mirroring time-bound role grants. An expired share authorizes
  nothing (filtered at the permission chokepoint and in the storage queries, so it neither
  grants access nor surfaces in "shared with me"); a past expiry is rejected at creation.
  Lapsed shares are reclaimed and audited (`share.expired`) by the JIT expiry scheduler.
  `POST /secrets/{id}/share` accepts an optional `expires_at`; the Share modal offers an
  "Access expires" preset (1h/24h/7d/30d). ([#284])
- **Secret version rollback** — restore a secret to a prior version's value, re-instated as
  a new version so history stays append-only and the rollback is itself undoable. Audited
  as `secret.rolled_back`; refuses rolling back to the current head. Exposed over HTTP
  (`POST /secrets/{id}/rollback`, scoped `secrets.write`), the web Version History view, and
  the `keyorix secret rollback` CLI command. ([#282], [#283])
- **Secret-expiry reminders** — an opt-in scheduler proactively notifies a project's
  approvers before (and once after) a secret with an expiration lapses, deduped on the
  unread reminder. Mirrors the rotation-reminder scheduler; single-replica-gated. ([#281])

[#281]: https://github.com/keyorixhq/keyorix/pull/281
[#282]: https://github.com/keyorixhq/keyorix/pull/282
[#283]: https://github.com/keyorixhq/keyorix/pull/283
[#284]: https://github.com/keyorixhq/keyorix/pull/284

## v0.51.0 — 2026-06-17

Rotation: Azure backend, failure alerts, status visibility.

### Added
- **Azure AD app-secret rotation** (ADR-047) — a generate-upstream backend completing the
  cloud trio (AWS IAM · GCP service-account keys · Azure): rotation mints a fresh client
  secret via Microsoft Graph and removes the app's prior secrets. Ambient Azure creds;
  fail-closed `allowed_refs`. ([#279])
- **Auto-rotation failure alerts** — a run that leaves any secret unrotated broadcasts one
  summary (names + reasons, never values) to the configured notification channel
  (Slack/Teams/webhook), so a silently-failed rotation is surfaced. ([#277])
- **Auto-rotation visibility in rotation status** — the rotation status read model now
  reports whether each covered secret self-rotates and via which backend; the web Secrets
  Health page shows a self-rotating count and an "Auto" badge on overdue items. ([#278])

[#277]: https://github.com/keyorixhq/keyorix/pull/277
[#278]: https://github.com/keyorixhq/keyorix/pull/278
[#279]: https://github.com/keyorixhq/keyorix/pull/279

## v0.50.0 — 2026-06-17

### Added
- **GCP service-account key rotation** (ADR-047) — a generate-upstream backend (like AWS
  IAM): rotation mints a fresh user-managed service-account key, deletes the account's
  prior user-managed keys, and stores the new key file. Credentials come from Application
  Default Credentials; fail-closed on a required `allowed_refs`. ([#275])

With this release, backend rotation spans **PostgreSQL · MySQL · MongoDB · Redis**
(password-set) and **AWS IAM · GCP service-account keys** (generate-upstream).

[#275]: https://github.com/keyorixhq/keyorix/pull/275

## v0.49.0 — 2026-06-17

### Added
- **MongoDB and Redis rotation backends** (ADR-047) — automated rotation can now rotate
  a MongoDB account (`updateUser`) or a Redis ACL user (`ACL SETUSER … resetpass`) in
  place, alongside PostgreSQL and MySQL. Both pass the username/password as typed/discrete
  values (injection-safe by construction) and are fail-closed on a required
  `allowed_refs`. ([#273])

Backend rotation now spans PostgreSQL · MySQL · MongoDB · Redis (password-set) and AWS
IAM (generate-upstream).

[#273]: https://github.com/keyorixhq/keyorix/pull/273

## v0.48.0 — 2026-06-16

More rotation backends (ADR-047).

### Added
- **MySQL rotation backend** — rotate a MySQL account's password in place
  (`ALTER USER … IDENTIFIED BY`), alongside PostgreSQL. Injection-safe, fail-closed on a
  required `allowed_refs`. ([#270])
- **Cloud-key rotation (AWS IAM)** — a *generate-upstream* backend: rotation mints a
  fresh IAM access key (deleting the user's prior keys) and stores the new
  `{access_key_id, secret_access_key}`, for credentials the cloud issues rather than
  accepts. Credentials come from the ambient AWS chain; same fail-closed `allowed_refs`.
  ([#271])

Backend rotation now spans PostgreSQL · MySQL (password-set) and AWS IAM (generate). The
auto-rotation toggle (incl. backend/ref) is also now manageable from the web console.

[#270]: https://github.com/keyorixhq/keyorix/pull/270
[#271]: https://github.com/keyorixhq/keyorix/pull/271

## v0.47.0 — 2026-06-16

Backend rotation executors (ADR-047) — rotate the upstream credential, not just the copy.

### Added
- **Backend rotation executors** — automated rotation can now rotate the **upstream**
  credential in place, so externally-owned secrets (not just Keyorix-generated values)
  can auto-rotate. A secret configured with a `rotation_backend` + `rotation_ref` has its
  new value applied upstream by the backend executor **before** it is stored in Keyorix,
  so the two never drift; if the upstream apply fails, nothing is stored. The first
  backend is **PostgreSQL** (`ALTER ROLE … WITH PASSWORD`, injection-safe). Configure
  via HTTP / gRPC / CLI `auto-rotate` (scoped `secrets.write`). ([#267], [#268])

### Security
- Rotation backends are **fail-closed**: each requires an `allowed_refs` allow-list (a
  backend without one is refused at registration and the executor refuses to rotate),
  bounding which upstream principals a rotation may touch; the named backend is validated
  when a secret is configured. Admin DSNs are operator-provided and env-sourced. ([#268])

[#267]: https://github.com/keyorixhq/keyorix/pull/267
[#268]: https://github.com/keyorixhq/keyorix/pull/268

## v0.46.0 — 2026-06-16

Automated secret rotation (ADR-046).

### Added
- **Automated rotation executor** — an opt-in scheduler that actually rotates secrets,
  not just tracks/reminds. A secret marked `auto_rotate` that is overdue under an active
  rotation policy has its value regenerated (a new version) automatically, audited as
  `secret.auto_rotated`. Opt-in per secret and only for Keyorix-owned (generated) values,
  so externally-managed credentials are never silently changed. ([#263])
- **Per-secret generated-value shape** — choose the rotated value's `length` (8–256,
  default 32) and `charset` (`alphanumeric` [default] / `lower_alphanumeric` / `hex` /
  `alphanumeric_symbols`) to meet a system's password requirements. ([#264])
- **Manage auto-rotation everywhere** — toggle it over HTTP (`PATCH
  /secrets/{id}/auto-rotate`), gRPC (`SecretService.SetSecretAutoRotate`), and the CLI
  (`keyorix secret auto-rotate`), all gated by scoped `secrets.write`. ([#263], [#265])

[#263]: https://github.com/keyorixhq/keyorix/pull/263
[#264]: https://github.com/keyorixhq/keyorix/pull/264
[#265]: https://github.com/keyorixhq/keyorix/pull/265

## v0.45.0 — 2026-06-16

Real-time audit streaming for SIEM consumers.

### Added
- **Gap-free audit-stream resume** — the gRPC `StreamAuditLogs` RPC accepts an optional
  `after_id`; a consumer that tracks its last-seen event id can reconnect from there,
  replaying the backlog before tailing live, so a disconnect loses no events. Omitting
  it keeps the head-start (tail-only) behavior. ([#261])

### Changed
- **`StreamAuditLogs` is now push-driven** — instead of polling the database on a fixed
  interval, an in-process broker wakes live tails the instant an audit event is written;
  the stream then drains new rows from its cursor (the database stays authoritative, so
  no event is lost). Delivery latency drops to ~immediate and steady-state poll load is
  removed; a long fallback ticker remains as a safety net. ([#260])

[#260]: https://github.com/keyorixhq/keyorix/pull/260
[#261]: https://github.com/keyorixhq/keyorix/pull/261

## v0.44.0 — 2026-06-16

Keyorix Connect per-reference RBAC — gRPC parity, group/glob support.

### Added
- **gRPC management of per-reference grants** — `ConnectService` gains
  `ListRefGrants` / `CreateRefGrant` / `DeleteRefGrant` (gated `roles.read` /
  `roles.write`), at parity with the HTTP `/connect/ref-grants` routes. ([#256])
- **Glob ref-grant patterns** — a grant pattern is a prefix by default, or a
  shell-style glob if it contains `*` `?` `[` (e.g. `prod/*/db`; `*` does not cross
  `/`). Existing prefix grants are unchanged; a malformed glob matches nothing. ([#258])

### Fixed
- **Per-reference grants honor group-derived roles** — ref-grant matching now resolves
  a caller's *effective* roles (direct **plus** group-derived for users,
  `machine_identity_roles` for machines), consistent with how `connect.read` itself is
  authorized. Previously a user whose granted role came via a group was wrongly denied.
  ([#257])

[#256]: https://github.com/keyorixhq/keyorix/pull/256
[#257]: https://github.com/keyorixhq/keyorix/pull/257
[#258]: https://github.com/keyorixhq/keyorix/pull/258

## v0.43.0 — 2026-06-16

Fine-grained authorization for Keyorix Connect.

### Added
- **Per-reference RBAC for Keyorix Connect** (ADR-045) — scope *which roles* may read
  *which references* on a connector with a `(role, connector, ref_prefix)` allowlist,
  refining the global `connect.read` permission and the uniform per-connector
  `allowed_refs`. Enforced in the core read path, so it covers both the HTTP and gRPC
  surfaces, and applies to user and machine-identity callers alike. Opt-in and
  backward compatible: a connector with no grants is unchanged; once it has any grant
  it is **deny-by-default** (only a caller holding a role with a matching ref-prefix
  may read), and denied reads are audited. Manage grants at
  `GET/POST/DELETE /api/v1/connect/ref-grants` (gated by `roles.read` / `roles.write`).
  ([#254])

[#254]: https://github.com/keyorixhq/keyorix/pull/254

## v0.42.0 — 2026-06-16

Keyorix Connect reaches full surface coverage — every cloud secret store, every transport.

### Added
- **Azure Key Vault Connect connector** — read-through federation now supports Azure
  Key Vault alongside AWS Secrets Manager, GCP Secret Manager, and HashiCorp Vault.
  `ref` is the secret name (optionally `name/version`); the vault URL is the
  connector's `address`. Credentials come from `DefaultAzureCredential` (managed /
  workload identity / env / CLI), never from config, and the per-connector
  `allowed_refs` prefix guardrail applies. No new dependency. ([#252])
- **gRPC ConnectService** — Keyorix Connect is now reachable over gRPC at parity with
  the HTTP `/connect` routes (`ListConnectors`, `ReadSecret`), gated by the dedicated
  `connect.read` permission. Values are proxied on demand and never persisted. ([#251])

With this release Keyorix Connect spans **4 stores × 2 transports** — AWS SM / GCP SM /
Azure KV / Vault, over HTTP and gRPC, all gated by `connect.read` and audited.

[#251]: https://github.com/keyorixhq/keyorix/pull/251
[#252]: https://github.com/keyorixhq/keyorix/pull/252

## v0.41.0 — 2026-06-16

Least-privilege for Keyorix Connect + upgrade-safe permission seeding.

### Added
- **`connect.read` permission** — Keyorix Connect now has its own permission instead
  of reusing `secrets.read`, so granting native secret-read access no longer implies
  read access to external stores (ADR-044). It ships granted to `admin` /
  `system_admin`. ([#249])
- **Idempotent RBAC permission reconciliation on startup** — new canonical
  permissions added in a release are now seeded into already-initialised installs
  automatically (created and granted to their baseline roles), so an upgrade no longer
  leaves a new permission unheld by any role. Additive and **non-clobbering**:
  existing permissions' grants are never altered, preserving operator customizations;
  a no-op on a pre-bootstrap install. ([#249])

### Changed
- The Keyorix Connect routes (`/connect/*`) now require `connect.read` instead of
  `secrets.read`. **Upgrade note:** a non-admin principal that used Connect via
  `secrets.read` must be granted `connect.read`; admins/`system_admin` receive it
  automatically on first start after upgrade. ([#249])

[#249]: https://github.com/keyorixhq/keyorix/pull/249

## v0.40.0 — 2026-06-16

Keyorix Connect adds HashiCorp Vault.

### Added
- **Keyorix Connect — HashiCorp Vault backend** (ADR-043): a `vault` connector reads
  a secret path via Vault's HTTP API and returns its data, completing the
  AWS / GCP / Vault trio. KV v2 is detected and unwrapped; KV v1 returns the data map
  as-is. Configure with `address` and `token_env` (default `VAULT_TOKEN`, read from
  the environment); the per-connector `allowed_refs` prefix allowlist applies as for
  the other backends. Read-only, gated by `secrets.read`, audited
  `connect.secret_read`. ([#247])

### Notes
- No new dependency (a Vault KV read is a single authenticated HTTP GET). A dedicated
  `connect.read` permission, caching, and per-reference scoping remain follow-ups.

[#247]: https://github.com/keyorixhq/keyorix/pull/247

## v0.39.0 — 2026-06-16

Keyorix Connect: read secrets from external stores through Keyorix.

### Added
- **Keyorix Connect — read-through federation** (ADR-043, opt-in, off by default). A
  new read-only API proxies an authorized, audited read of a secret's *current* value
  from an external store, without importing or persisting it — so teams reach existing
  external secrets through Keyorix's RBAC and audit trail. Backends:
  **AWS Secrets Manager** and **GCP Secret Manager**. Configure connectors under
  `connect.connectors`; `GET /api/v1/connect/{name}/secret?ref=…` returns the value
  (gated by `secrets.read`, audited `connect.secret_read`). Backend credentials come
  from the ambient identity chain (AWS env/instance-profile/IRSA; GCP ADC), never from
  config. An optional per-connector `allowed_refs` prefix allowlist bounds the
  readable set on top of the backend's IAM scope. ([#243], [#244])

### Fixed
- **RFC 3161 checkpoint anchors stay verifiable after the TSA cert expires** — anchor
  verification (ADR-029) now validates the timestamp-authority chain as of the token's
  asserted time rather than the current clock, so a stored anchor does not become
  unverifiable once its TSA signing certificate lapses. ([#245])

### Notes
- Connect is read-only (no import/sync); the external store stays authoritative.
  Vault, caching, and a dedicated `connect.read` permission are planned follow-ups.

[#243]: https://github.com/keyorixhq/keyorix/pull/243
[#244]: https://github.com/keyorixhq/keyorix/pull/244
[#245]: https://github.com/keyorixhq/keyorix/pull/245

## v0.38.0 — 2026-06-16

Hardware-sealed master key, plus secret-ownership and lockout-visibility fixes.

### Added
- **TPM 2.0 hardware-sealed KEK provider** — `key_provider.type: tpm` seals the
  key-encryption key to the host TPM 2.0 (`tpm_device`, default `/dev/tpmrm0`). A
  random KEK is generated and sealed on first start; only the sealed blob
  (`wrapped_key_path`) touches disk and it is unsealable only on that machine's TPM,
  so the KEK can't be recovered from a stolen disk alone. `KEYORIX_MASTER_PASSWORD`
  is not required; move an existing install on with `migrate-provider --to-type tpm`.
  This completes the KEK-custody set: passphrase · file · env · exec · Shamir · TPM ·
  AWS/GCP/Azure KMS. ([#241])

### Fixed
- **Ownerless (machine-created) secrets are owned by nobody** — secrets created by a
  machine identity carry `OwnerID 0`; the owner-equality gates compared that directly
  to the actor id, so a machine actor (id 0) matched every ownerless secret and was
  treated as its owner (owner permission + share/revoke). Ownership now requires a
  non-zero, matching id on both sides. ([#239])

### Changed
- **Admin visibility of login lockout** — the user API now exposes
  `login_locked_until` while a per-account lockout is active, so an admin can see a
  locked-out account and clear it (`POST /users/{id}/unlock`). ([#240])

### Notes
- Additive/opt-in; no schema changes. The TPM sealed blob is bound to one host — back
  up the data under a portable provider, as a TPM clear/replacement makes it
  unrecoverable.

[#239]: https://github.com/keyorixhq/keyorix/pull/239
[#240]: https://github.com/keyorixhq/keyorix/pull/240
[#241]: https://github.com/keyorixhq/keyorix/pull/241

## v0.37.0 — 2026-06-16

Split-custody master key + MFA recovery-code self-service.

### Added
- **Shamir K-of-N split-custody KEK provider** — a new `key_provider.type: shamir`
  splits the 32-byte key-encryption key into **N Shamir shares** with a **K-of-N**
  threshold, so no single custodian holds it and at least K must combine their shares
  to unseal — separation of duties for the master key (ISO 27001 / NIS2). Generate
  with `keyorix encryption shamir-split --shares N --threshold K` (the KEK is never
  printed or stored — only the shares are); supply ≥ K shares at startup via
  `shamir_share_files` / `shamir_share_env`, or move an existing install on with
  `migrate-provider --to-type shamir`. The KEK is framed before splitting so a
  sub-threshold or wrong set of shares fails closed (it does not silently establish a
  wrong key). ([#236])
- **MFA recovery-code regeneration + remaining count** — a user can now see how many
  recovery codes remain (`GET /auth/mfa/recovery-codes`) and generate a fresh set
  (`POST /auth/mfa/recovery-codes/regenerate`) after re-authenticating with a current
  authenticator code or their password. Regenerating replaces the whole set (so old
  or leaked codes are revoked) and returns the new codes once. Audited
  `mfa.recovery_codes_regenerated`. ([#237])

### Notes
- Both additive and opt-in/self-service. `shamir` adds no schema change; the MFA
  change adds no schema change. ⚠️ For `shamir`, losing more than N-K shares makes the
  KEK — and all data — permanently unrecoverable; store and back up shares separately.

[#236]: https://github.com/keyorixhq/keyorix/pull/236
[#237]: https://github.com/keyorixhq/keyorix/pull/237

## v0.36.0 — 2026-06-15

Independently verifiable audit trail: anchor checkpoints to a trusted timestamp
authority.

### Added
- **External-notary anchoring of audit checkpoints (RFC 3161)** — each signed
  audit checkpoint (ADR-029) can now be anchored to a trusted timestamp authority
  (TSA), producing an independent, third-party-signed proof that the checkpoint
  existed at a point in time — a proof the server cannot forge or backdate, even by
  an attacker holding the data-encryption key. The TSA token is stored on the
  checkpoint and re-verifiable offline. Configure via `audit.checkpoint_notary`
  (`enabled`, `url`, `timeout`, `ca_cert_path`); anchoring is best-effort and never
  blocks checkpointing. The anchor (asserted time + TSA) is shown by
  `keyorix audit checkpoint`. ([#234])

### Notes
- Additive (three nullable `audit_checkpoints` columns) and opt-in. Verification
  requires `ca_cert_path` (the TSA's trust anchor): the token signer is chained to
  it with the time-stamping EKU, so an untrusted/self-signed token is rejected, and
  verification fails closed when no trust anchor is configured.

[#234]: https://github.com/keyorixhq/keyorix/pull/234

## v0.35.0 — 2026-06-15

KEK flexibility + gRPC parity: resolve the KEK from any command, and pull
compliance posture over gRPC.

### Added
- **`exec` KEK provider** — a new `key_provider.type: exec` resolves the
  key-encryption key by running an operator-configured command (`exec_command`,
  an argv run **without a shell**) and reading the KEK (raw 32 bytes, or
  hex/base64) from its stdout. It's the universal escape hatch for any external
  secret store Keyorix has no built-in client for — 1Password (`op read`), sops
  (`sops -d`), Vault (`vault read -field`), or a CSI/sidecar helper. Runs at
  startup (fail-closed, 30s timeout); `KEYORIX_MASTER_PASSWORD` is not required.
  `keyorix encryption migrate-provider --to-type exec --to-exec-command …`
  re-wraps an existing install's DEK onto it. ([#231])
- **ComplianceService over gRPC** — the compliance posture
  (`GetCompliancePosture`) and the evaluated control matrix
  (`GetComplianceControls`, mapped to ISO 27001 / SOC 2 / NIS2 / DORA clauses)
  are now available over gRPC in addition to HTTP/CLI, so auditors' automation
  can pull the deployment's control posture on the same authenticated channel.
  Read-only, gated by `system.read`. ([#232])

### Notes
- Both additive and opt-in/parity. No schema changes. The `exec` command is
  trusted deployment config (like `file_path`/`env_var`), run without a shell.

[#231]: https://github.com/keyorixhq/keyorix/pull/231
[#232]: https://github.com/keyorixhq/keyorix/pull/232

## v0.34.0 — 2026-06-15

Brute-force hardening: per-account login lockout.

### Added
- **Per-account login lockout** (`security.login_lockout`, opt-in, default off) —
  brute-force protection distinct from the per-IP rate limiter (ADR-040). After
  `max_attempts` failed password logins within `window`, the account is locked for a
  cooldown that backs off exponentially across repeated lockouts (`base_cooldown` ×
  2ⁿ, capped at `max_cooldown`). It binds to the **account** (not the IP), so rotating
  source IPs cannot evade it; while locked, even a correct password is refused (the
  lock is checked before the bcrypt compare, so no work is spent on a guess). A
  successful login clears the counter and an admin can clear a lock immediately with
  `POST /api/v1/users/{id}/unlock` (`users.write`), which does not change
  `account_state`. The lock auto-expires on read — no scheduler. `account.locked` /
  `account.unlocked` are audited. ([#229])

### Notes
- Additive migration (four nullable/defaulted `users` columns); safe on existing DBs.
  Because the lock binds to the account, a known username can be kept locked by
  failing logins — keep `base_cooldown`/`max_cooldown` short (documented in
  `CONFIGURATION.md`); the lock always self-heals and an admin can clear it.

[#229]: https://github.com/keyorixhq/keyorix/pull/229

## v0.33.0 — 2026-06-15

The multi-cloud dynamic-secrets release: GCP and Azure join AWS STS.

### Added
- **GCP and Azure dynamic-secret backends** — two new cloud-IAM backends alongside
  `aws-sts`: `gcp` mints a short-lived service-account access token via the IAM
  Credentials API (`{"service_account":...,"scopes":[...],"lifetime_seconds":N}`), and
  `azure` acquires a short-lived Azure AD (Entra) token via DefaultAzureCredential
  (`{"scopes":[...]}`). Both return the token in the issued credential's `fields`
  (`access_token` / `expiration`). Like AWS STS they are self-expiring — revoke is a
  no-op, renew is refused, and they issue with the auto-revoke sweeper off (the cloud
  provider enforces expiry). Credentials for the mint call come from the ambient
  identity (GCP ADC / Azure DefaultAzureCredential), never from Keyorix config. ([#227])

### Notes
- Additive: new backend types only; no schema changes, no new Go module
  (GCP via the existing `google.golang.org/api`, Azure via the existing identity SDK).

[#227]: https://github.com/keyorixhq/keyorix/pull/227

## v0.32.0 — 2026-06-15

The cloud-IAM dynamic-secrets release: mint short-lived AWS credentials on demand.

### Added
- **AWS STS dynamic-secret backend** — a new `aws-sts` backend for dynamic secrets
  mints short-lived AWS credentials via `sts:AssumeRole` (alongside the existing
  postgres/mysql/mongodb/redis database backends). Issuing a lease returns
  `access_key_id` / `secret_access_key` / `session_token` (surfaced via the API, gRPC,
  and CLI). The config's encrypted "admin DSN" carries a small JSON blob
  (`{"role_arn":...,"region":...,"duration_seconds":...}`); the optional creation
  template is an inline STS session policy that scopes the assumed role down. AWS
  credentials for the AssumeRole call come from the standard chain (env /
  instance-profile / IRSA). STS credentials self-expire, so revoke is a no-op and
  renew is refused (issue a new lease); AWS enforces the expiry, so issuing does not
  require the auto-revoke sweeper. ([#225])

### Notes
- Additive: a new backend type + an optional `fields` map on issued credentials; no
  schema changes. GCP and Azure cloud backends are planned follow-ups.

[#225]: https://github.com/keyorixhq/keyorix/pull/225

## v0.31.0 — 2026-06-15

The gRPC-parity release: the newer subsystems are now scriptable over gRPC too.

### Added
- **gRPC ProjectService** — list/get/create/update/delete projects and list
  environments over gRPC, with the same scoped authorization as the HTTP/CLI
  surface (`secrets.read`/`write`/`delete`). ([#221])
- **gRPC MachineIdentityService** — machine identities and their bearer-token
  credentials over gRPC: list/create/transition/classify identities and
  issue/list/revoke/classify tokens (the raw token is returned once). ([#222])
- **gRPC DynamicSecretService** — dynamic-secret configs and lease lifecycle over
  gRPC: list/get/create/classify configs and issue/list/revoke/renew/revoke-all
  leases (the issued credential is returned once; the admin DSN is never
  returned). ([#223])

### Notes
- Additive — new gRPC services alongside the existing HTTP+CLI; no schema changes.
- All new RPCs authenticate via the existing interceptor (session / PAT / machine
  token) and enforce the same RBAC the HTTP routes do.

[#221]: https://github.com/keyorixhq/keyorix/pull/221
[#222]: https://github.com/keyorixhq/keyorix/pull/222
[#223]: https://github.com/keyorixhq/keyorix/pull/223

## v0.30.0 — 2026-06-15

The IdP-driven-RBAC & legal-hold release: let the IdP grant roles, and place
indefinite holds on archived evidence.

### Added
- **SSO group → role mapping** — `group_role_map` on an SSO provider maps an IdP
  group-claim value to a Keyorix system role (e.g. `keyorix-admins` → `system_admin`),
  so the IdP can drive role assignment directly on login without pre-granting roles.
  Authoritative only over the mapped roles (a user gains the roles their asserted
  groups map to and loses any mapped role they no longer qualify for; unmapped/manual
  grants are untouched); an absent groups claim is a no-op. Audited as
  `auth.sso_roles_synced`. ([#217])
- **S3 Object Lock legal hold on the evidence sink** — `evidence_delivery.object_store
  .legal_hold` places an indefinite S3 Object Lock legal hold on each uploaded
  evidence pack and signature (no expiry; cleared only out-of-band by a principal with
  `s3:PutObjectLegalHold`), for litigation/investigation preservation. Independent of
  the retention `lock_mode`. ([#218])

### Notes
- Both additive and opt-in (off unless configured). No schema changes.
- ⚠️ Any IdP group named in `group_role_map` becomes a privilege grant — map only
  groups governed by IdP administrators (a group → `system_admin` confers global admin).

[#217]: https://github.com/keyorixhq/keyorix/pull/217
[#218]: https://github.com/keyorixhq/keyorix/pull/218

## v0.29.0 — 2026-06-15

The immutable-evidence release: lock archived compliance evidence as WORM.

### Added
- **S3 Object Lock (WORM) on the evidence object-store sink** — each scheduled
  evidence pack and its detached signature can be uploaded with an S3 Object Lock
  retention (`governance` or `compliance` mode + a retain-until window), so archived
  evidence cannot be overwritten or deleted before it expires — tamper-resistant
  evidence an auditor can rely on. The bucket must be created with Object Lock
  enabled; configure via `evidence_delivery.object_store.{lock_mode,lock_retain_days}`.
  ([#215])

### Notes
- Additive and opt-in (object lock is off unless `lock_mode` is set). No schema changes.

[#215]: https://github.com/keyorixhq/keyorix/pull/215

## v0.28.0 — 2026-06-15

The classification-coverage release: data-sensitivity labels now span every
secret-bearing surface, not just static secrets.

### Added
- **Classify dynamic-secret configs** — a dynamic-secret config (ADR-035) carries a
  data-classification label (public/internal/confidential/restricted), set at create
  or via `PATCH /dynamic-secrets/configs/{id}/classification`, so the credentials it
  mints have a sensitivity tier. ([#212])
- **Classify machine identities & credentials** — machine identities (ADR-023) and
  their bearer-token credentials (ADR-030) carry a classification label too, set at
  create/issue or via `PATCH …/machine-identities/{id}/classification` and
  `…/tokens/{tokenId}/classification` (a token defaults to its identity's tier). Adds
  `keyorix machine create --classification`. ([#213])
- **Classification posture coverage** — the compliance posture's classification
  section now tallies dynamic configs, machine identities, and machine credentials by
  level alongside static secrets (in the evidence pack and `keyorix compliance
  report`), so an auditor sees sensitivity coverage across all of them. ([#212], [#213])

### Notes
- All additive — new indexed columns only; classification defaults to unclassified.

[#212]: https://github.com/keyorixhq/keyorix/pull/212
[#213]: https://github.com/keyorixhq/keyorix/pull/213

## v0.27.0 — 2026-06-15

The federated-identity-lifecycle & evidence-durability release: let your IdP onboard
and group users on first login, and archive signed evidence to immutable object storage.

### Added
- **SSO just-in-time (JIT) user provisioning** — with `auto_provision` enabled on a
  provider, a first SSO login whose verified identity matches no existing account
  creates one on the spot (active, passwordless, with a configurable `default_role`
  baseline) instead of being refused, so an IdP that isn't wired for SCIM push can
  still onboard users on demand. The IdP subject is stored as the account's
  `externalId` for later reconciliation; audited as `auth.sso_jit_provisioned`.
  ([#208])
- **SSO native-group sync** — with `group_sync` enabled, each SSO login reconciles the
  user's native Keyorix group memberships from the IdP's groups claim (the IdP is
  authoritative — memberships are added for asserted groups and removed for
  non-asserted ones), so group-based access follows the IdP without a separate SCIM
  push. Only existing native groups are touched; the claim name is configurable
  (`groups_claim`); an absent claim is a safe no-op. Audited as
  `auth.sso_groups_synced`. ([#210])
- **S3-compatible object-storage evidence sink** — scheduled compliance evidence packs
  can now be delivered to an object-storage bucket (AWS S3, MinIO, Cloudflare R2,
  Backblaze B2, GCS interop) in addition to a local dir and/or webhook, so evidence can
  land in immutable / object-locked (WORM) storage an auditor pulls from. The pack and
  its detached signature are uploaded; credentials resolve via the standard AWS chain.
  Configure via `evidence_delivery.object_store`. ([#209])

### Security
- SSO no longer trusts an email an IdP explicitly marks unverified
  (`email_verified: false`) for account matching or provisioning; an absent claim
  stays trusted (it is optional in OIDC and some enterprise IdPs omit it). ([#208])

### Notes
- All additive — no schema changes; every new behaviour is opt-in and off by default.

[#208]: https://github.com/keyorixhq/keyorix/pull/208
[#209]: https://github.com/keyorixhq/keyorix/pull/209
[#210]: https://github.com/keyorixhq/keyorix/pull/210

## v0.26.0 — 2026-06-15

The federated-identity & alerting release: sign in through your IdP, get compliance
pushed to your team channels, and prove your evidence is authentic.

### Added
- **Human SSO login via OIDC (RFC 6749 authorization-code flow)** — users sign in
  through their identity provider (Okta, Entra ID, …) and Keyorix mints the same
  session a password login would, so an IdP-provisioned (passwordless) user can
  actually sign in. The id_token is fully verified (signature against the issuer's
  JWKS, issuer, audience, expiry, and the nonce); the identity maps to a Keyorix
  account by the SCIM `externalId` then email (no auto-provisioning; suspended users
  refused). Endpoints discovered from the issuer; configure via `sso`. The web login
  page gains "Sign in with <provider>" buttons. ([#203])
- **Slack and Microsoft Teams notification channels** — the in-app notifications
  Keyorix creates (approvals, anomaly alerts, rotation/recertification reminders,
  break-glass) can now be delivered to a Slack or Teams channel via an incoming
  webhook, alongside email/webhook. Configure via `notifications.{slack,teams}`.
  ([#204])
- **Scheduled compliance digest** — an opt-in scheduler periodically broadcasts a
  posture + control-matrix summary (controls pass/gap, overdue recertifications,
  rotation gaps, unclassified secrets, open anomalies, active risk exceptions) to the
  configured notification channels — continuous monitoring without opening the
  console. Configure via `compliance_digest`. ([#205])
- **Signed, verifiable evidence packs (ISO 27001 / SOC 2)** — each scheduled evidence
  export is HMAC-signed with a DEK-derived key the database/DBA does not hold; a
  detached `.sig` is written next to the pack (and the signature rides the webhook in
  an `X-Keyorix-Evidence-Signature` header). `keyorix compliance verify` (and `POST
  /compliance/evidence/verify`) prove an archived pack is authentic and unmodified.
  Requires encryption enabled. ([#206])

### Notes
- Additive schema only (an `sso_login_states` table) — safe on existing databases.
- SSO logins bypass Keyorix-local MFA: the IdP is the authenticator.

[#203]: https://github.com/keyorixhq/keyorix/pull/203
[#204]: https://github.com/keyorixhq/keyorix/pull/204
[#205]: https://github.com/keyorixhq/keyorix/pull/205
[#206]: https://github.com/keyorixhq/keyorix/pull/206

## v0.25.0 — 2026-06-15

The enterprise-compliance release: an auditor-ready control matrix, a governed risk
register, and SCIM provisioning for IdP-driven identity lifecycle.

### Added
- **Compliance control matrix (ISO 27001 / SOC 2 / NIS2 / DORA)** — every control
  Keyorix enforces is now mapped to its clause references across the four regimes,
  with a **live status** (pass / gap / not-configured) derived from the posture.
  `GET /compliance/controls`, embedded in the evidence pack, `keyorix compliance
  controls`, and a control-matrix panel in the web console. ([#198])
- **Risk register / exceptions (ISO 27001 A.5.8)** — record a **governed, time-bound
  acceptance** of a known control gap (an SoD violation, an un-rotated secret, …):
  an owner, a justification, and a required expiry. Active exceptions surface in the
  posture and the evidence pack, so an auditor sees an accepted-with-a-deadline risk
  rather than an ungoverned gap. `GET/POST/DELETE /risk-exceptions`, `keyorix risk
  list|add|revoke`, and a register panel in the web console. ([#199])
- **SCIM 2.0 provisioning (RFC 7644)** — an opt-in `/scim/v2` endpoint group lets an
  IdP (Okta, Entra ID, …) **provision, update, deactivate, and deprovision users and
  sync groups** automatically, authenticated by a static bearer token. Users:
  Create/List/Get/Replace/PATCH(active)/Delete + `ServiceProviderConfig`; Groups:
  Create/List/Get/Replace/PATCH(members)/Delete. Configure via `scim`. ([#200], [#201])

### Notes
- Additive schema only (a `risk_exceptions` table; an `external_id` column on
  `users`) — safe on existing databases.
- A SCIM `userName` (typically an email/UPN) maps to the user's email and a compliant
  alphanumeric Keyorix username is derived from it; the IdP's `externalId` is stored
  for reconciliation. Provisioned users have no usable password (SSO / out-of-band).
- The Keyorix web console gains the control-matrix and risk-register panels on the
  Compliance page (keyorix-web).

[#198]: https://github.com/keyorixhq/keyorix/pull/198
[#199]: https://github.com/keyorixhq/keyorix/pull/199
[#200]: https://github.com/keyorixhq/keyorix/pull/200
[#201]: https://github.com/keyorixhq/keyorix/pull/201

## v0.24.0 — 2026-06-14

The operationalisation release: compliance controls run on a schedule, reach people
where they work, and deliver evidence off-box.

### Added
- **Scheduled access recertification (ISO 27001 A.5.18)** — an opt-in scheduler that
  enforces a review cadence: it finds projects overdue for review (never reviewed,
  or last reviewed longer ago than the configured window) and either auto-opens a
  recertification campaign or reminds the project's admins to, and nudges admins of
  in-flight campaigns with pending items. The cadence also drives a new
  "projects overdue" figure in the compliance posture. Configure via
  `recertification`. ([#192])
- **External notification channels (ISO 27001 A.5.5 / SOC 2)** — the in-app
  notifications Keyorix creates (approvals, anomaly alerts, rotation/recertification
  reminders, break-glass) can now be **fanned out to email and/or a webhook**,
  best-effort and asynchronously (a slow channel never blocks the triggering action).
  Configure via `notifications.{webhook,email}`. ([#193], [#194])
- **Off-box evidence delivery (ISO 27001 / SOC 2)** — scheduled compliance-evidence
  delivery can now **POST the evidence pack to a webhook** in addition to (or instead
  of) a local directory, so evidence survives the node without a mounted volume.
  Configure via `evidence_delivery.webhook`. ([#195])
- **Data-classification filter on the secrets API (ISO 27001 A.5.12)** — `GET
  /secrets` accepts a `classification` query parameter (`public|internal|
  confidential|restricted|unclassified`). ([#196])

### Notes
- No schema changes — every feature builds on existing tables.
- The Keyorix web console gains a classification column, filter, and bulk-classify on
  the secrets list, and surfaces the recertification-overdue count and the configured
  data-retention windows on the Compliance page (keyorix-web).

[#192]: https://github.com/keyorixhq/keyorix/pull/192
[#193]: https://github.com/keyorixhq/keyorix/pull/193
[#194]: https://github.com/keyorixhq/keyorix/pull/194
[#195]: https://github.com/keyorixhq/keyorix/pull/195
[#196]: https://github.com/keyorixhq/keyorix/pull/196

## v0.23.0 — 2026-06-14

The retention release: data is kept exactly as long as policy requires, and the
evidence that proves it is delivered automatically.

### Added
- **Per-record-type data-retention policies (ISO 27001 A.5.33 / GDPR
  storage-limitation / DORA)** — configurable retention windows for the compliance
  records that previously accumulated forever: anomaly alerts, closed
  recertification campaigns (and their items), the break-glass register, and
  resolved access requests (and their approvals). An opt-in scheduler hard-deletes
  records past their window — never touching active/open/pending rows, cascading to
  dependent rows, and **respecting legal hold** (an active hold preserves
  everything). The audit trail (append-only) and soft-deleted rows (the separate
  ADR-032 purge) are deliberately never touched. Each `*_days` window defaults to
  `0` = keep forever; the configured windows join the compliance posture and
  `keyorix compliance report` as A.5.33 evidence. ([#189])
- **Scheduled compliance-evidence delivery (ISO 27001 / SOC 2 continuous
  evidence)** — an opt-in scheduler that periodically generates the auditor evidence
  pack and writes it as a timestamped JSON file to a configured directory for
  off-box archival, emitting a `compliance.evidence_exported` audit event each run
  (so the export is itself in the tamper-evident trail and is SIEM-forwarded).
  Configure via `evidence_delivery`. ([#190])

### Notes
- No schema changes — both features build on existing tables.
- The Keyorix web console gains a per-secret data-classification badge and inline
  level picker on the secret-detail view (keyorix-web), closing the A.5.12
  classification loop the compliance posture already reported on.

[#189]: https://github.com/keyorixhq/keyorix/pull/189
[#190]: https://github.com/keyorixhq/keyorix/pull/190

## v0.22.0 — 2026-06-14

The detection-and-preservation release: proactive alerting on access anomalies and
a legal hold that preserves records under investigation.

### Added
- **Proactive anomaly alerting (NIS2 detection & response)** — detected access
  anomalies (off-hours / new-IP / new-user access to secrets) are now pushed out
  rather than just persisted: an in-app alert to the project's admins **and** a
  `security.anomaly_detected` audit event that the SIEM forwarder picks up (so
  anomalies reach the SOC). Each anomaly is announced once. Opt-in via the
  `anomaly_alerts` config (which also makes the existing scan schedule
  configurable); the open-anomaly count joins the compliance posture. ([#186])
- **Legal hold (ISO 27001 A.5.34 / eDiscovery / DORA)** — a deployment-wide
  litigation/investigation hold that, while active, **blocks every background
  hard-delete job** (the retention purge, the JIT role-grant-expiry sweep, the
  login-attempt prune) so records subject to hold are preserved. Storage-backed and
  runtime-toggleable (place it now, no restart); the guard fails safe (skips a purge
  if hold status can't be read). `GET/POST/DELETE /api/v1/legal-hold` and `keyorix
  legal-hold status|place|lift` (status `system.read`; place/lift `system.write`);
  placing/lifting is audited and the hold status joins the compliance posture. ([#187])

### Notes
- Additive schema only (new `legal_holds` table; an `alerted` column on
  `anomaly_alerts`) — safe on existing databases.
- The Keyorix web console gains an open-anomalies tile and a legal-hold banner with
  a place/lift control on the Compliance page (keyorix-web).

[#186]: https://github.com/keyorixhq/keyorix/pull/186
[#187]: https://github.com/keyorixhq/keyorix/pull/187

## v0.21.0 — 2026-06-14

### Added
- **Dual-control (N-of-M) approval for access requests (ISO 27001 A.5.3 / SOX)** —
  an access request can now require multiple **distinct** approvers before the role
  is granted, so no single admin can unilaterally grant access. Configure the
  threshold with `dual_control.required_approvals` (default 1 = single approval).
  Below the threshold the request stays pending; the listing shows the M-of-K
  progress, remaining approvers are notified, and each sign-off is audited. A
  requester can never approve their own request (maker ≠ checker). The web console
  shows the approval progress on the pending-requests view. ([#184])

[#184]: https://github.com/keyorixhq/keyorix/pull/184

## v0.20.0 — 2026-06-14

The compliance-reporting & data-classification release: turn the controls Keyorix
enforces into the artifacts an auditor (ISO 27001 / SOC 2 / NIS2 / DORA) consumes —
a single posture, an evidence pack, separation-of-duties detection, and secret
data classification.

### Added
- **Controls-posture report** — `GET /api/v1/compliance/posture` and `keyorix
  compliance report` roll up the deployment's control posture into one structured
  object: audit-trail integrity (chain verified, checkpointed), access governance
  (review-campaign coverage, dormant role grants, SoD violations), rotation hygiene
  (overdue / due-soon), identity (second-factor coverage), emergency access
  (break-glass usage), and data classification (secrets per sensitivity level).
  Gated by `system.read`. ([#177], [#180], [#182])
- **Auditor evidence pack** — `GET /api/v1/compliance/evidence` and `keyorix
  compliance export [--output FILE]` bundle the posture with the records that
  substantiate it (the audit-chain anchor, the access-review campaigns, the
  break-glass register, the overdue rotations, and the SoD violations) as a
  timestamped, archivable JSON. ([#178], [#180])
- **Separation of duties (ISO 27001 A.5.3 / SOX)** — define toxic permission
  combinations (two permissions one principal must not hold together) and detect
  every user who effectively holds both sides. `GET/POST/DELETE /api/v1/sod/policies`
  + `GET /api/v1/sod/violations`; `keyorix sod policy …` and `keyorix sod
  violations`. ([#179])
- **Secret data classification (ISO 27001 A.5.12 / A.5.13)** — label a secret with
  its sensitivity (`public` / `internal` / `confidential` / `restricted`), at
  creation or via `PATCH /api/v1/secrets/{id}/classification` and `keyorix secret
  classify`. The label is audited, filterable, and counted in the classification
  posture. ([#181])

### Notes
- Additive schema only (new tables `sod_policies`; a nullable `classification`
  column on `secret_nodes`) — safe on existing databases.
- The Keyorix web console gains a live **Compliance** posture dashboard surfacing
  the controls posture, SoD violations, and classification coverage (keyorix-web).

[#177]: https://github.com/keyorixhq/keyorix/pull/177
[#178]: https://github.com/keyorixhq/keyorix/pull/178
[#179]: https://github.com/keyorixhq/keyorix/pull/179
[#180]: https://github.com/keyorixhq/keyorix/pull/180
[#181]: https://github.com/keyorixhq/keyorix/pull/181
[#182]: https://github.com/keyorixhq/keyorix/pull/182

## v0.19.0 — 2026-06-14

The access-recertification / least-privilege / incident-response release (ISO 27001
A.5.18, SOC 2 CC6.2–6.3, NIS2/DORA): review who can reach a project's secrets, act
on it, time-bound it, run it on a schedule, spot stale access, and break the glass
in an emergency.

### Added
- **Project access review (ISO 27001 A.5.18)** — `GET /api/v1/projects/{id}/access-review`
  and `keyorix access-review` enumerate every grant of access to a project's secrets:
  role-based standing access (the role + the highest secrets action it confers) plus
  the per-secret grants — ownership and direct/group shares. The `source` of each
  grant is reported. Gated by `roles.read` at the project scope. ([#169], [#170])
- **Attest / revoke recertification (A.5.18)** — close the review loop: `POST
  …/access-review/{attest,revoke}` and the `keyorix access-review attest|revoke`
  subcommands certify a grant as reviewed-and-kept, or remove it (the underlying
  role assignment or share). Both are audited (`access_review.attested`/`.revoked`);
  attest needs `roles.read`, revoke `roles.assign`. ([#171])
- **Just-in-time / time-bound role grants** — role grants can carry an expiry and
  stop authorizing **the instant they pass** (the authorization queries filter on
  expiry — not sweep-dependent). Access-request approval can grant time-bound
  (`grant_ttl` on the resolve API, `keyorix request review --ttl`), and an opt-in
  HA-gated `jit_access_expiry` sweeper reclaims expired rows, auditing each as
  `role.expired`. ([#172])
- **Periodic access-review campaigns (A.5.18 "review at planned intervals")** —
  turn the point-in-time review into a tracked cycle: open a campaign (snapshots
  current access into per-grant items), attest/revoke each, then close it as the
  evidence record. `…/access-review/campaigns[/…]` endpoints +
  `keyorix access-review campaign open|list|show|decide|close`. ([#173])
- **Dormant / unused-access detection** — the review annotates each user grant with
  the principal's last secret access in the project (from the audit trail); a grant
  never used (or stale ≥90 days) is flagged as dormant standing access to prune. New
  `last_used_at` on review entries + a `LAST-USED` CLI column. ([#174])
- **Break-glass emergency access (NIS2/DORA incident response)** — opt-in,
  self-service `POST …/break-glass` + `keyorix break-glass`: immediately self-grant
  a configured emergency role, time-bound and auto-expiring, with a mandatory
  justification, a loud audit event (`break_glass.activated`), and an admin alert —
  recorded as a queryable activation for post-hoc review, with admin early-revoke.
  Configured via the `break_glass` block (off by default). ([#175])

### Notes
- New config blocks: `jit_access_expiry` (expiry sweeper) and `break_glass`
  (emergency access) — both opt-in, documented in CONFIGURATION.md.
- Additive schema only (new tables: `access_review_campaigns`,
  `access_review_items`, `break_glass_activations`; nullable `expires_at` on role
  grants) — safe on existing databases.
- The Keyorix web console gains a project **Access Review** tab surfacing the
  review, attest/revoke, dormancy, and the campaign cycle (keyorix-web).

[#169]: https://github.com/keyorixhq/keyorix/pull/169
[#170]: https://github.com/keyorixhq/keyorix/pull/170
[#171]: https://github.com/keyorixhq/keyorix/pull/171
[#172]: https://github.com/keyorixhq/keyorix/pull/172
[#173]: https://github.com/keyorixhq/keyorix/pull/173
[#174]: https://github.com/keyorixhq/keyorix/pull/174
[#175]: https://github.com/keyorixhq/keyorix/pull/175

## v0.18.0 — 2026-06-13

### Added
- **`keyorix audit` CLI** — operate the tamper-evident audit trail (ADR-029) from
  the terminal: `verify` (re-walk the hash chain; non-zero exit on tampering;
  `--json` emits the external anchor), `logs` (interactive filtered query for
  investigation/spot-checks), `export` (NDJSON SIEM pull), and `checkpoint` (write
  a signed checkpoint on demand). ([#152], [#155], [#157])
- **Signed in-DB audit checkpoints (ADR-029)** — an opt-in, HA-gated scheduler
  (`audit_checkpoints.enabled`) signs the verified audit-chain head with an HMAC
  keyed by a DEK-derived key the database/DBA does not hold, so tail-truncation /
  genesis re-seed becomes detectable **on-box** (not just via the off-box anchor).
  Surfaced as `checkpointed` on `GET /audit/verify`. Requires encryption. ([#153])
- **`keyorix rotation` CLI** — manage rotation policies (NIS2/ISO A.5.15) from the
  terminal: `list` / `create` / `show` / `delete` and `status` (overdue / approaching
  covered secrets). ([#156])
- **Personal access tokens & machine identities over gRPC** — gRPC authentication
  now has full parity with HTTP (session + PAT + machine): `kx_pat_` carries its
  ADR-042 least-privilege restriction onto the gRPC context, and `kx_machine_`
  authenticates a machine principal with machine RBAC and no admin bypass. ([#158], [#159])
- **`expires_before` filter on `GET /api/v1/secrets`** — list secrets already
  expired or expiring before a given RFC3339 time (for "expiring secrets" views and
  scripts). ([#167])

### Fixed
- **Owned-secrets listing** used `created_by == username` (a fragile string proxy)
  instead of `owner_id`, the canonical ownership the permission model enforces —
  CLI-created secrets were invisible to their owner and a deleted-then-reused
  username could mis-attribute ownership. Now filters by `owner_id`. ([#163])
- **Rotation evaluation** silently capped at 1000 secrets per policy, so overdue
  secrets in projects with more than 1000 went unreported by the reminder scheduler
  and the status/evaluate views — now pages through all of them. ([#164])
- **Dashboard "expiring secrets" warning** capped at 100, silently dropping
  expiring secrets for users with more than 100 — now uses an expiration filter and
  pages through all. ([#165])
- **`keyorix run`** injected only the first 1000 secrets as env vars (subprocess
  silently misconfigured), and **`keyorix secret get --name`** could not find a
  secret beyond the first 1000 — both now page through all. ([#166])

### Security / Hardening
- **PAT non-funnelled authz guards (ADR-042)** — `core.IsGlobalAdmin` and
  `middleware.RequireRole` now fail closed for a PAT-restricted request, so
  least-privilege scoping holds even on the two authz paths that do not funnel
  through `core.Authorize`. ([#154])
- **Tenant-isolation scope-boundary tests** — SQL-level tests pinning user-RBAC
  role resolution, machine-RBAC resolution, and secret-listing project/environment
  isolation, including the cross-project/cross-environment leak guards (so a
  regression of the `AND`/`OR` SQL precedence fails CI). ([#160], [#161], [#162])

[#152]: https://github.com/keyorixhq/keyorix/pull/152
[#153]: https://github.com/keyorixhq/keyorix/pull/153
[#154]: https://github.com/keyorixhq/keyorix/pull/154
[#155]: https://github.com/keyorixhq/keyorix/pull/155
[#156]: https://github.com/keyorixhq/keyorix/pull/156
[#157]: https://github.com/keyorixhq/keyorix/pull/157
[#158]: https://github.com/keyorixhq/keyorix/pull/158
[#159]: https://github.com/keyorixhq/keyorix/pull/159
[#160]: https://github.com/keyorixhq/keyorix/pull/160
[#161]: https://github.com/keyorixhq/keyorix/pull/161
[#162]: https://github.com/keyorixhq/keyorix/pull/162
[#163]: https://github.com/keyorixhq/keyorix/pull/163
[#164]: https://github.com/keyorixhq/keyorix/pull/164
[#165]: https://github.com/keyorixhq/keyorix/pull/165
[#166]: https://github.com/keyorixhq/keyorix/pull/166
[#167]: https://github.com/keyorixhq/keyorix/pull/167

## v0.17.0 — 2026-06-13

### Added
- **Rotation-reminder scheduler** — an opt-in background job
  (`rotation_reminders.enabled`) that proactively notifies project admins (in-app)
  of secrets overdue or approaching their rotation deadline under an active
  rotation policy, turning the reactive rotation-health views into proactive
  nudges (a NIS2/ISO credential-rotation-hygiene control). One standing reminder
  per project per admin, de-duplicated while unread; single-replica-gated in HA.
  Default off; `schedule` (Go duration) controls the cadence (default 24h). ([#150])

[#150]: https://github.com/keyorixhq/keyorix/pull/150

## v0.16.0 — 2026-06-13

### Added
- **`keyorix pat` CLI** — create, list, and revoke personal access tokens from the
  terminal (previously web-UI/API only). `pat create` surfaces the full ADR-042
  least-privilege model via flags: `--scope` (repeatable permission allowlist),
  `--project-id`, and `--environment-id` (which requires `--project-id`); the raw
  token is printed exactly once. Completes the PAT least-privilege story across
  backend, web UI, and CLI. ([#148])

[#148]: https://github.com/keyorixhq/keyorix/pull/148

## v0.15.0 — 2026-06-13

Migration reach and least-privilege completion. No config or schema changes
(the PAT scoping column is an additive, default-off migration).

### Added
- **Import from Google Cloud Secret Manager** — `keyorix secret import --source gcp
  --gcp-project <id>` is the fourth live migration source after Vault, AWS Secrets
  Manager and Azure Key Vault, completing big-3 cloud coverage. Authenticates with
  Application Default Credentials, reads each secret's latest enabled version, and
  explodes JSON values per field. Credentials stay CLI-side; the GCP SDK links into
  the CLI binary only. ([#145])
- **Per-environment PAT confinement** — a personal access token can now be confined
  to a single environment (`environment_scope` on `POST /auth/tokens`), the third
  and final least-privilege scoping axis alongside the permission allowlist and
  project confinement (ADR-042). A token scoped to an environment may act only on
  that environment's secrets — e.g. a staging-only CI credential. Enforced before
  the admin bypass, so it bounds even an admin's own token. Existing tokens are
  unaffected. ([#146])

[#145]: https://github.com/keyorixhq/keyorix/pull/145
[#146]: https://github.com/keyorixhq/keyorix/pull/146

## v0.14.0 — 2026-06-13

Dynamic-secrets expansion: a fourth backend and full CLI lifecycle coverage.

### Added
- **Redis dynamic-secrets engine** (`backend_type: redis`) — the fourth dynamic-
  secrets target after PostgreSQL, MySQL and MongoDB. It mints a short-lived Redis
  **ACL user** (`ACL SETUSER kx_dyn_<random> on >password <rules>`) and drops it on
  revoke (`ACL DELUSER`). The admin DSN is a Redis URI (`redis://…` / `rediss://…`)
  for a user holding the `+acl` command; the creation template is whitespace-
  separated ACL rule tokens (`~app:* +@read +@write`). Username/password are passed
  as discrete RESP arguments, so credential injection is structurally impossible.
  Like MySQL/MongoDB, Redis ACL users have no native expiry — enable the auto-revoke
  sweeper. ([#142], ADR-035)
- **`keyorix dynamic-secret create`** — register a dynamic-secrets target config
  from the CLI (previously API/UI-only). The privileged admin DSN is read from
  `KEYORIX_DYNAMIC_ADMIN_DSN` or a hidden prompt — never a flag, so it can't leak
  into shell history. The CLI now covers the full lifecycle: create → issue →
  leases → renew → revoke → revoke-all, across all four backends. ([#143])

[#142]: https://github.com/keyorixhq/keyorix/pull/142
[#143]: https://github.com/keyorixhq/keyorix/pull/143

## v0.13.3 — 2026-06-13

Further security/correctness fixes from the access-control & integrity audit. No
new features; no config or schema changes.

### Fixed
- **OIDC/JWKS: bounded stale-key fallback** (ADR-031). On a transient JWKS refetch
  failure the resolver fell back to a cached signing key with no age bound, so a
  key the issuer rotated out (e.g. because it was compromised) could keep verifying
  federation tokens indefinitely while the issuer's JWKS endpoint was unreachable.
  The fallback is now bounded to a short grace window past the cache TTL; beyond it
  a failed refetch fails closed. (Affects deployments using OIDC/Kubernetes-JWT
  federation.) ([#138])
- **Audit log: tamper-evidence anchor** (ADR-029). On-box chain re-verification
  could not detect tail-truncation or a genesis re-seed (a shorter, self-consistent
  chain still verifies), and the documented "SIEM export anchors the head"
  mitigation was not actually wired — the export omitted the chain hashes.
  `GET /audit/verify` now returns the chain `head_hash`/`head_id`, and
  `GET /audit/export` now carries each event's `prev_hash`/`entry_hash`, so an
  off-box observer can detect truncation. ([#139])

### Internal
- Added a router-wide regression guard asserting a read-only persona cannot succeed
  at any mutating route — preventing the access-control privilege-escalation class
  fixed in v0.13.2 from recurring. ([#140])

[#138]: https://github.com/keyorixhq/keyorix/pull/138
[#139]: https://github.com/keyorixhq/keyorix/pull/139
[#140]: https://github.com/keyorixhq/keyorix/pull/140

## v0.13.2 — 2026-06-13

Authorization-hardening fixes from a systematic adversarial audit of the access
control across HTTP, gRPC, and account provisioning. No new features; no config or
schema changes. Recommended for any deployment that enables gRPC or exposes the
admin API to non-super-admin personas.

### Fixed
- **Account-provisioning privilege escalation** (ADR-028). `POST /api/v1/users`
  (atomic provisioning, which can grant a system role + project assignments) was
  gated only by `users.read`, so a global read-only persona could create a
  `system_admin` and escalate to full admin. It now requires `users.write` and
  authorizes each grant at its scope. The password-reset / account-setup link now
  also evicts the subject's other sessions, so a self-service reset locks out a
  stolen session (matching change-password). ([#134])
- **`/users` and `/groups` route privilege escalation.** `PUT`/`DELETE`/`restore`
  on `/users/{id}` and all `/groups` CRUD + membership routes inherited only the
  group-level `users.read`; a read-only persona could edit/delete users and — via
  group membership, which confers the group's roles — escalate. User mutations now
  require `users.write`; group CRUD `users.write`; group membership `roles.assign`.
  ([#135])
- **gRPC cross-project privilege escalation & install-wide reads.** The Role,
  User, Audit and System gRPC services authorized against the flat (global)
  permission union, so a permission held at one project counted everywhere — a
  project admin could assign roles into any project, and project-scoped read
  permissions could read install-wide data. Every gRPC RPC now authorizes through
  scoped RBAC, identical to HTTP. (Affects deployments with gRPC enabled.) ([#136])

[#134]: https://github.com/keyorixhq/keyorix/pull/134
[#135]: https://github.com/keyorixhq/keyorix/pull/135
[#136]: https://github.com/keyorixhq/keyorix/pull/136

## v0.13.1 — 2026-06-12

Security/correctness fixes from an internal audit of the credential & crypto
subsystems. No new features; no config or schema changes.

### Fixed
- **Crash-durable key-material writes** (ADR-041) — every write of unrecoverable
  key material (the wrapped DEK on first run / rotation / KEK-provider migration,
  the KMS-wrapped KEK blob, and the KEK salt) is now `fsync`'d before returning,
  and each promote-`rename` is followed by a directory `fsync`. Previously these
  used `os.WriteFile`, leaving the bytes in the page cache; a power failure after
  `migrate-provider` reported success — and after the operator retired the old KEK
  — could lose the new wrapped DEK and orphan all ciphertext irreversibly. The
  data path and on-disk formats are unchanged. ([#131])
- **Dynamic-secrets lease fail-opens** (ADR-035) — (1) issuing from a backend with
  no database-level expiry (MySQL, MongoDB) is now refused while the auto-revoke
  sweeper is disabled, so a lease's advertised TTL is always enforced rather than
  silently never expiring; (2) if cleaning up a just-minted role after an aborted
  issue fails, a `revoke_failed` lease is recorded and audited so the orphaned
  credential is visible to an operator instead of being permanent and
  untrackable. ([#132])

[#131]: https://github.com/keyorixhq/keyorix/pull/131
[#132]: https://github.com/keyorixhq/keyorix/pull/132

## v0.13.0 — 2026-06-12

### Added
- **Personal access token least-privilege scoping** (ADR-042) — a PAT can now be
  minted **weaker than its owner**. At creation it may carry an optional permission
  allowlist (exact like `secrets.read`, the catch-all `*`, or a prefix like
  `secrets.*`) and/or a single-project confinement (`project_scope`). The
  restriction is a **filter that only ever narrows** the token below its owner —
  never an escalation, since the owner's live RBAC still runs after it. It is
  enforced at the single authorization chokepoint (before role resolution and the
  admin bypass), so it bounds even a global admin's own token across every
  authorization path. `POST /api/v1/auth/tokens` accepts `scopes` and
  `project_scope`; existing and unrestricted tokens are unaffected (full
  inheritance remains the default). Closes the last over-privileged-credential gap
  after machine identities (ADR-030). ([#129], ADR-042)

[#129]: https://github.com/keyorixhq/keyorix/pull/129

## v0.12.0 — 2026-06-12

### Added
- **MongoDB dynamic-secrets engine** (`backend_type: mongodb`) — the third dynamic-
  secrets target after PostgreSQL and MySQL, behind the same `CredentialEngine`
  interface. It mints `kx_dyn_<random>` users in the target's `admin` database
  (`createUser`) and drops them on revoke (`dropUser`, idempotent). The admin DSN is
  a MongoDB connection URI and the creation template is a JSON role spec
  (`{"roles": [{"role": "readWrite", "db": "app"}]}`); the username/password are
  passed as typed BSON values, so credential injection is structurally impossible.
  Like MySQL, MongoDB users carry no native expiry, so enable the auto-revoke
  sweeper for MongoDB targets. ([#127], ADR-035)

[#127]: https://github.com/keyorixhq/keyorix/pull/127

## v0.11.0 — 2026-06-12

KMS follow-ups: a third cloud backend for the wrapping key, plus zero-downtime
provider migration.

### Added
- **Azure Key Vault KEK provider** (`type: azure-kms`) — the third KMS backend for
  the KEK wrapping key, after AWS and GCP, behind the same `KMSClient` interface. It
  envelopes the KEK with the vault key's `wrapKey`/`unwrapKey` operations
  (RSA-OAEP-256); credentials come from `DefaultAzureCredential` (env / managed
  identity / workload identity) and the key is inherently pinned by name.
  ([#123], ADR-041)
- **`keyorix encryption migrate-provider`** — move an existing install between KEK
  providers (e.g. password → a cloud KMS) by **re-wrapping the DEK under the target
  provider's KEK without re-encrypting any data** — fast and with no database lock,
  unlike a DEK rotation. It backs up the previous wrapped DEK, verifies the target
  provider round-trips a probe before keeping the change, and prints the config block
  to apply. Migrating `--to-type password` also rotates the master passphrase.
  ([#125], ADR-041)

[#123]: https://github.com/keyorixhq/keyorix/pull/123
[#125]: https://github.com/keyorixhq/keyorix/pull/125

## v0.10.0 — 2026-06-12

The bring-your-own-KMS release.

### Added
- **KMS-backed KEK providers** — the key-encryption key's *wrapping* key can now
  live in a cloud KMS/HSM via envelope encryption: only the KMS-wrapped KEK blob
  is stored on disk and it is unwrapped via KMS at startup, so the wrapping key
  never exists in plaintext on the host. Both **AWS KMS** (`type: aws-kms`) and
  **GCP KMS** (`type: gcp-kms`) are supported, behind a common interface; startup
  is fail-closed if the KMS is unreachable. Joins the existing password / file /
  env providers. ([#120], [#121], ADR-041)
- **Dynamic-secret incident kill switch** — `keyorix dynamic-secret revoke-all
  <config-id>` (and `POST …/configs/{id}/revoke-all`) revokes every active lease
  from a config at once, for when a target database or config is compromised.
  ([#119], ADR-035)

[#119]: https://github.com/keyorixhq/keyorix/pull/119
[#120]: https://github.com/keyorixhq/keyorix/pull/120
[#121]: https://github.com/keyorixhq/keyorix/pull/121

## v0.9.0 — 2026-06-12

### Added
- **`keyorix dynamic-secret` CLI** — issue and manage on-demand database
  credentials (ADR-035) from the terminal: `list`, `issue <config-id>`,
  `leases <config-id>`, `renew <lease-id>`, `revoke <lease-id>` (aliases:
  `dynamic-secrets`, `dyn`). The issued username/password is shown once on
  `issue`. Config creation stays API/UI-only (it takes the privileged admin DSN).
  ([#117], ADR-035)

[#117]: https://github.com/keyorixhq/keyorix/pull/117

## v0.8.0 — 2026-06-12

### Added
- **Cluster-wide login rate limiting** — brute-force protection now counts failed
  attempts in the database rather than per-process memory, so the 10-attempts /
  15-minutes-per-IP limit holds across HA replicas (the old in-memory limiter
  enforced it independently on each replica). Covers every login surface —
  password, TOTP, WebAuthn second-factor, and passwordless. ([#114], ADR-040)

### Changed
- CI hygiene: the `lint` (golangci-lint) and `gitleaks` jobs are green and
  meaningful again — a `.gitleaks.toml` allowlist scopes the scanner to real
  source/config (away from sample-credential fixtures in demos/docs/tests), and
  the linter config keeps the bug-catching checks while dropping pure-style noise.
  Several genuine issues those linters surfaced were fixed. ([#115])

[#114]: https://github.com/keyorixhq/keyorix/pull/114
[#115]: https://github.com/keyorixhq/keyorix/pull/115

## v0.7.0 — 2026-06-12

Passwordless authentication and high-availability deployment.

### Added
- **Passwordless (usernameless) passkey login** — a registered passkey alone signs
  a user in, with no password. Registration now creates a discoverable credential,
  and login requires user verification (PIN/biometric), so a single gesture proves
  both possession and the user. Joins the existing password, password+TOTP, and
  password+passkey options. ([#112], ADR-036)
- **High-availability deployment** — Keyorix can now run as multiple stateless API
  replicas behind a load balancer. The background schedulers (anomaly detection,
  retention purge, dynamic-secrets auto-revoke) are gated by a PostgreSQL advisory
  lock so each runs on a single replica at a time instead of duplicating work on
  every replica. With the file/env KEK providers (v0.6.0) for shared keys, this
  completes the multi-replica story. ([#111], ADR-039)

[#111]: https://github.com/keyorixhq/keyorix/pull/111
[#112]: https://github.com/keyorixhq/keyorix/pull/112

## v0.6.0 — 2026-06-12

Key-management flexibility and a more complete dynamic-secrets engine: bring your
own KEK source (file/KMS/env), mint on-demand MySQL credentials, and cap or renew
leases — plus a full configuration reference.

### Added
- **Pluggable KEK providers** — the key-encryption key can now be sourced from a
  passphrase (default, unchanged), a **file** (a mounted CSI/sealed secret or KMS
  sidecar output), or an **environment variable** (KMS/secret-manager injection),
  via `storage.encryption.key_provider`. The default `password` provider is
  byte-identical to prior releases, so existing keys keep working with no
  migration. ([#106], ADR-038)
- **Dynamic secrets for MySQL** — on-demand MySQL accounts alongside the existing
  PostgreSQL engine, behind the same API (`backend_type: mysql`). ([#107], ADR-035)
- **Dynamic-secret lease lifecycle** — a per-config **max-TTL ceiling** that caps
  a credential's lifetime regardless of the TTL a caller requests, and **lease
  renewal** (`POST /dynamic-secrets/leases/{id}/renew`) to extend an active lease
  up to that ceiling instead of re-issuing. ([#109], ADR-035)
- **Configuration reference** — `docs/CONFIGURATION.md` documents every
  `keyorix.yaml` block (encryption/KEK providers, MFA, WebAuthn, dynamic secrets,
  OIDC, sessions, …) with examples, defaults, and environment variables. ([#108])

### Fixed
- The shipped `production.yaml` example used cron syntax for `purge.schedule`,
  which is parsed as a Go duration and silently fell back to the 24h default;
  corrected to a duration with a clarifying comment. ([#108])

[#106]: https://github.com/keyorixhq/keyorix/pull/106
[#107]: https://github.com/keyorixhq/keyorix/pull/107
[#108]: https://github.com/keyorixhq/keyorix/pull/108
[#109]: https://github.com/keyorixhq/keyorix/pull/109

## v0.5.0 — 2026-06-12

The authentication & dynamic-secrets release: phishing-resistant passkeys, MFA
you can mandate (deployment-wide or per-project), and on-demand database
credentials that expire on their own.

### Added
- **Dynamic secrets (PostgreSQL)** — on-demand, short-lived database credentials
  in the HashiCorp Vault database-secrets-engine model. Register a target with an
  admin DSN and an optional creation template; callers issue a lease that mints a
  fresh role on the target, returned once, and an opt-in sweeper auto-revokes
  every lease at expiry. The admin DSN and each issued credential are encrypted
  at rest and never returned by the API. ([#102], ADR-035)
- **WebAuthn / passkeys** — opt-in, phishing-resistant second factor alongside
  TOTP: origin-bound public-key assertions with no exportable shared secret and
  FIDO clone detection. Self-service registration of security keys / platform
  authenticators, and a two-step login that reuses the existing single-use
  challenge (no half-authenticated session is ever created). ([#103], ADR-036)
- **Deployment-mandated MFA** — `security.require_mfa` confines an interactive
  session without a second factor to the enrolment endpoints until the user
  enrols. Non-interactive credentials (personal access tokens, machine tokens,
  OIDC) are exempt so automation is never broken. ([#101], ADR-034)
- **Per-project MFA policy** — a project can require MFA for access to its scoped
  resources even when the deployment-wide policy is off, giving risk-proportionate
  step-up on a single install. A passkey or TOTP satisfies either mandate. ([#104], ADR-037)

### Security
- **Per-project MFA covers every project-scoped path** — a pre-merge security
  review found that secret *creation* authorised in-handler (the create route
  carries no path scope) and initially bypassed the per-project MFA gate; all
  in-handler-authorised mutations (secret create, dynamic-secret lease
  issue/revoke, rotation-policy create) now enforce it uniformly, with a
  regression test. ([#104])

[#101]: https://github.com/keyorixhq/keyorix/pull/101
[#102]: https://github.com/keyorixhq/keyorix/pull/102
[#103]: https://github.com/keyorixhq/keyorix/pull/103
[#104]: https://github.com/keyorixhq/keyorix/pull/104

## v0.4.0 — 2026-06-12

The security-hardening release: a new second factor, four subsystem security
audits with the findings fixed, and an auditor-ready evidence package.

### Added
- **Multi-factor authentication (TOTP)** — per-user opt-in second factor with a
  two-step login (a short-lived single-use challenge gates session issuance),
  single-use recovery codes, and the TOTP secret encrypted at rest. ([#99], ADR-034)
- **"Leave Vault in 5 minutes" demo** — a one-command, self-contained demo that
  stands up Keyorix + a throwaway Vault and migrates live secrets. ([#86])
- **Security verification & ENS evidence docs** — `SECURITY-VERIFICATION.md`
  (audits, fixes, CI gates) and `ENS-CONTROLS.md` (Spain's Esquema Nacional de
  Seguridad mapping), alongside the existing NIS2/DORA/ISO statement. ([#95], [#96])

### Security
Found by four subsystem security audits (auth/crypto/RBAC, HTTP, token/OIDC,
storage/remote-client), each fix regression-tested:
- **Cross-project privilege escalation / IDOR** — project-nested lifecycle routes
  (access-request approval, membership/machine-identity transitions, environment
  restore, invitation revoke/resend) acted on objects in a different project than
  the one the caller was authorised for. Now reconciled and rejected. ([#92], [#93])
- **Suspend/deactivate now revokes active sessions** — previously a suspended user
  kept access until their token expired. ([#87])
- **gRPC scoped RBAC** — secret and share operations over gRPC now enforce the same
  project-scoped permissions as HTTP (was the flat global set). ([#88], [#90])
- **Remote-client TLS secure-by-default** — an omitted `tls_verify` no longer
  disables certificate verification on the API channel. ([#97])
- **OIDC `jwks_uri` requires https** — signing keys are no longer fetched over
  plaintext. ([#94])
- **DEK-rotation completeness** — the re-encryption sweep is now ordered so a
  rotation can't skip rows and leave secrets under the old key. ([#89])

[#86]: https://github.com/keyorixhq/keyorix/pull/86
[#87]: https://github.com/keyorixhq/keyorix/pull/87
[#88]: https://github.com/keyorixhq/keyorix/pull/88
[#89]: https://github.com/keyorixhq/keyorix/pull/89
[#90]: https://github.com/keyorixhq/keyorix/pull/90
[#92]: https://github.com/keyorixhq/keyorix/pull/92
[#93]: https://github.com/keyorixhq/keyorix/pull/93
[#94]: https://github.com/keyorixhq/keyorix/pull/94
[#95]: https://github.com/keyorixhq/keyorix/pull/95
[#96]: https://github.com/keyorixhq/keyorix/pull/96
[#97]: https://github.com/keyorixhq/keyorix/pull/97
[#99]: https://github.com/keyorixhq/keyorix/pull/99

## v0.3.0 — 2026-06-11

The "adopt Keyorix" release: a complete path to bring your secrets in, install
the CLI, run it in CI, and deploy to Kubernetes.

### Added
- **Live secret migration** — `keyorix secret import --source {vault|aws|azure}`
  pulls secrets directly from a running HashiCorp Vault, AWS Secrets Manager, or
  Azure Key Vault (in addition to the existing file imports). Credentials stay
  client-side; the source is read-only. ([#79])
- **CI/CD integration** — a reusable GitHub Action
  (`keyorixhq/keyorix/integrations/github-action`) that injects secrets into a
  workflow as masked environment variables, plus GitLab CI and CircleCI
  examples. ([#82])
- **Kubernetes Helm chart** (`deploy/helm/keyorix`) — deploy the server + web UI
  + PostgreSQL to a cluster; bundled or external database; optional ingress;
  `helm test` hook. Published to `oci://ghcr.io/keyorixhq/charts` on release.
  ([#83], [#84])
- **Release pipeline** — a tagged workflow that cross-compiles and publishes the
  CLI + server binaries (with checksums) and the Helm chart on every `vX.Y.Z`
  tag. ([#81], [#84])

### Fixed
- **`install.sh`** downloaded assets under the wrong names (hyphens vs the
  published underscores), so it never worked against a real release. Corrected
  the names and added SHA-256 checksum verification. ([#80])
- A `.gitignore` pattern (`keyorix`) matched any nested directory of that name,
  silently hiding the new Helm chart from git. ([#83])

[#79]: https://github.com/keyorixhq/keyorix/pull/79
[#80]: https://github.com/keyorixhq/keyorix/pull/80
[#81]: https://github.com/keyorixhq/keyorix/pull/81
[#82]: https://github.com/keyorixhq/keyorix/pull/82
[#83]: https://github.com/keyorixhq/keyorix/pull/83
[#84]: https://github.com/keyorixhq/keyorix/pull/84

## v0.2.0 — 2026-04-27

Earlier release (binaries published out-of-band, before the automated pipeline).

## v0.1.0 — 2026-04-20

Initial tagged release.
