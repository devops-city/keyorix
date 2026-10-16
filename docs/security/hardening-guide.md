# Keyorix Production Hardening Guide

> **Positioning.** A checklist for taking a Keyorix deployment from default
> configuration to a production-appropriate one. Every config key named below
> was verified to exist in `internal/config/config.go` at the time of writing —
> if a key here doesn't match your running version, check that file directly
> rather than assuming this guide is current. See
> [`../security/architecture.md`](./architecture.md) for what each mechanism
> does and why, and [`../security/threat-model.md`](./threat-model.md) for the
> risk each item addresses.

## 1. Transport (TLS)

| Setting | Key | Recommendation |
|---|---|---|
| Require TLS on every listener | `security.require_transport_tls` | `true` in production. Refuses to start an enabled HTTP/gRPC listener with no TLS configured — fail closed rather than silently serving bearer tokens and secret values in cleartext. Leave `false` only if a TLS-terminating reverse proxy sits in front (the server still warns loudly if it ends up serving cleartext either way). |
| Server-terminated TLS | `server.http.tls.{enabled,cert_file,key_file}`, `server.grpc.tls.{enabled,cert_file,key_file}` | Set both if not using a front proxy or the Caddy profile. |
| Cipher suite allowlist | `server.http.tls.allowed_ciphers` / `server.grpc.tls.allowed_ciphers` | Leave unset to use the built-in secure AEAD-only default; only set to *further* restrict — any name outside `SecureCipherSuiteNames` is rejected at startup, not silently ignored. |
| TLS 1.3-only | `server.http.tls_mode` / `server.grpc.tls_mode` (`"strict"`) | Set once every client that will ever connect can speak TLS 1.3 — the default (1.2 floor, forward-secret AEAD ciphers) is already compliant, not a weaker fallback to graduate away from on a fixed timeline; `allowed_ciphers` has no effect once set. |
| Bundled auto-HTTPS | `docker compose --profile tls up` | Simplest path for a real public domain — auto-provisions a publicly-trusted certificate via Caddy. |

## 2. Encryption key management

| Decision | Key | Recommendation |
|---|---|---|
| KEK source | `encryption.key_provider.type` | For production, prefer `aws-kms` / `gcp-kms` / `azure-kms` / `tpm` over `password` (the default). This is the single highest-leverage decision in this guide — with a file/password-derived KEK, host root already has everything (see `threat-model.md` §5.1); with a KMS/HSM-backed KEK, host compromise alone is insufficient. |
| KMS install binding | `encryption.key_provider.kms_encryption_context` | Set to a value unique to this install (e.g. `{keyorix-install: <id>}`) if multiple Keyorix installs share one cloud CMK — prevents a different install's wrapped KEK from being planted and decrypting under this install's identity. Not supported for `azure-kms` (hard startup error if attempted, not a silent no-op). |
| Fallback chain | `encryption.key_provider.fallbacks`, `.insecure_allow_weaker_kek_fallback` (deprecated alias: `allow_weaker_fallback`) | Do not set `insecure_allow_weaker_kek_fallback: true` in production unless actively migrating — it is what allows a transient KMS/TPM outage to silently downgrade the deployment's real security floor. |
| Shamir split custody | `encryption.key_provider.type: shamir`, `.shamir_share_files`/`.shamir_share_env`, `.shamir_commitment` | If splitting KEK custody across people/systems, always set `shamir_commitment` (from `keyorix encryption shamir-split`'s own output) — without it, reconstruction is checked only by a forgeable 4-byte magic value. |

## 3. Recovery key custody

`keyorix-server admin recover-admin` (ADR-108 §B.2, `security.recover_admin`)
is a two-factor break-glass: it requires **both** host access **and** a
separately-held recovery key. This buys real security only if the key is
actually kept separately:

- **Store the recovery key offline, apart from the host** — a password
  manager, a sealed envelope, an HSM-backed secrets vault. If it lives on the
  same host (a file, an env var read at deploy time), the two-factor design
  collapses to one factor, which is exactly the keyless-mode risk profile
  without the mode being explicitly enabled.
- **Rotate the recovery key after any personnel change** with access to it —
  an operational control, not something the code enforces for you.
- **Do not enable keyless mode** in any environment other than a lab/demo. It
  deliberately collapses "host access" into "admin access," which is precisely
  what the default (required) mode exists to prevent.
- **On a file-based KEK install, say so to anyone relying on this control**:
  the recovery key protects the admin *account* from someone who is not you —
  it does not protect *secrets* from host root, which already holds the KEK
  material. Only a KMS/HSM-backed KEK (§2) makes the recovery key meaningfully
  add security against a host-compromise actor specifically.

## 4. Authentication hardening

| Setting | Key | Recommendation |
|---|---|---|
| MFA mandate | `security.require_mfa` | `true` deployment-wide, or scope to sensitive projects only via the per-project override (ADR-037) if a blanket mandate isn't feasible yet. TOTP and WebAuthn/passkeys both satisfy it; WebAuthn is phishing-resistant and preferred where client hardware supports it. |
| Password policy | `auth.password_policy.{min_length,require_uppercase,require_lowercase,require_digit,require_special,reject_personal_info,reject_common_passwords,history_count,max_age_days}` | Set explicitly rather than relying on defaults — a partial block only overrides the rules it names, so specify every rule you care about. Conservative baseline: 16-char minimum, full complexity, common-password rejection, and a non-zero history count. |
| Login lockout | `security.login_lockout.{max_attempts,window,base_cooldown,max_cooldown}` | On by default (`insecure_disable_login_lockout: false`, deprecated alias: `disabled`); tune `max_attempts`/`window` down for a higher-security posture. This is a per-account control, distinct from and complementary to per-IP rate limiting — keep both enabled, since a distributed guess against one account evades a per-IP limiter alone. |
| Rate limiting | `server.http.ratelimit.{enabled,requests_per_second,burst}` | Enable; tune burst/rate to observed legitimate traffic before an incident forces a rushed change. |
| Session/PAT tokens | issued via the API; PAT scoping is per-token, ADR-042 | Scope every automation PAT to the narrowest permission allowlist and, where the automation is single-project, a `ProjectScope` — a leaked unscoped PAT has the owner's full blast radius, a scoped one doesn't. |

## 5. Audit and monitoring

| Setting | Key | Recommendation |
|---|---|---|
| Checkpoint signing | `audit_checkpoints.{insecure_disable_audit_checkpoints,schedule}` (deprecated alias: `disabled`) | Leave enabled (the default whenever an encryption signing key is available) — this is what makes tail-truncation and genesis re-seed detectable, not just row-level tampering. Only set `insecure_disable_audit_checkpoints: true` with a documented reason. |
| External RFC 3161 anchoring | `audit.checkpoint_notary.{enabled,url,ca_cert_path}` | Opt-in; enable for the strongest guarantee against a host-admin-level adversary — this is the one check needing no shared secret and no trust in this host, since it's a third-party TSA. Set `ca_cert_path` — without it, anchoring still records tokens but verification fails closed on every check, since an untrusted issuer must not be trusted. |
| Offline-verify default anchor | `audit.offline_anchor_path` | Point at a signed checkpoint export (`admin audit export-checkpoint`'s output) held on write-once media, so `verify-audit`'s `--anchor` doesn't have to be remembered on every run — an explicit `--anchor` flag still overrides this when both are set. |
| Offline verification | `keyorix-server admin verify-audit` | Run on a schedule (nightly), append `--json` output to an off-box log — this *is* the operationalized external anchor `OFFLINE-AUDIT-VERIFICATION.md` describes. |
| SIEM forwarding | `audit.siem.{enabled,provider,endpoint,token or KEYORIX_SIEM_TOKEN,spool_dir}` | Enable for any regulated deployment — `spool_dir` gives a durable on-disk backlog so a SIEM outage doesn't silently lose the off-box audit copy. Use `KEYORIX_SIEM_TOKEN` rather than the inline `token` key so the credential isn't checked into a config file. |
| SIEM endpoint transport | `audit.siem.{insecure_allow_private_network_siem_target,insecure_allow_plaintext_siem_transport}` (deprecated aliases: `allow_private_network_target`, `allow_insecure_transport`) | Leave both `false` (the default) unless the SIEM collector is genuinely on a private network / self-signed — each opt-out is independently logged; don't flip one to work around the other's check. |
| What to monitor | anomaly-detection alerts, `GET /api/v1/audit/retention` | Watch built-in brute-force/unusual-access alerts, and periodically check `meets_nis2_12_month` / `coverage_days` on the retention endpoint as a durable evidence figure for an auditor, not just an internal metric. |
| Audit commit durability | `storage.database.audit_durability` (`strict` \| `standard`) | PostgreSQL defaults to `standard`; SQLite is always `strict`. Set `strict` if every disclosed secret must have an audit record that survives power loss. See §5a. |
| Secret-read auditing | `storage.database.insecure_audit_skip_reads` | Leave `false` (the default). `true` stops auditing successful secret reads entirely. See §5b. |

### 5a. Audit durability levels

`storage.database.audit_durability` (ADR-112 Amendment 3; spec:
[`../specs/fast-audit-mode.md`](../specs/fast-audit-mode.md)) chooses whether
the audit commit waits for the disk sync. It can only be set in the config
file; no API, CLI flag or environment variable can change it. At both levels
the audit row is written and committed **before** the secret is returned, and
a failed audit write fails the request.

| | `strict` | `standard` (PostgreSQL default) | Vault / OpenBao file audit device |
|---|---|---|---|
| Before the secret is returned | audit row committed **and synced to disk** | audit row committed; the disk sync is not awaited | one `write()` to an append-only file, buffered by the OS, never `fsync`ed |
| Audit write fails | request fails | request fails | request fails |
| Server process crash (`kill -9`, OOM, panic) | loses nothing | loses nothing | loses nothing |
| OS crash, power loss, PostgreSQL crash | loses nothing | up to ~600 ms (3 × `wal_writer_delay`) of audit entries, as a tail | up to ~30 s of audit entries on Linux defaults (dirty page writeback) |
| Hash chain after a crash | intact | intact: a lost tail, never a gap or a fork | no hash chain |
| Backends | PostgreSQL, SQLite (SQLite's only level) | PostgreSQL only | — |

Non-audit writes (secret writes, revocations, rotations) commit durably at both
levels: `standard` relaxes only the audit transaction's own commit
(`SET LOCAL synchronous_commit = off`).

**Defaults.** PostgreSQL: `standard` (allowed: `standard`, `strict`). SQLite:
`strict` only; `audit_durability: standard` on SQLite refuses to start with
`storage.database.audit_durability: standard is only supported with PostgreSQL;
SQLite runs strict only -- remove the setting or set it to strict`. SQLite's
`synchronous` pragma is per-connection and Keyorix shares one pool across every
query, so relaxing it would relax every table, not only audit (Amendment 1's
rejection, which stands).

**Choose `strict`** when your compliance position rests on "every disclosed
secret has an audit record that survives power loss" (DORA, NIS2, ENS evidence
of access), or when the host's power and write cache are not under your
control (a laptop, a bare consumer SSD, a desktop VM):

```yaml
storage:
  database:
    audit_durability: strict
```

`standard` is reasonable where losing the host's volatile write cache is not a
realistic event: a UPS that shuts the host down cleanly, a RAID controller with
a healthy battery- or flash-backed write cache, or replicated cloud block
storage (EBS, GCP PD, Azure managed disks).

**How you can tell which level is in effect.**

- one `INFO` line in the server log at every start, for example
  `audit durability: standard (PostgreSQL default; committed before every
  disclosure; up to ~600 ms of entries can be lost to an OS crash or power
  loss; set audit_durability: strict to wait for the disk sync)`;
- `keyorix-server admin validate` prints `Audit durability: <level> (...)`, and
  `admin validate --posture` lists it as an informational line. Neither level
  is a posture deviation;
- `GET /api/v1/system/info` reports `security.audit_durability`;
- a level change between two starts is recorded in the hash chain by the
  start-to-start settings diff (`security.posture_setting_changed`, old and
  new value).

**Deprecated alias.** `storage.database.insecure_audit_skip_durable_sync` still
works for one minor release: `true` means `standard`, `false` means `strict`.
It logs a deprecation line at start-up; setting both keys to conflicting levels
refuses to start.

### 5b. `insecure_audit_skip_reads`: successful secret reads unaudited

`storage.database.insecure_audit_skip_reads: true` (ADR-112 Amendment 4) stops
**successful secret-value reads** from writing an audit row or an access-log
row. This applies on every path: REST, gRPC, render, copy, federated connector
reads, and the CLI, k8s sync, MCP and operator clients through the API. These
are still audited:

- secret create, update, rotate and delete;
- permission, role, share and policy changes;
- authentication and its failures;
- denied reads, native and federated (see below);
- admin and break-glass actions;
- configuration and key operations.

**What you give up.** Nothing records who read which secret, or when. Read
history, read counts, usage and billing read counts, the access-log export and
anomaly detection all go blind to reads. Max-reads limits still apply.

**Denied reads stay audited, so probing still leaves a trace.** At both
settings, a refused read writes a `secret.read` row with `success=false`,
`outcome=denied` and a `reason=` class: `forbidden`, `not_found`,
`outside_schedule`, `expired`, `suspended`, `max_reads_exhausted`,
`classification_gate` or `mfa_required`. A read that breaks is recorded as
`internal_error` with `outcome=failed`. This covers REST, gRPC, render, copy,
environment copy and clone; federated denials are `connect.secret_read`
rows as before. A burst is aggregated per principal, reason, path and target:
the first refusal is written at once, then one summary row per 60-second
window carries the count. A `forbidden` and a `not_found` row look the same to
the caller (no secret or project column); `audit.read` holders see the reason
and, in the row's diff, which secret it was.

**How loud it is.** Every start logs `WARNING: storage.database.insecure_audit_skip_reads
is in effect (true; ...) — secret reads are NOT audited ...` and writes an
`admin.audit_reads_skipped_at_startup` audit event. A change in the value
between two starts is audited by the settings diff. `admin validate` and
`admin validate --posture` report it as a deviation.
`GET /api/v1/system/info` reports `security.audit_reads_skipped: true`, and
the web UI shows a persistent banner.

It is set in the config file only (no environment variable, API or CLI flag).
A compliance profile refuses it. Rows that are still written follow
`audit_durability` as usual.

## 6. Backup and key-material custody

`keyorix-server admin backup`/`admin restore` (ADR-108 §B3) is the supported
mechanism on both SQLite and Postgres installs — see
[`../AIRGAP_RUNBOOK.md`](../AIRGAP_RUNBOOK.md) for the full drill procedure.
On SQLite the command needs the database to itself (stop the server first); on
Postgres it reads a single `REPEATABLE READ` snapshot beside the live server by
default, or takes the exclusive lock with `--exclusive`
([`../SELF_HOSTING.md`](../SELF_HOSTING.md) §5). A manual `pg_dump` remains an
option there, but it does not bundle the key-material files.

- **A complete backup is the database plus every encryption key-material
  file, bundled into one archive** (`admin backup --output <path>`) — neither
  alone is useful (§2). The command takes the same exclusive database lock
  every other `admin` subcommand does, so it refuses to run alongside a live
  server rather than risk a torn snapshot, and it self-verifies (SQLite
  `PRAGMA integrity_check` on a fresh connection to the snapshot) before
  trusting the archive.
- **`--output` must not already exist** — each backup is a distinct,
  timestamped artifact by construction, not something a schedule can
  accidentally overwrite.
- **Move the archive OFF this host** — a backup that never leaves the machine
  it was taken on protects against nothing that machine itself could lose.
- **Export a checkpoint anchor too, held separately from the backup archive**
  (`admin audit export-checkpoint --output <path>`) — the archive's per-file
  checksums prove it wasn't corrupted in transit, not that it wasn't
  tampered with; an anchor held outside this host is what actually
  constrains a host admin who holds both the database and its checkpoint
  signing key (`../AIRGAP_RUNBOOK.md` "Exporting an audit-chain anchor").
- **Record `KEYORIX_MASTER_PASSWORD` (or the file/fd/stdin passphrase)
  separately from both** — required to derive the KEK that unwraps the
  backed-up DEK, and losing it makes an otherwise-perfect backup pair useless.
- **Treat a backup pair plus the passphrase, for a file-KEK install, as
  equivalent to a stolen host** — see `threat-model.md` §5.3. Restrict backup
  storage access accordingly; a backup bucket with looser access control than
  the production host defeats the KMS/HSM decision in §2.
- **Test restore, not just backup, as a drill** — `admin restore` runs
  `admin verify-audit` automatically and fails (non-zero exit) if the chain
  reports BROKEN, but an untested restore procedure can still surface
  operational surprises (wrong config, wrong key-file paths) that are best
  found in a drill, not an actual incident. `admin restore
  --overwrite-existing` moves any existing target aside
  (`<path>.pre-restore-<timestamp>`) rather than truncating it, so a botched
  drill still has a way back.

## 7. Process and host hardening

- **Disable swap** on the node/container runtime running the server
  (Kubernetes' default already does this) — this is now the durable control
  against decrypted secret memory surviving in swap, replacing the removed
  in-process `mlockall` (ADR-100). Skipping this leaves the exact gap
  `mlockall` originally existed to close.
- **Core dump suppression is automatic and unconditional** (`RLIMIT_CORE=0`,
  ADR-098) — no configuration needed, and no way to disable it from
  application config. An external supervisor that explicitly raises
  `LimitCORE=`/`ulimit -c` before exec-ing the process is outside this
  control's reach; don't do that in a production unit file.
- **CLI local mode is equivalent to direct database access** (see
  `threat-model.md` §5.2) — restrict local-mode CLI access to exactly the set
  of people/systems you'd trust with a raw database connection, not the
  broader set you'd trust with API access. This changes once ADR-108's
  CLI/server split ships; until then, treat it as unaudited, unrate-limited
  DB access, because it is.

## 8. Kubernetes delivery (operator / sync agent / ESO)

- **Default to single-namespace scope** for the operator (ADR-076) — only opt
  into bounded-multi-namespace or cluster-wide watch if the deployment
  genuinely spans namespaces the operator needs to manage. A broader scope is
  a proportionally broader RBAC surface if the operator's ServiceAccount is
  ever compromised.
- **Scope the machine-identity token** backing whichever delivery mechanism
  you use (operator, sync agent, ESO) to exactly the projects/environments it
  needs to read — the same PAT/machine-identity scoping principle as §4.
- **Leave `networkPolicy.enabled` at its default (`true`)** on all three
  charts (`keyorix`, `keyorix-operator`, `keyorix-k8s-sync`) — it scopes
  ingress to the server/bundled-Postgres pods to same-namespace traffic only;
  without it every pod in the cluster that can route to the Service can reach
  them. The web UI's own ingress is deliberately left unrestricted (it's the
  intended public entry point).
- **`networkPolicy.egress.enabled` also defaults to `true`** — without it,
  every pod has always had unrestricted egress (any destination the cluster
  network permits, including cloud metadata endpoints), independent of the
  ingress restriction above. `web` and `postgresql` get a fully static,
  known egress surface for free (web only calls the server; postgresql never
  calls out). `server`'s real egress surface is not static — SSO/OIDC/SAML
  IdPs, webhook sinks, and rotation-target backends (Vault/AWS/Azure/GCP)
  are admin-configured destinations the chart can't know ahead of time — so
  **populate `networkPolicy.egress.extraRules`** with those destinations
  yourself; it is empty by default, and an empty allowlist here means
  egress restriction is providing zero defense-in-depth on the one pod
  whose destinations actually matter. A NetworkPolicy egress drop looks like
  a hung/timed-out call to the feature it's blocking, not a clear error, so
  populate this before relying on it, not after something breaks.

## 9. Connectors, rotation targets, and external secret stores

- **Set per-connector `allowed_refs`** — an operator-configured allowlist is
  the outer boundary regardless of any caller's RBAC grant; don't rely on RBAC
  alone to bound which external paths a connector can reach.
- **Do not weaken the SSRF/link-local guard** — there is no supported
  configuration key to disable `internal/netutil`'s SSRF checks on connector/
  dynamic-secret/DSN-driven calls; if a legitimate target trips it (e.g. a
  genuinely intended private-network destination), that is a signal to
  re-examine the target, not to look for a bypass.

## 10. Supply chain and updates

- **Verify release artifacts before deploying them.** The `keyorix-server`
  image and `charts/keyorix` OCI chart publish to `ghcr.io`; pull with `helm
  pull` against the specific OCI reference (not the GitHub packages API, which
  does not reliably enumerate OCI-chart artifacts) and check the digest
  against what you expect.
- **For air-gapped installs, verify update bundles**
  (`keyorix bundle verify`) against the embedded, pinned `ed25519` public
  key before `import` — this is the offline equivalent of image-digest
  verification, and skipping it defeats the entire point of a signed bundle.
- **Pin a release tag, not `latest`**, in production
  (`docker-compose.yml` image tags) — `latest` makes an upgrade
  non-reproducible and complicates rollback.

## 11. What this guide does not cover

Network segmentation and firewalling, host OS patching cadence, PostgreSQL's
own hardening (connection limits, `pg_hba.conf`, encryption-at-rest for the
volume itself), and physical/facility security remain entirely the operator's
responsibility — see `architecture.md` §9 for the full list of what's
deployment-owned rather than an application-layer control.
