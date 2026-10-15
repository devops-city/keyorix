# ADR-112: Secure-by-default baseline, and loud, audited opt-outs

## Status

**Proposed** (2026-10-02). Two decisions are already recorded (see "Decisions recorded"); the remaining open questions are listed at the end.

Amended 2026-10-05 (decision by Andrei, "Amendment 1" below): the
audit-before-disclosure and `synchronous` baseline items gain one named
`insecure_` opt-out, `storage.database.insecure_audit_skip_durable_sync`,
**PostgreSQL only**. The defaults are unchanged, and SQLite's
`synchronous=FULL` becomes unconditional rather than merely default. Full spec
(Accepted): `docs/specs/fast-audit-mode.md`.

Amendment 3 (2026-10-15, **accepted by Andrei**): the audit durability opt-out
becomes `storage.database.audit_durability = strict | standard`, two baseline
levels rather than an `insecure_` opt-out, with `standard` the PostgreSQL
default and SQLite `strict` only. `insecure_audit_skip_durable_sync` becomes a
deprecated alias for one minor release. See "Amendment 3" below.

Amendment 4 (2026-10-15, **accepted by Andrei**): a new `insecure_` opt-out,
`storage.database.insecure_audit_skip_reads`, default false. When set,
successful secret-value reads write no audit row; everything else stays
audited. See "Amendment 4" below.

Amendment 2 (2026-10-10, **proposed, pending Andrei's OK**, #2908): the
`enable_file_permission_check` upgrade grace period is a reported state:
a start-up warning, a settings-diff value and a posture deviation.

Related: ADR-111 (signed connector host, host connector allowlist), ADR-098 (process memory hardening), ADR-064 (air-gap update bundles), ADR-109 (air-gapped build profile).

A read-only gap check of `main` @ 219160b2 against this baseline (2026-10-02) found 9 of 22 items in place, 5 partial and 8 missing; see "Gap check results".

## Context

Keyorix's promise is "easy to operate, secure by default, with opinionated settings from experienced security people". Today that is true in many places (fail-closed startup, no default passwords, hash-chained audit, signed releases), but it isn't written down as one baseline, so:
- nobody can check a deployment against it in one step;
- a new feature can ship with a weaker default without anyone noticing;
- an operator can weaken a setting without the change being visible to auditors.

Regulated buyers (DORA, NIS2, ENS, CRA) ask for exactly this: what the secure configuration is, and how deviations are detected.

## Decision (proposed)

### 1. The opt-out rule

Every setting that weakens security below the baseline:
- is named with an `insecure_` prefix (for example `insecure_allow_plain_http`), so it can't be enabled by accident or misread in review;
- logs a warning at **every** start, naming the setting;
- is audited when it changes: config has no hot reload, so at every start the server compares the security-relevant settings with those recorded at the previous start and writes an audit event with the old and new values for any difference;
- appears in the posture report (below) as a deviation.

No setting may weaken security silently. A new feature's defaults must meet the baseline; a PR that adds a weaker default must use an `insecure_` setting instead.

### 2. The posture report

`keyorix-server admin posture` (or an extension of `admin validate`) prints every deviation from the baseline: `insecure_*` settings in effect, file permissions, TLS configuration, admin MFA coverage, key rotation age, connector allowlist contents. It exits non-zero when any deviation exists, so it can run in CI or monitoring. The same data is available read-only over the API for dashboards.

### 3. The baseline

Each item is a default that holds unless an `insecure_` setting says otherwise.

**Process and host**
- Refuse to start if config, database or key files are readable by group or others (as `ssh` does with keys). The server already sets umask 0077 for files it creates (#1647).
- Core dumps disabled and the process marked non-dumpable, so a crash can't write keys or secrets to disk.
- Runs as non-root. The shipped systemd unit and container image are hardened: read-only root filesystem, no new privileges, no extra capabilities, minimal base image.
- Key material is wiped from memory after use where Go allows it (byte slices, not strings).

**Network**
- TLS 1.3 preferred; TLS 1.2 allowed by default but only with forward-secret AEAD cipher suites. TLS 1.0/1.1 are never accepted. A single setting (`tls_mode: strict`) switches to TLS 1.3 only, and the posture report shows which mode is in effect. Rationale: NIST SP 800-52 Rev. 2 requires servers to support both 1.2 and 1.3, BSI TR-02102-2 prefers 1.3 while planning 1.2's phase-out, and OT and legacy clients still need 1.2; TLS 1.2 with modern ciphers is therefore compliant, not an `insecure_` opt-out.
- No plaintext listener except a localhost health endpoint.
- Optional mutual TLS for machine identities.
- Administrative endpoints on a separate listener bound to localhost by default.

**Identity and access**
- No default credentials; first access uses the one-time bootstrap token.
- MFA required for admin accounts by default.
- Short default session lifetime; short-lived machine tokens; revocation takes effect immediately (#G18).
- Break-glass stays single-person, so it works in a real emergency, but it always produces an immediate alert and an audit event, and every activation must be reviewed afterwards: an open activation without a recorded review shows as a posture deviation. This matches the market (Infisical's "bypass approvals" works the same way) and DORA, which requires emergency access on a need-to-use basis and segregation of duties but not multiple approvers (RTS 2024/1774 Art. 21).
- Approval workflows ("dual control": a second person must approve before a secret is read, for selected policies) are a separate, later feature, not part of this baseline. Vault (control groups) and Infisical (access requests) both sell this as an enterprise feature; whether Keyorix includes it in the AGPL core or gates it is an open licensing decision (see open questions). Key-management dual control (PCI DSS 3.6/3.7) is already covered by the Shamir recovery split.
- Authorization is deny by default; any error while resolving permissions denies (fail closed). The fault-injection fuzzer's oracle (c) enforces this; #2412 is a current violation.

**Secrets and audit**
- A secret value is never returned before its audit record is committed (audit-before-disclosure, group commit). If the audit write fails, the read fails. `storage.database.audit_durability` chooses whether that commit also waits for the disk sync: `strict` waits, `standard` (the PostgreSQL default) skips only the *wait for the disk sync*, not the write and not the fail-closed behaviour — see Amendments 1 and 3.
- Secret values never appear in logs, error messages, URLs or metrics. Enforced by a test oracle over all operations, not by review alone.
- The audit log is hash-chained with signed checkpoints and offline verification (exists).
- SQLite runs `synchronous=FULL`, **unconditionally — no setting relaxes it**; Postgres runs with `fsync`, `synchronous_commit` and `full_page_writes` on (#2403). `storage.database.audit_durability: standard` (**PostgreSQL only**, the PostgreSQL default) is the only setting that relaxes any of this, and only `synchronous_commit`, only on the audit transaction, as described in Amendments 1 and 3. A SQLite backend set to `standard` refuses to start.

**Keys**
- Scheduled KEK rotation on by default, with a configurable interval.
- HSM/KMS key protection available as an option (exists: `server/admin/encryption.go`).
- The recovery key can be split among several people (Shamir), so no single person can recover alone (exists: `internal/crypto/shamir_provider.go`).

**Supply chain and updates**
- Every binary is signed (Ed25519/cosign), with SBOM and SLSA provenance (exists).
- The connector host is signature- and version-verified before it runs, and only allowed connector types and destinations are reachable (ADR-111).
- Update bundles, including air-gapped ones, are signed and **cannot downgrade**: an older bundle is refused even with a valid signature, so an attacker can't "update" a server to a known-vulnerable version (exists, with tests).

### 4. Enforcement in CI

- A test per baseline item that fails if the default changes.
- A test that every config key weakening security uses the `insecure_` prefix, the start-up warning and the audit event.
- The posture command run against the default configuration must report zero deviations.

## Gap check results (2026-10-02)

9 of 22 items exist, 5 are partial and 8 are missing.

**Exists:** bootstrap-token-only admin creation (no default credentials); hash-chained, signed audit log with offline verification; key-material memory wiping; HSM/KMS key protection; Shamir recovery-key split; signed binaries with SBOM and SLSA provenance; signed update bundles with tested downgrade protection; deny-by-default authorization; a posture-report foundation (`admin validate`, `keyorix compliance report`).

**Inverted defaults (fix first):** `enable_file_permission_check` and `require_mfa` are off unless enabled, so the weak state is the default. Flip both; existing deployments get a grace period with a start-up warning and a posture deviation until they comply.

**Missing or partial, in priority order:**
1. Audit-before-disclosure: secret values are returned before a fire-and-forget audit write (`secrets_crud.go`). In progress (group commit, alongside the read-throughput work).
2. Fail-closed authorization on the MFA path: #2412. In progress.
3. The opt-out rule: only 4 of 32 security-weakening settings use the `insecure_` prefix; none warns consistently or is audited on change. Work: rename with deprecation aliases, start-up warnings, start-to-start settings diff audited, plus the structural CI test.
4. Posture report: `admin validate --posture` with a non-zero exit on deviations.
5. TLS: keep 1.2 as the floor, restrict it to forward-secret AEAD suites, add the TLS 1.3-only strict mode, and show the mode in the posture report.
6. Separate admin listener bound to localhost.
7. Scheduled KEK rotation (manual only today).
8. Break-glass: keep single-actor (decided 2026-10-02); add the mandatory post-activation review and its posture deviation.
9. Optional mutual TLS for machine identities.
10. CI enforcement: one test per baseline item and the zero-deviation posture gate.

## Amendment 1 (2026-10-05): fast audit mode, an `insecure_` opt-out for guaranteed-power deployments

Decision by Andrei, 2026-10-05. Spec: `docs/specs/fast-audit-mode.md`.

### Why an opt-out is warranted here specifically

PERF-2 measured Keyorix at ~10x Vault's single-client read latency on pve01
(8.36ms vs 1.30ms p50) **with Vault's own file audit device enabled**, and
confirmed that at c=1 essentially the entire 8.36ms is one durable Postgres
commit (the independently measured `fdatasync` floor on that disk is 9.33ms). A
source-verified read of each competitor's audit write path
(Vault, OpenBao, Conjur, Infisical) found that **none of them fsync audit before
answering**: Vault and OpenBao do one `write()` to an `O_APPEND` file with no
`fsync` anywhere, Conjur fires into syslog, Infisical queues to Redis and
swallows request-path errors. Their speed is not a technique Keyorix is missing;
it is the durability Keyorix declines to skip.

That makes audit-before-disclosure a genuine differentiator worth keeping as the
default — and it also makes "I have a UPS and a battery-backed write cache, give
me Vault's number" a legitimate operator request that the baseline should answer
with a named, loud, audited setting rather than with a fork or a patch.

### The opt-out

`storage.database.insecure_audit_skip_durable_sync`, boolean, default **false**,
settable from the config file only. **PostgreSQL only** (decided 2026-10-05):
the audit-commit transaction, and only that transaction, issues `SET LOCAL
synchronous_commit = off`. `SET LOCAL` is transaction-scoped, so a concurrent
secret write still commits durably and the relaxation cannot follow the pooled
connection into the next transaction.

| `storage.type` | Behaviour |
|---|---|
| `postgres` / `postgresql` | supported; in effect when true |
| `local` / `sqlite` | **refuses to start** with a named error |
| `remote` | not applicable — a server cannot run with remote storage (ADR-083) |

It carries the full §1 opt-out treatment: a `WARNING:` line at **every** start, an
`admin.audit_durable_sync_skipped_at_startup` audit event at every start (so the
tamper-evident chain itself records the window the install ran weakened), an entry
in the `insecure_` registry, a line in `admin validate`'s posture output, and a
boolean in `GET /system/info` so a buyer's auditor can see it without host access.

### What the mode does and does not change

Unchanged, and tested to stay unchanged:

- The audit row is still INSERTed and COMMITted in the same transaction/batch,
  before the secret value is returned. No background writer, no queue.
- If the audit row cannot be written, the request still fails. Only the *wait for
  the disk sync* is skipped.
- The hash chain can lose a **tail** of entries to an OS crash or power loss. It
  can never gap or fork: WAL (Postgres) and `-wal` frames (SQLite) are totally
  ordered and recovery accepts only a valid prefix, so a surviving row's
  `prev_hash` always points at a row that also survived. `verify-audit` must pass
  after a `kill -9` under load, on both backends, and there is a test for it.

Changed, and stated plainly rather than minimised:

- Up to ~600ms (3 × `wal_writer_delay`) of audit entries can be lost to an OS or
  database-server crash. Measured effect of accepting that: a single-client read
  goes from 16.6ms to 3.7ms p50 on pve01, i.e. from 11.8x to 2.7x slower than
  Vault with its own audit device on (both sides re-measured in the same
  session).

Rejected, with the reasons recorded so the decision does not have to be
re-litigated:

- **SQLite.** `PRAGMA synchronous` is per-connection and the pool is shared, so
  the relaxation would be database-wide, not audit-only — a power loss could
  undo a just-committed secret rotation or revocation. And it was not a clean
  latency win: p99 got worse at 10 and 50 clients. The narrower alternative
  (flip the pragma per transaction, restore afterwards) was rejected separately
  for failing open — a skipped restore leaves a pooled connection permanently
  weakened with nothing reporting it.

This is Vault's guarantee, not a safe one, and the hardening guide says so in
those words.

## Amendment 2 (2026-10-10, PROPOSED — needs Andrei's OK): the grace period is a reported state, not a clean one

#2908, decided by Andrei 2026-10-10 to fix after #2454 and #2478. The gap check
above says existing deployments get "a grace period with a start-up warning and
a posture deviation until they comply". For `enable_file_permission_check` only
the start-up warning existed: its `insecure_skip_startup_validation` registry
entry was the boolean `!enable_file_permission_check`, which is false all through
the grace period, so a deployment whose failed startup checks only **warn** was
reported as clean by the §1 start-up warning, the §1 settings-diff audit and the
§2 posture report.

The setting now has four states, the registry entry's settings-diff value:

| State | When | Deviation |
|---|---|---|
| `off` | `enable_file_permission_check: false` written | yes (explicit) |
| `grace-warn-only` | key absent, upgraded deployment (users exist) with no `adr112.file_permission_check.enforced` marker: a failed check only warns | **yes** (shipped default) |
| `enforcing-implicit` | key absent, fresh install or already ratcheted past the grace period | no |
| `enforcing-explicit` | `enable_file_permission_check: true` written | no |

Choices made where neither #2908 nor this ADR was explicit, each the stricter option:

- **Four states, not three.** #2908 names three (off / enforcing implicitly /
  explicitly enabled). The implicit default covers two different behaviours
  since the grace decision moved into the database (fresh installs enforce,
  upgrades warn), so "implicit" is split. Every pair has its own value, so every
  transition (entering or leaving the grace period, writing the key down) is an
  audited settings-diff change. `enforcing-implicit` is not a deviation because
  §4 and the definition of done require zero deviations for the default
  configuration, which is that state.
- **The posture report decides the grace period from the database**, using
  the same facts as the boot. If the database cannot be read, an
  implicit-default deployment is counted as a deviation (cannot be shown to be
  enforcing), not reported as enforcing.
- **The registry warning moves after the grace decision at boot**, and names
  the state (`... is in effect (grace-warn-only)`).
- **Derived fields are swept.** The grace state lives in fields the config file
  cannot set (`yaml:"-"`), which the config-surface sweep skipped. Every such
  field must now be read by a registry entry (`DerivedInputs`) or exempted with a
  reason. `require_mfa`'s two are exempted for now: it has no registry entry at
  all (#2986).

Upgrade note: the settings-diff value of `security.insecure_skip_startup_validation`
changes from `true`/`false` to the state names, so the first boot after upgrade
writes one audit event for it.

## Amendment 3 (2026-10-15): audit durability levels, `standard` by default on PostgreSQL

Accepted by Andrei, 2026-10-15. Supersedes the opt-out shape of Amendment 1
(the mechanism, its scope and its crash argument are unchanged); Amendment 1's
rejection of SQLite stands. Spec: `docs/specs/fast-audit-mode.md`.

### The decision

One setting, `storage.database.audit_durability`, config file only:

| Level | Meaning |
|---|---|
| `strict` | The audit commit waits for the disk sync (the pre-Amendment-3 default). No audit entry is lost to any crash or power loss. |
| `standard` | The audit row is still INSERTed and COMMITted before the secret is returned (audit-before-disclosure unchanged; a failed audit write still fails the request). Only the wait for the disk sync is skipped: `SET LOCAL synchronous_commit = off` on the audit transaction only, exactly Amendment 1's mechanism. A Keyorix process crash loses nothing; an OS crash, power loss or PostgreSQL crash can lose up to ~600 ms (3 × `wal_writer_delay`) of audit entries as a TAIL, never a gap or fork (the WAL-prefix argument in the spec, §5, and `TestFastAuditMode_PostgresCrashLosesOnlyATail`). |

Non-audit writes (secret writes, revocations, rotations) always commit durably
at both levels.

| `storage.type` | Default | Allowed |
|---|---|---|
| `postgres` / `postgresql` | `standard` | `standard`, `strict` |
| `local` / `sqlite` | `strict` | `strict` only; `standard` refuses to start with a named error |

### Reporting

`standard` is the PostgreSQL baseline, **not** a posture deviation, and neither
is `strict`. The setting is therefore not an `insecure_` registry entry (§1's
rule applies to settings that weaken security below the baseline; both levels
are the baseline). Instead:

- every start logs one `INFO` line (not `WARNING`) with the effective level and
  its meaning, e.g. `audit durability: standard (PostgreSQL default; committed
  before every disclosure; up to ~600 ms of entries can be lost to an OS crash
  or power loss; set audit_durability: strict to wait for the disk sync)`;
- a level change between two starts is audited by §1's start-to-start settings
  diff (old and new value). The diff records the EFFECTIVE level, so a default
  changing on upgrade is recorded too, not only an edit of the config file;
- `GET /system/info` (`security.audit_durability`) and `admin validate` report
  the effective level; `admin validate --posture` shows it as an informational
  line, so a default PostgreSQL install still reports zero deviations (§4).

Removed with the registry entry: Amendment 1's per-start `WARNING`, its
per-start `admin.audit_durable_sync_skipped_at_startup` audit event (the
settings-diff event replaces both), and the `audit_durable_sync_skipped` /
`audit_durable_sync_skip_not_in_effect_reason` fields of `GET /system/info`.

### Migration

`storage.database.insecure_audit_skip_durable_sync` is a deprecated alias for
one minor release: `true` → `standard`, explicit `false` → `strict`. Both keys
set with conflicting levels refuses to start; the old key logs a deprecation
line at start-up. Existing PostgreSQL installs that set neither key move to
`standard` on upgrade (there are no production customers yet). The release
notes, `docs/UPGRADING.md` and the start-up line say so, with how to stay on
`strict` (`audit_durability: strict`).

### Comparison

Vault's and OpenBao's file audit device writes each entry with one `write()` to
an append-only file and never calls `fsync`: a process crash loses nothing (the
entry is in the OS page cache), but an OS crash or power loss can lose
everything not yet written back, up to ~30 s on Linux's default dirty-page
writeback. `standard`'s window is ~600 ms and `strict`'s is zero; at both
levels the hash chain can lose only a tail.

### Enforcement

Default per backend, SQLite refusal, alias mapping and conflict refusal
(`internal/config/audit_durability_test.go`); config-file-only reachability
(`audit_durability_reachability_test.go`); non-audit writes durable at
`standard` (`TestAuditDurabilityStandard_NonAuditWritesStayDurable`, pg-gated);
the crash test at both levels (`TestFastAuditMode_PostgresCrashLosesOnlyATail`,
`TestAuditDurabilityStrict_PostgresCrashLosesNothing`, manual); the settings-diff
event (`TestSecurityPostureSnapshot_AuditsAuditDurabilityLevelChange`); zero
posture deviations on a default PostgreSQL install
(`TestCollectAuditDurabilityPosture_DefaultPostgresIsNotADeviation`); the INFO
line (`TestLogAuditDurability_StartupInfoLine`); the real binary on PostgreSQL
(`TestAuditDurability_PostgresEndToEnd`) and SQLite
(`TestAuditDurability_SQLiteRefusesStandardEndToEnd`,
`TestAuditDurability_SQLiteDefaultBootIsStrict`).

## Amendment 4 (2026-10-15): `insecure_audit_skip_reads`, successful secret reads unaudited

Accepted by Andrei, 2026-10-15. Independent of Amendment 3.

### The decision

1. `storage.database.insecure_audit_skip_reads`, boolean, default **false**,
   config file only. When true, a SUCCESSFUL secret-value read does not write an
   audit row. This covers every path that discloses a value: REST, gRPC,
   connectors/sync/injection, and the CLI through the API. Everything else stays
   audited: secret create/update/delete and version changes;
   permission/role/share/policy changes; authentication events and failures;
   DENIED reads; admin and break-glass actions; configuration and key
   operations.
2. Loud, per §1: the `insecure_` prefix and a registry entry; a `WARNING` at
   every start ("secret reads are NOT audited"); an
   `admin.audit_reads_skipped_at_startup` audit event at every start; a
   start-to-start settings-diff event when the value changes; a posture
   deviation in `admin validate`; a flag in `GET /system/info`; a persistent
   web UI banner.
3. Refusal hook: a compliance profile setting refuses this setting, if one
   exists or whenever one is added. Denied reads are always audited.
4. Independent of `audit_durability`: that level governs every row that is
   still written.

### How it is implemented

- **Where the skip happens.** It is in `internal/core/audit_skip_reads.go`, at
  the three audit-emit choke points every core audit write passes through
  (`emitAudit`, `emitAuditOn` and `emitAuditWithAccessLog`;
  `TestDirectLogAuditEventCallersAreSafe` keeps it that way). The check runs
  before any storage call, so a skipped read opens no database transaction and
  takes no audit-chain lock. That also holds under `single_writer`: a skipped
  read never reaches the write path.
- **What it skips.** Exactly two event types, and only with `Success=true`:
  - `secret.read`: every native value read through
    `LogSecretReadWithProject`. That is REST `GET /secrets/{id}?include_value=true`
    and `/secrets/value`, gRPC `GetSecretValue`, render, and the source read of
    a copy, environment copy or environment clone. The CLI, k8s sync, MCP and
    the operator all read through these routes.
  - `connect.secret_read`: a federated read through a connector.

  The atomic `secret_access_logs` row written with `secret.read` is skipped
  too. Writing it would need a transaction, and it is part of the same read
  record.
- **What it does not skip:**
  - `secret.metadata_read` and `secret.versions_listed`: no value is disclosed.
  - `dynamic_lease.issued`: this mints a credential, so it is a create.
  - `share_access_elevated`: it records that access came through a share.
  - `secret.certificate_inspected`: it covers public metadata only.
  - Every event with `Success=false`.
  - Every event written outside core: `server/admin`, `internal/encryption`,
    and the start-up events in `server/main.go`.
- **Denied reads.** The denied reads Keyorix audits today, the six
  `connect.secret_read` deny paths, stay audited (`Success=false`). Native
  value-read denials (403, 404, expired, suspended, schedule, max reads) write
  no audit row at either setting, on `main` as well. Adding them is a separate
  change that applies to both settings; it is not part of this amendment. Max
  reads is enforced by a counter on the secret, not by audit rows, so it is
  unaffected.
- **What operators lose.** Read history, read counts, `total_reads`, usage and
  billing read counts, the access-log export and anomaly detection all key on
  `secret.read` and access-log `read` rows. None of them see reads while the
  setting is on. The WARNING and the hardening guide say so.
- **Compliance profile.** No compliance profile setting exists yet.
  `config.complianceProfileGates` is the hook: `Validate` refuses
  `insecure_audit_skip_reads` while any registered profile is active.
  `TestInsecureAuditSkipReads_ComplianceProfileKeyIsGated` fails if a
  compliance-profile-looking key is added to Config without registering it
  there.

### Enforcement

| Claim | Test |
|---|---|
| default false | `TestInsecureAuditSkipReads_DefaultFalse` |
| registry entry | `TestInsecureAuditSkipReads_RegistryEntry`, plus the registry sweep |
| config file only | `TestInsecureAuditSkipReads_NoWriteAssignment`, `_NotSettableFromTheEnvironment`, `_ReferencesAreAllowlisted` |
| compliance profile refusal | `TestInsecureAuditSkipReads_RefusedByAnActiveComplianceProfile`, `_ComplianceProfileKeyIsGated` |
| a successful read writes nothing and opens no transaction | `TestInsecureAuditSkipReads_SuccessfulReadWritesNothingAndOpensNoTransaction` |
| a denied read is still audited | `TestInsecureAuditSkipReads_DeniedReadIsStillAudited` |
| one subtest per still-audited event class | `TestInsecureAuditSkipReads_EveryOtherEventClassStillAudited` |
| the skip set is exactly the two value-read types | `TestInsecureAuditSkipReads_SkipSetIsExactlyTheSuccessfulValueReads` |
| REST, through the real router, at both settings | `TestInsecureAuditSkipReads_RESTValueReadsUnauditedWritesAudited` |
| gRPC | `TestSecretService_GetSecretValue_InsecureAuditSkipReads` |
| `/system/info` | `TestMakeSystemInfoHandler_ReportsAuditReadsSkipped` |
| `admin validate` | `TestAppendAuditSkipReadsPosture` |
| the real binary | `TestInsecureAuditSkipReads_EndToEnd`: every-start WARNING and event over two starts, the settings diff, `validate` and `validate --posture`, a chain that verifies, and the default install showing none of it |

With the setting off, behaviour is unchanged. The existing
audit-before-disclosure tests are untouched and still pass.

## Consequences

- The baseline becomes part of the product's documentation and sales material: "here is the secure configuration, and here is how you prove you're running it."
- Some existing settings may need renaming to the `insecure_` form, with a migration note and a deprecation period for the old names.
- Every new feature carries a small extra cost: its defaults must meet the baseline, and any weaker option needs the opt-out plumbing.
- Some items (non-dumpable process, memory wiping) are best-effort in Go and are documented as such, not overclaimed.

## Open questions

1. Posture report: a new `admin posture` command, or extend `admin validate`? Proposal: extend `validate` with a `--posture` mode (the gap check found `admin validate` and `keyorix compliance report` already provide most of the foundation).
2. ~~TLS 1.2 default~~ Decided 2026-10-02: TLS 1.2 stays allowed by default with modern ciphers only; TLS 1.3-only is a strict-mode setting.
3. Admin MFA by default on fresh installs: also enforced on upgrades of existing deployments, with a grace period? Proposal: yes, with a grace period and a posture warning until enabled.
4. Shamir split of the recovery key: default or optional? Proposal: optional, recommended in the hardening guide.
5. Approval workflows (dual control on secret reads): include in the AGPL core as a differentiator, or make it a third gated feature? Today exactly two features are gated (`airgap_updates`, billing); either choice changes the licensing story. Decide before the feature is built.

## Decisions recorded (2026-10-02)

- Break-glass remains single-person, with mandatory alert, audit event and post-activation review. Two-person break-glass is rejected: an emergency path that needs a second person fails exactly when it's needed.
- TLS 1.2 remains allowed with forward-secret AEAD suites; TLS 1.3-only is available as strict mode.
- Approval workflows are deferred to a separate feature; licensing is open question 5.

## Decisions recorded (2026-10-05)

- Audit-before-disclosure stays the default. One named `insecure_` opt-out
  (`storage.database.insecure_audit_skip_durable_sync`) is added for deployments
  with guaranteed power, giving Vault-equivalent semantics and Vault-equivalent
  speed. See Amendment 1.
- **The opt-out is PostgreSQL only.** A SQLite backend that sets it refuses to
  start, with a named error — not a silent ignore. SQLite was rejected because
  `PRAGMA synchronous` is per-connection and the pool is shared, so the
  relaxation would cover every table (a power loss could undo a just-committed
  secret rotation, not merely lose audit entries), and because the measured p99
  got *worse* under concurrency anyway (328.8→518.0 ms at 10 clients,
  703.7→919.0 ms at 50).
- **A configured setting that cannot take effect is reported as off, with the
  reason, as a structured field** — not as a weakening, and not only in log
  text. One start-up warning still prints, worded as "ignored".

## Decisions recorded (2026-10-15)

- Audit durability is two baseline levels, `storage.database.audit_durability:
  strict | standard`, not an `insecure_` opt-out. `standard` is the PostgreSQL
  default; SQLite runs `strict` only. Neither level is a posture deviation; a
  level change is audited by the settings diff. See Amendment 3.
- `storage.database.insecure_audit_skip_reads` (Amendment 4): a boolean
  `insecure_` opt-out, default false. It stops audit rows for successful
  secret-value reads only; denied reads and every other event stay audited. A
  compliance profile refuses it. It is independent of `audit_durability`.

## Definition of done

- The gap check is recorded, and every baseline item is either present with a test or scheduled.
- `insecure_` naming, start-up warnings and audit events are enforced by a test over all config keys.
- The posture report exists and reports zero deviations on a default install.
- The hardening guide in `docs/` lists the baseline, the posture command and every `insecure_` setting.
