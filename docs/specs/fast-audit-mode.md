# Spec: audit durability levels (`storage.database.audit_durability`)

Status: **Accepted.** The levels (§0) were accepted by Andrei on 2026-10-15
(ADR-112 Amendment 3). §1–§8 are the original fast audit mode spec (accepted
2026-10-05, Amendment 1): its mechanism, scope, crash argument and SQLite
rejection are unchanged and still hold; where §2–§4 describe the opt-out's
*reporting* (the `insecure_` name, the per-start WARNING and audit event, the
posture deviation, the `/system/info` booleans), §0 supersedes them.

Amends: ADR-112 (secure-by-default baseline) — `docs/adr-112-secure-by-default-baseline.md`
§3 "Secrets and audit", Amendments 1 and 3.
Related: ADR-029 (audit hash chain), ADR-115 (local append-only audit journal —
a **different** mechanism, not this one), #2403/#2420 (audit group commit).

## 0. The levels (Amendment 3, current)

One setting, `storage.database.audit_durability`, config file only (no API,
CLI flag or environment variable):

- **`strict`**: the audit commit waits for the disk sync. No audit entry is
  lost to any crash or power loss.
- **`standard`**: the audit row is still INSERTed and COMMITted before the
  secret is returned, and a failed audit write still fails the request; only
  the wait for the disk sync is skipped (`SET LOCAL synchronous_commit = off`
  on the audit transaction only — the fast audit mode of §3–§6 below).

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

| `storage.type` | Default | Allowed |
|---|---|---|
| `postgres` / `postgresql` | `standard` | `standard`, `strict` |
| `local` / `sqlite` | `strict` | `strict` only; `standard` refuses to start with `storage.database.audit_durability: standard is only supported with PostgreSQL; SQLite runs strict only -- remove the setting or set it to strict` (§5 explains why) |

**Reporting.** Neither level is a posture deviation, and the setting is not an
`insecure_` registry entry.

- Every start logs one `INFO` line with the effective level and its meaning:
  `audit durability: standard (PostgreSQL default; committed before every
  disclosure; up to ~600 ms of entries can be lost to an OS crash or power
  loss; set audit_durability: strict to wait for the disk sync)` or
  `audit durability: strict (committed and synced to disk before every
  disclosure; no audit entry is lost to any crash or power loss)`.
- A level change between two starts is audited by ADR-112 §1's start-to-start
  settings diff (`security.posture_setting_changed`, old and new value), keyed
  `storage.database.audit_durability` and recording the EFFECTIVE level
  (`config.TrackedSettings`), so an upgrade that changes the default is on the
  record too.
- `keyorix-server admin validate` prints `Audit durability: <level> (<meaning>)`;
  `admin validate --posture` lists it as an informational line.
- `GET /api/v1/system/info` reports `security.audit_durability`.

**Single source of truth.** `config.DatabaseConfig.EffectiveAuditDurability`
is the only implementation of the rule (explicit level, else the alias mapping,
else the backend default; only postgres/postgresql can ever be `standard`).
The storage factory, the start-up line, `admin validate`, the posture report,
the settings diff and `/system/info` all read it, and
`TestAuditDurability_ReferencesAreAllowlisted` fails if any file outside
`internal/config` reads the raw fields.

**Migration.** `storage.database.insecure_audit_skip_durable_sync` is a
deprecated alias for one minor release: `true` → `standard`, explicit `false`
→ `strict`. Both keys with conflicting levels refuses to start; the old key
logs a deprecation line. An existing PostgreSQL install that sets neither key
moves to `standard` on upgrade (`docs/UPGRADING.md` §6c).

**Acceptance tests.**

| Requirement | Test |
|---|---|
| default per backend | `TestEffectiveAuditDurability_DefaultPerBackend` |
| SQLite refuses `standard` | `TestConfigValidate_RejectsStandardAuditDurabilityOnSQLite`, `TestAuditDurability_SQLiteRefusesStandardEndToEnd` (real binary) |
| alias mapping, conflict refusal, deprecation line | `TestEffectiveAuditDurability_ExplicitLevelsAndAlias`, `TestConfigValidate_RefusesConflictingAuditDurabilityAlias`, `TestLoad_DeprecatedAuditDurabilityAliasAddsDeprecationLine` |
| non-audit writes stay durable at `standard` | `TestAuditDurabilityStandard_NonAuditWritesStayDurable` (pg-gated), `TestWithTransaction_CloneNeverInheritsAuditSkipDurableSync` |
| crash under load at both levels, chain verifies | `TestFastAuditMode_PostgresCrashLosesOnlyATail` (standard), `TestAuditDurabilityStrict_PostgresCrashLosesNothing` (strict); manual, they kill a database server |
| settings-diff event on a level change | `TestSecurityPostureSnapshot_AuditsAuditDurabilityLevelChange`, `TestAuditDurability_PostgresEndToEnd` (real binary, pg-gated) |
| zero posture deviations on a default PostgreSQL install | `TestCollectAuditDurabilityPosture_DefaultPostgresIsNotADeviation` |
| INFO line content | `TestLogAuditDurability_StartupInfoLine`, `TestAuditDurabilityStatus_StartupLine` in `internal/config` |
| config file only | `TestAuditDurability_NoWriteAssignment`, `TestAuditDurability_NotSettableFromTheEnvironment` |

## 1. Why

PERF-2 measured the single-client secret read path on pve01 and confirmed its
H1: at c=1 there is nothing for the group-commit flusher to batch, so
essentially the whole read latency *is* one durable Postgres commit, and the
independently measured `fdatasync` floor on that disk is 9.326ms. The read
path cannot go faster than one disk sync as long as it waits for one.

A source-verified survey of how competitors get their numbers
(`~/proj/prompts/reports/2026-10-05-competitor-audit-write-paths.md`) found that
**none of them fsync audit before answering**:

| Product | Audit write path | Durable before the response? |
|---|---|---|
| HashiCorp Vault | one `write()` per entry to an `O_APPEND` file, no `fsync` anywhere | No — OS page cache only |
| OpenBao | same design (fork) | No |
| CyberArk Conjur | Ruby `Logger` over a UNIX socket to syslog | No (fire-and-forget) |
| Infisical | Redis `XADD`, background batch insert, request-path errors swallowed | No, and may drop events |
| Keyorix today | audit row committed durably before the secret is returned | **Yes** |

Keyorix's default is strictly stronger than every one of them, and that stays the
default. This spec adds an explicit, loud, audited opt-out so an operator whose
power is genuinely guaranteed (UPS, battery-backed RAID write cache, replicated
cloud block storage) can choose Vault's guarantee and Vault's speed.

## 2. User journey

*Amendment 1 (2026-10-05). Superseded by §0: the setting is now `audit_durability`, `standard` is the PostgreSQL default and is reported as a level, not a deviation.*


1. An operator reads the hardening guide's "Fast audit mode" section, which states
   plainly what is given up.
2. They add `insecure_audit_skip_durable_sync: true` under `storage.database` in
   the server's config file and restart. There is no API, CLI flag, or environment
   variable that can turn it on.
   - On a **SQLite** install the server refuses to start, naming the setting and
     telling them to remove it or switch to PostgreSQL. It is never ignored
     silently.
   - If the setting is present but cannot take effect on this backend, every
     surface reports it as **ignored, with the reason** — and nothing claims
     durability was weakened, because it was not.
3. Every subsequent start prints a `WARNING:` line naming the setting and what it
   weakens, and writes an audit event into the hash chain itself.
4. `keyorix-server admin validate` lists it as a posture deviation.
5. `GET /system/info` reports `security.audit_durable_sync_skipped: true`, so a
   buyer's auditor can see the deviation over the API without host access. When
   the setting is configured but not in effect, that field is `false` and
   `security.audit_durable_sync_skip_not_in_effect_reason` carries the reason, so
   the two states are distinguishable from the response alone.
6. To turn it off they remove the line and restart. The next start's audit event
   is absent and the warning stops; the chain carries the dated record of the
   window during which the mode was on.

## 3. The setting

*Amendment 1 (2026-10-05). Superseded by §0; the boolean below is now the deprecated alias.*


| | |
|---|---|
| Canonical name | `storage.database.insecure_audit_skip_durable_sync` |
| YAML path | `storage` → `database` → `insecure_audit_skip_durable_sync` |
| Go field | `config.DatabaseConfig.InsecureAuditSkipDurableSync bool` |
| Type / default | `bool`, **`false`** |
| Settable from | the config file only |
| NOT settable from | any HTTP handler, any gRPC RPC, any environment variable, any CLI flag |
| Supported backends | **PostgreSQL only.** `local`/`sqlite` refuses to start; `remote` cannot back a server at all (ADR-083) |
| ADR-112 registry entry | `storage.database.insecure_audit_skip_durable_sync`, `DeprecatedAlias: ""` (ships compliant) |

Name: the leaf key carries the `insecure_` prefix, which is ADR-112 §1's rule as
the registry implements it (`InsecureSetting.Name` is a dotted path whose leaf is
prefixed — e.g. `security.recover_admin.insecure_keyless_admin_recovery`). It
lives under `storage.database` and not under `audit` because the thing it changes
is the *commit durability of the database transaction* the audit chain is written
in, which is also why its blast radius differs per backend (§6).

## 4. Required semantics

These are the acceptance criteria for the implementation. Each one names the test
that holds it.

**S1 — Still fails closed on a write failure.** If the audit row cannot be
WRITTEN, the request fails exactly as it does today. The only thing removed is
the wait for the disk sync. Concretely: `logAuditEvent` and every caller keep
returning the commit's error unchanged; nothing is swallowed, nothing becomes
best-effort.
*Test:* `TestFastAuditMode_StillFailsClosedOnWriteFailure` — a storage whose
audit insert is forced to fail must still make `GetSecret` fail with the mode on.

**S2 — Same order, same code path.** The audit row is INSERTed and its
transaction COMMITted, in the same transaction/batch as today, before the secret
value is returned. No queue, no background writer, no deferred write is
introduced. A Keyorix **process** crash loses nothing: the database server is a
separate process and its WAL is untouched by Keyorix dying.
*Test:* `TestFastAuditMode_ChainStaysLinkedWhenEnabled` — consecutive appends
still link (`prev_hash` chains) and the chain still verifies with the mode on,
which is what "committed, and immediately visible, before the response" means in
practice.

**S3 — The hash chain is never corrupted or forked.** Losing a tail of entries is
permitted in this mode. A broken chain, a gap in the middle, or two rows claiming
the same `prev_hash` is not. `verify-audit` must pass after a crash.
*Test:* `TestFastAuditMode_PostgresCrashLosesOnlyATail` — write async-committed
audit events, `SIGKILL` the **postmaster** mid-write (the only event that can
lose an async commit on Postgres), restart, and assert both that the surviving
rows are a PREFIX of the written order — never a gap — and that
`VerifyAuditChain` is valid. Gated on an explicitly-named disposable container,
so it is `manual` by construction and skips in every automated run; the recorded
run is in the implementation PR's body. See §5 for why the property holds rather
than being hoped for.

*(Superseded by §0 on 2026-10-15; kept as the Amendment 1 record.)* **S4 — Default off, and not remotely flippable.** With no setting present the
sync wait still happens: the Postgres audit transaction issues no
`SET LOCAL synchronous_commit` statement **at all** (a strict no-op, so the
default path is byte-identical to before this setting existed), and SQLite's DSN
says `_synchronous=FULL` unconditionally because it has no other branch.
*Tests:* `TestFastAuditMode_DefaultIsDurableSync`,
`TestApplyAuditCommitDurability_OffIssuesNoStatementAtAll`,
`TestSQLiteDSN_SynchronousIsAlwaysFULL`,
`TestSQLitePragmas_EnabledOnFreshConnection` (unchanged),
`TestInsecureAuditSkipDurableSync_NoWriteAssignment` and
`TestInsecureAuditSkipDurableSync_NotSettableFromTheEnvironment` (the
reachability guards, modelled on `keyless_mode_reachability_test.go`). After the
Postgres-only decision the raw field is read in exactly ONE package
(`internal/config`); every other surface reads the computed
`AuditDurableSyncStatus`, and the reachability guard now asserts that empty-set
invariant rather than a five-file allowlist.

*(Superseded by §0 on 2026-10-15; kept as the Amendment 1 record.)* **S5 — Loud and audited.** Every start with the mode on prints a `WARNING:` line
naming the setting, and writes one `admin.audit_durable_sync_skipped_at_startup`
audit event with `ActorType = system`. Both repeat on every boot, not just the
first — the same treatment `keyless_mode` gets, and for the same reason: an
auditor reading the chain should not have to trust a point-in-time config dump.
The audit event fires only when the mode is actually **in effect** — a
configured-but-ignored setting weakened no window, and the event must not claim
one in the one place an auditor is told to trust literally.
*Tests:* `TestFastAuditMode_DefaultBootIsSilentAndDurable` and
`TestFastAuditMode_SQLiteRefusesToStartEndToEnd` (both against the real built
binary).

*(Superseded by §0 on 2026-10-15; kept as the Amendment 1 record.)* **S6 — Visible in the posture surface and over the API, with the ignored state
distinguishable from both "off" and "weakened".**
`keyorix-server admin validate` lists it among its warnings AND carries a
structured `InsecureSettings` entry (`Name`, `Configured`, `InEffect`,
`NotInEffectReason`, `Describe`). `GET /system/info` reports
`security.audit_durable_sync_skipped` (which means IN EFFECT, not merely
configured) plus `security.audit_durable_sync_skip_not_in_effect_reason`,
omitted when empty.
*Tests:* `TestValidateStartup_ReportsFastAuditModeAsAPostureDeviation` (all
three states),
`TestMakeSystemInfoHandler_AuditDurableSyncSkippedReflectsConfig`,
`TestAuditDurableSyncStatus` (the rule itself).

**S7 — A SQLite backend refuses to start.** `storage.database.insecure_audit_skip_durable_sync`
with `storage.type: local`/`sqlite` fails config validation with
`storage.database.insecure_audit_skip_durable_sync is only supported with
PostgreSQL; remove it or switch storage to postgres`. No silent ignore.
*Tests:* `TestConfigValidate_RejectsFastAuditModeOnSQLite` (both directions —
the same SQLite config without the setting still validates),
`TestConfigValidate_AllowsFastAuditModeOnPostgres`,
`TestFastAuditMode_SQLiteRefusesToStartEndToEnd` (the real binary's process
exits non-zero rather than serving).

### Error and concurrency cases

- **The audit insert fails mid-batch.** Unchanged. `commitAuditBatch`'s bisection
  still isolates a poisoned item; every surviving item still gets full chain
  linkage, and the failing item's caller still gets a non-nil error. The
  durability setting is orthogonal to this path.
- **A second request lands between the audit commit and the HTTP response.** It
  reads the chain head from the table. Async commit on Postgres and
  `synchronous=NORMAL` on SQLite both make a committed row **immediately
  visible**; only its *durability* lags. So the second request links onto the
  first, exactly as today.
- **Two server replicas appending concurrently (Postgres).** Unchanged: both still
  take `pg_advisory_xact_lock(auditAdvisoryLockKey)` inside the audit
  transaction, so the read-head-then-insert critical section is still atomic
  across processes. Async commit does not weaken an advisory lock.
- **A crash between a secret *mutation*'s durable commit and the audit row's
  async commit.** The mutation survives, the audit entry does not. This is a real
  consequence of the mode and is called out in §6 — it is the write path's
  version of the same tail loss the read path accepts.
- **Config present but the backend is `remote`.** Reported as **configured but
  NOT in effect**, with the reason, everywhere the setting is listed — the
  posture report, `GET /system/info`, and the start-up log. **Decided by Andrei,
  2026-10-05 (was NEEDS ANDREI (1)):** show it as OFF, with the reason, and
  carry that reason as a *structured field* (`NotInEffectReason`), not only as
  log text. One start-up warning still prints, worded as **ignored** — never as
  "audit durability weakened", because nothing was weakened and a line implying
  otherwise would send an operator chasing a problem they do not have. No
  start-up audit event is written in this state: that event exists to record a
  weakened *window* in the tamper-evident chain, and there is no such window.

  Implemented as `config.DatabaseConfig.AuditDurableSyncStatus`, the single
  source of truth all three surfaces read, so "configured" and "in effect"
  cannot drift apart between them.

  **Reachability, stated rather than assumed:** this state is currently
  **unreachable in any deployment.** `Config.Validate` rejects
  `storage.type: remote` unconditionally for a server config
  (`validateRemoteStorageNotServer`, ADR-083 — remote storage is a CLI/client
  mode, never a deployable server backend), so no server can boot with it and
  neither the posture report nor `/system/info` can observe the branch; and the
  thin CLI is a separate Go module that cannot import `internal/config` at all.
  The branch is kept because it is the decided rule and this function is where
  the rule belongs, and it is unit-tested directly against the pure function.
  `TestValidateStartup_RemoteConfigIsRejectedBeforePostureReporting` pins the
  reachability condition itself, so if ADR-083 is ever relaxed the omission goes
  red rather than silently becoming a gap.

## 5. Why the chain cannot fork or gap, and why SQLite was rejected

This is the part of the mode that must be argued, not asserted, because "lost tail
is fine, broken chain is not" is the whole safety claim.

### Postgres (`SET LOCAL synchronous_commit = off`)

The mechanism is one statement issued inside the audit transaction only:
`SET LOCAL synchronous_commit = off`. `SET LOCAL` is transaction-scoped — it
reverts at COMMIT/ROLLBACK and never leaks to the next transaction that borrows
the same pooled connection. `synchronous_commit` is evaluated at commit time, so
setting it inside the transaction is what takes effect for that transaction's
commit.

Why no gap is possible:

1. WAL is a single, totally ordered byte stream per cluster. Every transaction's
   commit record occupies one position (LSN) in it.
2. Crash recovery replays a **prefix** of that stream: it stops at the first
   record that is absent or fails its checksum. There is no mechanism by which a
   later record survives while an earlier one does not.
3. Therefore the set of surviving audit rows is always a prefix of the committed
   sequence — i.e. the chain loses a suffix, never a hole.
4. Mixing durability settings cannot invert this. A *synchronous* commit flushes
   WAL up to its own LSN, which necessarily makes every earlier async commit
   durable too. So a sync-committed secret mutation can survive while a *later*
   async-committed audit row is lost, but never the reverse — and never with an
   intervening audit row lost while a still-later one survives.
5. The chain head is read from the table inside the same transaction that inserts.
   After a restart, the head is whatever row actually survived, and the next
   append links onto it. Two rows can never claim the same `prev_hash`, because
   the only writer that could have produced the second one was rolled back by
   recovery, not merely made invisible.

Loss window: Postgres's WAL writer flushes every `wal_writer_delay` (default
200ms), and the documented worst case for async commit is three times that, so
**≤ ~600ms** of audit entries on a default-tuned cluster.

### SQLite: not supported, and why

SQLite was evaluated and **rejected** (Andrei's decision, 2026-10-05). The
mechanism would have been `_synchronous=NORMAL` in the WAL mode that is already
the default, and the chain-integrity argument above does carry over — SQLite's
own `PRAGMA synchronous` documentation states both halves ("WAL mode is safe
from corruption with synchronous=NORMAL" / "A transaction committed in WAL mode
with synchronous=NORMAL might roll back following a power loss or system
crash"). It is not rejected for being unsafe *for the chain*. It is rejected for
two other reasons:

1. **The blast radius is the wrong shape.** `PRAGMA synchronous` is a
   PER-CONNECTION property set once per DSN, and Keyorix shares one connection
   pool across every query, so NORMAL relaxes commit durability for **every
   table**. A power loss could then undo a just-committed secret rotation or
   revocation — a materially different and larger promise to break than "the
   last fraction of a second of audit entries may be lost", which is the only
   trade this setting is meant to offer. A per-transaction flip-and-restore was
   considered and rejected separately for failing *open*: a skipped restore
   (early return, panic, connection handed back to the pool mid-sequence) leaves
   a pooled connection permanently weakened with nothing reporting it.
2. **It was not even a clean latency win.** Measured on pve01 (W1 hot secret
   read, median of 3 reps, interleaved arms, same host and same binary) the
   median improved but the p99 got WORSE under concurrency:

   | clients | p99 durable (FULL) | p99 relaxed (NORMAL) |
   |---|---|---|
   | 1 | 125.5 ms | 53.3 ms |
   | 10 | 328.8 ms | **518.0 ms** |
   | 50 | 703.7 ms | **919.0 ms** |

   Likely mechanism, stated as a hypothesis rather than a measured attribution:
   at FULL every commit fsyncs, pacing the writer and keeping the WAL short; at
   NORMAL commits are cheap, the WAL grows faster between checkpoints, and the
   checkpoint that fires has more to sync — a rarer but bigger stall that
   SQLite's single-writer lock imposes on every waiting writer.

   These numbers are the **reason the path was removed**, not a feature anyone
   can opt into.

Consequently the SQLite `NORMAL` branch does not exist in the shipped code at
all: `sqliteDSN` says FULL unconditionally, and config validation refuses to
start the combination rather than ignoring it
(§4 S7). The measured figures are retained above as the evidence for the
decision, and in `docs/security/hardening-guide.md` §5a for the same reason.

## 6. What you actually give up (PostgreSQL)

**Decided by Andrei, 2026-10-05 (was NEEDS ANDREI (2)): PostgreSQL only.** The
SQLite database-wide scope was NOT accepted; see §5 for the two reasons and the
measured p99 regression that settled it.

| | Default (`false`) | Fast mode (`true`) |
|---|---|---|
| Keyorix process crash (`kill -9`, OOM, panic) | loses nothing | loses nothing — the database server is a separate process |
| Database **server** process crash | loses nothing | loses ≤ ~3 × `wal_writer_delay` of audit entries (~600ms at the default) |
| OS crash / power loss | loses nothing | as above |
| Chain integrity after any of the above | intact | intact (prefix only — §5) |
| Scope of the relaxation | — | **the audit transaction only.** `SET LOCAL` is transaction-scoped, so a concurrent secret WRITE still commits durably, and the relaxation cannot follow the pooled connection into the next transaction |

The scope row is the one that makes PostgreSQL acceptable where SQLite was not,
and it is machine-checked rather than asserted:
`TestFastAuditMode_PostgresSetLocalDoesNotLeak` asserts `SHOW
synchronous_commit` is back to `on`, on the same single pooled connection, after
the audit transaction commits.

## 7. Non-goals

- Not a background/async audit writer. The row is still written and committed
  before the response. ADR-115's local append-only journal is a different
  mechanism with a different trade; this spec does not touch it.
- Not a change to any default. Every default in ADR-112 §3's "Secrets and audit"
  block stays exactly as it is.
- Not a change to the hash-chain algorithm, the signed checkpoints, or
  `verify-audit`'s verification logic.
- Not reachable from any API. A compromised admin API must not be able to weaken
  an install's durability posture remotely, for the same reason `keyless_mode`
  is not reachable.
- Not available on SQLite, now or as a follow-up. §5 explains why; the measured
  numbers there are the evidence for the removal, not a backlog item.

## 8. Measurement (done)

pve01 VM 250, PERF-2 kit, W1 (hot secret read), c=1/10/50, 3 reps, 10s warmup +
20s measure — the same harness PERF-2 and PERF-4 used. Four arms from one image
built from the implementation branch, differing per pair by exactly one config
line, interleaved so host drift cannot land on one arm.

PostgreSQL, strict (then the default) → standard (then "fast mode"):

| clients | strict | standard |
|---|---|---|
| 1 | 16.59 ms / 51.7 rps | **3.74 ms / 243.0 rps** |
| 10 | 83.28 ms / 115.1 rps | **24.90 ms / 384.8 rps** |
| 50 | 150.82 ms / 320.4 rps | **65.84 ms / 726.5 rps** |

p99 improves at every concurrency too (64.6→9.3, 157.9→51.5, 227.5→115.9 ms).

The SQLite figures that decided §5's rejection, and the full cell table, are in
`~/proj/prompts/reports/SESSION-FASTAUDIT-1.md`; raw data, summary and
SHA256SUMS in `~/proj/bench-footprint/results/2026-10-05-fastaudit-1/`.
