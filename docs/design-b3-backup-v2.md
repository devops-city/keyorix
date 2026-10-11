# Design: `keyorix-server admin backup`/`restore` v2 — backend-neutral, authenticated, streaming

**Status:** Implemented (2026-09-28). Canonical design for ADR-108 §B3's
remaining scope — supersedes the parallel draft `docs/design-b3-offline-
backup-restore.md` (#2101); this document folds in everything from that draft
worth keeping (§2 threat model, §7 schema-delta refusal, §9 automatic
post-restore verification, and several §11 test-plan items), noted inline as
"folded from #2101" where relevant. Follow-up to PR #2099 (v1: SQLite-only,
`VACUUM INTO`-based). §13 tracks the implementation PRs.

Every open question from both drafts has been resolved by Andrei (2026-09-25)
and is recorded below as a **Decision**, not a recommendation. §12 is a
compact index of every decision for quick reference; the detail and rationale
for each lives in its own section.

## 1. Scope note: what v1 ships vs. what v2 adds

v1 (#2099) ships a **physical, SQLite-only** backup: `VACUUM INTO` produces a
byte-for-byte consistent copy of the SQLite file, bundled with every
`internal/keyfiles.Registry` key-material file into a checksummed tar.
Postgres refuses loudly (`docs/SELF_HOSTING.md` §5's manual `pg_dump`/`psql`
path stands). This is real, working disaster recovery for the common
single-node SQLite deployment — not a stopgap to throw away.

v2 does not replace that mechanism so much as generalize the *archive format*
underneath the same `admin backup --output` / `admin restore --input`
surface, closing gaps ADR-108 §B3 already scoped together (it lists
"consistent offline backup and restore," "version-skipping upgrades," **and**
"the SQLite → PostgreSQL move" as one bucket — v1 only did the first fully):

1. **Backend-neutral logical format** (§3) — the same archive restores into
   SQLite *or* Postgres. This is also, by construction, the SQLite → Postgres
   move ADR-108 already named as a sibling requirement — not a separate
   feature, the same mechanism.
2. **Postgres backup consistency** (§4) — a single `REPEATABLE READ`
   snapshot, because Postgres deployments are the ones running HA (ADR-039)
   and cannot tolerate v1's SQLite answer to consistency (stop everything,
   hold the exclusive admin lock for the whole dump).
3. **An authenticated manifest** (§5) — HMAC-SHA256 over the manifest,
   derived from the KEK exactly like the existing audit-checkpoint key
   (`internal/core/audit_checkpoint.go`), domain-separated from it, so
   archive tampering is caught *before* any byte reaches the restore target,
   not only by a post-hoc `verify-audit`.
4. **Rollback protection** (§6) — restoring an old backup is a legitimate
   disaster-recovery operation, but it also silently un-revokes any user or
   token revoked *after* that backup was taken. Detected via the audit
   chain's signed high-water mark (and, optionally, an external anchor);
   **fails closed** by default, overridable only with an explicit flag that
   itself is audited.
5. **Streaming** (§7) — v1 reads the whole database into memory
   (`os.ReadFile` → `[]byte` → one tar entry). Fine at today's typical
   install size; not fine indefinitely, and doubly not once Postgres
   deployments (larger, by the kind of customer who chooses Postgres) are in
   scope.

**Decision: full backup only, no new CLI subcommands.** v1 backs up
everything or nothing — no per-project, per-table, or time-range selective
export, and v2 does not change that scope. Both the version-skipping upgrade
and the SQLite → Postgres move (§8) are **documented usage patterns of this
same `admin backup`/`admin restore` pair**, not dedicated subcommands (no
`admin migrate-to-postgres`) — the whole point of §3's backend-neutral,
schema-tolerant format is that no new code or UX is needed for either. Revisit
selective backup only if a real customer need arises; it is not designed for
here, and would materially affect §3's format and §6's restore semantics if
added later.

## 2. Threat model

*(Folded from #2101 §2, adapted to this design's actual mechanisms — notably
witness-file-based rollback detection in addition to the anchor-based
approach, and the schema-delta refusal from §7.)*

| Actor / scenario | Can they compromise confidentiality or integrity? | Why / mitigation |
|---|---|---|
| Someone steals the backup file | No secret plaintext | Secret values are copied ciphertext-verbatim; the DEK travels only *wrapped* under the KEK (same wrapped bytes already on disk, relocated into the portable archive — no new cryptography). Stealing the file alone reveals nothing decryptable. |
| Someone steals the backup file **and** the passphrase/KMS access | Yes, fully | Same trust boundary as the live system today: whoever can unwrap the KEK there can already read everything. This design does not, and cannot, improve on that — stated explicitly, not silently assumed. |
| Backup file tampered (any single byte, anywhere) | Detected, restore refuses, before the real target is touched | Manifest carries a signed per-table hash (§5.4) verified in the stage-then-verify-then-commit sequence (§5.3) — plain checksums alone (v1's existing control) cannot catch a tamper that also recomputes its own checksum; the HMAC can't be forged without the KEK. |
| Backup file truncated (mid-row, mid-table, or before the manifest) | Detected, restore refuses, nothing loaded | Streaming parse (§7.3) into the staging directory fails cleanly on a truncated stream; the manifest verification step never passes on an incomplete archive. |
| An older, validly-signed backup is restored in place of a newer one (rollback / replay) | **Detected by default; fails closed** | §6 — the signed audit high-water mark (witness file, always checked) plus an optional external anchor (§6.4) both feed the same fail-closed gate: a mismatch refuses unless `--allow-rollback` is given, which itself writes an audit event. This is a stronger posture than #2101's original draft (which treated this as opt-in/warn-only) — see §6, §12. |
| Wrong passphrase / no KMS access supplied at restore | Detected, restore refuses before touching the target | KEK-unwrap (from staged key files) and the manifest signature check (§5.3) both depend on the correct KEK; a wrong key fails both independently, in pass order, before any real-target write. |
| Backup taken from a schema newer than the restoring binary, or carrying a renamed/type-changed column the restoring binary doesn't recognize | Detected, restore refuses | `schema_epoch` reuses `checkSchemaEpoch`'s exact refusal logic (§7); an unrecognized column name is refused rather than silently dropped or misparsed (§7.4). |
| Restore target already has data | Detected, restore refuses | v1's `refuseNonEmptyExisting`, unchanged; still checked before any staging work begins. |
| A host admin holding both the target database and its KEK | Can fabricate a fully self-consistent, validly-signed backup | Not attempted to be closed here — this is the same ceiling design-b4 (`admin verify-audit`) already states for its own trust model (`Result.NotProven`). Stated plainly, not silently assumed away. |

## 3. Backend-neutral logical format

### 3.1 Why logical, not "teach VACUUM INTO to also speak Postgres"

There is no Postgres equivalent of `VACUUM INTO` that produces a
SQLite-compatible file, and no tool reads a raw Postgres heap file
independent of a running Postgres of the exact same major version. A
byte-identical *physical* copy is inherently single-backend. The only format
that can restore into either backend is a **logical** one: table name → rows,
independent of on-disk representation, read through the same
backend-neutral `storage.Storage` interface both `createLocalStorage` and
`createPostgresStorage` already implement identically
(`internal/storage/factory.go`, both end in `store.NewLocalStorage(db)` over
a dialect-only-different `*gorm.DB`) — a row read from SQLite and a row read
from Postgres are the same Go struct; the export format never needs to know
which backend produced or will consume it. This is also exactly what a
SQLite → Postgres move needs — you cannot "physically" turn a SQLite file
into a Postgres cluster; you read rows out of one and insert them into the
other.

### 3.2 Table enumeration: derive it, don't hand-list it

The schema has 90 GORM model structs today (`internal/storage/models/*.go`)
across `internal/storage/factory.go`'s `AutoMigrate` calls, and that number
only grows. **Do not hand-enumerate the table list in backup/restore code.**
This codebase has already been burned by hand-picked model lists silently
drifting from the real schema — see the `internal/storage/store` test-fixture
incident where a hand-picked `AutoMigrate` subset let 40 fixtures bypass
`core.CreateUser` folding undetected. The fix there was "derive the table set
from something that can't drift," and the same fix applies here:

- Build the table list from GORM's own schema registry — call
  `db.Migrator().CurrentDatabase()` / iterate the same model slice
  `factory.go` already passes to `AutoMigrate` (refactor that slice into an
  exported `storage.AllModels()` so both migration *and* backup consume the
  single real list — one source of truth, not two hand-maintained ones,
  per this repo's "generate it, or derive-and-check it" preference order).
- A CI test asserts `len(storage.AllModels())` table names round-trips
  against `db.Migrator().GetTables()` on a freshly migrated database in both
  backends — this is the check that fails loudly the day a model is added to
  `AutoMigrate` and forgotten in the backup list, instead of silently
  exporting a partial backup.

### 3.3 Per-table row encoding

Each table becomes one streaming NDJSON (newline-delimited JSON) tar entry —
`tables/<table_name>.ndjson` — one JSON object per row, GORM column name as
key, using the same JSON encoding GORM/the API layer already uses for typed
columns (so no new marshal/unmarshal logic for e.g. `time.Time`,
`encoding/json` `RawMessage` columns, or nullable fields). NDJSON over a
single-JSON-array-per-table for one reason: it's streamable in both
directions without holding the whole table in memory (§7) — a JSON array
requires either buffering the whole thing or a streaming array-aware decoder;
NDJSON just reads one line at a time. Rows within a table are written in
primary-key-ascending order; restore reads them back in the same order, with
no re-sorting on either side (the manifest's per-table hash — §5.4 — is
computed over exactly these bytes, in this order).

### 3.4 Restore ordering and referential integrity

**Correction (2026-09-28, confirmed against the live schema during H1):** the
mechanism originally specified below — deriving order from GORM's own
relationship metadata, with real FK constraints deferred as defense in depth
— assumed this schema has both. Verified directly: zero `gorm:"foreignKey"`
tags exist anywhere in `internal/storage/models`, so
`*gorm.Statement.Schema.Relationships` is empty for every model, and zero
`FOREIGN KEY`/`REFERENCES` constraints exist anywhere in `factory.go`'s
migrations (the only 4 occurrences of either term in that file are in
comments). Neither premise holds. This section now describes the mechanism
actually implemented instead — decided with Andrei the same day this was
found.

**Decision: FK-dependency order derived from each model's `XxxID`-shaped
field names by naming convention, loaded inside a single transaction per
backend, with a mandatory application-level dangling-reference check
replacing the deferred-constraint defense-in-depth that would otherwise have
come from the database.**

- **Primary mechanism, both backends: a derived topological order.**
  `internal/backupfmt.RestoreOrder()` walks every model in `storage.
  AllModels()`'s registry order (§3.2), finds every field shaped like a row
  reference (an unsigned integer, or pointer to one, whose name ends in
  `ID`, excluding the primary key field itself), and resolves each to its
  referenced model by suffix-matching the field name against every real
  model type name. A small, explicit, CI-verified exception list handles the
  rest: `referenceOverrides` for fields whose name doesn't match their table
  (`CreatedBy` → `User`, `SecretID` → `SecretNode`, `HeadID` on
  `AuditCheckpoint` → `AuditEvent`, ...), `notReferences` for ID-shaped
  fields that are genuinely polymorphic and have their own type-discriminator
  field (`AccessReviewItem.PrincipalID`, `ShareRecord.RecipientID` — neither
  participates in ordering or the dangling-reference check below), and
  `selfReferences` for a field that references its own model's table
  (`SecretNode.ParentID` — not a cycle, ordered within that table's own
  section, never a cross-table edge). Three CI tests keep this self-checking
  the same way §3.2's own list is: every ID-shaped field on every live model
  must classify via the convention or one of the three exception lists (a
  new model or field can never silently fall out of ordering); every
  exception-list entry must still name a real (model, field) pair (no stale
  entries); the derived order must be a valid topological sort of every
  derived edge.
- **No deferred-constraint defense in depth exists at the database level,
  because no FK constraints exist to defer.** In its place: restore, inside
  the same transaction that loads the data (§3.4 below is unchanged on this
  point — one transaction, no partial restore), checks after loading each
  table that every non-zero `XxxID`-shaped value it just inserted has a
  matching row in the referenced table — for every edge `RestoreOrder()`
  derived, not a sample. Any dangling reference refuses the whole restore
  (rolls back the transaction) and reports the table, column, row id, and the
  missing target id. **There is no flag to skip this check.** This is the
  mechanism that does the job deferred FK constraints would have done on a
  schema that had them — restore is still referentially checked throughout,
  the failure mode is just detected in application code instead of by the
  database.
- `admin backup` runs the identical check read-only against the *source*
  database and records any dangling reference it finds as a warning in the
  manifest (never a refusal — a pre-existing orphan in a live database is a
  fact about that database, not something `admin backup` should block on),
  so an operator learns about it before they ever need to restore, not only
  when a restore refuses.
- **Never disable constraint checking to make loading easier.** No
  `session_replication_role = replica`, no equivalent shortcut on either
  backend — moot now that there is nothing to disable, but the principle
  (restore is referentially checked throughout, by construction, not
  bypassed for convenience) still holds and is enforced by the mandatory
  check above.

Either way, restore runs as one transaction per backend connection — partial
restore on failure is not an acceptable state (same principle v1 already
applies with `refuseNonEmptyExisting` and archive-clean error handling).

**Out of scope for this design:** adding real `gorm:"foreignKey"` associations
and database-level FK constraints to this schema was considered and
explicitly rejected for Session H — it would touch every model file, and
retrofitting real constraints onto an existing Postgres install fails outright
on any row that is already orphaned (a real possibility this design's own
dangling-reference check now surfaces for the first time). Tracked as a
separate, standalone proposal if the schema is ever meant to gain real FK
constraints — that decision needs its own orphan-row migration plan and does
not belong in a backup/restore feature.

### 3.5 Schema-delta refusal and the additive-only migration rule

*(Folded from #2101 §8's "one real hazard this does not close" — resolved
here, not left open.)*

§8 explains why version-skipping upgrades and the SQLite → Postgres move
fall out of this format for free: restore always creates its target fresh
and runs the normal migration path against it *before* loading any row, and
each row is a JSON object keyed by column name, not a positional record — so
a column the current schema doesn't have yet takes its GORM-defined default,
and a column the backup had that current models no longer define is simply
not read back. Plain column **removal** is safe by construction under this
scheme.

A column **rename** or **type change**, however, is not safe by
construction: to a naive column-name match, a rename looks identical to "old
column removed, unrelated new column added" — silently losing the data's
continuity rather than failing loudly. A type change can silently coerce or
fail to parse.

**Decision: two layers, prevention and detection.**

1. **Prevention (project-wide convention): migrations are additive-only.** No
   migration may rename an existing column or change its type in place.
   Adding a new column (and, if truly needed, a separate deprecation/backfill
   path away from the old one) is the only sanctioned way to change a
   column's shape going forward. This should be captured in this codebase's
   migration-authoring guidance alongside the other AutoMigrate conventions —
   tracked as a follow-up doc note, out of scope for this docs-only PR to
   land in the same change. Per CLAUDE.md's own preference order ("generate
   it" > "derive and check it" > "assert it in prose"), this is the
   cheapest layer: it prevents the hazard class at the source rather than
   detecting it after the fact.
2. **Detection (runtime safety net): restore refuses an unrecognized
   column.** For each table, compare the manifest's declared column set
   against the current model's column set. Any manifest column name that is
   **neither** present in the current model **nor** on a small, explicit,
   hand-maintained "known-intentionally-removed" allowlist (one entry per
   table per removed column, added deliberately alongside the migration that
   removed it, the same "derive and check" discipline as everywhere else in
   this design) is refused — restore stops and names the exact table and
   column, rather than silently dropping data or corrupting a parse. This
   makes rule 1's violation loud the very first time it would matter (a
   failing restore test in the same PR that introduces an in-place rename),
   instead of a silent data-loss bug discovered later during an actual
   disaster-recovery restore.

The manifest also carries `schema_epoch`, checked with `checkSchemaEpoch`'s
exact existing refusal logic (`internal/storage/factory.go`) — a
backup taken on a schema epoch newer than the restoring binary understands is
refused with the same reasoning already established for a newer-than-this-
binary live database. No new refusal logic to get subtly wrong.

### 3.6 Format versioning and v1 compatibility

v1's `backupFormatVersion = 1` const already exists as the guard. v2 bumps to
`FormatVersion: 2` and changes `Backend` from a single string (`"sqlite"`) to
something that names the *logical* format explicitly (e.g. `"logical-v1"`) —
restore refuses any `FormatVersion` it doesn't recognize (v1 already does
this; keep it).

**Decision (Andrei): backups always write v2 (logical format) once v2 ships
— there is no conditional or opt-in physical mode.** §12 Q6 (from the
original draft of this document) asked whether to keep a
`--format=physical` escape hatch for SQLite; dropped — §3.1 already
establishes the logical format is a strict superset for the SQLite case, and
maintaining two archive-writer code paths indefinitely is exactly the kind
of unnecessary-abstraction cost this repo's engineering practices warn
against paying for a hypothetical need.

**Decision (Andrei): `admin restore` keeps a v1-physical-format reader until
Keyorix 1.0, then drops it.** An archive taken under #2099 before v2 ships is
not stranded; restoring one prints a deprecation warning recommending a
fresh backup under the new format. Track the reader's removal at 1.0 like any
other deprecation, not silently.

## 4. Postgres backup consistency: `REPEATABLE READ` vs. the admin lock

v1's SQLite path gets consistency from `serverguard.AcquireExclusive` (a hard
exclusive `flock`, held for the whole run — see
`internal/serverguard/serverguard.go`) plus `VACUUM INTO`'s own atomicity.
That's the right tradeoff for SQLite: those deployments are inherently
single-process, so "briefly refuse to start a server while a backup runs" is
cheap.

**Decision (Andrei): `REPEATABLE READ` is the default for Postgres backup;
`--exclusive` is an explicit opt-in.** `serverguard.AcquireExclusive` already
supports Postgres today (`pg_try_advisory_lock`, non-blocking, session-scoped)
— reusing it verbatim for backup would work, but it means every replica in
an ADR-039 HA deployment refuses to (re)start for the entire duration of the
backup, which is exactly the downtime story Postgres deployments choose
Postgres to avoid. `BEGIN ISOLATION LEVEL REPEATABLE READ` takes one MVCC
snapshot at `BEGIN` and every subsequent read in that same transaction sees
exactly that snapshot, regardless of concurrent commits — Postgres's own
built-in answer to "consistent multi-table dump without blocking anyone," and
the same mechanism `pg_dump`'s ordinary mode uses.

**The entire backup — every table — reads through ONE `REPEATABLE READ`
transaction/connection, not one transaction per table.** This is the specific
point that closes the ordering hazard the parallel draft (#2101 §6) raised
against a snapshot-based approach: that draft's concern was that reading
`audit_checkpoints` and `audit_events` as *separate* statements could let a
concurrent checkpoint write land between them, so the backup captures a
checkpoint that doesn't yet cover every event row the same run captured. That
hazard is real **only if** each table read is its own transaction. Because
every table here is read inside the same single `REPEATABLE READ`
transaction (§7.2), all of them see the identical fixed snapshot taken at
`BEGIN` — there is no window between reading `audit_checkpoints` and reading
`audit_events` in which a concurrent write becomes visible to one but not the
other, so the hazard does not apply to this design.

**Tradeoff to document, not hide:** a long-held `REPEATABLE READ` transaction
holds back Postgres's `xmin` horizon for its duration — `VACUUM` cannot
reclaim rows deleted or updated by concurrent transactions until this backup
transaction finishes. On a large, write-heavy table this is the same
well-known operational cost `pg_dump` itself carries on a big database, not a
new problem this design introduces — called out in the command's `--help`
text and in `docs/SELF_HOSTING.md`, the way v1's own `--help` text already
tells the operator to store the archive off-host.

`--exclusive`, wired to the existing `serverguard.AcquireExclusive`, remains
available for an operator who wants v1's stronger guarantee (zero concurrent
writes at all, not just snapshot isolation) and is willing to pay for it with
the availability hit — e.g. a maintenance-window backup before a major
upgrade.

SQLite keeps its existing `VACUUM INTO`-backed exclusive-lock path for
consistency (unchanged from v1) and gains the same logical-format
table-by-table export for parity with Postgres (needed for SQLite → Postgres
restores, and so both backends are exercised by the same restore code, not
two).

## 5. Authenticated manifest

### 5.1 Threat this closes

v1's manifest already carries a SHA-256 checksum per file
(`backupFileEntry.SHA256`), verified before restore
(`verifyChecksum`/`validateKeyFileSet`). That catches accidental corruption
(bit rot, a truncated copy) but is **not an authenticity control**: the
checksums live in the same file an attacker who can modify the archive
controls, so they can recompute a matching checksum for tampered content.
Detecting deliberate tampering needs a MAC keyed by something the attacker
does not have — exactly the gap `verify-audit` closes for the live audit
chain (ADR-029) but which v1's *archive* has no equivalent of. Today,
tampering would only surface later, if at all — e.g. via `verify-audit`
after the restored server is already running.

### 5.2 Key derivation: same pattern as the audit checkpoint key, domain-separated from it

`internal/encryption/keymanager_lifecycle.go` already derives the
audit-checkpoint HMAC key from the KEK via HKDF-SHA256 with a fixed `info`
string (`deriveAuditCheckpointKey`, distinct `info` from
`evidenceSignKeyInfo`) — chosen over the DEK specifically so a routine DEK
rotation does not invalidate it (`#502`). Reuse the exact same construction
for the manifest key.

**Decision: the manifest-signing key is its own, independently-derived key —
domain-separated from the audit-checkpoint key by a distinct `info` string,
never the literal audit-checkpoint key reused for a second protocol.**

```go
const backupManifestKeyInfo = "keyorix-backup-manifest-signing-key-v1"

func deriveBackupManifestKey(kek []byte) (key []byte, keyID string, err error) {
    // identical shape to deriveAuditCheckpointKey — HKDF-SHA256(kek, nil, info)
}
```

Reusing one derived key across two independent signature protocols (audit
checkpoints vs. backup manifests) is the kind of cross-protocol key reuse
worth avoiding on principle, not because a concrete attack against this
specific pair is known — HKDF's domain separation exists exactly so two
derived keys never collide and a compromise of one protocol's signing context
doesn't automatically hand over the other's. No new key-management surface
beyond this: this is the fourth HKDF-from-KEK derivation in the same file
(evidence-signing, audit-checkpoint, and now this), all following one
established pattern.

### 5.3 Verification order: before the restore target is touched, not before the archive is touched

The real constraint: on a **fresh host** (the common restore case — the data
directory being restored into is empty by definition, per v1's
`refuseNonEmptyExisting`), the KEK itself only exists *inside* the archive
being restored. Verifying the manifest signature requires the KEK; getting
the KEK (for `key_provider.type: file`) requires the archive's own key files.
This is circular if "verify before restore" is read as "verify before writing
any byte to disk at all."

**Decision (Andrei): stage, then verify, then commit — never write directly
to the final target before verification succeeds, and the unwrapped KEK/DEK
are never written to disk at any point, including inside the staging
directory.**

1. Parse the archive (streaming — §7) into a temporary staging directory
   (`os.MkdirTemp`, mode 0700). The staging directory holds **archive
   contents exactly as extracted** — wrapped key material (ciphertext, the
   same bytes already on disk in normal operation), table NDJSON, and the
   manifest — never the unwrapped KEK or DEK in any form. Same
   checksum-per-file verification v1 already does.
2. Unwrap the KEK **in process memory only**, using the staged (still
   wrapped) key files, through the exact same `internal/encryption` code path
   `admin diagnose`'s "KEK/passphrase access" step already uses today — no
   new unwrap logic, just pointed at the staging directory instead of the
   real key-file paths. The KEK and DEK exist only as Go byte slices in this
   process's memory for the duration of the command; they are never
   serialized to the staging directory or anywhere else.
3. Derive the manifest key (§5.2), canonicalize the manifest (fixed field
   order, mirroring `checkpointCanonical` in
   `internal/core/audit_checkpoint.go` — same idiom, new struct), compute
   HMAC-SHA256, compare with `hmac.Equal` (constant-time, matching this
   codebase's existing convention for every other secret comparison; see
   `crypto/subtle.ConstantTimeCompare` calls elsewhere).
4. **Only on success**: move the staged database and key files into their
   real target paths (rename within the same filesystem is atomic; still
   subject to v1's non-empty-target refusal, checked once before staging even
   begins, so a doomed restore fails fast without doing the work) — and run
   §6's rollback check and §9's automatic post-restore verification before
   the command reports success.
5. On any failure — checksum, signature, rollback refusal, or otherwise —
   delete the staging directory and refuse. The real target directory is
   never touched.

This satisfies "detected before restore" in the sense that matters: nothing
at the operational target (the database and key files a running server will
actually read) is ever written unless the manifest signature checks out. It
costs one temporary on-disk copy of the archive's (still-wrapped) contents
during restore, which §7's streaming design already has to reckon with
regardless (see §7.3) — the unwrapped secret material itself never touches
disk, staged or otherwise.

### 5.4 What the signature covers

Every field needed to detect a meaningful tamper: `FormatVersion`, `Backend`,
`CreatedAt`, `SchemaEpoch` (§3.5), the full per-table checksum/row-count list,
the key-file checksum list, and the `AuditHighWater` fields from §6 — i.e.,
the whole manifest except the `Signature` field itself. An attacker who can
modify archive content but not derive the KEK cannot produce a matching
signature for any combination of those fields, including silently dropping a
table, substituting a different key file than the one actually backed up, or
altering the recorded high-water mark to defeat §6's rollback check.

The manifest's checkpoint fields (`head_id`, `head_hash`, `chained_events`,
`key_version`, `signature`) are recorded in the **same JSON shape**
`auditverify.ExternalAnchorBundle` already uses (`internal/auditverify/
anchor_bundle.go`) — reuse, not a parallel schema. This means a backup's own
manifest can be handed directly to `admin verify-audit --anchor` as an
external anchor with zero translation, and is also what makes §6.4's optional
`--anchor` restore flag a small amount of new glue rather than a new anchor
format.

## 6. Rollback protection

### 6.1 The threat

Restoring is index-blind to *when* the backup was taken relative to
subsequent legitimate changes. A backup taken at T1, restored at T3 after a
user or machine credential was revoked at T2, silently resurrects that
access — the restored database simply doesn't know T2 happened. This is a
real, not hypothetical, category for a secrets manager specifically (compare
the "auth-boundary lockout-vs-bypass asymmetry" principle already in
CLAUDE.md: a revoke is exactly the kind of action whose accidental undo must
fail loud, not silent).

Genuine disaster recovery *legitimately* restores an old backup sometimes —
this must not be blocked outright, only require the operator to say so
explicitly, loudly, and on the record.

### 6.2 Decision: fails closed by default; override is explicit and audited

**This design's posture is stricter than the parallel draft's (#2101 §9,
which treated an anchor mismatch as opt-in/advisory).** Andrei's resolution:
**a detected rollback always refuses by default — witness-file mismatch or
anchor mismatch, whichever fires — and the only way past it is an explicit
`--allow-rollback` flag, which itself writes an audit event recording that
the override was used.** There is no silent, warning-only path.

### 6.3 Primary detection: the signed audit high-water mark, plus a host-local witness

`internal/core/audit_checkpoint.go` already maintains exactly the primitive
needed: `auditHighWaterKey` (`system_metadata` key
`audit_checkpoint_highwater`), a single overwritten row holding the greatest
signed `chained_events` count this install has ever certified, HMAC-signed
with the same checkpoint key so it can't be forged without it
(`auditHighWaterFloor`, `advanceAuditHighWater`). This is precisely "how far
has this install's audit trail legitimately progressed" — the same question
rollback detection needs answered.

**The subtlety: the high-water row itself lives inside the database being
restored.** An old backup's own embedded high-water row reflects the OLD
(lower) value — comparing the archive against *itself* proves nothing.
Detecting rollback needs a reference **outside** the archive, one that
survives being overwritten by whatever gets restored:

- A small **witness file**, outside the database and outside anything backup
  or restore ever bundles into an archive (e.g. `<data-dir>/.audit-highwater-
  witness`, sibling to the DB file, never listed in `keyfiles.Registry` and
  never a tar member) — holds the single greatest signed high-water value
  ever observed *on this host*, written every time the live server advances
  the real high-water (`advanceAuditHighWater`'s existing call site is the
  natural hook) and every time a restore completes.
- Every `admin backup` also records the archive's own high-water value (and
  its existing signature — no new signing scheme, reuse
  `auditHighWaterValue`/`signCheckpoint`'s existing format) at the top level
  of `MANIFEST.json` (§5.4), so restore can read it without first opening the
  staged database.
- `admin restore`, after manifest-signature verification (§5.3) but before
  the commit step, compares the archive's recorded high-water against the
  witness file's value:
  - **Witness file absent** (genuinely fresh host, first restore ever on this
    machine): nothing to compare against — proceed, and write the witness
    file from the archive's value so *subsequent* restores on this host are
    protected. This is the legitimate bootstrap case, not a gap to close.
  - **Archive's high-water ≥ witness's value**: proceed normally — this
    backup is at least as current as anything this host has certified.
  - **Archive's high-water < witness's value**: **refuse (§6.2).** Requires
    `--allow-rollback` to proceed; using it writes an audit event stating
    exactly how far back this goes — "restoring a backup that is N events
    behind this host's last known state; users/credentials revoked since then
    will be un-revoked" — once the restored chain is writable again.

### 6.4 Optional stronger detection: an external anchor

*(Folded from #2101 §9.)* Because the manifest's checkpoint fields are
already in `ExternalAnchorBundle` shape (§5.4), restore optionally accepts
`--anchor <path>`, forwarded into the same `crossCheckExternalAnchor` logic
`admin verify-audit`/design-b4 already uses: an anchor certifying *more*
chained events than the archive being restored is exactly the rollback
condition, detected independent of (and in addition to) the host-local
witness file. This gives an operator who has a separately-held, trusted
anchor (e.g. exported and stored off-host after a previous `verify-audit`
run) a check that doesn't depend on the restoring host's own state at all —
useful specifically against the witness file's stated limitation below. Per
§6.2, an anchor mismatch **also** fails closed and **also** requires
`--allow-rollback`.

### 6.5 Stated limitation

The witness file is host-local. It defeats an attacker who steals a stale
backup archive and tries to restore it somewhere the real host's witness file
already exists — but an attacker with **both** an old archive and the ability
to wipe or never-had the witness file (a genuinely fresh replacement host, or
deliberate destruction of the witness alongside the rest of the data
directory) is indistinguishable from the legitimate "first restore on a fresh
host" case and is not caught by the witness file alone. This is the same
class of caveat this codebase already states plainly elsewhere rather than
pretending is solved — compare `CheckpointAnchorVerifiable`'s own doc comment
distinguishing "anchored" from "anchor cryptographically re-verified."

**Decision (Andrei): notary anchoring (`SetCheckpointNotary`, RFC 3161
receipts in `internal/notary`) remains optional and off by default** — it is
a stronger answer to exactly this gap when configured (an anchored
checkpoint's timestamp is attested by a third party outside this host
entirely, so a host-wipe-and-replay can't antedate it, and §6.4's `--anchor`
flag is how a notary-anchored bundle would actually be supplied at restore
time), but is not required or newly coupled to backup/restore by this design
— it's an existing opt-in feature this design doesn't change, only reuses
when present. Document it as the stronger option for installs that care
about a host-wipe-and-replay attacker (`docs/SELF_HOSTING.md`).

## 7. Streaming

### 7.1 What v1 does today

`snapshotSQLiteDatabase` returns `[]byte` (the whole database), and
`writeBackupArchiveContents` takes `dbBytes []byte` plus `keyBlobs [][]byte`
— the complete backup payload is held in memory at once, both directions
(`readBackupArchive` similarly collects everything into `dbBytes`/
`keyBlobsByName` before returning). Acceptable at today's typical SQLite
install size; not something to carry forward unchanged once Postgres
deployments (larger by self-selection) are in scope, and not something to
carry forward for the logical, per-table format either — buffering 90 tables'
worth of rows defeats half the point of moving to a row-streamed format.

### 7.2 Backup-side streaming

Chain writers directly, no intermediate full-payload buffer:
`os.File` → `gzip.Writer` → `tar.Writer`, and for each table, a Postgres
cursor (`DECLARE ... CURSOR` inside the single `REPEATABLE READ` transaction
from §4, or GORM's row iterator) / SQLite `rows.Next()` loop that encodes
each row as one NDJSON line and writes it straight into the current tar
entry via `tw.Write` — bounded memory is "one row plus encoder overhead," not
"one table" and certainly not "the whole database." `tar.Writer` requires
knowing an entry's size up front in its header for the classic API; use
`tar.FileInfoHeader`-style streaming with a known-in-advance size only for
the small fixed entries (`MANIFEST.json`), and for per-table NDJSON entries
either buffer just that one table to determine its size (acceptable — single
tables, not the whole DB, are still far smaller than a whole-DB buffer) or
switch to PAX headers, which support a still-unknown size via GNU/PAX
sparse-entry extensions — pick whichever `archive/tar` cleanly supports;
this is an implementation detail to resolve during the PR, not a design
blocker.

### 7.3 Restore-side streaming

Read the tar/gzip stream forward-only, one entry at a time (`tar.Reader`
already supports this — no need to seek), into the staging directory (§5.3).
For each table entry, decode NDJSON line-by-line and batch-insert (e.g.
groups of a few hundred rows via a single multi-row `INSERT`, not
row-by-row — GORM's `CreateInBatches` is the natural fit and would be new
usage in this codebase, not existing precedent, so budget review time for it)
inside the one restore transaction from §3.4. Key files and the manifest are
small and fine to hold in memory as today; only the potentially large
per-table row streams need this treatment.

Combined with §5.3's staging-then-verify sequence: the archive is read
*once*, streamed into the staging directory's files, verified, then the
already-staged files are what get inserted/moved — there is no second full
read of the archive after verification succeeds.

### 7.4 Preflight free-space check

**Decision (Andrei): both commands refuse up front if there isn't enough free
space, rather than failing messily partway through.** Restore's
stage-then-commit design (§5.3) means the staging directory's contents and
the eventual real target coexist briefly — on SQLite this is roughly the
uncompressed archive size again, on top of whatever the target filesystem
already holds. Before starting, restore checks available space on the target
filesystem against the archive's own declared uncompressed size (each
manifest table entry already records enough to compute this — §5.4) plus a
safety margin, and refuses with a clear, specific error (naming the required
vs. available space) rather than discovering the shortfall mid-stream with a
half-populated staging directory. `admin backup` applies the same preflight
check against the output path's filesystem, using the source database's
current on-disk size as the estimate. Neither check is a hard guarantee
(concurrent disk usage by anything else on the host can still exhaust space
mid-run), but it converts the common case — a target that was never going to
fit — from a confusing mid-run failure into an immediate, actionable one.

## 8. Reuse: version-skipping upgrade and the SQLite → Postgres move

Both of ADR-108's two derived capabilities are the **same restore path**, run
with no new code, once two properties already designed above hold:

1. Restore always creates its target fresh and runs the normal migration path
   against it *before* loading any row (§6.3's commit step, after §5.3's
   staging) — so the target always has the complete current-schema table
   shape, all columns, all defaults, from the binary doing the restoring,
   regardless of which binary produced the backup.
2. Each row is stored as a JSON object keyed by column name (§3.3), not a
   positional/binary record — so a column the backup's schema didn't have yet
   simply takes its GORM-defined default on insert, and a column the backup
   had that current models no longer define is simply not read back (§3.5
   covers the one case this isn't automatically safe for — a rename or type
   change — and how it's refused rather than silently mishandled).

**Version-skipping upgrade** is then: take a backup on the old binary (which
needs no schema knowledge beyond what it already has), restore it through a
current binary into a freshly-migrated-to-current-schema empty database.
*Same command, same code path as any other restore* — no per-version
column-mapping table, no special "upgrade mode" flag.

**The SQLite → Postgres move** is the same restore, pointed at a Postgres
target instead of a SQLite one — the format is backend-neutral by
construction (§3), so nothing about the container format or the load logic
changes; only the target DSN does. No SQLite↔Postgres data-migration path
exists anywhere in this repo today (`internal/cli/migrate` implements only
`migrate user-to-machine`, ADR-023, an unrelated user→machine-identity
conversion) — this is genuinely new ground, delivered as a side effect of §3
rather than separate work.

As stated in §1: neither gets a dedicated subcommand. Both are documented
usage patterns of `admin backup`/`admin restore`.

## 9. Automatic post-restore verification

*(Folded from #2101 §7 — a decision, not left as future work.)*

**Decision: after the atomic commit (§5.3 step 4) but before the command
reports success, restore runs a full audit-chain verification against the
now-live target** — the same walk `auditverify.Verify` performs
(`internal/auditverify`), using the KEK-derived key material already in hand
at this point in the command (no extra flag needed, since §5.3 already
unwrapped it to verify the manifest).

- **`VerdictBroken`** fails the whole restore command (non-zero exit) but
  **does not delete the already-committed database** — a loud failure that
  leaves a forensic artifact in place beats a silent one that leaves nothing,
  matching this repo's own standing principle: don't trade loud failure for
  silent data loss. The operator is left with a database that loaded
  successfully but whose audit chain doesn't verify — worth investigating,
  not worth erasing.
- **`VerdictIndeterminate`** (e.g. no checkpoint key reachable) is reported as
  a warning, matching design-b4's own verdict semantics — it does not fail
  the command.

This runs in addition to, not instead of, §6's rollback check — rollback
detection happens before commit (it's a precondition on whether to load the
data at all), this runs after commit (it's a postcondition on what actually
got loaded).

## 10. CLI surface

```
keyorix-server admin backup  --output <path> [--exclusive] [--force]
keyorix-server admin restore --input  <path> [--anchor <path>] [--allow-rollback] [--force]
```

No new subcommands (§1). Both commands take the same `--config` every admin
command already takes (source DB for backup, target DB for restore).
`--force` behaves exactly as it does for every other admin command: still
attempts the relevant lock/preflight checks first, proceeds unprotected with
a loud warning only if acquisition itself fails — it does not bypass §6's
rollback gate or §5's manifest verification, only the lock-contention and
preflight-space checks that have an existing `--force` precedent elsewhere in
`server/admin`.

## 11. Test plan

### 11.1 Core correctness property: `restore(backup(state)) == state`

The load-bearing test, across both backends and both directions
(SQLite → SQLite, Postgres → Postgres, SQLite → Postgres, Postgres → SQLite):
seed a database with representative rows across every table (or, better,
derive the seed from the same `storage.AllModels()` list from §3.2 so a new
model automatically gets covered — same "derive, don't hand-list" discipline
applied to the test as to the implementation), `admin backup`, wipe the
target, `admin restore`, then assert the restored database is row-for-row
equal to the pre-backup state — reusing the *same* per-table hash the
manifest already computes (§5.4) as the test oracle where possible, rather
than a second, parallel comparison mechanism, and falling back to a full
canonical per-table row dump comparison where it isn't (since backend-neutral
means the physical bytes are never expected to match across SQLite ↔
Postgres). This generalizes v1's existing
`TestAdminBackupRestore_SQLite_RoundTrip`, which already checks the
audit-chain-length invariant (`chainedCount` before backup equals
`chainedCount` after restore, plus exactly one more for the restore's own
audit event) — keep that exact assertion, it's still correct and still the
right way to catch a subtly incomplete restore.

### 11.2 Cross-backend move test

A dedicated `TestAdminBackupRestore_SQLiteToPostgres` (gated on
`KEYORIX_TEST_PG_DSN`, this repo's existing convention for Postgres-only
tests, per `docs/security-closures.d/`'s `pg-gated` category) exercising
exactly the "SQLite → PostgreSQL move" ADR-108 names: back up a SQLite
install, restore into a fresh Postgres database — and the reverse direction —
confirm `verify-audit` reports VALID and the row-equality check from §11.1
holds both ways. This is the test that proves §3's backend-neutral format
claim is real, not theoretical.

### 11.3 Consistency test (Postgres)

Start the `REPEATABLE READ` backup transaction, then — from a second,
concurrent connection — commit writes to a table already read and to a table
not yet read by the in-progress backup. Assert the resulting archive reflects
neither concurrent write (true snapshot isolation, not "whatever happened to
be visible when each table was scanned") — this is also the test that would
catch a regression back into #2101's raised ordering hazard (§4) if the
implementation ever accidentally split the backup across more than one
transaction.

### 11.4 Manifest authenticity: red/green, a genuine tamper, and exhaustive byte-flip coverage

Following this repo's "validate a mechanism against a real failure, not the
one imagined" discipline (per CLAUDE.md's core-principle section):

- **Green**: an unmodified archive restores successfully.
- **Red — tampered payload, untouched signature**: flip a byte in a table's
  NDJSON content (or a key file) without recomputing the manifest signature.
  Restore must refuse at the signature-verification step in §5.3 — before
  anything is written to the real target — distinctly from v1's existing
  per-file-checksum refusal (`TestAdminRestore_ChecksumMismatchDetected`
  already covers that layer; this test proves the *authenticity* layer, not
  just the corruption-detection layer, actually fires).
- **Red — content AND its checksum both altered to match, but the manifest
  signature left stale**: this is the case plain checksums (v1's existing
  control) cannot catch and HMAC verification specifically exists to catch —
  the test that would have caught the checksum-only design's actual gap if
  it existed today.
- **Exhaustive single-byte tamper** *(folded from #2101 §11)*: extend
  `internal/auditverify/tamper_exhaustive_test.go`'s approach (introduced in
  PR #2097, in flight at time of writing) to this manifest — on a small
  fixture, flip every byte offset of the manifest JSON and of one
  representative table's NDJSON section in turn, and assert restore's pass-1
  verification never succeeds for any single-byte mutation.
  Mutation-kill-validate the same way that PR does: temporarily disable the
  manifest-hash/signature comparison and confirm the test goes red before
  trusting it green.
- **Fuzz**: extend `checkpoint_key_fuzz_test.go`'s existing pattern
  (`internal/core`) with a sibling fuzz target over manifest
  canonicalization/signing with adversarial field content — same rationale
  that file already documents for the checkpoint case, applied to the new
  canonical-encoding function from §5.4.

### 11.5 Truncation / corruption fuzz

A fuzz target feeding truncated and randomly-mutated archives (gzip stream
cut short, tar header corrupted mid-entry, an entry claiming a size it
doesn't have) into the restore parser (§7.3) — the property under test is
"never panics, never partially writes to the real target, always either
restores completely or refuses cleanly with the staging directory cleaned
up." Include truncation at every section boundary explicitly (start of a
table, mid-table, before the trailing manifest), not only random offsets.
This is a new fuzz target, not an extension of an existing one — closer in
spirit to `fuzz_encryption_command_fault_test.go`'s fault-injection style
than to a pure-parsing fuzz target, since the property being checked spans
"did the staging/verify/commit sequence uphold its own atomicity guarantee,"
not just "did the parser crash." This directly answers the original TRACK
OFFLINE-FUZZ ask that motivated #2101: arbitrary/truncated/oversized backup
input must never panic and never partially restore.

### 11.6 Wrong-key test

*(Folded from #2101 §11.)* Restore with an incorrect passphrase / no KMS
access. Assert clean refusal during §5.3's KEK-unwrap/manifest-verification
pass, zero rows written to the real target, staging directory cleaned up.

### 11.7 Post-restore verification test

*(Folded from #2101 §11.)* Corrupt the *source* database's audit chain before
taking a backup of it. Assert restore still succeeds at loading rows (the
data itself round-trips faithfully) but §9's automatic post-restore
`verify-audit` step reports `VerdictBroken`, the overall restore command
exits non-zero, and the loaded (broken) database is left in place, not
deleted.

### 11.8 Rollback protection

- Witness-file-absent (fresh host): archive with a low high-water restores
  without `--allow-rollback` and the witness file is created from it.
- Witness-file-present, archive is current or ahead: restores normally, no
  flag needed.
- Witness-file-present, archive is behind: refused without
  `--allow-rollback`; succeeds with it, and the printed/audited message
  states the actual event-count gap (assert on the message content, not just
  the exit code — matching this repo's "assert the effect, not the return
  value" convention for a control whose whole point is a specific,
  human-readable warning), and a corresponding audit event is written once
  the restore completes.
- **Anchor-based rollback test** *(folded from #2101 §11)*: take backup A, log
  further audit events and a new checkpoint, take backup B. Restore A while
  supplying `--anchor` derived from B's checkpoint; assert §6.4's check
  refuses the same way §6.3's witness-file check does, without
  `--allow-rollback`.

## 12. Decisions index

Every open question from this document's own earlier draft and from the
parallel draft (#2101) is resolved. This is a compact index; see the linked
section for detail and rationale.

| # | Decision | Section |
|---|---|---|
| 1 | KEK/DEK are never written unwrapped to disk, at any point, including inside the staging directory — only in process memory. | §5.3 |
| 2 | Notary anchoring stays optional, off by default; reused via `--anchor` when configured. | §6.4, §6.5 |
| 3 | `admin restore` accepts v1-physical-format archives until Keyorix 1.0, then drops that reader; new backups always write v2 (logical) once v2 ships. | §3.6 |
| 4 | `REPEATABLE READ` is the default consistency mechanism for Postgres backup; `--exclusive` is an explicit opt-in. | §4 |
| 5 | Restore ordering: FK-dependency order derived from each model's ID-shaped field names by convention (small CI-verified exception list for the rest), single transaction, mandatory post-load dangling-reference check (no skip flag) in place of deferred constraints, since this schema has no real FK constraints to defer. Corrected 2026-09-28. | §3.4 |
| 6 | No `--format=physical` escape hatch — logical format only, once v2 ships. | §3.6 |
| 7 | Anti-rollback fails closed by default (witness or anchor mismatch); override only via `--allow-rollback`, which writes an audit event. | §6.2 |
| 8 | Preflight free-space check on both commands, refusing up front rather than failing mid-run. | §7.4 |
| 9 | Restore refuses unrecognized/unsupported schema deltas (renamed or type-changed columns); migrations are additive-only by convention going forward. | §3.5 |
| 10 | Manifest-signing key is domain-separated from the audit-checkpoint key via its own HKDF `info` string. | §5.2 |
| 11 | SQLite → Postgres move and version-skipping upgrade are documented usage patterns of `admin backup`/`admin restore` — no new subcommands. | §1, §8 |
| 12 | v1 (and this redesign) supports full-database backup only — no selective/partial export. | §1 |

## 13. Implementation status

Implemented across a stacked PR series (2026-09-28). Two real bugs surfaced
while building the version-skipping upgrade proof (§8's real-binary
validation, below) landed as their own `fix` PRs, stacked in the order the
work actually needed them, per this repo's "a real bug found along the way
gets its own PR" convention — neither is a design change, both are noted
here for traceability.

| PR | What | Section(s) |
|---|---|---|
| #2261 | Logical format writer: `storage.AllModels()`, table-walk NDJSON writer, manifest v2, restore-order derivation, preflight free-space check | §3, §7.4 |
| #2263 | Authenticated manifest: KEK-derived signing key, HMAC-SHA256 sign/verify | §5 |
| #2270 | Full CLI wiring: `admin backup` writes v2 only, `admin restore` dispatches v1/v2, stage-then-verify-then-commit, rollback protection reused unchanged | §3.6, §5.3, §6 |
| #2280 | Postgres backup source: `REPEATABLE READ` default, `--exclusive` opt-in | §4 |
| #2284 | Core property test: `restore(backup(state))==state` across all 4 backend directions, registry-driven seeding | §11.1 |
| #2288 (fix) | `internal/backupfmt`'s row encoding was silently dropping every `json:"-"`-tagged column (encrypted secret values, password hashes, token hashes) — present since #2261, found via the version-skip proof below | §3.3 |
| #2291 (fix) | Postgres restore never resynced a table's auto-increment sequence after loading rows with explicit primary keys — also the root cause of a spurious first-request auth failure on a freshly-restored server | implementation gap, not itself a design decision above |
| #2293 | Version-skipping upgrade proof: a real old release binary backs up, HEAD restores onto Postgres, secrets/audit/authz all confirmed unchanged -- validates §8's reuse claim empirically, beyond §11.2's unit-test-level cross-backend check | §8 |

**Implemented, not built:** §6.4's externally-anchored rollback check
(notary/anchor-based, beyond the host-local witness file) — §6.5 states this
limitation explicitly; still open.
