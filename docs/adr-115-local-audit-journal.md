# ADR-115: Local append-only audit journal (opt-in alternative durability point)

**Status:** Parked (2026-10-13)
**Date:** 2026-10-05
**Context:** PERF-4 (performance-parity study, `~/proj/prompts/reports/SESSION-PERF-2.md`).
Confirmed H1: with audit-before-disclosure enforced (non-negotiable, see below),
a solo request at concurrency 1 pays one full synchronous Postgres transaction
(advisory lock + chain-head `SELECT` + `INSERT` + commit) before the HTTP
response can include the secret value — PERF-2's measured `keyorix-pg` W1 c=1
p50 (8.36ms) is statistically indistinguishable from the independently measured
`fdatasync` floor on the same disk (9.326ms). ADR-029 + #2420 already batch this
cost away at concurrency (group commit, median batch size 28 at c=50), but at
c=1 there is nothing to batch — group commit cannot amortize a cost that only
one caller is paying.

## Non-negotiable invariants this ADR must not weaken

- **Audit-before-disclosure**: a secret value is never returned to a caller
  before its audit record is **durable**. This ADR changes *where* "durable"
  points to (a local journal fsync instead of a Postgres/SQLite commit), not
  whether the guarantee holds.
- **Immediate revocation (#G18)**: a revoked token/session/role must stop
  working on the very next request, on every replica. Unaffected by this ADR —
  revocation checks read live authorization state, not the audit trail.
- ADR-029's tamper-evidence hash chain over `audit_events`, its signed
  checkpoints, `VerifyAuditChain`, `MigrateAuditChainEncoding`, and the
  `/audit/export`/`/audit/verify` APIs must keep working **unmodified** against
  the DB table in the steady state. This ADR adds a new component in front of
  that table; it does not replace it.

## Context

The current durability point (ADR-029 + #2420's group-commit flusher) is "the
audit event is a committed row in the operator's relational database." On
Postgres, committing a row requires a synchronous network round trip plus a
`fdatasync` on the database server's WAL — a cost floor independent of how
efficient Keyorix's own application code is. PERF-2 measured this floor
directly (`pg_test_fsync -s 5` against the real Postgres data volume,
cross-validated with `fio --sync=1`): **~9.3ms per durable commit** on PERF-2's
reference disk, with nothing to batch at c=1.

Vault/OpenBao's file audit device is architecturally cheaper per operation at
low concurrency: a flat-file sequential `fsync`-append is a single local
`fsync(2)` call with no network round trip, no transaction machinery, and no
relational constraints to check. PERF-2's own data shows this gap directly —
audit-on vs audit-off Vault is -25% throughput at c=1 but within noise at c=50
(Finding 2), the same batching-vs-nothing-to-batch shape H1 predicts for
Keyorix.

## Decision

Introduce an **opt-in local append-only audit journal** as an alternative
durability point, sitting in front of the existing Postgres/SQLite
`audit_events` table rather than replacing it:

1. An audit write's durability point becomes **"fsynced to this replica's
   local journal file,"** not "committed to the relational database." A read
   (or any disclosure) still blocks on this exactly as it blocks on the
   Postgres commit today — the invariant is preserved, only the mechanism
   providing it changes.
2. A background **replicator** goroutine asynchronously replays journal
   records into `audit_events`, using the **same** `computeAuditEntryHash`
   encoding, the **same** Postgres advisory lock
   (`auditAdvisoryLockKey`/`pg_advisory_xact_lock`), and the **same**
   chain-head-read-then-insert transaction shape `commitBatchAttempt` already
   uses today — the only thing that moves is *when* this runs (asynchronously,
   off the request's critical path) and *who* triggers a batch (the
   replicator's own drain loop, not a caller blocked waiting for it).
3. `audit_events`, `VerifyAuditChain`, checkpoints, and every existing audit
   API are **completely unchanged**. The journal is new machinery in front of
   an unmodified backend.

Gated off by default behind a new config block
(`local_audit_journal.enabled: false`); see Prototype section.

### Journal format

One journal directory per replica (server process), e.g.
`<data_dir>/audit-journal/<replica_id>/`, containing a sequence of append-only
segment files (`NNNNNNNNNNNNNNNN.seg`, segment-rotated at a fixed size so no
single file grows unbounded and old, fully-replicated segments can be
retired). Each record:

```
[4B  magic+version]
[8B  journal_seq      — monotonic per-journal, big-endian uint64]
[4B  payload_len      — big-endian uint32]
[payload_len B  payload — TLV-encoded audit event fields, same field set and
                 same length-prefixed encoding discipline as
                 computeAuditEntryHash (ADR-029 / #1452's injectivity fix),
                 plus the optional access-log row]
[32B local_prev_hash  — this journal's own chain predecessor's local_entry_hash]
[32B local_entry_hash — SHA256(payload ‖ local_prev_hash), journal-local chain]
[4B  crc32            — IEEE CRC32 of every preceding byte of this record]
```

The **local journal chain** (`local_prev_hash`/`local_entry_hash`) is
*provisional and journal-scoped* — it exists so the journal is tamper-evident
and so corruption/reordering within one replica's own journal is detectable
before trusting it enough to replay (see "Corrupt journal" below). It is
**not** written into `audit_events.prev_hash`/`entry_hash` — those columns are
still assigned by the replicator at replay time, against the real,
shared, global DB chain head, exactly as `commitBatchAttempt` computes them
today. This is the key compatibility property: `VerifyAuditChain` never needs
to know the journal exists.

### Group fsync batching and its latency bound

A single writer goroutine per journal (mirroring `runAuditFlusher`) drains a
bounded channel of pending append requests, appends every currently-queued
record to the open segment file in memory, and issues **one `fsync(2)` call
per batch** before acknowledging any caller in that batch — the same
group-commit shape #2420 already proved out for Postgres, applied to a local
file instead. Latency bound: a solo call at c=1 pays exactly one local fsync
(no batching possible, same as today's floor, but against local disk instead
of a network Postgres commit — the PERF-2 fsync-floor table shows a *local*
`fdatasync` is the same physical operation Postgres itself eventually pays,
minus the network round trip and Postgres's own transaction/WAL overhead on
top of it). Under concurrency, N concurrent callers arriving within one drain
window share one fsync, identical amortization to the existing flusher.
Default linger window is 0 (no deliberate wait), mirroring
`AuditFlusherLingerWindow`'s already-measured rationale (#2420): a fixed
per-call tax to artificially wait for a batch that may not materialize is a
net loss at low concurrency.

### Hash-chaining compatible with the existing audit chain and signed checkpoints

- **Local journal chain**: tamper-evidence for the journal itself (detect
  reordering/corruption of already-fsynced-and-acknowledged records before
  replay). Independent per replica; never compared across replicas.
- **Global DB chain**: unchanged. The replicator calls the existing
  `computeAuditEntryHash`/chain-head-read/insert logic, under the existing
  advisory lock, exactly as `commitBatchAttempt` does today — just triggered
  by the replicator's drain loop instead of a blocked HTTP request. ADR-029's
  checkpoints keep signing the same table with the same key; this ADR adds no
  new signing key and no new verification surface for the DB chain itself.
- Each replicated row additionally records its origin
  (`journal_replica_id`, `journal_seq`) in two new nullable columns on
  `audit_events`, added the same additive, `columnExists`-guarded way ADR-029
  added `prev_hash`/`entry_hash` — so a reconciliation tool (and the "DB copy
  converges" test, see Prototype) can prove every acknowledged journal record
  has a corresponding DB row, independent of trusting the replay cursor alone.

### Asynchronous replication, crash replay, idempotent exactly-once-visible DB copy

- A **replay cursor** (`audit_journal_replay_state(replica_id, last_replayed_seq)`)
  is advanced in the **same transaction** as the batch of `audit_events` rows
  it covers (an `INSERT ... ON CONFLICT (replica_id) DO UPDATE` upsert,
  alongside the batch's own inserts). This is the load-bearing property: the
  rows and the cursor commit atomically, so there is no crash window where
  rows are durable in the DB but the cursor was not advanced (would cause
  re-replay/duplicate insert on restart) or vice versa (would cause the
  replicator to skip rows it never actually replayed). On restart, the
  replicator reads `last_replayed_seq` for its own `replica_id` and resumes
  from `last_replayed_seq + 1` — no separate dedup/idempotency key is needed
  because the transactional boundary already makes "replayed" and "cursor
  advanced" a single atomic fact.
- **Crash replay**: on startup, before serving any traffic that could emit a
  new audit event, the replicator (a) validates the local journal (see
  "Corrupt journal" below), (b) reads its persisted cursor, (c) replays every
  un-replayed, already-fsynced record in cursor order. Because every
  journal-fsynced record was, by construction, acknowledged to its caller
  (group fsync completes before any `done <- nil` in that batch), this closes
  the loop: **no acknowledged read can lack a durable audit entry after
  restart**, because every acknowledged entry already survived an fsync and
  the replicator's only job after a crash is to catch the DB copy up to what
  the journal already durably holds.

### Multi-replica behaviour

Each replica owns exactly one local journal directory; journals are **never**
shared or merged across replicas, and the journal's own per-record
`journal_seq` is only ever compared within its own journal. The **global**
`audit_events` chain order is defined purely by **DB insertion order** —
whichever replica's replicator transaction wins the race to read the current
chain head next becomes the next link, exactly the same "some total order
imposed by a single serialization point, not a claim about real-world causal
order across replicas" property `commitAuditBatch`'s own doc comment already
states for the single-process case today. The cross-process Postgres advisory
lock (`auditAdvisoryLockKey`) is unchanged and continues to be the mechanism
that makes this safe with multiple replicas' replicators running concurrently.
SQLite deployments are single-node by construction, so "multi-replica" does
not apply there; the journal still exists as a single local queue in front of
SQLite's own writer-lock-serialized commit.

### Disk-full and corrupt-journal behaviour (fail closed)

- **Disk-full on journal append** (the batch's `write`/`fsync` returns
  `ENOSPC` or any other error): every caller in that batch receives that
  error — `done <- err`, exactly as `commitAuditBatch` already propagates a
  failed Postgres commit to its waiters today. The caller's read/disclosure
  **must fail**, not proceed without a durable audit record. This is the same
  "audit-before-disclosure is non-negotiable" guarantee, just enforced at a
  different I/O boundary.
- **Corrupted journal tail** (the expected case — the process crashed
  mid-append, after `write()` but before the batch's `fsync()` completed, or a
  torn write at the OS/disk level): on startup validation, a record at the
  **physical end of the file** that fails its length/CRC/local-chain check is
  treated as an **incomplete, never-acknowledged tail write** — safe to
  discard, because the group-fsync protocol only ever acknowledges a caller
  *after* the whole batch's `fsync()` returns success, so a torn record at the
  tail can only be in-flight, unacknowledged data. The replicator truncates
  the journal at the last verified-good record boundary and resumes normally.
  No alarm, no manual step — this is the routine, expected post-crash state.
- **Corruption in the middle of the journal** (a valid-looking record
  boundary is found *after* a record that fails its CRC/chain check — i.e.
  corruption of data that previous, already-fsynced-and-presumably-replayed
  records prove was once intact): this is unambiguous evidence of corruption
  of already-acknowledged data (bit rot, a disk fault, or tampering), not an
  in-flight crash artifact. The replicator **fails closed**: it refuses to
  replay past the corruption point, marks the journal unhealthy, and the
  server **stops disclosing secrets** (the same posture
  `refuseIfAuditChainBroken` already takes for the DB chain: never silently
  route around possible evidence tampering) until an operator investigates and
  explicitly clears the condition. This mirrors
  `MigrateAuditChainEncoding`'s refusal design, applied to the journal layer.

### Air-gapped / SQLite single-node fit

The replicator is backend-agnostic — it performs the same batched-insert
transaction shape against either Postgres or SQLite. The *latency* win is
Postgres-specific (removing a network round trip); on SQLite the local
journal mainly changes *who* contends for SQLite's single-writer lock (one
replicator goroutine, instead of every request's own transaction racing
`SQLITE_BUSY` — a plausible mitigation for PERF-2 Finding 4, the SQLite W4
write-contention errors, though that is not this ADR's goal and is not
claimed as fixed by it). An air-gapped single-node SQLite deployment works
identically to any other deployment: one replica, one journal, one replicator.

### Backup / restore

This is a genuine new operational requirement, stated honestly: between
"fsynced to the journal" (durable, already disclosed) and "replayed into the
DB" (visible to `VerifyAuditChain`/`/audit/export`), an event is durable but
**not yet present in a database-level backup**. A `pg_dump`-style backup taken
without accounting for this could restore to a state missing audit events
that were already disclosed to callers. Operators enabling this feature must
either (a) back up the local journal directories alongside the database, or
(b) sequence backups to run only after confirming each replica's replay
cursor has caught up to that replica's journal tail (a "drain" step exposed
via the status endpoint below). This ADR does not attempt to automate either
option in the prototype; it is documented as a required operational change
when `local_audit_journal.enabled: true`, same spirit as ADR-029's own honest
"on-box re-verification cannot by itself detect tail-truncation" scoping.

### What changes for auditors

In the steady state: nothing. `/audit/verify`, `/audit/export`, and
`keyorix audit verify`/`export` keep working against the unmodified
`audit_events` table. The new, honest difference: a **replication-lag
window** exists where an event has already happened (and is durable in the
journal) but has not yet appeared in the DB-backed audit trail. A new
read-only status surface, `GET /api/v1/audit/journal-status`
(`system.read`-scoped, per-replica), exposes `journal_tail_seq`,
`db_replicated_seq`, and the resulting lag, so an auditor (or the backup
procedure above) can tell whether the DB view is current or is lagging, and
by how much. This endpoint is new API surface this ADR introduces; it is not
required for correctness, only for operational honesty about the lag window.

## Consequences

- **Durability is preserved, immediate DB-queryability is not** — the
  trade-off this entire ADR exists to make. Explicitly scoped and surfaced
  (previous section), not hidden.
- **New failure mode surface**: local-disk exhaustion/corruption on the
  journal's own volume becomes a direct cause of "server stops disclosing
  secrets," where previously only the database's own availability caused
  that. This is the intended fail-closed behaviour, not an oversight, but it
  does mean the journal's disk needs the same operational attention the
  database's disk already gets.
- **New backup/restore step** operators must adopt when this flag is on
  (previous section).
- **No change** to ADR-029's tamper-evidence model, checkpoint signing, or
  verification APIs — this ADR is additive in front of that mechanism, not a
  replacement for it.
- Expected effect on PERF-2's H1 finding: removes the network-Postgres-commit
  cost from the disclosure critical path at low concurrency, replacing it with
  a local fsync — the measured delta is the Prototype's benchmark task
  (PERF-4 item 3), not asserted here.

## Outcome

The prototype (#2758, now closed) was built and measured (PERF-5). Findings:

- The original slowness of the prototype came from syncing a growing file with
  a full `fsync`. Using `fdatasync` on pre-written (zero-filled) segments
  fixes that.
- Even with that fix, the journal only improved **median** latency over the
  existing group commit (ADR-029 + #2420). It did not change the picture
  enough to justify what it adds: a second durability component with its own
  failure modes, and a not-yet-replayed tail (journalled but not yet copied to
  the database) whose loss is undetectable.
- Decision: **parked**. Revisit only if group commit becomes the bottleneck.

The design above is kept intact for that case. Nothing in the codebase
implements it.

## Status

Parked (2026-10-13). Andrei approved the idea in principle on 2026-10-03 (per
PERF-4's brief), and approved parking it on 2026-10-13 after PERF-5's findings
(see Outcome). Originally Proposed; the prototype (PERF-4 item 2) was measured
and closed rather than adopted.
