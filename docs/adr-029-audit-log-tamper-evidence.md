# ADR-029: Audit-log tamper-evidence (hash-chained audit events)

**Status:** Accepted
**Date:** 2026-06-10
**Context:** NIS2 / DORA audit-log provisions; the honest "tamper resistance"
gap flagged in `docs/compliance/AUDIT-LOG-PROVISIONS.md` (checklist row 11).

## Context

Keyorix audit events are stored in the operator's PostgreSQL with no purge and
no cap (retention is unbounded — see the audit-retention coverage API). The
remaining integrity gap is **tamper-evidence**: nothing detects after-the-fact
modification, deletion, or reordering of audit rows by anyone with database
access. Auditors (DORA Art. 9-style record integrity) want evidence that the
trail has not been altered, not just that it exists.

Full WORM (write-once-read-many) immutability needs infrastructure outside the
application's control (append-only storage, an external notary/timestamp
authority, or a managed immutable ledger). What the application *can* provide,
self-contained, is **tamper-evidence**: a cryptographic hash chain over the
audit rows so that any modification/deletion/insertion is detectable.

## Decision

Maintain a SHA-256 **hash chain** over `audit_events`. Each event stores:

- `prev_hash` — the `entry_hash` of the immediately preceding chained event
  (or a fixed genesis constant for the first chained event).
- `entry_hash` — `SHA256( canonical(event fields) ‖ prev_hash )`.

Because each entry's hash binds the previous entry's hash, altering any field of
any row, deleting a row, inserting a row, or reordering rows breaks the chain at
that point and is detectable by re-walking it.

### Canonical encoding

**Corrected 2026-09-07**: this section originally described the encoding as
null-separated. It is now length-prefixed (TLV), a later fix closing a field-
boundary injectivity gap a pure separator can't close (two different field
splits could otherwise hash identically) — see
`TestComputeAuditEntryHash_FieldBoundaryCollisionRejected`
(`internal/storage/store/local_audit_chain_test.go`). `entry_hash` is
computed over a **fixed-order** encoding of the
semantically meaningful fields: `prev_hash`, `event_type`, `user_id`,
`secret_node_id`, `project_id`, `ip_address`, `description`, `success`,
`event_time`, `diff`, `impersonated_by`, `acting_as`, `impersonation`,
`actor_type`. The DB-assigned `id` is **deliberately excluded** — it is not
known before insert, and chain linkage already pins each row's position.

`event_time` is encoded as **Unix microseconds** (`UnixMicro`), and the stored
`event_time` is truncated to microseconds before both hashing and insert. This
is required for correctness: PostgreSQL `timestamptz` has microsecond precision,
so a nanosecond-precision `time.Now()` would not round-trip and verification
would fail for every row. Truncating up front makes the stored value exactly
equal to the hashed value on both Postgres and SQLite.

### Serialization (correctness under concurrent writers)

Audit events are emitted from detached goroutines, so appends are concurrent. A
hash chain requires the read-previous-hash + insert to be atomic. The write is
therefore serialized:

1. A process-level mutex on the storage handle (covers the common single-writer
   self-host topology and SQLite, which serializes writes anyway).
2. Inside a DB transaction, a PostgreSQL **transaction-scoped advisory lock**
   (`pg_advisory_xact_lock`) guards the critical section across processes for
   multi-instance Postgres deployments (no-op on SQLite).

The transaction reads the current chain head (`entry_hash` of the highest-`id`
row), computes the new `entry_hash`, and inserts — all under the lock.

### Verification

`VerifyAuditChain` walks events by ascending `id` in bounded batches and, for
each chained row, (a) checks `prev_hash` equals the running previous
`entry_hash` (genesis for the first), and (b) recomputes `entry_hash` from the
row's stored fields and checks it matches. The first divergence is reported with
the offending `id` and reason. Exposed as `GET /api/v1/audit/verify`.

Since AUDIT-VERIFY-INCR-1, that endpoint, the checkpoint scheduler, the
on-demand checkpoint and the compliance posture no longer walk the whole chain.
They use a tail check from the latest signed checkpoint, and a rolling full
re-walk spread over the scheduler ticks that keeps its progress in a signed
state row. Every row is still re-hashed at least once per cycle. The full walk
stays available as `?full=true` (a background job) and as the offline
`admin verify-audit`. What each mode proves and does not prove:
`docs/specs/audit-incremental-verification.md`.

### Legacy rows

Events written before this ADR have empty `prev_hash`/`entry_hash`. Verification
treats a leading run of empty-hash rows as an **unchained legacy prefix** (counted,
not failed); the chain begins at the first row written after the columns exist.
New columns are added via additive `ALTER TABLE` guarded by `columnExists`
(never via a full `AutoMigrate` on an existing table — avoids the pgx
double-migration hazard).

## Consequences

- **Detectable**, not **prevented**: an attacker with DB write access can still
  modify rows, but cannot do so *undetectably* without recomputing the entire
  forward chain — and cannot at all if a verified `entry_hash` has been exported
  off-box. Re-anchoring the head to an external notary is a future enhancement.
- **On-box re-verification cannot, by itself, detect tail-truncation or a
  genesis re-seed** (clarified 2026-06-13 after an internal audit). Because the
  genesis hash is a fixed public constant and nothing on-box records how long the
  chain *should* be, deleting the most recent N events — or wiping the chain and
  re-seeding from genesis — leaves a shorter-but-self-consistent chain that
  `VerifyAuditChain` accepts. Reorder, insert and middle-deletion remain
  detectable (they break the linkage). Truncation/re-seed detection requires an
  **off-box anchor**, now actually delivered:
  - the verification API returns the chain **`head_hash` + `head_id` +
    `chained_events`**; an external monitor recording these sees the count drop or
    the head move for a known prefix — the truncation signal; and
  - the audit **export** (`GET /audit/export`, SIEM pull) now carries each event's
    `prev_hash`/`entry_hash`, so the off-box observer holds the chain links and can
    prove a later on-box head diverges. (Previously the export omitted the hashes,
    so the "exported `entry_hash` anchors the head" claim was aspirational; it is
    now real.)
  - A **signed/notarised in-DB checkpoint** makes truncation detectable **on-box**
    too — **delivered.** An opt-in scheduler (`audit_checkpoints.enabled`, HA-gated)
    periodically writes an `audit_checkpoints` row recording the verified
    `(chained_events, head_id, head_hash)` plus an **HMAC-SHA256 signature** keyed
    by a key the running server holds in memory but the database/DBA does not —
    it is HKDF-derived from the **KEK** (`encryption.Service.AuditCheckpointKey`,
    info `keyorix-audit-checkpoint-kek-v2`; **#502, corrected 2026-07-05** — it was
    originally HKDF-derived from the DEK, info `keyorix-audit-checkpoint-v1`, which
    meant every routine `RotateDEKWithSweep` followed by a server restart caused
    every existing checkpoint to fail its signature check, so `VerifyAuditChain`
    reported the whole trail invalid until the next checkpoint write re-baselined
    it — a real, if self-healing, false-tamper-alarm on every DEK rotation. Mirrors
    the identical #268 fix for the evidence-signing key: the KEK is untouched by a
    routine DEK rotation and only changes on a rare, deliberate KEK-provider
    migration, so a checkpoint signed before a DEK rotation now stays verifiable
    after one, with no window where `keyorix audit verify` falsely reports
    tampering), so signed checkpoints require encryption enabled. `VerifyAuditChain`
    then verifies the live chain against the latest checkpoint. The checkpoint is
    **authenticated first** (the HMAC covers every field, so nothing it claims —
    including `key_version` — is trusted until the signature verifies under the
    current key); then a chain shorter than the certified length, or a rewritten
    certified head, flips `valid` to false with a `checkpoint_reason` — catching
    the tail-truncation / genesis re-seed the bare re-walk cannot. A checkpoint row
    altered in **any** field without the key fails the signature check and is
    reported as a tamper signal — there is deliberately no unauthenticated field
    (e.g. `key_version`) a DB-level actor can edit to skip enforcement. A new
    checkpoint is refused over a chain shorter than an authenticated prior
    checkpoint, so a truncation is never silently re-baselined away. Surfaced as `checkpointed`/`checkpoint_reason` on `/audit/verify` and in
    `keyorix audit verify`.
  - **Checkpoint-write serialization (#300):** `WriteAuditCheckpoint` is reachable
    from three unsynchronized triggers — the scheduler tick, the HTTP
    `POST /api/v1/audit/checkpoint` endpoint, and the gRPC `WriteAuditCheckpoint`
    RPC — which can land on different replicas (HA). Without serialization, two
    overlapping calls could interleave the chain-walk + decide + create sequence
    and commit a checkpoint out of chain-length order: the row with the higher DB
    `id` could end up certifying FEWER chained events than an earlier-committed
    row, so `LatestAuditCheckpoint`'s `id DESC` pick would silently miss coverage
    of events that landed in the interleaving window — a real gap even with a
    fully-intact, validly-signed chain. `WriteAuditCheckpoint` now runs its whole
    sequence under `storage.WithAuditCheckpointLock`, mirroring the per-event
    append serialization above: a process-level mutex for the common single-writer
    topology and SQLite, extended across processes/replicas on PostgreSQL with a
    blocking session advisory lock (`pg_advisory_lock`, distinct from the
    per-append lock key). Unlike the scheduler's own `WithSchedulerLock` (a "try"
    lock that skips a tick on contention), this blocks until free, so an
    operator-triggered write racing the scheduler is serialized, not dropped.
  - **Key rotation:** a checkpoint signed under a superseded signing key cannot be
    re-verified on-box, so after a rotation `verify` fails closed (reports invalid)
    until the next checkpoint write re-baselines under the new key — the scheduler
    does this on its next tick / at startup, and an operator can force it
    immediately with `keyorix audit checkpoint` (`POST /api/v1/audit/checkpoint`,
    system.write). `WriteAuditCheckpoint` re-baselines over an *unverifiable* prior
    checkpoint but still refuses over an *authenticated* truncation. Trusting the
    unauthenticated `key_version` to suppress that alarm was rejected — it would let
    an attacker forge the rotation case to mask a truncation. **Since #502** the
    signing key is KEK-derived, not DEK-derived (see above), so a routine
    `RotateDEKWithSweep` no longer triggers this at all — only a genuine
    KEK-provider migration (ADR-041, a far rarer, deliberate operator action) does.
  - **Residual (honest scope):** enforcement consults the latest checkpoint row.
    A DB-level actor who can write `audit_checkpoints` can therefore *neutralise*
    on-box enforcement — delete every row, or overwrite the latest slot with an
    unverifiable row — which makes `verify` **fail closed** (reports invalid) until
    the next scheduler write re-baselines; if they truncate within that window the
    fresh checkpoint blesses the shortened chain. In all such cases detection
    reverts to the off-box external anchor above (#139): an external monitor that
    recorded `(ChainedEvents, HeadHash)` sees the count drop. What a DB-level actor
    can **never** do is *forge* a checkpoint that makes `verify` return valid over a
    truncated chain — the HMAC key is never in the database. (Enforcing the latest
    *signature-valid* checkpoint rather than the latest row would shrink this window
    further; deferred as hardening.)
  - The anchor is **operator-accessible from the CLI**: `keyorix audit verify`
    (exit non-zero if the chain breaks; `--json` emits `head_hash`/`head_id`/
    `chained_events` for recording) and `keyorix audit export` (NDJSON SIEM pull
    carrying the per-event hashes). A nightly `keyorix audit verify --json` appended
    to an off-box log is the intended way to operationalise the external anchor.
- Audit writes now take a lock + transaction. Audit emission is already
  asynchronous/best-effort and off the request hot path, so the added latency is
  not user-visible.
- WORM/immutability (append-only physical storage) remains out of scope and
  operator-owned; this ADR delivers tamper-*evidence*, moving compliance
  checklist row 11 from "⚠️ Roadmap" to "✅ hash-chained (verification API);
  physical immutability operator-owned".
