# Spec: incremental audit-chain verification (AUDIT-VERIFY-INCR-1)

Status: **Proposed** (2026-10-15). Builds on ADR-029 (hash chain, signed
checkpoints, high-water mark) and #3258 (purge-aware checkpoints: checkpoints
certify `chained + purged`).

## 1. Why

AUDIT-SCALE-1 (§2.2, §4 item 3; figures in that internal report) measured
that every verification was a full linear walk, whose cost grows with the
audit table. As a result:

- every server start walked the whole chain in the startup checkpoint tick;
- `GET /audit/verify`, `POST /audit/checkpoint` and `GET /compliance/posture`
  each walked it per call, and on large trails failed on the HTTP write
  timeout.

The work cannot be dropped: the per-row hash chain is unkeyed, so re-hashing
every row is the only way to find a row whose content changed. This spec
**moves** the work off the request path and off startup. Every row is still
re-hashed at least once per rolling cycle (weekly by default), and every
response states what it covers.

## 2. Three verification modes and exactly what each proves

Notation: `cp` is the latest checkpoint row, authenticated (HMAC) under the
current key, with `head_id > 0`. `hw` is the signed high-water mark. `P` is the
cumulative purged count from the authenticated retention anchor.

### 2.1 Full walk (unchanged: `KeyorixCore.VerifyAuditChain`)

Walks every chained row from genesis or the authenticated retention anchor to
the end, then applies the checkpoint and high-water checks (ADR-029, #3258).

**Proves:** at the moment of the walk, every chained row recomputes to its
stored `entry_hash` and links to its predecessor. The earliest surviving row is
genesis-linked or matches the signed anchor. The live count plus `P` is at least
the certified count and the high-water mark. The latest checkpoint's head row is
present and unchanged.

**Does not prove:** anything about rows appended after the last checkpoint and
then removed from the tail (no signed point covers them; this is unchanged
from ADR-029).

Used by: the `?full=true` background job, the checkpoint write when no usable
`cp` exists (first checkpoint, key rotation recovery), and `GET /audit/verify`
when incremental verification is not configured (no signing key, or
`insecure_disable_audit_checkpoints`). Offline `admin verify-audit` stays an
independent full walk with its own code (`internal/auditverify`).

### 2.2 Tail check (new: incremental)

1. Authenticate `cp` (as today). Apply the strict high-water check (as today).
2. Load row `cp.head_id`. It must exist, its stored `entry_hash` must equal
   `cp.head_hash`, and its `entry_hash` must recompute from its own stored
   fields and `prev_hash` (current encoding).
3. Walk rows with `id > cp.head_id` in id order, seeded with `cp.head_hash`:
   every row must link and recompute (same per-row rules as the full walk).
4. Derived certified count = `cp.chained_events + tail_rows`. This is the
   `chained + purged` unit, because rows purged after `cp` were counted in `cp`
   and are now counted in `P`. It must be at least the high-water floor. That
   catches "delete the newer checkpoints, then truncate the tail".

**Proves:** the certified head row is unchanged. Every row after it is intact
and hash-linked to it. No tail truncation below the high-water mark.

Read path and write path differ only where the old code differed:

- The request path is strict, like `enforceAuditCheckpoint`: a missing
  high-water mark while checkpoints exist is a tamper signal, and a configured
  TSA root re-verifies the checkpoint's external anchor.
- The checkpoint write keeps `writeAuditCheckpointLocked`'s rules: a missing
  mark or a mark under a superseded key does not block it, and the write
  re-establishes the mark. An anchor-verification failure does not block a
  fresh checkpoint.
- When every checkpoint row has been deleted, the request path checks the tail
  from the signed high-water mark, which certifies the same (count, head)
  snapshot. The write path falls back to the full walk instead.

**Does not prove:** that rows **before** `cp.head_id` are unchanged since they
were last walked. That is the job of the rolling cycle (§2.3) and of the full
walk. A response from the tail check never claims more than this. Its
`status` is `valid` only if a recent full verification also exists (§4).

### 2.3 Rolling full re-walk (new)

A cycle walks the whole chain in 7 (`DefaultAuditFullVerificationSegments`; not a
setting, since a larger value would only delay detection — ADR-112)
id-range segments, one per scheduler tick (default tick 24 h, so one cycle per
week). It is persisted in signed state (§3), so restarts and HA failover resume
it.

- **Cycle start:** the target is the head of the checkpoint written in this
  tick (`target_id`, `target_hash`, both signed in that checkpoint).
  `started_at` is set to now. The segment width is
  `max(ceil(target_id / segments), 100 000 ids)`, so a chain of up to 100k ids
  completes a cycle every tick (the pre-change cost).
- **Segment:** walk ids `(seed_id, seed_id + width]`. The first segment starts
  from the chain start with the full walk's rules (legacy unchained prefix,
  genesis or signed retention anchor). Each later segment is seeded with the
  `(seed_id, seed_hash)` that the previous segment verified and the signed state
  recorded. The seed row is pinned: it must still exist with that hash and
  recompute from its fields. The first new row must link to `seed_hash`. If a
  sanctioned purge has removed rows past `seed_id` (anchor row id > `seed_id`),
  the segment restarts from the chain start (anchor rules), because nothing
  before the anchor exists any more.
- **Cycle end:** the last segment must end exactly on (`target_id`,
  `target_hash`). The result is recorded as `last_full` with
  `started_at`/`completed_at`, and the cycle is cleared.

**Proves (when a cycle completes):** each row in `[chain start, target_id]`
recomputed and linked to its predecessor at the moment its segment was walked,
between `started_at` and `completed_at`. The walk ends on a signed checkpoint
head.

**Does not prove:** that the whole range was consistent at one single instant.
A row changed after its segment was walked is caught:

- at the next tick, if the change rewrites hashes through any checkpoint head:
  the tail check pins `cp.head_hash`, and a later segment pins its seed;
- otherwise when its segment is walked again, at most one cycle plus one tick
  later. Leaving a hash unchanged breaks the row's own recompute. Rewriting it
  without rewriting everything up to a checkpoint head breaks the next row's
  link.

That is the "tamper in an old segment is caught within one rolling cycle"
guarantee. It is the same unkeyed-chain argument ADR-029 already relies on, with
the walk spread over time.

## 3. Persisted verification state

One `system_metadata` row, `audit_verification_state`, single and overwritten:
`avs-v1␟<base64url(JSON)>␟<hex HMAC>`. The HMAC is computed with the checkpoint
signing key (KEK-derived, not held by the DB) over
`"auditverify-state-v1\x00" + JSON`. This domain-separates it from checkpoint,
high-water and anchor bytes. Fields:

- `gen`: the generation, +1 on every save. Saves are serialised by
  `WithAuditCheckpointLock`, so it strictly increases across replicas.
- `bind`: `{checkpoint_id, high_water}`, the latest checkpoint row id and the
  authenticated high-water count when the row was saved. Every checkpoint write
  saves the state in the same locked section, after the checkpoint and the mark.
- `rejected`: `{at, gen, reason}` when a writer found the previous row untrusted
  and started over (see below), or null.
- `cycle`: `{started_at, started_gen, target_id, target_hash, seed_id, seed_hash, scanned_through, width}` or null.
  A cycle older than two cycle durations is restarted from the chain start, not resumed.
- `last_full`: `{started_at, completed_at, through_id, source: rolling|job|checkpoint-full, valid, first_broken_id, reason, unchained_events}`.
- `last_check`: the last scheduler tail check `{at, valid, from_id, through_id, head_hash, certified_events, checkpoint_id, first_broken_id, reason}`.
- `failure`: the first detected break `{detected_at, gen, source, first_broken_id, reason}`. It is sticky.
  Only a **passing full verification that started after it** (its start generation ≥ `failure.gen`)
  clears it: a completed rolling cycle whose target covers `first_broken_id` (a failure without a
  row id, i.e. a refusal, needs a full job), or a full job that walked past `first_broken_id`.
  The checkpoint full-walk fallback never clears it. It refuses while a failure is recorded, like
  the tail path does.
- `job`: the latest `?full=true` job `{id, state, started_at, started_gen, finished_at, result}`.

A state row is **not trusted** when it is malformed, fails its signature (tampered,
or signed before a KEK-provider migration), or is **older than the trail**:
`bind.checkpoint_id` below the latest checkpoint row id, `bind.high_water` below the
authenticated high-water count, `gen` below a generation this process already read
or wrote, or the row is missing after this process read one. The trail is read
before the row, so a concurrent writer can only make the row look newer. An
untrusted row claims nothing: the API reports `not_proven` with `state_reason`.
An authentic but stale row keeps only its sticky `failure`, since a failure can
only make the verdict stricter.

A writer that finds an untrusted row does **not** overwrite it silently. It starts a
fresh state (no cycle, no `last_full`, plus an authentic row's failure and job). That
state records `rejected` and is reported `not_proven`, with the reason, until a full
verification that started after the rejection completes valid. The writer also appends
a `system.audit_verification_state_rejected` audit event. The checkpoint refusal gate
cannot apply to a failure it cannot read. A failure that was lost is re-detected
instead: by the tail check at every tick, or by the fresh cycle within one cycle.
The `system.audit_chain_verification_failed` event stays in the chain.

Writes are read-modify-write under `WithAuditCheckpointLock` (cross-replica on
PG), held only for the short merge, not for the walk. The rolling cycle is
advanced only by the scheduler tick, which also runs under the HA scheduler
lock, so at most one replica advances it.

When a tick, a segment or a job **first** records a failure, it also appends a
`system.audit_chain_verification_failed` audit event. That event becomes part of
the chain and is covered by later checkpoints, so the detection survives a
rollback of the state row.

## 4. API status rules

`status` is one of `valid`, `broken`, `not_proven`. `valid` (bool) is true
**only** when `status == "valid"`. `broken` takes precedence over `not_proven`.

- `broken`: the request's own tail check failed; or the state carries a sticky
  `failure`; or `last_full.valid == false`.
- `not_proven`, with `not_proven_reason`, in any of these cases:
  - no authenticated base checkpoint for a tail check;
  - no trusted state (forged, unverifiable or older than the trail, §3), or a
    state that records a rejection no later full verification has cleared;
  - no completed full verification yet;
  - the last full verification completed more than 2 cycles ago (stale);
  - the request's tail check ran out of its row budget (250 000 rows) before
    the end.
- `valid`: none of the above.

The checks above are **not** run on every request. A request only reads the
signed state and runs a bounded tail check (§2.2).

## 5. API contract changes (additive)

### `GET /api/v1/audit/verify`

Existing fields are kept; `valid` has the meaning in §4. New fields:

| field | meaning |
|---|---|
| `status` | `valid` \| `broken` \| `not_proven` |
| `mode` | `incremental` (tail check + persisted state) or `full` (walked now; incremental not configured) |
| `not_proven_reason` | set when `status = not_proven` |
| `coverage` | `{tail_from_id, tail_through_id, tail_complete, checkpoint_id}`: what this request walked |
| `last_full_verification_at` | `completed_at` of the last completed full verification (null if none) |
| `last_full_verification_started_at` | its `started_at`: every row through `last_full_verification_through_id` was re-hashed at or after this time |
| `last_full_verification_through_id` | last row id it covered |
| `last_full_verification_source` | `rolling` \| `job` \| `checkpoint-full` |
| `rolling_cycle` | `{started_at, target_id, verified_through_id}` when a cycle is in progress |
| `state_reason` | why the persisted state was ignored, when it was |

In `incremental` mode, `chained_events` is the derived live count
(`cp.chained_events − P + tail_rows`), and `head_id`/`head_hash` are the tail
walk's head.

Without a signing key no job state can be kept (it would be forgeable), and
the default report is already a full walk. So in that case `?full=true` returns
the full-walk report with 200.

`GET /api/v1/audit/verify?full=true` returns **202**
`{job_id, state: "running", status_url}`. It starts a background full walk
(§2.1). At most one job runs at a time across replicas: a scheduler-style
advisory lock on PG, plus an in-process guard. A request made while a job runs
returns 202 with that running job's id.

`GET /api/v1/audit/verify/jobs/{id}` returns 200
`{job_id, state: running|succeeded|failed|interrupted, started_at, finished_at, result}`.
`result` is the full-mode verify body. It returns 404 for an unknown or
superseded id. `interrupted` means the state says running but no replica holds
the job lock (the process died). Authorization is the same as `/audit/verify`
(the audit group's `audit.read`). A passing job records `last_full`
(`source=job`) and clears a sticky failure. A failing job records the failure.

### `POST /api/v1/audit/checkpoint`

The response shape is unchanged. The work done is now the tail check (§2.2)
from the latest usable checkpoint. The response refuses with **409**:

- if the tail check fails; or
- while a sticky failure is recorded: a broken chain must not be re-notarised.
  Today's full walk refuses then too.

It falls back to the full walk when there is no usable checkpoint (unchanged
recovery path).

### `GET /api/v1/compliance/posture` (`audit_integrity`) and evidence-pack `audit_anchor`

These read the persisted state only and walk nothing:

- `chain_verified` = `status == valid` (with no request-time tail check, the
  last scheduler tail check is used).
- New fields: `verification_status`, `last_full_verification_at`,
  `last_checked_at`.

### gRPC `VerifyAuditChain`

Same as HTTP default mode. New optional fields: `status`, `mode`,
`not_proven_reason`, `last_full_verification_at`. The full job is HTTP-only for
now (gRPC parity is a follow-up).

### CLI `keyorix audit verify`

- Prints `VALID`, `BROKEN` or `NOT PROVEN` with the coverage lines. Exit status
  is non-zero for both BROKEN and NOT PROVEN (fail closed for scripts).
- `--full` starts the job and polls the status endpoint until it finishes.

### Web compliance page

The "Audit chain verified" tile shows `Yes` / `No` / `Not yet proven`, with
the last full verification time.

## 6. Scheduler and startup

- The audit-checkpoint scheduler tick does three steps under the scheduler
  lock:
  1. tail check and checkpoint write;
  2. one rolling segment;
  3. a state save.

  Its cost is O(tail since the last checkpoint + one segment), not O(chain).
- **Startup:** when the latest checkpoint authenticates and is younger than the
  interval, the first tick is deferred until `created_at + interval`.
  `created_at` is not signed, so the deferral is clamped to `[0, interval]`: a
  forged timestamp can delay the first tick by at most one interval. Otherwise
  the first tick runs at once, at the cost above. Nothing on the startup path
  walks the chain synchronously.

## 7. Acceptance criteria

1. Tamper in the tail (a row after the latest checkpoint head, content edit
   without rehash) is caught at the next tick: the checkpoint is refused, a
   failure is recorded, and the API reports `broken`.
2. Tamper in an old segment (a content edit, or an edit plus rehash up to just
   before a checkpoint head) is caught within one rolling cycle (≤ segments + 1
   ticks), and the API then reports `broken`.
3. Before the first cycle completes, the API reports `not_proven` with a
   reason. It never reports `valid`.
4. A forged, rolled-back or foreign-key state row is ignored (`not_proven`).
5. A checkpoint head rewrite, a tail truncation with newer checkpoints deleted,
   and a high-water forgery are all still caught by the tail check.
6. The startup tick at 1M rows costs O(tail + segment), and is deferred
   entirely when a fresh checkpoint exists.
7. Every existing tamper test stays unchanged and green: `VerifyAuditChain` and
   `WriteAuditCheckpoint` keep their full-walk semantics.

## 8. Concurrency and failure cases

- **Two replicas tick at once:** the scheduler lock lets one run; the other
  skips.
- **A tick races `POST /audit/checkpoint`:** the checkpoint write is serialised
  by `WithAuditCheckpointLock` (#300). The on-demand path does not advance the
  cycle.
- **A full job races the tick:** both merge state under the checkpoint lock. The
  job only touches `job`/`last_full`/`failure`, and the tick touches
  `cycle`/`last_check` (it also sets `failure`/`last_full`).
- **Crash between a segment walk and the state save:** the segment is redone
  next tick. Progress is never claimed before the save.
- **A purge between segments:** handled by the anchor restart rule (§2.3). A
  purge that removes the cycle target row fails the cycle (the same residual
  as the head check in #3258).
- **Key rotation (KEK-provider migration):** the state fails its signature and
  is rejected (`rejected`, audit event). The checkpoint falls back to the full
  walk, which records `last_full` (`checkpoint-full`) and clears that rejection.
- **A checkpoint written outside the incremental path** (a replica with the
  checkpoint scheduler disabled serving `POST /audit/checkpoint`): the state
  is now older than the trail. Reads report `not_proven`, and the next tick
  records a rejection. That is fail-closed, not silent. Run every replica with
  the same scheduler setting.
- **All checkpoint rows deleted:** the write path, like the read path, checks
  the tail from the authenticated high-water mark (pinning its head). It falls
  back to the full walk only when the mark does not authenticate either.

## 9. Not covered (stated, not hidden)

- Replay of an older signed state row **within one checkpoint interval, in a
  process that has not read the newer row** (just after a restart or failover)
  is not detectable: the binding to the checkpoint trail is the same. That
  replay can roll back at most one interval of progress, or drop a failure
  recorded in that interval. The tail check re-detects a tail failure at the
  next tick. The next checkpoint makes the replayed row stale. The cycle age
  bound restarts a cycle that does not complete within two cycle durations.
  A deleted state row after a restart reads as a fresh deployment
  (`not_proven`, the cycle restarts from the chain start). Rolling back the
  checkpoint rows, the high-water mark and the state together after a restart
  is ADR-029's on-box rollback residual (external anchoring closes it).
- Rows appended after the last checkpoint and then removed from the tail before
  the next tick are not detectable on-box. That is ADR-029's existing residual.
- gRPC has no full-job RPC yet.
