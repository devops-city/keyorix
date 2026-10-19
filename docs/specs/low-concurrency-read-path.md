# Low-concurrency read path (PERF-LOWCONC-1)

Design note for the low/moderate-concurrency work on the machine-token secret read
(`GET /api/v1/secrets/{id}?include_value=true`). It records, per step, what the request does
today, what changes, which invariants the change touches, and what was considered and not
done. Measurements are in the session report, not here.

## The request today

A warm machine-token read makes these database round trips:

| | without single_writer | with single_writer (guard authoritative) |
|---|---|---|
| credential re-check (INV-MW-02) | 1 statement: the folded credential statement (credential, identity state, node stamp, roles at the node's scope, role→permission generation, schedule/versions; `local_folded_credential.go`) | 0: served by the fold memo while no fenced write is in flight or has finished since the fill (`local_folded_credential_memo.go`) |
| secret node, value | 0: node cache confirmed by the folded statement's stamp | 0 |
| audit row + access-log row | 1 flight: BEGIN, lock, insert-with-check, access-log insert, COMMIT (`local_audit_chain_one_flight.go`), batched with concurrent reads | same |

The audit append runs before the value is put in the response
(INV-CORE-secret-read-means-value-disclosure; audit-before-disclosure, AUDIT-001). It is
committed by the batching flusher, one committer at a time, in chain order.

## Step 1: adaptive flush — premise not found; one bug fixed

The premise was a fixed linger in the single_writer flush at low load. There is none: the
audit flusher's linger window defaults to 0 (a non-blocking drain; `audit_flusher_linger_window`
is opt-in), with or without single_writer, and reads that are not audited show the same open-loop
tail. The tail measured at 50 % open-loop load comes from the benchmark's warm-up: a fresh
single_writer stack cannot serve that rate until its caches are warm, and the requests that
queue during warm-up complete inside the measured window, counted from their intended send time.
In steady state the server's own per-request latency stays low. Two changes were built and
measured, and rejected because they did not move the numbers:

- an inline commit when no commit is in progress (no hand-off to the flusher goroutine): no
  measurable gain at c=1/10; unconditional, it cost throughput at c=100 (an append committing
  alone while the rest waited); with a contention window it was neutral;
- one slow-path validation per token at the auth-cache rollover (the others waiting, then taking
  the cache-hit path with their own live re-check): the rollover burst is real (each request also
  queued on the last-used row lock, which OPT-LASTUSED-1, #3348, takes off the request path), but
  it does not show in the benchmark cells.

What is kept is a bug the work found in the flusher (INV-STORE-audit-flusher-no-stranded-submission).
A submission reads the queue and releases the flusher lock before it sends; the idle exit checked
only that the queue was empty, so a send in that window landed in a channel nobody read and its
read failed closed at its audit deadline. Submissions now register under the lock before sending,
and the idle exit stops only when none is registered. Nothing else about the flusher changes: one
committer, chain order, batching, durability, the linger setting.

## Step 2: read and audit in one round trip — not done

The request already reads the secret in the same statement as the credential re-check (step
table above), so "fetch + audit insert in one statement" means folding the audit append into
the credential statement. That cannot keep the invariants:

- The audit row may be written only for a disclosure (INV-CORE-secret-read-means-value-disclosure),
  and whether the value is disclosed is decided in Go from the credential statement's answer:
  revoked / expired against the request's clock with the backward-clock-step bound
  (`authEffectiveNow`), identity state, the network allowlist, the scoped permission, schedule
  window, break-glass state. Writing the row in the same statement means either recording reads
  that are then refused, or re-implementing every one of those decisions in SQL, where the
  clock and the break-glass checks would run on the database's clock instead of the
  fail-closed Go checks. Neither is acceptable.
- Pipelining the credential statement with an uncommitted audit append (COMMIT or ROLLBACK sent
  after the Go decision) still needs a second flight, holds the chain lock across the decision
  and leaves the batching flusher, so it removes no round trip and costs throughput at high
  concurrency.
- With single_writer the credential re-check is already served from the memo, so a warm read
  is already one round trip (the audit flight).

What remains of step 2's goal is the cost of the audit flight itself: its client-side CPU
(statement building, step 3) and its execution in the database.

## Step 3: prepared statements

Without a transaction-mode pooler every pgx connection already runs
`QueryExecModeCacheStatement`: each statement text is prepared once per connection and executed
by name afterwards (the pgx default; `database_pooler.go` turns it off only behind a pooler, by
design). GORM's `PrepareStmt` would add a second, redundant cache on top. So the server-side
parse/plan cost is already paid once per connection and statement text. The remaining
per-request client cost on the hot path is building statement text: the audit flight resolved
the audit table name with a GORM DryRun on every batch; it is now resolved once per store. The
INSERTs themselves still go through GORM, because `AuditEvent` and `SecretAccessLog` have
`BeforeSave` hooks that normalise the stored values (the chain hashes cover them).

## Step 4: caches for token and permission checks

What is cached today, and what invalidates it:

| cache | holds | served when | invalidated by |
|---|---|---|---|
| auth token cache (`server/middleware/auth.go`) | the principal, ≤ `validTokenTTL` | every hit still runs the live re-check (or the fold memo) | TTL; explicit eviction on revoke/suspend/logout (INV-MW-07/08); machine-cache generation |
| fold memo (single_writer only) | the folded credential statement's last answer | guard authoritative, no fenced write in flight or finished since the fill, entry younger than `foldMemoTTL` | every fenced write (tracker generation), every epoch move seen by the poller, lease lapse |
| node / role→permission caches | node rows, role permission sets | confirmed by the stamp / generation read in the same statement | stamp and generation triggers |

Without single_writer the credential re-check is one statement per request, and it has to be:
a revocation, suspension, role or grant change made through another replica, or directly in
the database, must be refused on the very next request on every replica (INV-MW-02/08). No
in-process cache can know that without asking the database, and the folded statement is that
one question, already answering the node, role and schedule reads too. Step 4 therefore adds no
new cache. A cache with cross-replica invalidation (LISTEN/NOTIFY or a polled epoch) would
still need a read per request to be "very next request" exact, or would introduce a bounded
staleness window, which the recertification and CACHE-FAILCLOSED rules exclude. The existing
guards for that property are `TestFoldedCredential_CrossReplicaInvalidation` and
`TestFoldedCredentialCheck_RefusesExactlyAsUnfolded` (`server/http`, SQLite and PostgreSQL:
each change made through replica A, replica B's very next read answers like a cold replica).

## Step 5: single_writer writes — not changed here

Two serialisation points sit on every secret mutation today:

- the audit row of a mutation is appended inside the mutation's own transaction
  (INV-CORE-secret-mutation-audit-same-tx), which takes the chain's transaction-scoped advisory
  lock and holds it through the durable COMMIT, so all mutations queue behind one fsync each;
- with single_writer, the fence's guard trigger bumps the one write-epoch row at the
  transaction's first fenced write and holds that row lock to COMMIT as well, from an earlier
  point in the transaction than the audit append, so the single_writer critical section is the
  longer of the two.

Neither can be lifted by batching writes the way reads are batched (each mutation's audit row
must commit in its own transaction) or by letting writes bypass the single writer (the fence and
the epoch are how the caches learn about writes). What would help, and needs its own design
review because it changes the audit write path or the fence:

- committing the mutation with the audit lock held only until the commit record is written, and
  waiting for the WAL flush after releasing it, so concurrent mutations share flushes again;
- spreading the epoch over several rows (a transaction bumps one of them, the poller reads all of
  them with their row versions), which removes the epoch row as a single lock while keeping the
  row-version tamper check. A different trigger definition would stop `InstallFence` on existing
  deployments ("refuse, the operator drops it"), so this has to stay inside the function bodies
  and an additive own table.

Until both are addressed, single_writer costs write throughput, so it should not become the
default for write-heavy deployments.
