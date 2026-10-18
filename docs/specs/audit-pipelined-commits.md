# Audit flusher: pipelined batch commits (PERF-HIGHLOAD-1)

Design note for the high-concurrency work on the audited secret read. It records what the
audit flusher does per batch today, what changes, which invariants the change touches, and
what was considered and not done. Measurements are in the session report, not here.

## The batch commit today

Every audited read hands its audit row (and its `secret_access_logs` row) to the root
store's flusher and waits for that row's batch to commit before the value is returned
(audit-before-disclosure, AUDIT-001; INV-CORE-secret-read-means-value-disclosure). One
flusher goroutine per store commits one batch at a time. On PostgreSQL a batch is already:

- one multi-row INSERT per table, with the hash-chain links computed in memory first
  (`chainAuditBatch`; INV-STORE-audit-batch-insert-values-order);
- the events INSERT and the head and link checks in ONE statement (`auditInsertCheckSQL`);
- the whole transaction in one network flight while the flusher's chain-head cache is armed
  (INV-STORE-audit-one-flight-commit), two flights otherwise (INV-STORE-audit-pipelined-commit).

So step 1 of the brief (one statement per batch, links computed once) is already the shipped
shape. COPY is not used: it cannot carry the in-statement head and link checks or return the
stored ids, and those checks are what make a cached head safe.

What is left is that the batches run strictly one after another. A batch's cycle is:
build the statements and hash the rows on the flusher goroutine, send, wait for Postgres to
execute the INSERTs and COMMIT, deliver the results, then start building the next one. Under
high load the flusher's connection is idle while the next batch is being built, and the
flusher goroutine is idle while Postgres executes. Postgres itself serialises the batches on
the KEYAUDIT advisory lock either way, so the only part that can overlap is the client side:
statement building, hashing, the network flight and the hand-off between goroutines.

## Step 1: indexes

`audit_events` carries the primary key plus four list indexes (`AuditListIndexes`: event time,
and project / secret / machine identity each with event time); `secret_access_logs` the primary
key plus three (secret + time, time + secret, secret + action). Every audited read updates all
nine. Each one has a consumer: the audit list keyset filters (docs/specs/audit-list-keyset.md),
the per-secret access history and `total_reads`, the access-time window of anomaly detection
and the first-seen query. None is removed or merged here: that changes which queries are
served by an index, which is a product decision (the session report carries the measured
write cost of the indexes and the question).

## Step 2: pipelined commits

### Shape

The flusher keeps up to `auditPipelineDepth` (2) batches in flight on PostgreSQL. While batch
N is executing (or waiting for KEYAUDIT), the flusher already builds batch N+1 and sends it on
a second pool connection. Postgres grants the lock to N+1 when N commits and runs N+1's
statements at once, with no client round trip in between.

A batch is sent pipelined only in the one-flight form: BEGIN, the fast-mode `SET LOCAL` when
enabled, `pg_advisory_xact_lock(KEYAUDIT)`, the events INSERT with its head and link checks,
the access-log INSERT, COMMIT. Its rows are chained client-side onto the row it expects to be
the chain head:

- the first batch of a pipeline run chains onto the cache head (id and entry_hash known), as
  the one-flight commit does today, and only while the cache is armed;
- every later batch of the run chains onto the last row of the batch sent just before it.
  That row's id is not known yet (the INSERT takes ids from the column default), so the head
  is "the row with this entry_hash, id pending".

Chain positions are therefore assigned before the batch is sent, in send order, and the
batches are sent one after another from the flusher goroutine: N's flight is on the wire
before N+1 is built.

### Why a pending id is still checked exactly

The check runs inside N+1's transaction, after its lock statement, over one snapshot: the
id-DESC head `h` of the table followed by the rows `e` the INSERT stored. It passes only when
there are exactly `len(e) + 1` rows (so `h` exists), the lowest of them by id has the expected
entry_hash (so it is `h`: every stored row's entry_hash differs from it, each one hashing its
predecessor's), and every later row links prev_hash to the previous row's entry_hash in id
order. That already implies every stored id sorts above `h`. With the id known the check also
compares it, as today; with it pending only the comparison of the id is left out, nothing else.

A failing check must raise, never evaluate to NULL: the raise is a cast of a message to int,
and a NULL message would cast to NULL and let COMMIT run. The message therefore never
concatenates the pending id; `TestAuditInsertCheck_PendingHeadMismatchRaises` pins it.

### Results, in order

Each in-flight batch is completed in send order: batch N+1's outcome is handled only after
batch N's (its rows delivered, the cache updated, any recovery finished). A read is answered
only after ITS batch's COMMIT has been acknowledged; nothing is delivered earlier than today,
and a batch that committed implies every batch before it committed (its check proved their
rows are below it in the chain).

### Failure semantics (fail closed)

- A batch whose flight failed in a way that provably wrote nothing (an error Postgres answered
  before COMMIT: a head that moved, a check that raised, a bad row, a lost lock) is retried
  exactly as a failed one-flight commit is today: the cache is disarmed and the batch goes
  through the two-flight path, which re-reads the head under the lock; if that fails too, the
  existing bisection confines the error to the poisoned item. This is the same code path as
  today's one-flight miss, run from the completion step in send order.
- Every batch sent after a failed one was chained onto rows that are not there, so its check
  raises and it is rolled back; it is then retried the same way, after the failed batch's
  recovery and in send order. Until the pipeline has drained, the flusher sends nothing new; it
  then continues with serial commits until the cache re-arms (the existing `need` rule).
- A batch whose outcome is unknown (connection lost, an error answered for COMMIT itself) fails
  its readers, as today. The batch sent after it either commits (N did commit: its check sees
  N's rows) or is rolled back by its check and retried. Either way the chain stays linear.
- Every read waiting on a batch that did not commit gets the error, so its value is never
  disclosed: the same rule as today, batch by batch.

### What does not change

The flusher is still the only committer of batched audit rows for its store; the chain order
is the order batches are sent; the statements, their order and the chain bytes are unchanged
(`TestAuditChain_GoldenBytes_Postgres`); durability per `audit_durability` is unchanged (the
`SET LOCAL` is per transaction); the connection goes back to the pool idle or closed.

### KEYAUDIT and the mutation path (#3297)

Two kinds of transaction take KEYAUDIT: the flusher's batch (held until its COMMIT, which
under `audit_durability: standard` does not wait for the WAL flush) and a secret mutation's
in-transaction audit append (INV-CORE-secret-mutation-audit-same-tx; held from the append to
the mutation's durable COMMIT, fsync included). Revocations are neither: they commit their
effect and an owed-audit record first (`commitOwingAudit`), so audit never blocks them.

With pipelining, up to `auditPipelineDepth` flusher transactions can be queued on the lock. A
mutation that asks for the lock behind them waits for those batches instead of one. A mutation
that is granted the lock between two pipelined batches moves the head, so the later batch's
check raises and it is retried (one wasted flight); the mutation's append also invalidates the
cache, so the flusher stops pipelining until the cache re-arms. A write-heavy mix therefore
falls back to today's serial commits; the write cells are measured against main.

Lifting the mutation's hold of the lock through its fsync (an ADR-029/112 amendment) is not
part of this change.

### Several Keyorix nodes on one database

Each node has its own flusher and its own cache. A node's pipelined batch whose predicted head
was overtaken by another node's batch fails its check and is retried in two flights, and the
miss disarms that node's cache with the `need` doubling, so nodes that keep appending in turn
settle on serial two-flight commits, as today. KEYAUDIT is cluster-wide, so the chain stays
one linear sequence across nodes.

### SQLite

Not pipelined: the SQLite path is in-process (no flight to overlap) and every write goes
through one database write lock and the in-process write gate, so a second transaction in
flight would only wait on them. The flusher's serial commit on SQLite is unchanged. The fault
tests run on both dialects.

### Considered and not done

- Pipelining several transactions on one connection: a failed transaction would not abort the
  next one (each ends with its own Sync), so it would work, but pgx's statement cache does not
  support a second batch on a busy connection, and preparing the statements by hand would cost
  more than the second connection.
- More than a small fixed depth: Postgres runs the batches one at a time on KEYAUDIT, so a
  third batch in flight only waits, holding a pool connection.
- An in-memory cache of decrypted values: out of scope (brief).
