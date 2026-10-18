- **INV-STORE-audit-pipelined-batches** On PostgreSQL the audit flusher keeps at most
  `auditPipelineDepth` (2) batches in flight (`local_audit_chain_pipelined_batches.go`). A run starts
  only from an armed chain-head cache and ends at any move of the cache epoch (a miss, a failure, an
  invalidation); the flusher then waits for the batches in flight and commits serially. Every batch
  in a run after the first is chained onto the last row of the batch sent before it (a pending head:
  entry_hash known, id not) and goes as the one-flight transaction whose single events statement
  (`auditInsertCheckSQL`) raises unless that row is the id-DESC head and the stored rows link onto it
  in id order; the raise never degrades to NULL (every part of its message is non-NULL, and an
  unknown condition takes the ELSE branch). Batches are sent one after another from the flusher
  goroutine, and their outcomes are handled in send order with the serial rules: a commit updates the
  cache; a failure that provably wrote nothing is retried in two flights and then bisected
  (`finishAuditBatch`); any other failure fails its items. Every item gets nil only after its own
  batch's COMMIT was acknowledged. SQLite and non-pgx pools never pipeline (their cache never arms).
  Why: PERF-HIGHLOAD-1 — at high concurrency the single flusher spent each batch's Postgres execution
  idle on the client side and each batch's client-side build idle on the connection.
  Guard: `internal/storage/store` `TestAuditInsertCheck_PendingHeadMismatchRaises` (red with the
  pending id concatenated into the message: the check returns NULL and COMMIT runs),
  `TestPipelinedBatches_PostgresBatchFailsWhileNextInFlight`,
  `TestPipelinedBatches_PostgresBackendDiesWhileNextInFlight`,
  `TestPipelinedBatches_PostgresLostConnectionOutcomeUnknown`,
  `TestPipelinedBatches_PostgresConcurrentReadersChainInOrder` (red when items are answered at send
  time: rows not yet committed), `TestPipelinedBatches_PostgresInterleavedDirectAppends`,
  `TestPipelinedBatches_PostgresTwoReplicasConcurrent` (all pg-gated; all red with both the head-hash
  and the link check disabled for a pending head: the chain breaks), and
  `TestPipelinedBatches_SQLiteFailedBatchFailsClosedNextCommits`.
  **Not covered**: as for the serial path, a batch whose COMMIT acknowledgement is lost may have
  committed although its readers were refused.
