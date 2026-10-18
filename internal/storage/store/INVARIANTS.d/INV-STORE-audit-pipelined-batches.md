- **INV-STORE-audit-pipelined-batches** On PostgreSQL the audit flusher keeps at most
  `auditPipelineDepth` (2) batches in flight, on ONE pool connection it holds while it runs, in pgconn
  pipeline mode with one Sync per transaction (`local_audit_chain_pipelined_batches.go`), so Postgres
  runs them strictly in send order on one backend. A run starts only from an armed chain-head cache
  and ends at any move of the cache epoch (a miss, a failure, an invalidation); the flusher then reads
  every batch in flight and commits serially. Every batch in a run after the first is chained onto the
  last row of the batch sent before it (a pending head: entry_hash known, id not) and goes as the
  one-flight transaction whose single events statement (`auditInsertCheckSQL`) raises unless that row
  is the id-DESC head and the stored rows link onto it in id order; the raise never degrades to NULL
  (every part of its message is non-NULL, and an unknown condition takes the ELSE branch). A batch
  whose result is an error ends the run: every later result is read, the connection is rolled back
  (the aborted transaction still holds KEYAUDIT) before any retry runs, and the batches are resolved in
  send order with the serial rules: a commit updates the cache; a failure that provably wrote nothing
  (a Postgres error before COMMIT, or a batch queued behind one the backend ended with a FATAL error)
  is retried in two flights and then bisected (`finishAuditBatch`); any other failure fails its items.
  Every item gets nil only after its own batch's COMMIT was acknowledged. The flusher's own serial
  commits and retries reuse the held connection, passed explicitly in their context
  (`withHeldAuditConn`; no other caller can reach it), so the flusher never waits for a second pool
  connection; a held connection that broke is handed back to the pool first. A pipelined batch stores exactly the rows the serial path stores for the same items in
  the same order (the parameters are re-encoded for the pipeline; an empty value stays "", never
  NULL). SQLite, non-pgx pools and a store with a flusher linger window never pipeline.
  Why: PERF-HIGHLOAD-1 — at high concurrency the single flusher left Postgres idle while it built and
  delivered each batch. A first version on two connections let the second batch's backend take
  KEYAUDIT first (measured: most batches then missed and fell back to serial commits).
  Guard: `internal/storage/store` `TestAuditInsertCheck_PendingHeadMismatchRaises` (red with the
  pending id concatenated into the message: the check returns NULL and COMMIT runs; red with the
  head-hash and link checks disabled), `TestPipelinedBatches_PostgresInterleavedDirectAppends` and
  `TestPipelinedBatches_PostgresTwoReplicasConcurrent` (another writer moves the head under batches in
  flight: red with both checks disabled for a pending head, the chain breaks),
  `TestPipelinedBatches_PostgresConcurrentReadersChainInOrder` (red when items are answered at send
  time: rows not yet committed), `TestPipelinedBatches_PostgresBatchFailsWhileNextInFlight`,
  `TestPipelinedBatches_PostgresBackendDiesWhileNextInFlight`,
  `TestPipelinedBatches_PostgresLostConnectionOutcomeUnknown` (failure handling in send order),
  `TestPipelinedBatches_PostgresStoresTheSameRowsAsTheSerialPath` and
  `TestPipelinedBatches_PostgresStoresEmptyStringsNotNull` (raw-SQL row comparison: red when an empty
  parameter is copied as NULL, found by `admin verify-audit` on the bench; all pg-gated),
  `TestPipelinedBatches_SQLiteFailedBatchFailsClosedNextCommits`, and the one-connection-pool tests
  (`pipelinePGStore`, e.g. `TestOneFlight_PostgresTwoReplicasConcurrent`), which hang if the
  flusher's serial commits ask the pool for a second connection.
  **Not covered**: as for the serial path, a batch whose COMMIT acknowledgement is lost may have
  committed although its readers were refused; and a connection that breaks during a send can leave a
  committed batch that the serial commit then appends again (a read recorded twice, never not at all).
