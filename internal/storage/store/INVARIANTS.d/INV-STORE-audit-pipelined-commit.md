- **INV-STORE-audit-pipelined-commit** On Postgres the audit flusher's transaction
  (`commitBatchAttemptPipelined`) runs the same statements in the same order as the GORM
  transaction (`commitBatchAttemptTx`), in two pipelined flights: BEGIN, the fast-mode
  `SET LOCAL` (only when enabled), `pg_advisory_xact_lock(KEYAUDIT)`, the id-DESC head read
  and the event-id allocation; then the INSERTs (GORM's own SQL) and COMMIT. Three rules
  hold. (1) The head is read by its own statement after the lock statement, so it sees every
  batch committed before the lock was granted. (2) Nothing that decides whether to commit
  runs between the INSERTs and COMMIT: the event ids are allocated from the table's sequence
  under the lock, assigned in chain order and checked (`checkAuditInsertIDOrder`, first id
  above the head id) before flight 2 is sent; an error in either flight makes Postgres skip
  the rest of it, COMMIT included. (3) The connection goes back to the pool idle or closed,
  never inside the transaction: an idle connection left in it would hold KEYAUDIT and stall
  every replica's appends until it was next checked out. The chain bytes for a fixed input
  are pinned. Why: PERF-FIX-1 — the single flusher spent each batch waiting on six sequential
  round trips.
  Guard: `internal/storage/store` `TestCommitBatchAttempt_PostgresTwoFlights` (counts flights
  on the wire; red on the GORM path), `TestAuditChain_GoldenBytes_SQLite`/`_Postgres`
  (digest recorded on main), `TestCommitBatchAttempt_PostgresFailureBetweenFlightsRollsBack`
  (lock checked from another session), `TestCommitAuditBatch_PostgresBackendDiesMidBatch`,
  `TestCommitBatchAttempt_PostgresFastModeAppliesToTheInsert`,
  `TestCommitBatchAttempt_PostgresHeadReadReusesItsPlan` (the head read's LIMIT is in its text,
  so its cached plan is reused instead of re-planned per flight),
  `TestAuditAllocateIDsSQL_PostgresLooksUpTheSequenceOnce` (one pg_depend scan per allocation,
  not one per id), plus the
  `INV-STORE-audit-batch-insert-values-order` guards (all pg-gated on the Postgres side).
  **Not covered**: a COMMIT whose acknowledgement is lost with the connection is reported as
  an error although it may have committed (unchanged from the GORM path).
