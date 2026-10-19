- **INV-STORE-audit-one-flight-commit** On Postgres the audit flusher sends a batch as ONE
  pipelined flight (`runAuditOneFlight`) only while its chain-head cache
  (`auditChainHeadCache`, the last row this flusher committed) is armed, and the cache is a
  hint, never trusted: inside the transaction, after `pg_advisory_xact_lock(KEYAUDIT)`, the head
  check raises unless the id-DESC head is exactly the cached (id, entry_hash), and the link check
  raises unless the rows the events INSERT stored are the batch, above the cached row, linked
  prev_hash -> entry_hash in id order. Either raise makes Postgres skip COMMIT. Since
  OPT-AUDIT-RT-1 the INSERT and both checks are ONE statement (`auditInsertCheckSQL`: the INSERT
  in a WITH, the checks over the snapshot's head followed by its RETURNING rows; the statement's
  snapshot is taken after the lock statement and does not contain its own rows), so a steady-state
  audited read runs 5 statements and a write 4 (+1 at the standard level); a batch too large for
  one INSERT still runs them as three statements (`queueAuditEvents`).
  Four rules hold. (1) A one-flight failure is retried, once, through the two-flight path (which
  re-reads the head under the lock) only when it provably wrote nothing
  (`auditOneFlightRolledBack`: an error Postgres answered for a statement before COMMIT, or none
  sent); a lost connection or an error on COMMIT is returned as is. (2) The cache arms only after
  a two-flight batch found the flusher's own last row as the head (`need` such batches in a row,
  doubled per miss up to `auditOneFlightMaxQuiet`), and any failure or invalidation disarms it;
  first batch after boot and first after any error take two flights. (3) Every in-process path
  that moves the head outside the flusher invalidates it (`invalidateAuditChainHead`): the
  transaction-scoped direct append, `DeleteAuditLogsBefore`, `MigrateAuditChainEncoding`;
  `WithTransaction`/`RemoveGlobalAdminRoleGuarded` clones share the pointer for that only.
  Out-of-process writers (another replica, `admin restore`, hand-written SQL) are caught by the
  in-transaction checks. (4) The SQLite path and a non-pgx Postgres pool never arm it. A pipelined batch (`INV-STORE-audit-pipelined-batches`) is a one-flight attempt chained onto the
  previous in-flight batch's last row instead of the cache's, with the same checks (the head's id
  left out while it is pending) and the same retry rule. The chain
  bytes are unchanged (`TestAuditChain_GoldenBytes_Postgres`), and fast mode's `SET LOCAL`
  is part of the single flight. Why: AUDIT-1FLIGHT-1 — one round trip fewer per audited request
  and a shorter flusher transaction.
  Guard: `internal/storage/store` `TestOneFlight_PostgresTwoReplicasAlternate`,
  `TestOneFlight_PostgresTwoReplicasConcurrent`, `TestOneFlight_PostgresOutOfBandWritesAreCaught`
  (all red with both checks removed: the chain forks; each check alone keeps them green),
  `TestOneFlight_PostgresOutOfOrderIDsFailClosed` (red without the link check),
  `TestOneFlight_PostgresInProcessPathsInvalidate` (red without the purge's invalidation),
  `TestOneFlight_PostgresBackendDiesMidFlight`, `TestOneFlight_PostgresChecksRunFromGenericPlans`,
  `TestAuditOneFlightRolledBack`, `TestOneFlight_SQLiteNeverArms`,
  `TestCommitBatchAttempt_PostgresFlightCount`,
  `TestCommitBatchAttempt_PostgresFastModeAppliesToTheInsert`,
  `TestAuditStatementsPerRequest_Postgres` (statements per audited read/write, counted by a pgx
  tracer: red at 7/6 before the merge) (all pg-gated except
  `TestAuditOneFlightRolledBack` and `TestOneFlight_SQLiteNeverArms`).
  **Not covered**: a writer that inserts into audit_events without taking KEYAUDIT can race the
  checks exactly as it can race the two-flight path's head read (with one statement the checks
  read one snapshot, so such a row committed while the statement runs is not seen; with three it
  was seen only if it committed between the head check and the link check).
