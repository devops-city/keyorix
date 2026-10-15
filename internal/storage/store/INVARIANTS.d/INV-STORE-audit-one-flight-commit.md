- **INV-STORE-audit-one-flight-commit** On Postgres the audit flusher sends a batch as ONE
  pipelined flight (`runAuditOneFlight`) only while its chain-head cache
  (`auditChainHeadCache`, the last row this flusher committed) is armed, and the cache is a
  hint, never trusted: inside the transaction, after `pg_advisory_xact_lock(KEYAUDIT)`, the head
  check raises unless the id-DESC head is exactly the cached (id, entry_hash), and after the
  events INSERT the link check raises unless the top n+1 rows are the cached row followed by the
  batch, linked prev_hash -> entry_hash in id order. Either raise makes Postgres skip COMMIT.
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
  in-transaction checks. (4) The SQLite path and a non-pgx Postgres pool never arm it. The chain
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
  `TestCommitBatchAttempt_PostgresFastModeAppliesToTheInsert` (all pg-gated except
  `TestAuditOneFlightRolledBack` and `TestOneFlight_SQLiteNeverArms`).
  **Not covered**: a writer that inserts into audit_events without taking KEYAUDIT can race the
  checks exactly as it can race the two-flight path's head read.
