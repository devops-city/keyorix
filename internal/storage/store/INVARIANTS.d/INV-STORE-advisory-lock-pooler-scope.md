- **INV-STORE-advisory-lock-pooler-scope** Every Postgres advisory lock held across statements
  (`WithNamedLock`, `WithSchedulerLock`, `WithBootstrapLock`, `WithAuditCheckpointLock`, the
  migration lock in `internal/storage`'s `withMigrationLockPooled`, the server-presence lock in
  `internal/serverguard`) is held on one PostgreSQL backend for the whole critical section and
  released with it. Default (`storage.database.pooler` none/pgbouncer-session): a session lock on
  a pinned connection, unlocked before the connection is pooled, the connection discarded if the
  unlock fails. `pgbouncer-transaction` (`SetTransactionPooling`): the transaction-scoped lock
  inside a transaction opened for the critical section (`advisoryLockSession`), ended by ROLLBACK,
  with `idle_in_transaction_session_timeout` 0 for that transaction only; a nested named lock is
  released with the outermost one. A session lock taken in autocommit behind a transaction pooler
  stays on a server connection shared with other clients, so two replicas both hold it; a server
  behind one without the setting refuses to start when two open connections share a backend
  (`refuseUndeclaredTransactionPooler`). Guard: `internal/storage`
  `TestPgBouncer_StorageSlice` (named and scheduler lock exclusion across two factory-built
  replicas, no advisory lock left behind), `TestPgBouncer_TransactionModeUndeclared_RefusesToStart`,
  `internal/serverguard` `TestPgBouncer_ServerGuard_PresenceExcludesAdmin`,
  `TestPgBouncer_ServerGuard_KilledHolderReleasesLock` (all pg-gated; direct Postgres runs the
  transaction shape, `scripts/pgbouncer-matrix.sh` runs them through PgBouncer session /
  transaction / transaction+prepared; red on the base through PgBouncer transaction mode).
