- **INV-STORE-advisory-lock-pooler-scope** Every Postgres advisory lock held across statements
  (`WithNamedLock`, `WithSchedulerLock`, `WithBootstrapLock`, `WithAuditCheckpointLock`, the
  audit list index build lock (`BuildAuditListIndexesPostgres`, on its own connection, idle while
  the DDL runs on another), the migration lock in `internal/storage`'s `withMigrationLockPooled`, the server-presence lock in
  `internal/serverguard`) is held on one PostgreSQL backend for the whole critical section and
  released with it. Default (`storage.database.pooler` none/pgbouncer-session): a session lock on
  a pinned connection, unlocked before the connection is pooled, the connection discarded if the
  unlock fails. `pgbouncer-transaction` (`SetTransactionPooling`): the transaction-scoped lock
  inside a transaction opened for the critical section (`advisoryLockSession`), ended by ROLLBACK,
  with `idle_in_transaction_session_timeout` 0 for that transaction only, and its lock
  statements sent over the simple query protocol so the idle transaction holds no snapshot (an
  extended-protocol portal keeps one until the transaction ends, pinning xmin: VACUUM stalls and
  every CREATE INDEX CONCURRENTLY waits for it); a nested named lock is
  released with the outermost one. A session lock taken in autocommit behind a transaction pooler
  stays on a server connection shared with other clients, so two replicas both hold it; a server
  behind one without the setting refuses to start when two open connections share a backend
  (`refuseUndeclaredTransactionPooler`). Guard: `internal/storage`
  `TestPgBouncer_StorageSlice` (named and scheduler lock exclusion across two factory-built
  replicas, no advisory lock left behind), `TestPgBouncer_TransactionModeUndeclared_RefusesToStart`,
  `internal/serverguard` `TestPgBouncer_ServerGuard_PresenceExcludesAdmin`,
  `TestPgBouncer_ServerGuard_KilledHolderReleasesLock`,
  `TestPgBouncer_ServerGuard_HeldLockKeepsNoSnapshot`, `internal/storage`
  `TestPgBouncer_AuditIndexBuild_LockFollowsThePooler` (all pg-gated; direct Postgres runs the
  transaction shape, `scripts/pgbouncer-matrix.sh` runs them through PgBouncer session /
  transaction / transaction+prepared; red on the base through PgBouncer transaction mode).
  A pinned lock transaction whose backend dies is reported, not silently dropped: every
  transaction-shape lock holder pings its connection every `config.PinnedLockPingInterval`
  (`config.WatchPinnedLockConn`), cancels the critical section's context with cause
  `ErrAdvisoryLockLost` and returns that error joined with its own; `serverguard.Presence.Lost`
  closes and the server shuts down. The ping never shares the connection with a
  lock statement: a nested `WithNamedLock` waits in PostgreSQL on the outer call's
  session, and a ping queued behind that wait timed out before it was sent, pgx
  closed the healthy connection and both locks were dropped (REVIEW-2 on #3299).
  Lock statements hold the session's `config.PinnedConnGate`; a tick that finds
  it held is skipped, and the next one pings again. Guard (this part):
  `TestWithNamedLock_TransactionPooling_NestedWaitIsNotALoss` (pg-gated, nested
  wait longer than the ping timeout, outer lock still held from another session),
  `config` `TestWatchPinnedLockConnGated_NoPingWhileGateHeld`. Guard: `config` `TestWatchPinnedLockConn_*` (fake driver),
  `internal/storage/store` `TestWithNamedLock_TransactionPooling_KilledLockBackendIsReported`,
  `TestWithSchedulerLock_TransactionPooling_KilledLockBackendIsReported`, `internal/serverguard`
  `TestPgBouncer_ServerGuard_LostPresenceLockIsReported` (pg-gated, `pg_terminate_backend`).
