- **INV-STORAGE-session-advisory-lock-loss** A PostgreSQL advisory lock held across statements is
  watched for loss in every `storage.database.pooler` mode, not only in `pgbouncer-transaction`
  (INV-STORE-advisory-lock-pooler-scope): a session lock (direct connection, `pgbouncer-session`)
  ends with its backend just as silently as a transaction-scoped one ends with its transaction (a
  `pg_terminate_backend`, a PostgreSQL restart or failover, a network partition), and another
  replica can take it at once. Every holder pings its lock connection
  (`config.WatchPinnedLockConnGated`, `advisoryLockSession.watch` in both shapes, under the
  session's `config.PinnedConnGate`, which the session-shape `pg_advisory_lock` and
  `pg_advisory_unlock` hold too) and reports a loss with one log line
  (`config.ReportAdvisoryLockLost`). Per-section locks (`WithNamedLock`, `WithSchedulerLock`,
  `WithBootstrapLock`, `WithAuditCheckpointLock`, the audit list index build lock) cancel the
  context their critical section runs under (fn receives it: `func(ctx context.Context) error`)
  with cause `store.ErrAdvisoryLockLost` and return that error joined with fn's own.
  Process-wide locks fail closed: `serverguard.Presence.Lost` and `solewriter.Guard.Lost` (the
  holder poller, which checks the lock itself every 250 ms, closes it) end `server/main.go`'s wait
  (`awaitShutdown`), and the server shuts down gracefully and exits 1. Why: before
  LOCKLOSS-SESSION-1 only the transaction shape was watched, so after a backend kill on the most
  common install two schedulers or two single-writer servers ran at once. Guard: pg-gated,
  `pg_terminate_backend`, red without the watcher and green with it:
  `internal/storage/store`
  `TestSessionAdvisoryLock_KilledLockBackend_StopsTheHolder` (named, scheduler, bootstrap,
  audit-checkpoint: a second replica takes the lock, the first one's ctx is cancelled),
  `TestWithNamedLock_SessionLock_NestedWaitIsNotALoss` (red without the gate),
  `internal/serverguard` `TestPostgres_ServerGuard_LostSessionPresenceLockIsReported`,
  `internal/solewriter` `TestGuard_KilledHolderBackend_ClosesLost`, `server`
  `TestAwaitShutdown_LostProcessLockEndsTheServer` and `TestSingleWriter_Postgres_OperatorJourney`
  (exit 1), `scripts/e2e` `TestLockLoss_Postgres` (real server, presence and single_writer, exit
  status 1). **Not covered**: the overlap itself (detection takes up to one ping interval plus
  its timeout, 10 s by default; the error makes the overlap visible, it does not prevent it); a
  pooler that reconnects a client to a new backend unseen (only PgBouncer is supported,
  docs/postgresql-poolers.md); the audit list index build lock has no fn hook, so its loss case
  is covered only through the shared `advisoryLockSession.watch`; `serverguard.Exclusive` (held
  only by the test hook `admin __hold-lock-for-test`) is not watched.
