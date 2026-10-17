### Fixed
- **A lost advisory lock is detected on direct and `pgbouncer-session` connections too.** On the most common install (PostgreSQL direct, or PgBouncer in session mode) the locks are session locks, and a `pg_terminate_backend`, a PostgreSQL restart or failover or a network partition ended them silently: the holder kept running while another replica took the lock, so two scheduler jobs or two single-writer servers could run at once. Every advisory lock held across statements is now checked in every pooler mode (the same 5-second ping as `pgbouncer-transaction`, one log line for every kind of lock). A named, scheduler, bootstrap, audit-checkpoint or audit-index-build lock holder's context is cancelled with `ErrAdvisoryLockLost`, so its work stops, and the call returns that error. A server whose presence lock or `single_writer` holder lock is lost shuts down gracefully and exits with status 1. Guarded by `TestSessionAdvisoryLock_KilledLockBackend_StopsTheHolder`, `TestPostgres_ServerGuard_LostSessionPresenceLockIsReported`, `TestGuard_KilledHolderBackend_ClosesLost` and `TestLockLoss_Postgres` (a real server, `pg_terminate_backend`, exit status 1).

### Changed
- **`single_writer` emergency SQL: the server now restarts.** After `SELECT pg_terminate_backend(holder_pid) FROM keyorix_sole_writer` the server exits 1 instead of running on with confirming caches; its supervisor starts it again, which closes the write fence again. Run the terminate and the change in one `psql` call (`docs/single-writer.md`, "Emergency SQL").

### Documentation
- **Only PgBouncer is a supported pooler.** `docs/postgresql-poolers.md` and `docs/CONFIGURATION.md` now say that other poolers and proxies (PgCat, Odyssey, RDS Proxy, Supavisor, pgpool-II) are not tested and not supported, and describe what each lock holder does when its lock is lost.

### Internal
- `Storage.WithSchedulerLock`, `WithBootstrapLock` and `WithAuditCheckpointLock` pass the lock-watched context to `fn` (`func(ctx context.Context) error`), like `WithNamedLock`.
