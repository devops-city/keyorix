- **INV-STORE-named-lock-own-pool** A `WithNamedLock` holder needs at most one request-pool
  connection at a time. Its Postgres advisory-lock session comes from the dedicated named-lock
  pool (`SetNamedLockDB`, wired by `createPostgresStorage`, capped at
  `storage.NamedLockPoolSize`), never from the request pool fn's own queries use, so the request
  pool drains however many distinct keys are held at once. It is not the scheduler lock pool
  (INV-STORE-scheduler-lock-own-pool): scheduler jobs take named locks inside their lock-held
  section, and one capped pool for both could pin every session waiting for one more. Lock
  semantics are unchanged: per-key in-process FIFO first (top-level calls only,
  INV-STORE-named-lock-nested-no-queue), then one blocking session advisory lock
  per key (mutual exclusion across replicas), nested keys reuse the outer session (INV-STORE-05),
  unlocked before the session is pooled; a session whose unlock fails is discarded. Never call
  `WithNamedLock` while holding a request-pool connection (inside a transaction). `LocalStorage.Close`
  closes the request pool and both lock pools; the factory closes every pool it opened when it
  fails. Why: NAMEDLOCK-POOL-1, same hold-and-wait class as POOL-HANG-1 (#3232). Guard:
  `internal/storage` `TestWithNamedLock_Postgres_SmallPool_DistinctKeysAndReadsComplete`
  (factory-built, pool 3, 12 distinct keys + reads; red on the base: context deadline exceeded),
  `TestPostgresStorage_Close_ReleasesEveryPool` (pg_stat_activity back to 0 after Close),
  `internal/storage/store` `TestWithNamedLock_LockPool_HolderRunsOnAOneConnectionRequestPool`
  (red with the lock pool unused), `TestWithNamedLock_LockPool_SameKeySerializesAcrossInstances`
  (all pg-gated).
