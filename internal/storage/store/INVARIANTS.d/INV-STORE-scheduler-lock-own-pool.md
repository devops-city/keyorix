- **INV-STORE-scheduler-lock-own-pool** A scheduler job never holds a request-pool connection
  while it waits for another one. `WithSchedulerLock` takes its Postgres advisory-lock session
  from the dedicated lock pool (`SetSchedulerLockDB`, wired by `createPostgresStorage`, capped at
  `storage.SchedulerLockPoolSize`), never from the request pool the job's own queries use, so the
  request pool always drains whatever the pool size or number of jobs. The lock itself is
  unchanged (INV-STORE-07): one session advisory lock per job on its own session, released
  before the session is pooled. Why: POOL-HANG-1 (Detected-by: PERF-6), max_open_conns 5 with
  load at startup pinned every connection under a lock holder waiting for one more, and the
  server never recovered. Guard: `internal/storage`
  `TestWithSchedulerLock_Postgres_SmallPool_JobsAndReadsComplete` (factory-built, pool 5, 20
  jobs + reads; pg-gated), `internal/storage/store`
  `TestWithSchedulerLock_LockPool_JobRunsOnAOneConnectionRequestPool`,
  `TestWithSchedulerLock_LockPool_ExactlyOneRunsAtOnce` (pg-gated). Verified red: with the lock
  pool unused, the first two time out (context deadline exceeded).
