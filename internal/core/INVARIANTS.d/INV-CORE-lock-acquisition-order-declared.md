- **INV-CORE-lock-acquisition-order-declared** Every lock a call chain can hold while it acquires
  another is acquired in ONE declared order, outermost first: `lockOrderTable` in
  `lock_order_inprocess_static_test.go`. That table covers in-process `sync.Mutex`/`RWMutex`
  (fields, array shards, returned pointers), `sync.Once`/`singleflight` waits, the
  `storage.NamedLockOrder` families (placed as one block), `WithTransaction` (the SQLite write gate,
  a Postgres request connection) and the `WithBootstrapLock`/`WithAuditCheckpointLock`/
  `WithSchedulerLock` primitives. The legal shape is: the TryLock-only verify-job mutex and
  `accessReviewDecisionMu`, then the scheduler/bootstrap/checkpoint locks, then named locks, then
  the in-process guard mutexes taken inside them (`accountStateMu`, `globalAdminGuardMu`,
  `secretDependencyMu`, ...), then the transaction, then the audit-chain mutex taken inside it. A
  named lock is never acquired inside a transaction, and an in-process guard mutex is never held
  while waiting for a named lock. A class that is only ever acquired last (caches, clock
  watermarks) needs no row; a class held across another acquisition without a row fails the test.
  Why: #2694 (an ABBA between a mutex and a `WithNamedLock` key deadlocks one process: the named
  lock's first layer is an in-process queue, and neither `NamedLockOrder` nor its runtime check
  saw mutexes) and #2685. The guard's first run found `RestoreSecret` running the restore without
  the environment lock when its pre-read failed, so the storage restore took that lock inside the
  transaction; fixed (`restore_secret_preread_fault_test.go`).
  Guard: `lock_order_inprocess_static_test.go` (`TestLockOrder_InProcessLocksFollowDeclaredOrder`:
  a type-checked call graph of `internal/core`, `internal/core/storage` and `internal/storage/store`
  that follows `storage.Storage` interface calls into `LocalStorage`, callbacks passed to lock
  primitives and to helpers, and the audit flusher hand-off; `TestLockOrder_PlantedABBAIsCaught`,
  red/green calibration on `testdata/lockorder`). Edge exemptions carry a reason and fail once
  stale. Not covered (stated in the test's header): callers outside those three packages (a one-off
  scan of `server/...` found no server-side mutex held across a core call), calls through stored
  function values or non-storage interfaces, and same-family named-lock ID order (the runtime
  check's job).
<!-- section: Atomicity / transactions -->
