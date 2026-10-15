- **INV-SW-in-process-writes-seen** In a single-writer server every write this process makes to a fenced
  table moves `Tracker.Gen` before the call that made it returns (at COMMIT/ROLLBACK, or at the
  statement's end outside a transaction), and `Inflight` is non-zero from the statement's start until
  then. `ROLLBACK TO [SAVEPOINT]` does not end the transaction; `... AND CHAIN` ends it and starts the
  next. Every database epoch move the poller sees flushes every entry, whether or not such a write
  explains it; one that no write explains (the canary) is also counted in `/system/info`. Why:
  REVIEW-SINGLE-WRITER-1 F3/F4; per-site eviction missed sites before (INV-MW-08,
  #2518); authoritative caches (PR 3) depend on this. Guard: `TestTracker_EveryEpochMoveIsAWriteTheTrackerSaw`
  (red with the tracer not installed, and with `machine_identity_roles` misclassified),
  `TestTracker_CanaryCatchesAWriteTheTrackerMissed` (red without the canary),
  `TestTracker_TransactionEndsTheWriteNotItsFirstStatement` (red when BEGIN is not seen),
  `TestTracker_SavepointRollbackDoesNotEndTheTransaction` (red with every ROLLBACK an end, and without the
  AND CHAIN re-open), `TestPoll_EveryEpochMoveFlushes` (copied tag in the same poll window as an own
  commit; red without the flush on every move), `TestClassifyStatement`,
  `TestFill_RejectsAnOverlappingWrite`, `TestFencedTables_NoCascadeFromUnfencedParent` (with calibration).
