- **INV-SW-in-process-writes-seen** In a single-writer server every write this process makes to a fenced
  table moves `Tracker.Gen` before the call that made it returns (at COMMIT/ROLLBACK, or at the
  statement's end outside a transaction), and `Inflight` is non-zero from the statement's start until
  then. Every database epoch move is accounted for by such a write; one that is not (the canary) flushes
  every entry and is counted in `/system/info`. Why: per-site eviction missed sites before (INV-MW-08,
  #2518); authoritative caches (PR 3) depend on this. Guard: `TestTracker_EveryEpochMoveIsAWriteTheTrackerSaw`
  (red with the tracer not installed, and with `machine_identity_roles` misclassified),
  `TestTracker_CanaryCatchesAWriteTheTrackerMissed` (red without the canary),
  `TestTracker_TransactionEndsTheWriteNotItsFirstStatement` (red when BEGIN is not seen), `TestClassifyStatement`,
  `TestFill_RejectsAnOverlappingWrite`, `TestFencedTables_NoCascadeFromUnfencedParent` (with calibration).
