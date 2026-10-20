- **INV-ENCRYPTION-pending-dek-kept-after-commit** Once a DEK-sweep rotation's transaction has
  committed, or may have (a failed COMMIT, a panic after it), `dek.key.pending` is the only copy
  of the DEK the rows are under, and nothing deletes or overwrites it except
  `RecoverInterruptedRotation(db)`, which promotes it when the redo marker committed and
  discards it otherwise. `RotateDEKWithSweep` keeps it on a failed pending→active rename and on
  `errSweepOutcomeUnknown`; every key-writing admin command (rotate, upgrade-aad, rotate-kek,
  migrate-provider: `internal/encryptionops` `openKeyWriter`) runs that recovery under the
  exclusive key lock before it touches the key files. Before REVIEW-COVERAGE-2 the rename-failure
  path removed the file, upgrade-aad and rotate-kek called a bare `CleanPendingDEK`, and
  migrate-provider's re-wrap overwrote it; each lost every swept row. Guard:
  `rotate_post_commit_failure_test.go:TestRotateDEKWithSweep_RenameFailsAfterCommit_NewDEKRecoverable`,
  `:TestKeyManagerRotateDEKWithSweep_OutcomeUnknownKeepsPending`,
  `internal/encryptionops/review_coverage_test.go:TestKeyWriters_AfterInterruptedRotation_NewDEKSurvives`,
  `pending_dek_cleanup_guard_test.go:TestCleanPendingDEK_OnlyBehindTheRedoMarker` (no new bare
  caller). **Not covered**: a pending file removed by path or overwritten by a new writer outside
  these commands (the source guard matches `CleanPendingDEK` calls only); the sweep's
  `os.Rename` is not behind the `durableRename` fault seam, so `FuzzFaultInjectedOperations`
  does not reach it.
<!-- section: Crash consistency (write-pending → rename → fsync) -->
