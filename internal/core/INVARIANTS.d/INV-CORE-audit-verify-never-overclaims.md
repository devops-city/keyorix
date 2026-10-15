- **INV-CORE-audit-verify-never-overclaims** Incremental audit-chain verification
  (docs/specs/audit-incremental-verification.md) moves the full re-hash of every row off the
  request path and off startup without dropping it, and never reports `valid` for rows it has
  not verified. `VerifyAuditChain` and `WriteAuditCheckpoint` keep their full-walk semantics.
  The scheduler tick and the on-demand checkpoint extend the latest signed checkpoint with a
  tail check that pins the certified head row (stored hash and recompute), and they refuse
  while a failure is recorded. A rolling cycle re-walks the whole chain in seeded segments
  that end on a signed checkpoint head, so every row is re-hashed at least once per cycle.
  Progress, the last full result and a sticky failure live in one HMAC-signed state row
  (domain-separated; a row that is forged or unverifiable is ignored and reads as
  `not_proven`). The row carries a strictly increasing generation and is bound to the latest
  checkpoint id and the signed high-water count at save time, so an older signed row put
  back (replay/rollback) is not trusted either; a writer that finds an untrusted row records
  the rejection (not_proven until a later full verification, plus an audit event) instead
  of silently replacing it. A sticky failure is cleared only by a passing full verification
  that started after it and covers its row, never by the checkpoint full-walk fallback; a
  rolling cycle older than two cycle durations is restarted, not resumed. The API, posture and gRPC report `valid` only when the tail check passed
  AND a full verification completed within two cycles with no failure recorded. Why: AUDIT-SCALE-1
  §4.3 (full walks failed over HTTP on large trails). Guard: `audit_verify_incremental_test.go`
  (`TestIncrementalVerify_NotProvenUntilFirstCycleCompletes`, `_TailTamperCaughtAtNextTick`,
  `_OldSegmentTamperCaughtWithinOneCycle`, `_RehashBelowCheckpointHeadCaughtWithinOneCycle`,
  `_RehashThroughCheckpointHeadCaughtImmediately`, `_HeadRowContentEditCaughtImmediately`,
  `_TailTruncationWithNewerCheckpointsDeleted`, `_ForgedStateIgnored`,
  `_TickAndPostureNeverWalkTheWholeChain`, `_FullJob`), `audit_verify_state_replay_test.go`
  (`_ReplayedOlderStateRejected`, `_RolledBackStateWithinProcessRejected`,
  `_DeletedStateRowReported`, `_TamperBelowCheckpointStaysDetectedAcrossReplay`,
  `_StaleCycleRestarted`, `_FailureSurvivesUnrelatedCycleCompletion`,
  `_FailureSurvivesFullWalkFallback`, `_CorruptedStateRowReportedNotResigned`,
  `_WritePathUsesHighWaterBaseWhenCheckpointsDeleted`), `_Postgres`, and
  `store.TestVerifyAuditChainSegment_*`. Not covered: a replay within one checkpoint
  interval in a process that has not read the newer row (spec §9; bounded to one interval).
