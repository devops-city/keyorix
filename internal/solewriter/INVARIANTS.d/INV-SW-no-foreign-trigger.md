- **INV-SW-no-foreign-trigger** Every trigger on a covered table is one of the fence's, with exactly
  the definition this build creates, or one the store's migrations install (`migrationTriggers`,
  checked against the store's names by `TestMigrationTriggers_MatchTheStore`). InstallFence compares each fence trigger's full
  `pg_get_triggerdef` (WHEN clause and function schema included) with a probe created from the same
  spec and refuses on any difference; any other non-internal trigger on a covered table keeps the guard
  out of the authoritative state and is a posture deviation (`FenceReport.ForeignTriggers`); the
  fingerprint covers every trigger on a covered table, so one added later is seen within one poll.
  Why: REVIEW-SINGLE-WRITER-3 (TRIGGER privilege). Guard: `TestFence_ForeignTriggerOnACoveredTable`,
  `TestInstallFence_RefusesAFenceTriggerThatDiffers`.
