- **INV-CORE-audit-purge-keeps-checkpoints-verifiable** A sanctioned audit retention purge never
  makes the trail fail its checkpoint or high-water checks, and nothing else can borrow that
  allowance: `PurgeAuditLogs` signs the cumulative count of CHAINED rows it removed into the
  retention anchor (layout v2, `retanchor-v2` HMAC, same transaction as the DELETE, previous count
  taken only from an authenticated anchor); checkpoints certify chained + purged; and
  `checkpointTruncationPurged`, `enforceAuditHighWater` and the write-path floor compare chained +
  the authenticated count. An anchor that fails its signature (inflated count, v2→v1 downgrade,
  rewritten without the key) contributes 0. A v1 anchor reads as 0 (pre-#3257 behaviour). Head-row
  checks are unchanged. Why: #3257. Guard: `audit_purge_after_checkpoint_test.go`
  (`TestPurgeAfterCheckpoint_VerifyAndCheckpointSucceed`, `_Postgres`, `_RestartedReplicaAgrees`,
  `_SecondPurgeAccumulates`), `audit_purge_after_checkpoint_tamper_test.go` (`_UnsanctionedDeleteBeyondAnchor_Detected`,
  `_TailTruncationWithCheckpointsDeleted_Detected`, `_InflatedPurgedCount_SignatureFails`,
  `_AnchorLayoutDowngrade_SignatureFails`, `_DeleteAndRewriteAnchorWithoutKey_Detected`),
  `store.TestDeleteAuditLogsBefore_PurgedEventsCountsChainedRowsOnly`, and the offline mirror
  `auditverify` `TestDifferential_PurgeAfterCheckpoint_*`. Not covered: a purge that removes the
  latest checkpoint's head row (still flagged by the head check) or empties the table (no row to
  anchor, count not recorded).
