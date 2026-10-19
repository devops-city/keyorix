- **INV-AUDITVERIFY-chunked-read-no-held-snapshot** The chain walk reads `audit_events` in
  bounded statements (`StreamAuditEvents`, one autocommit `SELECT ... WHERE id > ? ORDER BY id
  LIMIT ?` per batch), resuming by id and re-anchoring each batch on the last verified
  `entry_hash`, never on a batch's own first `prev_hash`. It never wraps the walk in one read
  transaction: on SQLite (WAL) a snapshot held across the walk pins the WAL (the checkpointer
  cannot backfill, the file grows with every concurrent commit), on PostgreSQL it holds back
  the xmin horizon. The verdict must not depend on where the batch boundaries fall: any
  `BatchSize` gives the same `Result` as one batch covering the whole table.
  Guard: `internal/core/audit_long_reader_snapshot_test.go`
  (`TestAuditLongReaders_OfflineVerifyDoesNotHoldOneSnapshot`: 300k rows, concurrent writer,
  SQLite WAL checkpoint progress and PostgreSQL snapshot age; calibrated by
  `TestAuditLongReaders_CalibrationHeldSnapshotIsReportedPinned`) and
  `internal/core/audit_chunked_walk_differential_test.go`
  (`TestAuditChunkedWalk_SameVerdictAsWholeChainWalk_SQLite`/`_Postgres`: batch sizes 1, 7 and
  the default against one whole-table batch, with altered/deleted rows on every boundary and
  v1/v2 retention-anchored prefixes).
  **Not covered**: a caller that opens its own transaction and hands this package a `*DB`
  inside it (no such caller exists: `OpenSQLiteReadOnly`/`OpenPostgres*` own the pool).
