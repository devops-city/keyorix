- **INV-CORE-audit-walk-chunked-read** Every audit-chain walk the core runs (the full
  `VerifyAuditChain`, the incremental tail check, the audit_checkpoint rolling segment) reads
  through `VerifyAuditChainSegment`, one autocommit statement per 1000-row batch, and is never
  wrapped in a transaction (`WithTransaction`, a held read snapshot, or a lock taken by a
  transaction): a walk is long in wall time, and a snapshot held across it pins the SQLite WAL
  or the PostgreSQL xmin horizon; under `_txlock=immediate` a wrapping transaction would also
  block every writer. A rolling segment resumes from the previous segment's verified head (id
  and hash), and the verdict, first broken id and head of any chunking equal those of one
  whole-chain walk.
  Guard: `audit_long_reader_snapshot_test.go`
  (`TestAuditLongReaders_RollingRewalkDoesNotHoldOneSnapshot`: WAL checkpoint progress, PG
  snapshot age and writer stalls during a 300k-row tick), `audit_chunked_walk_differential_test.go`
  (`TestAuditChunkedWalk_SameVerdictAsWholeChainWalk_SQLite`/`_Postgres`).
  **Not covered**: `MigrateAuditChainEncoding` deliberately walks inside one exclusive
  transaction (it rewrites the chain); it is an operator action, not a reader.
<!-- section: Audit (ADR-029) -->
