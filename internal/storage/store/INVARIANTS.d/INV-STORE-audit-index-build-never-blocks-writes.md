- **INV-STORE-audit-index-build-never-blocks-writes** The audit list indexes are never
  created by a gorm tag or inside a transaction on Postgres. `BuildAuditListIndexesPostgres`
  issues `CREATE INDEX CONCURRENTLY IF NOT EXISTS` / `DROP INDEX CONCURRENTLY` in
  autocommit on one connection while a second, idle one holds the build advisory lock
  (`auditIndexBuildLockKey`, shaped by INV-STORE-advisory-lock-pooler-scope),
  rebuilds an INVALID leftover, and drops the replaced single-column indexes only after
  every composite is valid. A plain `CREATE INDEX` takes a SHARE lock and blocks every
  audit INSERT, and with it every secret read, for the whole build. Why: coordinator hold
  on #3256. Guard: `internal/storage`
  `TestAuditListIndexes_Postgres_BuildNeverBlocksAuditWrites` (an INSERT completes while
  the build waits on an open writer; its control case shows a plain CREATE INDEX
  blocking it), `_InvalidIndexIsRebuilt`, `_BuildIsIdempotentAndDropsReplaced`,
  `TestAuditListIndexes_SQLite_FreshAndUpgrade`.
