- **INV-STORAGE-no-fk-from-history-tables** No audit or history table holds a foreign key to another
  table, on SQLite or on Postgres: `audit_events`, `secret_access_logs`, `anomaly_alerts` and
  `access_review_items` (the tables `backupfmt.HistoricalReferences` names, which keep their rows after
  the secret they reference is purged, `internal/storage/store/local_purge_secret_refs.go`). Production
  GORM leaves foreign-key creation on, so a model that gains an association field or a
  `gorm:"constraint:..."` tag gets a real FK from `AutoMigrate` with nobody deciding it. Why
  (DB-TUNE-1, Analysis 1): every purge behaviour an FK allows breaks something: RESTRICT makes
  soft-delete retention impossible, CASCADE deletes chained audit rows, SET NULL rewrites them and
  fails hash-chain verification (`entry_hash` covers the row); it also costs a parent-index probe and
  a `FOR KEY SHARE` lock per audit row (+10% per flight measured, worse on a hot secret). Referential
  integrity of history against live rows is meaningless by design: the chain and append-only
  handling are the integrity mechanism. Guard: `internal/storage`
  `TestNoForeignKeysFromHistoryTables_SQLite` (`pragma_foreign_key_list` over the migrated schema) and
  `TestNoForeignKeysFromHistoryTables_Postgres` (`pg_constraint`, pg-gated, real
  `CreateStorage` migration); red with a planted FK (a belongs-to association on
  `models.AuditEvent.SecretNodeID` fails both), and the detector is itself pinned by
  `TestNoForeignKeysFromHistoryTables_DetectsPlantedFK_SQLite` / `_Postgres`.
  `TestNoForeignKeysFromHistoryTables_CoversBackupfmtHistoricalReferences` keeps the table list in step
  with `backupfmt.HistoricalReferences`. **Not covered**: a new history table that is in neither list is
  not inspected (add it to `historyTables` in `no_fk_from_history_tables_test.go`); foreign keys between
  live tables are out of scope and allowed.
