- **INV-STORE-audit-list-index-served** Every newest-first `GetAuditLogs` read (the
  audit list, search, per-secret trail and CSV export) is ordered `event_time DESC, id
  DESC` and served by one of `AuditListIndexes` with no full sort, on SQLite and
  Postgres. Deep pages use the keyset cursor (`AuditFilter.Before`), never a caller-chosen
  OFFSET beyond `core.AuditOffsetCap`. The total is exact only when the caller asks
  (`AuditCountExact`); the public views count at most `AuditCountCap+1` rows. An ascending
  read with a `StartTime` resolves it to a start id through the time index
  (`MIN(id + 0)`, so Postgres cannot turn it into a primary-key walk from id 1) and then
  pages by primary key. Why: AUDIT-SCALE-1 measured full-table sorts, multi-second counts
  and 45–57 s deep pages at 10M rows (docs/specs/audit-list-keyset.md). Guard:
  `TestAuditListQueries_UseTheirIndexes_SQLite` / `_Postgres` (pg-gated, EXPLAIN of the SQL
  production code issued; red when an index is removed), `TestGetAuditLogs_CappedCount`,
  `internal/core` `TestListAuditPage_SQLite` / `_Postgres`.
