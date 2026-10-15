- **INV-CORE-audit-list-cursor-exactly-once** `ListAuditPage` (REST `/audit/logs`,
  `/audit/search`, gRPC `GetAuditLogs`) pages in the total order `(event_time DESC, id
  DESC)`. A `next_cursor` walk returns every row present at its start exactly once, also
  when many rows share a timestamp. A row inserted during the walk is returned when it
  sorts below the cursor and never when above it, and no row is ever returned twice.
  Offset/page requests stop at `AuditOffsetCap` (`ErrAuditOffsetBeyondCap`, 400 /
  InvalidArgument naming the cursor). A malformed cursor is `ErrInvalidAuditCursor`. The
  cursor carries no authority: every filter and the route's permission gate apply on every
  page. Why: docs/specs/audit-list-keyset.md. Guard: `TestListAuditPage_SQLite` /
  `_Postgres` (pg-gated; red when the id tie-break is dropped from the keyset predicate),
  `TestListAuditPage_TotalAboveTheCap`, `server/http/handlers`
  `TestAuditLogs_CursorWalkAndTotals`, `TestAuditLogs_OffsetCapAndBadCursorAre400`,
  `server/grpc/services` `TestAuditService_GetAuditLogs_CursorWalk`.
