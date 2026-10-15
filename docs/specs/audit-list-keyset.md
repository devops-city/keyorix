# Spec: audit list/search at scale (keyset cursor, time indexes, bounded totals)

Status: **Proposed** (AUDIT-LIST-KEYSET-1, 2026-10-14). Ordering decided by Andrei on
2026-10-14: the audit list keeps **event-time order**, served by an `(event_time, id)` index
(not commit/id order).

Related: ADR-029 (audit hash chain, walked by `id`, untouched here), INV-STORE-22 (retention
purge deletes an id prefix, untouched), DB-TUNE-1 (every audit index costs every audit
INSERT, i.e. every secret read).

## 1. Why

`audit_events` grows by one row per secret read. Every reader of the table sorted the whole
table: `ORDER BY event_time DESC` had no index, every list and search call ran an exact
`COUNT(*)` over every matching row, and pagination was `OFFSET` based. The cost grows
linearly with the table, and a deep `OFFSET` sorts on disk, so one request can tie up the
database for its whole duration. That is a resource-exhaustion lever for any `audit.read`
holder. The CSV export (up to 10,000 rows newest-first) and the SIEM export's `since` hit the
same scan.

## 2. User journey

- **Web UI, Audit log and project Activity tab.** The first page loads at once. Under the
  table, "Showing 100 of 10,000+ events" and a **Load more** button append the next page;
  the button disappears when the server reports no further page. Client-side filters apply
  to everything loaded so far, as before.
- **CLI.** `keyorix audit logs` / `keyorix audit search` print the page plus
  `Next page: --cursor <c>` when there is more; `--cursor <c>` continues. `--include-total`
  asks for the exact count. `--offset` beyond the cap fails with the server's message.
- **API / gRPC clients.** Old clients keep `page`/`page_size` (`offset`/`limit` on search)
  and see unchanged results up to the cap. New clients follow `next_cursor`.

## 3. API contract (additive)

`GET /api/v1/audit/logs` and `GET /api/v1/audit/search`:

| | request | response (`data`) |
|---|---|---|
| new | `cursor` (opaque string) | `next_cursor` (string; absent/`null` = no further page) |
| new | `include_total` (`true` = exact `COUNT(*)`) | `total_exact` (bool) |
| changed | `page`, `page_size`, `offset`, `limit` keep their meaning, but `(page-1)*page_size + page_size` (search: `offset + limit`) must be ≤ **10,000** (`AuditOffsetCap`) | `total`: exact when `total_exact`; otherwise the bounded count, capped at 10,000 |

- **Order.** Always `event_time DESC, id DESC`. The `id` tie-break makes the order total, so
  pages are deterministic even when many events share a timestamp (on main, equal timestamps
  could swap places between two page requests).
- **Cursor.** `next_cursor` = base64url(`v1.<event_time unix nanoseconds>.<id>`) of the
  last row returned. A request with `cursor` returns the rows strictly after that position in
  the order above, `event_time < t OR (event_time = t AND id < i)`, with the same filters.
  When `cursor` is present, `page`/`offset` are ignored. The cursor is opaque to clients, has
  no authority and is not signed: it only selects a starting point inside a result set the
  caller is already allowed to read. Every filter and the authorization gate are applied
  again on each request.
- **Totals.** Without `include_total`, the first page (no cursor) counts at most 10,001
  matches (`SELECT COUNT(*) FROM (SELECT 1 ... LIMIT 10001)`). `total` is exact up to
  10,000; above that it is 10,000 with `total_exact: false`. Cursor pages skip the count
  unless `include_total=true` (then `total`/`total_exact` are present; otherwise both are
  absent). `total_pages` is derived from `total`, so it never exceeds the cap.
- **Errors (400, `InvalidRequest`).**
  - Offset beyond the cap: "page × page_size reaches beyond the newest 10000 audit events;
    use cursor=<next_cursor> to page further".
  - Malformed `cursor`: "invalid cursor".
- **gRPC `AuditService.GetAuditLogs`:** `cursor` (9), `include_total` (10) on the request,
  `next_cursor` (6), `total_exact` (7) on the response. Same rules; errors are
  `InvalidArgument`.
- **`GET /api/v1/audit/export.csv`.** Unchanged parameters and rows (newest-first, `limit` ≤
  10,000). It streams: internal keyset batches of 500 over the index, each batch written and
  flushed before the next is read. There is no count.
- **`GET /api/v1/audit/export` (SIEM, ascending id, `after_id`).** Unchanged contract, no
  count. On the first page (no `after_id`), `since` is resolved to `id0 = MIN(id)` over every
  row with `event_time ≥ since`. That is an index-only range of `(event_time, id)` from `since`
  to the end, so it costs as much as the rows the export then returns. The page is then
  `id ≥ id0 AND event_time ≥ since ORDER BY id`. This is exact even when id order and time
  order disagree (a writer that waited between stamping `event_time` and taking an id, or
  clock skew between replicas). Later pages start from `after_id`, already past the older
  rows, with the same `event_time` filter. A first version resolved `id0` only over
  `[since, t0 + 5 min]`; review showed it could drop a lower-id row stamped more than
  5 minutes ahead, and `TestAuditExportSIEM_SinceResolvesToAStartID` pins the case.

Internal callers of `GetAuditLogs` keep the exact count by default (dashboard counters rely
on it). Callers that discard the total pass `CountNone`.

## 4. Indexes and migration

| index | columns | replaces |
|---|---|---|
| `idx_audit_events_event_time_id` | `(event_time, id)` | — |
| `idx_audit_events_project_event_time` | `(project_id, event_time)` | `idx_audit_events_project_id` |
| `idx_audit_events_secret_event_time` | `(secret_node_id, event_time)` | — |
| `idx_audit_events_machine_event_time` | `(machine_identity_id, event_time)` | `idx_audit_events_machine_identity_id` |

The keys grow with time, so inserts append at the right edge of each b-tree.
`models.AuditEvent` drops the two single-column `gorm:"index"` tags, and the four indexes
are declared once (`store.AuditListIndexes`) and created by code, not by gorm tags. A gorm
tag would be a plain `CREATE INDEX` inside the migration transaction.

**Postgres.** This runs after the migration transaction has committed, never inside it.
1. Read `pg_index` for the four names.
2. If all four exist and are `indisvalid`, finish now (the cost of every boot after the first).
3. Otherwise take the build advisory lock on one connection (so one replica builds while the
   others skip; a session lock, or with `storage.database.pooler: pgbouncer-transaction` a
   transaction-scoped one in a pinned transaction that holds no snapshot,
   INV-STORE-advisory-lock-pooler-scope) and run the DDL on a second. For each index:
   - an `INVALID` leftover from an interrupted build is dropped with
     `DROP INDEX CONCURRENTLY IF EXISTS`;
   - then `CREATE INDEX CONCURRENTLY IF NOT EXISTS`;
   - validity is re-checked.
4. When all four are valid, the replaced indexes are dropped with `DROP INDEX CONCURRENTLY
   IF EXISTS`.

Every statement is a single autocommit statement. `CONCURRENTLY` takes `SHARE UPDATE
EXCLUSIVE`, which does not conflict with the `ROW EXCLUSIVE` an audit INSERT needs, so audit
writes (and with them secret reads) are never blocked. A plain `CREATE INDEX` takes `SHARE`
and blocks every INSERT for the whole build.

Small tables (estimate < 200k rows, e.g. a fresh install) build synchronously before the
server starts serving, bounded by a 30 s timeout. A CONCURRENTLY build waits for every open
writer transaction, so an idle-in-transaction session must not hold the start; past the
timeout the build is cancelled and continues in the background. While another session holds
the build lock, a background build retries every 5 s for up to 5 minutes. A cancelled build
aborts only the DDL connection; the idle lock connection releases the lock before the build
returns. Larger tables build in a background goroutine, logged as
`audit index build: <name> started/done in <d>`, so a liveness probe never kills a long build
halfway and loops. Until the build finishes, list queries use the old plans. A process that
dies mid-build leaves an `INVALID` index, which the next boot drops and rebuilds. A build
error is logged and retried at the next boot, and never stops the server: a missing index
costs speed, not correctness.

**SQLite.** Plain `CREATE INDEX IF NOT EXISTS` inside the migration, before the server
listens, with one log line per index giving the row estimate and the elapsed time. SQLite has
a single writer, so the build holds the database for its duration. The replaced indexes are
dropped in the same step.

Measured with the server's own DSN on a laptop NVMe disk: 10M rows (a 2.7 GB file) took
2 min 23 s in total for the one-time upgrade start, 17 / 28 / 37 / 48 s per index in the
order above. Expect a multiple of that on slower disks. The build runs in one transaction,
so the WAL file grows to about 1.9 GB and keeps that size afterwards (`journal_size_limit`
is unset, AUDIT-SCALE-1 §3.8). Every later start finds the indexes and does nothing.

**Rollback and rolling upgrades.** An older binary started against a migrated database finds
the composites and ignores them. If an older replica's migration does create the
single-column indexes again during a rolling upgrade, the next start of this version drops
them again. On the upgrade path it does not recreate the dropped single-column indexes;
those are only created by a fresh-install AutoMigrate. Nothing here changes the schema
epoch.

## 5. Acceptance criteria

1. EXPLAIN-shape tests on SQLite and Postgres. On Postgres they run with `enable_seqscan` and
   `enable_bitmapscan` off: on test-sized data the planner otherwise always prefers scanning
   the few matching rows and sorting them, which only real statistics tell apart from the
   index walk needed at scale. They
   EXPLAIN the SQL each production query actually issued (captured from gorm), and pin:
   - logs page 1 and cursor pages, unfiltered → `idx_audit_events_event_time_id`, no sort
     node;
   - `project_id` filter → `idx_audit_events_project_event_time`;
   - `secret_id` (logs, search `resource_id`, per-secret trail) →
     `idx_audit_events_secret_event_time`;
   - time-window filters, search filters without their own index (action, actor, ip, success,
     resource_type, actor_type) → `idx_audit_events_event_time_id` walked newest-first;
   - export.csv batches → the same indexes as logs;
   - SIEM export (ascending id + `since`) → the time index for the id resolution, then the
     primary key;
   - the bounded count → the same index as the page.

   A full `Sort` node fails the test. Postgres may use an `Incremental Sort` for the
   `id` tie-break inside equal timestamps on the two-column composites; that is allowed.
2. Cursor correctness, both DBs:
   - 250 rows sharing three timestamps, paged at sizes 1, 7 and 50: the concatenation equals
     one `ORDER BY event_time DESC, id DESC` read (no gap, no duplicate);
   - the same with rows inserted between page requests: rows already passed never reappear,
     and rows older than the cursor that are inserted meanwhile are returned.
3. Offset cap: `page`/`page_size` and `offset`/`limit` beyond 10,000 → 400 with the cursor
   hint, REST and gRPC. Exactly at the cap → 200.
4. Totals: no exact `COUNT(*)` over the filter unless `include_total=true` (asserted on the
   captured SQL); the bounded count is exact below the cap; `total_exact` is right on both
   sides.
5. Migration (Postgres, pg-gated):
   - idempotent (a second run issues no DDL);
   - an `INVALID` index with the same name is rebuilt;
   - the replaced indexes are gone afterwards;
   - an audit INSERT completes while the build waits on an open writer transaction. The same
     test with a plain `CREATE INDEX` blocks: this is the red/green proof of "never block
     audit writes".

   SQLite: the indexes exist after migrate, the replaced ones are gone, and the log line is
   printed.
6. Journey: `/audit/logs` and `/audit/search` cursor walk through the real server (scripts/e2e
   coverage); CLI `--cursor`; web real-backend e2e: "Load more" appends the next page and
   disappears at the end.
7. Read path: W1/W2 c=1 and c=50, SQLite and Postgres, before vs after, at least 10
   interleaved reps. Secret-read throughput must not regress beyond noise.

## 6. Security

- Authorization is unchanged: the same `audit.read` (and for the exports, `system.read`)
  gates, and every filter stays in SQL. A cursor cannot widen what a request can read. It
  only bounds the starting position, and its fields are parsed as integers and bound as
  parameters.
- The hash chain is not touched. It is ordered and walked by `id`, and nothing in this change
  writes to `audit_events`. Retention still deletes an id prefix (INV-STORE-22).
- Exact `COUNT(*)` stays available through `include_total=true`. It costs the same as on main,
  but only when it is explicitly requested.

## 7. Not in scope

- Secret listing keyset (AUDIT-SCALE-1 §4 #5), incremental chain verification (#3), chunked
  purge (#4), `/audit/retention` estimate (#6).
- No audit query filters on `machine_identity_id` today. The composite replaces the
  single-column index so that "everything this identity did" stays index-served when such a
  filter is added.
- Internal offset pagers (`pat_restriction_listing`, `user_baseline_role_reconcile`) keep
  `OFFSET`. They now walk the time index instead of sorting, and they are not reachable with
  caller-chosen depths.
