# Last-activity window of access recertification

Access recertification (ISO 27001 A.5.18) and the compliance evidence show, for each
user grant, when the user last used the project's secrets. That lookup reads the audit
trail, so it is bounded: it looks back over the **recertification period**, not over
the whole audit log.

**"No activity" means "no activity within the last N days", never "no activity ever".**

## The window

| Where | Window (N days) |
| --- | --- |
| Project access review (`GET /api/v1/projects/{id}/access-review`), and the items a campaign snapshots from it | The review cadence, `recertification.cadence_days` (default 90), at most 366 |
| Dormant role grants in the compliance posture, the `dormant-access` control, the digest and the evidence export | 90 days, the dormancy threshold the count is judged against (not the cadence) |

`recertification.cadence_days` is read whether or not the recertification scheduler is
enabled (see [CONFIGURATION.md](CONFIGURATION.md#recertification)). A value above 366
is treated as 366, a value of 0 or less as 90. The window start is inclusive: an event
exactly N days before the lookup counts.

## What each surface says

- **API.** The access-review response carries `activity_window_days`. An entry without
  `last_used_at` had no use in that window. Campaigns carry `activity_window_days` too,
  fixed when the campaign was opened.
- **Web UI.** An entry or campaign item with no use reads "no use in the last Nd"
  (the tooltip of a used one says "last N days").
- **Campaign CSV export** (`.../campaigns/{id}/export.csv`). The last column,
  `last_used_window_days`, repeats the window on every row; an empty `last_used_at`
  means no use in that many days before the campaign was opened. A campaign opened
  before this change says `all_history`: its `last_used_at` looked back over the whole
  audit log.
- **Compliance controls and digest.** The `dormant-access` control detail and the
  digest line read "N dormant role grant(s) (no use in the last 90 days)".
- **CLI.** `keyorix accessreview` still prints `never` for an entry without
  `last_used_at`; read it as "none in the last `activity_window_days` days" (the API
  response it reads carries the window). The CLI wording is not changed here and is a
  follow-up.

## How it is bounded

All five lookups (`LastUserSecretActivity`, `LastUserSecretReadActivity`,
`LastUserSecretWriteActivity`, `LastUserRoleManagementActivity`,
`LastUserSecretDeletionActivity`) share one statement on `audit_events`:
`project_id = ? AND event_time >= <window start> AND event_type IN (...)`. That is a
range scan of the existing `idx_audit_events_project_event_time (project_id, event_time)`
index on SQLite and PostgreSQL, so the rows read are the project's events inside the
window, however large the table. No new index and no migration of `audit_events` is
needed. The store raises any window start older than 366 days to 366, so a caller
cannot widen it.

There is deliberately no row limit and no id bound: results are reduced to the newest
event per user in Go, so a `LIMIT` would drop quiet users, and the time range already
gives the planner a lower bound on the index. Tests:
`internal/storage/store/local_access_activity_window_test.go` (period boundary, hard
maximum, SQLite plan on a 240k-row table) and
`local_access_activity_window_postgres_test.go` (PostgreSQL plan and rows read).

`last_activity_inventory_test.go` fails if a new `LastUser*Activity` method is added to
the storage interface without being listed there.
