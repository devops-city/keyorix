### Fixed
- **`admin restore` no longer refuses a backup taken after a secret purge (#3085).** The retention purge hard-deleted
  the secret and its versions but left rows that still referenced them, and restore's mandatory
  dangling-reference check counted every one. The purge now deletes, in the same transaction, the
  rows of every mutable table that references the secret or a version: access requests (and their
  approvals), shares, tags, access schedules, metadata history, version comments and notifications.
  `audit_events.secret_node_id` (append-only), `anomaly_alerts.secret_node_id` (an unacknowledged alert is a
  live security signal), `secret_access_logs` (append-only, exported) and the `access_review_items`
  snapshot (its own campaign retention) are historical references the purge keeps and restore's check
  skips by name; every other reference stays strictly checked. Rows orphaned by purges that ran before
  this fix are not swept: such a backup is still refused until the orphans are removed by hand. A guard test fails when a new table
  references a secret without being classified as one or the other.
