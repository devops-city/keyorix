- **INV-CORE-bulk-suspend-audited-before-effect** A project-wide suspend records ONE
  `secret.bulk_suspend_attempted` event, with the per-suspension `clear_synced_copies` choice and the
  number of secrets it targets, BEFORE it suspends any secret (it is written for a plain bulk suspend too, but only the clear-synced-copies request is fail-closed); when the request carries the
  clear-synced-copies choice and that event is not persisted, it suspends nothing and returns
  `ErrBulkSuspendAuditUnavailable`. Each affected secret then gets the marker through
  `SuspendSecretWithOptions` (the single code path), never by writing the column directly, so the bulk
  and single paths cannot diverge. Why: a decision to empty copies in other clusters must be on record
  first. Guard: `internal/core/project_suspend_clear_copies_test.go`
  (`TestSuspendProjectSecrets_ClearSyncedCopies`: audit-before-effect ordering, fail-closed, marker per
  secret, resume clears it, a caller without write authority marks nothing).
  A clear-synced-copies bulk suspend is also fail-closed per secret: when a secret's own
  `secret.suspended` row is refused (`ErrSuspendAuditUnavailable`) the operation stops at the first such
  secret and returns `*BulkSuspendPartialError{Suspended, Failed}` (secrets already suspended stay
  suspended, each with its own audit row), and `POST /projects/{id}/secrets/suspend-all` answers 500 with
  `details.suspended`/`details.failed`, never 200. Both audit refusals (bulk event, per-secret row) carry
  `SuspendWithoutClearingHint` in their message, under the same stable code
  `SuspendAuditUnavailableCode` as the single-secret refusal (`core.IsSuspendAuditRefusal`; the
  per-secret one keeps its `details`). Any other per-secret failure in clear mode (a storage
  error in the write-permission re-check, a failed status transition or commit, a concurrent status
  change) is counted, the run continues, and it ends with `*BulkSuspendPartialError{Suspended, Failed}`
  (`AuditRefused` false) and the same 500: a secret left readable is never reported as suspended. Only a
  permission denial or a secret deleted since the list is a skip. A plain bulk suspend stays best-effort
  (revocation is never blocked). Guard: `TestSuspendProjectSecrets_ClearSyncedCopies` (per-secret subtests) and
  `TestSuspendProjectSecrets_ClearSyncedCopies_OverTheRouter` (bulk-audit and per-secret audit failure).
