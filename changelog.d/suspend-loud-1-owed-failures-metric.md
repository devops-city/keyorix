### Added

- **Refused suspend audit writes are now a metric.** `keyorix_audit_owed_failures_total` (authenticated `GET /api/v1/admin/scheduler-metrics` only) counts owed audit rows, such as a plain secret suspend's `secret.suspended`, that the audit log refused. It moves even when the pending record could not be written either, which `keyorix_audit_owed_pending` cannot see. Suspending is still never blocked by the audit log. See `docs/operations/metrics.md`.
