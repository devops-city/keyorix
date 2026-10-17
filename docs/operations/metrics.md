# Prometheus metrics reference

<!-- GENERATED FILE: do not edit by hand.
     Regenerate: go test ./internal/metricsdoc -run TestMetricsDocIsCurrent -update
     Source of truth: the promauto/prometheus definitions in the Go code. -->

Every metric the server and the Kubernetes operator define, generated from the code. A test fails if a metric is added, renamed or relabelled without regenerating this file, and another fails if a label is not on the bounded-label list below.

Go runtime (`go_*`) and process (`process_*`) metrics from the default collectors are also served on `/metrics`; `go_info` and `process_start_time_seconds` are deliberately suppressed. Series for a labelled metric appear only after its first observation, so a missing series can mean "never happened"; use `absent()` only on metrics documented as pre-registered.

## Server: public `/metrics`

Served at: server `GET /metrics` (unauthenticated; keep inside your perimeter)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `keyorix_account_state_unrecognized_total` | counter | - | Count of AccountLoginBlocked calls against a blank or unrecognized users.account_state value, failed closed. |
| `keyorix_audit_flusher_batch_size` | summary | - | Number of audit-chain entries committed per batch flush. |
| `keyorix_audit_flusher_flushes_total` | counter | - | Audit-chain batch-commit flushes (one per transaction/fsync, covering 1-N queued entries each). |
| `keyorix_auth_rate_limit_fallback_total` | counter | `budget` | Count of auth rate-limit operations that fell back to the in-memory limiter because the budget's storage failed. |
| `keyorix_best_effort_failures_total` | counter | `step` | Panics or returned errors from a best-effort step that runs after a commit, by step name. Never counts the primary operation -- only the best-effort step that followed it. |
| `keyorix_grpc_request_duration_seconds_total` | counter | - | Cumulative gRPC unary handler time in seconds; divide its rate by the request rate for average latency. |
| `keyorix_grpc_requests_total` | counter | `status` | Total gRPC unary requests, by outcome (success or error). |
| `keyorix_http_request_duration_seconds` | histogram | `method`, `route` | HTTP request latency in seconds, by method and matched route. |
| `keyorix_http_requests_total` | counter | `method`, `route`, `status` | Total HTTP requests, by method, matched route, and status code. |
| `keyorix_notify_deliveries_total` | counter | `channel`, `outcome` | Notification deliveries by channel and terminal outcome (delivered\|failed\|dropped). |
| `keyorix_notify_delivery_retries_total` | counter | `channel` | Notification deliveries retried after a transient failure, by channel. |
| `keyorix_scheduler_run_duration_seconds` | histogram | `scheduler` | Duration of scheduler ticks that actually ran (success or failure), by scheduler name. |
| `keyorix_scheduler_runs_total` | counter | `scheduler`, `outcome` | Background scheduler ticks, by scheduler name and outcome (success\|failure\|skipped). |
| `keyorix_siem_forward_retries_total` | counter | - | SIEM audit-event forwards retried after a transient failure. |
| `keyorix_siem_forwards_total` | counter | `outcome` | SIEM audit-event forwards by terminal outcome (delivered\|failed\|dropped\|spool_corrupt). |

## Server: authenticated scheduler timings

Served at: server `GET /api/v1/admin/scheduler-metrics` (needs `system.write`; NOT on `/metrics`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `keyorix_scheduler_last_run_timestamp_seconds` | gauge | `scheduler` | Unix time of the last tick that actually ran (success or failure; not a skip), by scheduler name. |
| `keyorix_scheduler_last_success_timestamp_seconds` | gauge | `scheduler` | Unix time of the last successful tick, by scheduler name. |

## Operator

Served at: operator manager metrics endpoint (controller-runtime registry)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `keyorix_operator_auth_failures_total` | counter | - | KeyorixSecret reconciles where Keyorix rejected the operator's own credential (HTTP 401); the target Secret was kept untouched. |
| `keyorix_operator_fetch_errors_total` | counter | `reason` | KeyorixSecret reconciles where Keyorix could not answer a value read (reason=unreachable\|timeout\|server_error); the target Secret was kept untouched. |
| `keyorix_operator_mass_revocation_suspected_total` | counter | - | KeyorixSecret reconciles where the mass-revocation circuit breaker withheld a confirmed-gone/revoked wipe pending an explicit keyorix.io/confirm-prune ack. |
| `keyorix_operator_source_secrets` | gauge | `state` | KeyorixSecrets that currently reference a suspended, expired or soon-to-expire Keyorix secret, by state. |

## Label cardinality

Every label used above and why its values are bounded. Secret names, paths, user ids and other unbounded values must never be labels.

| Label | Why bounded |
|---|---|
| `budget` | name of a built-in auth rate-limit budget (fixed set in internal/core) |
| `channel` | notification channel type (webhook/email/slack/... fixed set) |
| `method` | HTTP method collapsed to the 9 RFC verbs plus `other` (middleware.normalizeMethod) |
| `outcome` | closed enum documented in the metric help (success/failure/skipped, delivered/failed/dropped, ...) |
| `reason` | closed enum documented in the metric help (unreachable/timeout/server_error) |
| `route` | chi route pattern (`/api/v1/secrets/{id}`), never the raw path; unmatched requests share `unmatched` |
| `scheduler` | name of a built-in background job (fixed set registered in server startup) |
| `state` | closed enum of source states (suspended/expired/expiring) |
| `status` | HTTP status code (a few dozen values) or gRPC `success`/`error` |
| `step` | string literal at each besteffort.Run call site (fixed set in source) |
