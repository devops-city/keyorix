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
| `keyorix_audit_flusher_pipelined_batches_total` | counter | - | Audit-chain batches sent while the previous batch was still in flight (pipelined commits). |
| `keyorix_audit_group_commit_wait_seconds` | histogram | - | Time an audit event waited in the group-commit queue (including the linger window) before its batch began committing. |
| `keyorix_audit_write_duration_seconds` | histogram | - | End-to-end latency of an audit event append (LogAuditEvent*), including group-commit queueing, whether it succeeded or failed. |
| `keyorix_auth_rate_limit_fallback_total` | counter | `budget` | Count of auth rate-limit operations that fell back to the in-memory limiter because the budget's storage failed. |
| `keyorix_best_effort_failures_total` | counter | `step` | Panics or returned errors from a best-effort step that runs after a commit, by step name. Never counts the primary operation -- only the best-effort step that followed it. |
| `keyorix_breakglass_degraded_activations_total` | counter | - | Count of break-glass activations committed while the audit log refused their rows (recorded as owed, short expiry, review mandatory). |
| `keyorix_db_pool_connections` | gauge | `pool`, `state` | Open database connections in a pool, by pool and state (in_use\|idle). in_use close to keyorix_db_pool_max_connections means callers are queueing for a connection. |
| `keyorix_db_pool_max_connections` | gauge | `pool` | Configured maximum open connections of a pool (0 = unlimited). |
| `keyorix_db_pool_wait_seconds_total` | counter | `pool` | Total time callers spent waiting for a free connection in a pool; rate() of it is the average number of goroutines blocked on the pool. |
| `keyorix_db_pool_wait_total` | counter | `pool` | Number of times a caller had to wait for a free connection in a pool. |
| `keyorix_grpc_request_duration_seconds_total` | counter | - | Cumulative gRPC unary handler time in seconds; divide its rate by the request rate for average latency. |
| `keyorix_grpc_requests_total` | counter | `status` | Total gRPC unary requests, by outcome (success or error). |
| `keyorix_http_request_duration_seconds` | histogram | `method`, `route` | HTTP request latency in seconds, by method and matched route. |
| `keyorix_http_requests_total` | counter | `method`, `route`, `status` | Total HTTP requests, by method, matched route, and status code. |
| `keyorix_notify_deliveries_total` | counter | `channel`, `outcome` | Notification deliveries by channel and terminal outcome (delivered\|failed\|dropped). |
| `keyorix_notify_delivery_retries_total` | counter | `channel` | Notification deliveries retried after a transient failure, by channel. |
| `keyorix_rate_limit_rejections_total` | counter | `limiter` | Requests refused by a rate limiter (HTTP 429 / gRPC ResourceExhausted), by limiter (principal\|token_auth_failure\|grpc_principal\|grpc_token_auth_failure). |
| `keyorix_scheduler_run_duration_seconds` | histogram | `scheduler` | Duration of scheduler ticks that actually ran (success or failure), by scheduler name. |
| `keyorix_scheduler_runs_total` | counter | `scheduler`, `outcome` | Background scheduler ticks, by scheduler name and outcome (success\|failure\|skipped). |
| `keyorix_siem_forward_retries_total` | counter | - | SIEM audit-event forwards retried after a transient failure. |
| `keyorix_siem_forwards_total` | counter | `outcome` | SIEM audit-event forwards by terminal outcome (delivered\|failed\|dropped\|spool_corrupt). |
| `keyorix_single_writer_enabled` | gauge | - | 1 when storage.database.single_writer is on for this process, else 0. |
| `keyorix_single_writer_last_poll_age_seconds` | gauge | - | Seconds since the guard's last successful epoch poll; approaching the lease length means the guard is about to leave authoritative. |
| `keyorix_single_writer_state` | gauge | `state` | single_writer guard state, one series per state (settling\|authoritative\|confirming) with value 1 for the current one. Only authoritative lets caches skip confirming reads; confirming means the lease lapsed or polls are failing. |
| `keyorix_tls_certificate_not_after_timestamp_seconds` | gauge | `listener` | Unix time at which the TLS certificate served by a listener (http\|grpc) expires. Alert on this minus time() before it reaches zero; a renewed file is picked up by new handshakes within about 30 seconds. |

## Server: authenticated-only (`/api/v1/admin/scheduler-metrics`)

Served at: server `GET /api/v1/admin/scheduler-metrics` (needs `system.write`; NOT on `/metrics`): metrics that would reveal security-job timing or integrity-check results to an anonymous reader

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `keyorix_audit_owed_failures_total` | counter | - | Owed audit rows (every owed revocation, e.g. a plain secret suspend) the audit log refused when they were due, per process. The action itself still took effect. Each one is either pending for the backfill or logged as lost (SECURITY log line naming the user and secret). |
| `keyorix_audit_owed_pending` | gauge | - | Number of owed audit rows (every owed revocation, not only suspend and degraded break-glass) not yet backfilled (the audit log refused the write after the action took effect). 0 is normal; NaN means the count could not be read. Cluster-wide; alert when above 0 for 10 minutes. |
| `keyorix_audit_verify_failure_recorded` | gauge | - | 1 while a sticky audit-chain verification failure (a detected break) is recorded; it clears only after a passing full verification. NaN until this process has read the state. Page on 1. |
| `keyorix_audit_verify_last_success_timestamp_seconds` | gauge | `check` | Unix time of the last audit-chain verification that passed, by check (tail = latest-checkpoint tail check; full = complete rolling or background re-walk). Absent until one has passed. |
| `keyorix_audit_verify_state_rejected` | gauge | - | 1 while the persisted verification state was found untrusted (bad signature, replayed or rolled back) and the status is therefore not_proven; it clears after a passing full verification. NaN until this process has read the state. |
| `keyorix_audit_write_failures_total` | counter | - | Audit event appends that returned an error to the caller (the audited mutation may already have committed). |
| `keyorix_auth_budget_rejections_total` | counter | `budget` | Authentication budget checks that answered limited (login, password reset, SSO begin, account lockout), by budget. A rising rate is brute-force pressure or a misbehaving client. |
| `keyorix_encryption_kek_provider_downgrades_total` | counter | - | Times a configured KEK fallback chain actually fell back to a weaker provider at runtime. |
| `keyorix_encryption_kek_provider_info` | gauge | `provider` | Configured KEK source (password\|file\|env\|exec\|shamir\|tpm\|aws-kms\|gcp-kms\|azure-kms\|other); always 1. |
| `keyorix_encryption_operation_failures_total` | counter | `op` | Secret encrypt/decrypt operations that returned an error (including a service that was not initialised), by op (encrypt\|decrypt). Decrypt failures after a restore or key change mean the wrong key or corrupt rows. |
| `keyorix_encryption_state` | gauge | `state` | Encryption service state, one series per state (disabled\|uninitialized\|ready) with value 1 for the current one. disabled means secrets are stored as plaintext. |
| `keyorix_scheduler_last_run_timestamp_seconds` | gauge | `scheduler` | Unix time of the last tick that actually ran (success or failure; not a skip), by scheduler name. |
| `keyorix_scheduler_last_success_timestamp_seconds` | gauge | `scheduler` | Unix time of the last successful tick, by scheduler name. |
| `keyorix_single_writer_unattributed_bumps_total` | counter | - | Write-epoch changes no in-process write accounted for; a non-zero value means something else wrote to the fenced tables. |

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
| `check` | closed set: tail, full (audit verification kinds) |
| `limiter` | closed set of rate limiters (ratelimitmetrics.Limiter: principal, token_auth_failure, grpc_principal, grpc_token_auth_failure) |
| `listener` | closed set: http, grpc (tlsmetrics.HTTP / tlsmetrics.GRPC) |
| `method` | HTTP method collapsed to the 9 RFC verbs plus `other` (middleware.normalizeMethod) |
| `op` | closed set: encrypt, decrypt |
| `outcome` | closed enum documented in the metric help (success/failure/skipped, delivered/failed/dropped, ...) |
| `pool` | fixed names of the database pools (request, scheduler_lock, named_lock; storage/db_pool_metrics.go) |
| `provider` | KEK provider type normalised to the 9 known provider names plus `other` (encryption.providerLabel) |
| `reason` | closed enum documented in the metric help (unreachable/timeout/server_error) |
| `route` | chi route pattern (`/api/v1/secrets/{id}`), never the raw path; unmatched requests share `unmatched` |
| `scheduler` | name of a built-in background job (fixed set registered in server startup) |
| `state` | closed enum: source states (suspended/expired/expiring), pool connection state (in_use/idle), single_writer guard state (settling/authoritative/confirming), encryption state (disabled/uninitialized/ready) |
| `status` | HTTP status code (a few dozen values) or gRPC `success`/`error` |
| `step` | string literal at each besteffort.Run call site (fixed set in source) |
