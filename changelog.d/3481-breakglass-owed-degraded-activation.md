### Security

- Break-glass works while the audit log is down and is never unrecorded (BREAKGLASS-OWED-1, ADR-112 Amendment 6). When the audit log refuses an activation's rows, the activation, its role grant and an owed-audit record of each row commit in one transaction instead of failing; the activation is marked degraded, expires after `break_glass.degraded_ttl` (default 15m, never longer than a normal activation), is logged at ERROR, counted in `keyorix_breakglass_degraded_activations_total`, notified to the project's admins, shown in a web banner and `GET /api/v1/system/info` (`security.break_glass_degraded`), and must be reviewed at once. The owed-audit backfill writes its rows into the hash chain with their original times and marks it settled; `verify-audit` reports unsettled ones (INDETERMINATE). If even the owed record cannot be written, activation is refused with 503 `BreakGlassUnrecordable` naming the offline `recover-admin` procedure.

### Changed

- Schema epoch 5 (additive; compatibility floor unchanged): `break_glass_activations.degraded`, `.audit_settled_at`, `pending_audit_events.break_glass_activation_id`. Break-glass activations carry `degraded` / `audit_settled_at` over HTTP and gRPC. The audit-owed banner now counts "audit records", not only suspensions.
