- **INV-CORE-break-glass-never-unrecorded** A break-glass activation commits with its
  `role.assigned` and `break_glass.activated` rows in the hash chain, OR with a
  `pending_audit_events` record of each of those rows (linked by
  `break_glass_activation_id`) in the SAME transaction, OR not at all. When the normal,
  fail-closed transaction (`withAuditedMutation`) fails only because its audit append
  failed (`breakGlassAuditRefused`: an error, a panic, or the chain lock not coming within
  the write path's 10 s), `activateBreakGlassDegraded` commits the activation, the role
  grant and the owed records together, marked `degraded`, with the short expiry
  (`break_glass.degraded_ttl`, default 15 min, never later than the same request's normal
  expiry) on both the record and the grant. If that transaction fails as well (error or
  panic), the activation is refused with `ErrBreakGlassUnrecordable` (HTTP 503, gRPC
  Unavailable) naming the offline recover-admin procedure, and nothing changed. A
  degraded activation is logged at ERROR, counted in
  `keyorix_breakglass_degraded_activations_total`, notified to the project's admins,
  reported in `GET /api/v1/system/info` `security.break_glass_degraded`, and listed for
  review at once (no grace window). `BackfillPendingAuditEvents` writes its owed rows in id
  order with their ORIGINAL event times and, in the transaction of the last one, sets
  `audit_settled_at` (`SettleBreakGlassOwedAudit` locks the activation row first, so two
  writers of its last two rows cannot both skip it). An unsettled degraded activation is
  never purged by retention; `verify-audit` reports it and answers INDETERMINATE.
  Why: Andrei 2026-10-16 (break-glass must work during an audit-subsystem incident without
  ever being unrecorded), BREAKGLASS-OWED-1; ADR-112 Amendment 6.
  Guard: `break_glass_degraded_test.go` (SQLite always, PostgreSQL pg-gated):
  `TestBreakGlass_AuditRefusedCommitsDegradedWithOwedRecord` (append error,
  effect-then-error, panic, chain-lock wait; owed records, short expiry on record and
  grant, metric, status, review list; backfill keeps times, settles, idempotent, chain
  verifies), `TestBreakGlass_AuditAndOwedRecordRefusedIsRefused`,
  `TestBreakGlass_CrashNeverLeavesAnUnrecordedActivation` (goroutine death at the append,
  at the owed insert, after the commit with a restart, and in the backfill's append),
  `TestBreakGlass_AttackerMakesAuditUnwritable` (a trigger, including the offline
  verifier), `TestBreakGlass_AuditChainLockHeldGoesDegraded_Postgres` (a real held
  advisory lock), `TestBreakGlass_NormalPathUnchanged`,
  `TestBreakGlass_DegradedTTLNeverLongerThanNormal`; `break_glass_lock_guard_test.go`
  (both paths inside the revoke lock, the degraded path reachable only from the locked
  one); `server/http` `TestBreakGlass_DegradedOverTheRouter`; `internal/auditverify`
  `TestVerify_OwedBreakGlassActivations`; `internal/storage`
  `TestMigrateDatabase_AddsBreakGlassOwedColumnsOnUpgrade`.
  Not covered: an older (epoch-4) replica's backfill writes such rows without settling the
  activation (runbook: "Settling by hand"); the offline verifier trusts `audit_settled_at`
  and does not re-derive it from `audit_events`.
