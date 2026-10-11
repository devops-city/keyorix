- **INV-CORE-login-budget-storage-fallback** The per-IP login budget
  (`IsLoginRateLimited` / `RecordFailedLogin` / `ReserveLoginAttempt` /
  `ReleaseLoginAttempt`) neither fails open nor fails closed on a LoginAttempt
  storage error: it falls back to a bounded in-memory per-IP limiter with the same
  `LoginMaxAttempts` / `LoginWindow`, keyed by the same `CanonicalIP`, per process
  (`login_budget_fallback.go`). Fallback attempts count in addition to stored ones
  and age out with the window; they are never merged into storage. A fallback
  reservation carries `loginFallbackIDBit` so a delivered login's release refunds
  it in memory; such an id is per-process and is NEVER persisted to a shared row
  (`sharedLoginSlot`: mfa_challenges / web_authn_sessions `login_attempt_id` get
  nil, so the slot stays counted). A COUNT that fails while writes succeed still
  binds: a successful write made while the budget is degraded (a fallback within
  `LoginWindow`) is mirrored in memory, and a failed count is judged on memory
  including mirrors (a working count ignores them, so nothing is counted twice)
  (#3023 review). Memory is bounded (`loginFallbackMaxIPs` addresses, LRU; per-address
  attempts capped). Every fallback is audited `auth.rate_limit_error`
  (Success=false) and counted (`keyorix_login_budget_fallback_total`); the client
  sees the same 429. Why: Andrei, 2026-10-10 (AUTH-AUDIT-1) — fail-open removed
  the brute-force backstop during any DB fault; fail-closed would lock everyone
  out. The password-reset and SSO-begin budgets still fail open (not covered by
  this decision). Guard: `login_budget_fallback_test.go`
  (`TestLoginBudgetFallback_StorageDownStillEnforcesTheLimit`, `_ADeliveredLoginReturnsItsMemorySlot`,
  `_RecoveredStorageIsAuthoritativeAgain`, `_NoFaultNoChange`, `_IsAuditedAndCounted`,
  `_BoundedUnderManyDistinctIPs`), `login_budget_review_test.go`
  (`TestLoginBudget_CountOnlyFailureStillBinds`, `_CountOnlyFailure_RecoveryDoesNotDoubleCount`,
  `_CountOnlyFailure_DeliveredLoginReleasesItsMirror`, `_CountOnlyFailure_MirrorAgesOutWithTheWindow`,
  `TestFallbackLoginSlot_IsNeverPersistedToSharedRows`,
  `_ReleaseOnAnotherReplicaRefundsNothingThere`),
  `server/http/handlers/login_budget_fallback_http_test.go` and
  `login_budget_fallback_slot_http_test.go`.
