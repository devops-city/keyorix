- **INV-CORE-auth-budgets-never-fail-open** No auth budget fails open on a
  storage error. Every budget goes through the shared limiter in `auth_budget.go`:
  the per-IP `login`, `password_reset` and `sso_begin` budgets (stored in
  `login_attempts`) and the per-account `account_lockout` budget (stored in the
  user row's lockout columns, which bounds password, TOTP, recovery-code,
  step-up and WebAuthn guessing). The stored count is primary. When it cannot be
  read or written, the attempt is counted in that budget's own bounded in-memory
  fallback (same limit and window, `authFallbackMaxKeys` keys, LRU, per process),
  which the check adds to the stored count. `loginLocked` and
  `recheckLoginLockFailClosed` consult the account fallback; a delivered login
  (`clearLoginFailures`) and `UnlockUser` clear it. The fallback has no
  exponential cooldown: an account stays locked while its stored failures inside
  the window plus its in-memory ones reach MaxAttempts (`accountFailuresSpent`;
  compared separately, an intermittently failing lockout write let up to
  2*(MaxAttempts-1) failures through, #3029 review). Each fallback is audited `auth.rate_limit_error`
  (Success=false; attributed to the account for `account_lockout`) and counted
  in `keyorix_auth_rate_limit_fallback_total{budget}`. The client response is
  unchanged. Why: Andrei, 2026-10-10 18:52 (AUTH-AUDIT-1 item 5). Guard:
  `auth_budget_storage_guard_test.go` (`TestAuthBudgetStorage_OnlyThroughTheSharedLimiter`:
  no login_attempts storage call outside `auth_budget.go` except the relay),
  `account_lockout_storage_fallback_test.go`,
  `account_lockout_stored_plus_fallback_test.go`, and
  `server/http/handlers/auth_budget_routes_guard_test.go`
  (`TestEveryAuthBudget_HoldsWithItsStorageDown`).
