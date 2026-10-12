- **INV-HTTP-every-auth-route-budgeted** Every route router.go registers under
  `/auth/` is classified. A public route that takes a guessable input is budgeted
  and its handler calls that budget's check (`checkLoginRateLimit`,
  `IsPasswordResetRateLimited`, `IsSSOBeginRateLimited`) through the shared limiter
  (INV-CORE-auth-budgets-never-fail-open). An authenticated route is mounted behind
  the Authentication middleware. A public route with no budget carries its reason.
  Each budgeted route, with its LoginAttempt storage failing on every call, still
  refuses once the budget is spent, with byte-for-byte the 429 the healthy store
  sends. Why: Andrei, 2026-10-10 18:52 (AUTH-AUDIT-1 item 5): no new endpoint may
  add a fail-open path. Guard: `server/http/handlers/auth_budget_routes_guard_test.go`
  (`TestEveryAuthRoute_IsClassifiedAndBudgeted` derives the route list and the
  authenticated/public split by parsing router.go, so a new route fails until it is
  classified; `TestEveryAuthBudget_HoldsWithItsStorageDown` is the storage-fault
  sweep over the budgeted rows). Not covered: whether an authenticated route's
  credential check feeds the per-account lockout (core owns that bound).
