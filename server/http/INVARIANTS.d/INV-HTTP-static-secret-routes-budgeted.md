- **INV-HTTP-static-secret-routes-budgeted** The public routes outside `/auth/` that
  check a static secret with no per-account lockout behind it, `POST /system/init`
  (bootstrap token, 403) and `GET /metrics` (metrics token, 401), sit behind
  `customMiddleware.FailureBudget`: per client IP, a rejected secret spends one unit
  reserved before the handler runs, a success costs nothing, and once the budget is
  spent the route answers 429 without reaching the check (so no bootstrap lock is
  taken). Why: HARDEN-HTTP-1: both accepted unlimited guesses, and an operator-pinned
  `KEYORIX_BOOTSTRAP_TOKEN` can be a guessable phrase. Guard:
  `failure_budget_routes_test.go` (`TestSystemInit_BootstrapTokenGuessingThrottled`,
  `TestMetrics_TokenGuessingThrottled`, through the real router);
  `server/middleware/failure_budget_test.go`
  (`TestFailureBudget_ConcurrentBurstBoundedByBudget`). Not covered: the budget is in
  memory and per replica. `/auth/*` routes are covered by
  INV-HTTP-every-auth-route-budgeted instead.
