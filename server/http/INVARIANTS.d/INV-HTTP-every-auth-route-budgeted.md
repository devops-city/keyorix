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
  sweep over the budgeted rows). An AUTHENTICATED route that checks the caller's
  password or second factor (`POST /auth/change-password`, `PUT /auth/profile` with
  `current_password`, MFA activate / disable / recovery-code regenerate,
  `POST /auth/mfa/stepup`, passkey register-finish and delete) spends the same login
  budget: its handler calls `admitCredentialCheck` (the limiter's check, then a slot
  reserved before the credential check) and `settleCredentialCheck` (a rejected
  credential keeps the slot: `ErrIncorrectCurrentPassword`, `ErrReauthRejected`,
  `ErrLoginPostVerdict`; any other outcome hands it back) and defers
  `releaseCredentialSlotOnPanic` (a panic, answered 500 by Recovery, hands an unsettled
  slot back so the 500 changes nothing; no client can cause one, and unlike the login
  handlers' identical-response rule, INV-HTTP-login-panic-release-pre-verdict-only, no
  lockout-cost parity is at stake behind a 500). AUTH-2 items 2 and 4
  (AUTH-PW-BUDGET): with only the account lockout, one IP holding stolen sessions for
  many accounts could guess on each of them. `POST /auth/webauthn/reauth/finish` is
  not budgeted: it takes a signed passkey assertion, which cannot be guessed (its
  failures still feed the lockout). Guard: the same route test (classification
  `budget: "login"` on a `routeAuthenticated` row; the helper is checked to call the
  limiter, and the deferred panic release), `current_password_budget_test.go`
  (`TestChangePassword_PanicReturnsTheSlot`), `reauth_budget_test.go`. Not covered
  here: whether the credential check feeds the per-account lockout (core owns that
  bound, INV-CORE-current-password-check-is-a-login-attempt).
