- **INV-CORE-login-reservation-identifiable** Every stored auth-budget write to
  `login_attempts` (a releasable `ReserveLoginAttempt` reservation AND an outcome-agnostic
  `RecordFailedLogin` / `RecordPasswordResetAttempt` / `RecordSSOBeginAttempt` record) is
  identified by a key core generates BEFORE the write, and the storage write is idempotent per
  key (`login_attempts.reservation_key`, unique; ON CONFLICT DO NOTHING, id read back by key).
  Core retries a failed write exactly once with the SAME key (`budgetWriteKeyed`, the only
  caller of `ReserveLoginAttempt` in `auth_budget.go`; no budget write uses the
  non-idempotent `RecordLoginAttempt`). So a write that landed but reported an error is
  recovered (released when the login delivers a session, kept when it fails), a write that
  failed once is still stored, and a write recovered by the retry is never counted twice.
  Never under-count: a failed credential always leaves exactly one row; a write that fails on
  the retry too falls back to the in-memory limiter (INV-CORE-login-budget-storage-fallback,
  #3023), and if those failed writes had in fact landed the attempt is over-counted (stored row
  plus fallback slot), never under-counted. Why: the exhaustive login-op sweep on #2956
  (`ReserveLoginAttempt#1/effect-then-error` on /auth/login, /auth/mfa/verify,
  /auth/webauthn/login/finish): the row landed with no handle, so a delivered login stayed
  counted; and #2837 shape 2 (`RecordLoginAttempt#1/error` on /auth/password-reset,
  FUZZ-SEEDS-1): one transient error moved the attempt off the shared table into the
  per-process fallback (oracle (a) [LoginAttempt AuditEvent]). Guard: `server/faultops`
  `TestLoginEffectThenErrorTuples_PassEveryOracleWithoutARow`,
  `TestPasswordResetAttemptAccounting_PassesEveryOracleWithoutARow`; `internal/core`
  `TestAuthBudget_EveryStoredWriteIsKeyed`, `auth_budget_record_keyed_test.go`;
  `server/http/handlers` `login_budget_identifiable_reservation_test.go`;
  `internal/storage/store` `TestReserveLoginAttempt_IsIdempotentPerKey`; `internal/storage`
  `TestLoginAttemptReservationKey_AddedOnUpgrade`.
