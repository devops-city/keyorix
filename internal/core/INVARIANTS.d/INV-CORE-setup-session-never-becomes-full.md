- **INV-CORE-setup-session-never-becomes-full** A login that owes both account-setup steps (a
  restricted account with no second factor under `security.require_mfa`: recover-admin,
  one-time-password user, forced reset, pending first login) mints a `models.Session.SetupOnly`
  session whose absolute lifetime is at most `SetupSessionTTL` from login; refresh carries the
  flag and never extends the ceiling; and `EndSetupSessionIfComplete` revokes every session of
  the account once nothing is owed, so the next login is a normal two-step MFA login. If that
  revocation fails, the surviving setup-only session owes nothing and both transports refuse it
  (HTTP 401, gRPC Unauthenticated), and the completion audit event says the revocation failed.
  Why: #3024; #3041 review.
  Guard: `server/http/account_setup_session_ttl_test.go:TestAccountSetup_SetupSessionIsShortLived`,
  `TestAccountSetup_LiveSessionForcedReset`,
  `server/http/account_setup_gate_test.go:TestAccountSetup_EitherOrder_EndsInMFALogin`,
  `server/http/account_setup_session_facts_test.go:TestAccountSetup_SessionFactsReadFailure_FailsClosed`,
  `server/grpc/setup_session_gate_test.go:TestEveryGRPCMethod_RefusesSetupOnlySession`.
<!-- section: Account-state / exhaustiveness -->
