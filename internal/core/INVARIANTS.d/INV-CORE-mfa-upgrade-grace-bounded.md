- **INV-CORE-mfa-upgrade-grace-bounded** ADR-112's `security.require_mfa` upgrade grace period
  (`mfa_upgrade_grace.go`) is the only thing that can make `MFARequired` false while the
  deployment requires MFA, and it is bounded: it ends at the first global admin-tier holder with
  a second factor or at its deadline (30 days after the start recorded durably by
  server/adr112_grace.go), whichever comes first; once ended it latches, writes
  `adr112.require_mfa.enforced` and never reopens. Its clock never reads earlier than the
  recorded high-water mark nor than install time plus monotonic elapsed time, so a backward
  clock step cannot extend it. A check that cannot read its facts reports "not in grace" (MFA
  enforced) without ending it. Every MFA gate (session issuance here, the HTTP setup gate, the
  gRPC interceptors) reads `MFARequired`/`MFAUpgradeGraceActive` per request, never a value
  captured at boot. Why: #2923 (the grace period had no end). Guard:
  `mfa_upgrade_grace_test.go:TestMFAUpgradeGrace_*` (SQLite + pg-gated),
  `server/http/account_setup_mfa_grace_test.go:TestMFAGrace_FirstAdminEnrolmentEndsItWhileRunning`,
  `server/grpc/interceptors/auth_mfa_grace_test.go:TestAuthInterceptor_MFAUpgradeGrace`.
<!-- section: Last-admin / lockout -->
