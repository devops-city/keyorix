- **INV-MW-account-setup-union-of-pending-steps** A principal owing account-setup steps
  (`core.PendingAccountSetupSteps`: change_password while restricted, enroll_mfa for an
  interactive session without a second factor under `security.require_mfa`) reaches exactly the
  union of its pending steps' routes plus `GET /api/v1/auth/profile`, matched on method AND full
  path, and every other authenticated route answers 403 naming the pending steps. No setup step
  may require another pending step's completion to be reachable: two gates that each refused
  the other's endpoint locked a recovered admin out for good (#3024). A session owing both steps
  must be setup-only, and a setup-only session owing nothing is refused (401), so a one-time
  password's session never becomes a full session. Why: #3024 (INSTALL-WALK-1 step 6a). Guard:
  `server/http/account_setup_gate_test.go:TestAccountSetupGate_EveryOtherRouteDenied` (walks the
  real router's registry), `TestAccountSetup_EitherOrder_EndsInMFALogin`;
  `account_setup_test.go:TestEnforceAccountSetup`.
<!-- section: Account/node gates -->
