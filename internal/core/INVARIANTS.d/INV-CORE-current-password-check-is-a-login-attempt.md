- **INV-CORE-current-password-check-is-a-login-attempt** A self-service check of the
  caller's current password (`ChangePassword`; `UpdateOwnProfile`'s email change on an
  account with no second factor) goes through `verifyCurrentPassword` and costs exactly
  what a password login costs, on the SAME per-account counter: refused while the account
  is locked, even with the right password (an equivalent bcrypt is spent first); a wrong
  password is counted by `recordFailedLogin`; a match re-checks the lock
  (`recheckLockAfterCredentialMatched`, whose storage fault is counted and wrapped
  `ErrLoginPostVerdict`). Every refusal wraps `ErrIncorrectCurrentPassword`, so the client
  sees the wrong-password answer. The counter is cleared only after the change has
  committed and only when the password alone is full authentication (no TOTP, no
  passkey): with a second factor enrolled, a correct password plus a refused new password
  must not reset the count that factor's guesses feed, as the password step of an MFA
  login does not. The account-security-factor changes (`requireReauth`) already fed the
  counter; their refusals now also carry `ErrReauthRejected` (text unchanged) so the
  transport can keep the per-IP slot (INV-HTTP-every-auth-route-budgeted). Why:
  AUTH-PW-BUDGET (HARDEN-HTTP-1's rate-limit inventory, #3321): both endpoints used a bare
  bcrypt comparison, so a stolen session or PAT could guess the account's password with
  no bound (the per-principal budget is off by default). Guard:
  `account_current_password_lockout_test.go` (`TestCurrentPassword_WrongGuessesLockTheAccount`,
  `TestCurrentPassword_SharesTheLoginCounter`, `TestCurrentPassword_CorrectPasswordWorksAndClears`,
  `TestChangePassword_RefusedNewPasswordLeavesTheCounter`,
  `TestChangePassword_SecondFactorAccountDoesNotClear`,
  `TestCurrentPassword_RecheckFaultCostsTheSameAsAWrongPassword`,
  `TestRequireReauth_RejectionsCarryTheSentinel`), and the call-site allowlist in
  `login_lockout_clear_site_guard_test.go` (the two clears and the re-check are listed with
  their reasons).
