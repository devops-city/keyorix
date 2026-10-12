- **INV-CORE-reissue-one-time-password-never-takes-over** `ReissueOneTimePassword` (REISSUE-1) hands an
  administrator a credential for ANOTHER user's account, so it may never be a takeover path. It refuses,
  writing nothing: the caller's own account (`ErrCannotActOnSelf`; recover-admin is the way back), an
  unidentified actor (`adminID == 0`, the machine sentinel), an actor under the admin-rank ceiling
  (`requireAdminRankCeilingForTarget`), an externally-managed account (`ExternalID != ""`, a local password
  would bypass the IdP) and a suspended/inactive one (`password_reset_required` is a login-able state, so a
  reissue would silently reactivate it) -- the last two re-checked on the row lock inside the transaction.
  It never strips an enrolled second factor. The new hash, its OTP-EXPIRY-1 expiry, the restricted state, the
  cleared lockout and the session deletion commit in ONE transaction; sessions and PATs are evicted from the
  auth cache only after commit. The audit event `user.one_time_password_reissued` names actor and target and
  never the password. Why: REISSUE-1.
  Guard: `internal/core/reissue_otp_test.go:TestReissueOneTimePassword_RefusesOwnAccount`,
  `TestReissueOneTimePassword_RefusesSSOOnlyUser`, `TestReissueOneTimePassword_RefusesSuspendedUser`,
  `TestReissueOneTimePassword_AdminRankCeiling`, `TestReissueOneTimePassword_KeepsAnEnrolledSecondFactor`,
  `TestReissueOneTimePassword_AuditsActorAndTargetNeverThePassword`,
  `TestReissueOneTimePassword_EndsSessionsAndClearsLockout`.
