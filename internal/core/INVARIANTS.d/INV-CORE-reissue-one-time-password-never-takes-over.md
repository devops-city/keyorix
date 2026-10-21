- **INV-CORE-reissue-one-time-password-never-takes-over** `ReissueOneTimePassword` (REISSUE-1) hands an
  administrator a credential for ANOTHER user's account, so it may never be a takeover path. It refuses,
  writing nothing: the caller's own account (`ErrCannotActOnSelf`; recover-admin is the way back), an
  unidentified actor (`adminID == 0`, the machine sentinel), an actor under the admin-rank ceiling
  (`requireAdminRankCeilingForTarget`), an externally-managed account (`ExternalID != ""`, a local password
  would bypass the IdP) and a suspended/inactive one (`password_reset_required` is a login-able state, so a
  reissue would silently reactivate it) -- the last two re-checked on the row lock inside the transaction.
  It never strips an enrolled second factor. A reissue narrows and widens access, so it is two commits
  (INV-CORE-mixed-request-split, MERGE-FIX-3482G): first the restricted state and the session deletion
  (owed: an audit outage never keeps a session alive; `user.one_time_password_reissue_restricted`), then
  the new hash with its OTP-EXPIRY-1 expiry and the cleared lockout (fail closed: the credential never
  exists without its expiry or its `user.one_time_password_reissued` row). Both re-check the refusals on
  the row lock; if the second fails the account stays restricted with no new password (503, partial
  apply) and a retry is safe. Sessions and PATs are evicted from the auth cache only after the first
  commit. The audit events name actor and target and never the password. Why: REISSUE-1.
  Guard: `internal/core/reissue_otp_test.go:TestReissueOneTimePassword_RefusesOwnAccount`,
  `TestReissueOneTimePassword_RefusesSSOOnlyUser`, `TestReissueOneTimePassword_RefusesSuspendedUser`,
  `TestReissueOneTimePassword_AdminRankCeiling`, `TestReissueOneTimePassword_KeepsAnEnrolledSecondFactor`,
  `TestReissueOneTimePassword_AuditsActorAndTargetNeverThePassword`,
  `TestReissueOneTimePassword_EndsSessionsAndClearsLockout`,
  `internal/core` `TestMixedRequestSplit_NarrowingNeverBlockedRemainderFailsClosed` (reissue-one-time-password).
