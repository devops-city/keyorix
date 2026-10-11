- **INV-CORE-one-time-password-expires-like-wrong-password** Every one-time password the system
  issues (`CreateUserWithOneTimePassword`, recover-admin) is stored with
  `users.one_time_password_expires_at`, written by the same insert / transaction as the password
  hash. `VerifyPasswordCredentials` refuses an expired one only AFTER the bcrypt comparison
  succeeded, with the identical `invalid credentials` error a wrong password gets (no new oracle,
  matched latency), counts it toward the account lockout (`recordFailedLogin`) and audits
  `auth.one_time_password_expired` ASYNCHRONOUSLY (goSafe, detached context): a synchronous
  hash-chained insert on the expired branch only would make it slower than a wrong password;
  the expiry instant itself is refused (`!now.Before`).
  Scope: expiry is a LOGIN gate. `ChangePassword`, the email change in `UpdateOwnProfile` and
  `requireReauth` run inside an already-authenticated session and do not check it (a session that
  exists before the expiry is deliberately not cut off at it).
  `SetPasswordHash` always clears the expiry, so a password the user chose never expires this way.
  A non-positive configured TTL means the default, never "no expiry". The legacy backfill runs once,
  in the transaction that adds the column. Why: OTP-EXPIRY-1.
  Guard: `internal/core/otp_expiry_test.go:TestOneTimePassword_ExpiredIsRefusedLikeAWrongPassword`,
  `TestOneTimePassword_ExpiredAuditDoesNotBlockTheLoginPath`,
  `TestOneTimePassword_ExpiredAttemptsCountTowardLockout`, `TestOneTimePassword_RefusedAtTheExpiryInstant`,
  `TestOneTimePassword_NewPasswordClearsTheExpiry`,
  `server/http/otp_expiry_login_test.go:TestLogin_ExpiredOneTimePassword_SameResponseAsWrongPassword`,
  `internal/storage/otp_expiry_migration_test.go:TestMigrateDatabase_OneTimePasswordExpiry_UpgradeBackfill`.
