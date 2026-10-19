### Security
- **A late MFA enrolment can no longer replace an activated TOTP secret (#2692).** If
  `ActivateMFA` committed between `BeginMFAEnrollment`'s check and its write, the enrolment
  overwrote the activated secret with a fresh seed it returned to the caller, and that seed
  then passed MFA on an MFA-enabled account. The write is now conditional and the late
  enrolment is refused with the existing "MFA is already enabled" error. A pending
  (not activated) secret is also no longer accepted by login, re-auth or step-up
  verification.
- **Deleting a user no longer reverts a concurrent password change (#2677).** `DeleteUser`
  wrote back the user row it had read before its lock, so a password change (or suspension,
  MFA enable) committing in between was undone, and a later `RestoreUser` let the old
  password in. It now writes only the columns it changes, under the row lock; `RestoreUser`
  does the same.
- **Last-admin guards no longer count an environment-scoped grant as a global admin
  (#2857).** An admin role granted at project 0 with an environment set (accepted by
  `POST /api/v1/user-roles`) applies only inside that environment, but the core-side
  last-admin guards counted it as a surviving global administrator, so the install's only
  real global admin could be suspended. The global holder query now matches the storage-side
  guard.
