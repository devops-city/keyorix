### Testing
- Re-auth grant revocation is now pinned against faults: an audit-write failure or a `GetUser` fault no longer
  can stop the step-up grant purge on suspend, `UpdateUser` deactivation, SCIM update and SCIM deprovision, and a
  faulted use-time account re-check counts toward the lockout like a wrong guess.
- A static guard (`internal/besteffort`) fails if `besteffort.Run` is used inside a `WithTransaction` closure
  (directly, or through a same-package helper such as `purgeStepUpGrants`); the package doc now names the one
  sanctioned in-transaction shape, a nested savepoint step.
