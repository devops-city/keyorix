- **INV-CORE-access-request-notify-never-fails-committed-transition** Every access-request
  transition (`RequestProjectAccess`, `ApproveAccessRequestWithExpiry` on both the grant and
  the below-threshold path, `RejectAccessRequest`, `RequestSecretAccess`,
  `ApproveSecretAccessRequest`, `RejectSecretAccessRequest`) runs its notification step under
  `runPostCommitNotification`, AFTER the transition has committed. A failure of that step
  (a returned error from recipient resolution or `notifyChecked`, or a panic anywhere in it)
  never changes the transition's result: it is logged at `SECURITY: WARN` with the step,
  access request, project and actor, recorded as one `notification.failed` audit event in the
  request's project, and the success response stands. Why: #3075 — a CreateNotification
  panic answered a committed approval (role granted) with HTTP 500, and a CreateNotification
  error left no trace that the requester or approvers were never told.
  Guard: `access_request_notify_failure_test.go` (every transition × panic/error, real SQLite,
  committed state and the audit row read back), `server/faultops`
  `TestAccessRequestNotificationFailure_IsNotReportedAsFailure` (through the real harness and
  every oracle, incl. bulk approve/reject) and the corpus entry
  `FuzzStorageFaultOperations/0b2369d76a986e0e`. `guards/notify_recipients_guard_test.go` treats
  `notifyChecked` as a delivery primitive, so a notifier built on it is still discovered.
  **Not covered**: notifications outside the access-request family keep `notify`'s silent
  swallow of a CreateNotification error (reminder schedulers hit benign dedup errors, #488);
  a panic there is the besteffort guard's concern, not this invariant's.
