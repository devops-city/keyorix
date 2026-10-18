- **INV-CORE-revocation-audit-owed** A revocation (role / group-role / permission / role
  delete, group member removal and delete, project member removal, share revoke / self-removal /
  expiry sweep, secret ACL revoke, machine suspend / revoke / token revoke / role removal, PAT and
  session revoke, user suspend / deactivate / delete, SCIM deactivate / deprovision, break-glass
  revoke, JIT role expiry sweep, invitation revoke, access-request withdraw, risk-exception revoke)
  is never blocked, delayed or failed by the audit log (Andrei 2026-10-14), and its audit row is
  never silently lost (AUDIT-TX-3, extending INV-CORE-plain-suspend-audit-owed to every revocation).
  The change runs through `withOwedAuditMutation` / `runOwedAuditMutation` (`audit_owed.go`) in ONE
  transaction in which the audit writers, given the owing target, record a `pending_audit_events`
  row instead of appending, so the change and the record of the row it owes commit together. After
  the commit, and after any auth-cache eviction (`settle` is called last: the audit log never
  delays a revocation taking effect), each owed row is appended and its record claimed in one
  transaction with a bounded wait; the first refusal stops the attempts (the rest stay queued and
  are counted). A refused append is loud (`SECURITY:` log, `audit_owed_failures`, the pending
  count in `GET /api/v1/system/info`) and the record stays for `BackfillPendingAuditEvents`. If the
  record itself cannot be written the change still commits (the closure runs again with a
  collect-only target) and the row is attempted directly. A crash between the commit and the append
  loses nothing: the record committed with the effect. Direction-dependent operations choose the
  rule from the change itself (`auditedByDirection`: account state into a blocked state and machine
  suspend/revoke are revocations, back to active is a grant that fails closed).
  Why: Andrei 2026-10-14; before AUDIT-TX-3 these wrote a plain best-effort row after the commit
  with no record, so a refused append or a crash lost the row for good.
  Guard: `internal/core` `TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost` (31 kinds x
  success / append error / effect-then-error / panic / crash at the append / pending-record error
  / pending-record panic, SQLite always, PostgreSQL pg-gated; the backfill completes the trail
  exactly once and the chain verifies), `TestUpdateUser_DeactivateAuditInOwnTransaction_NoSQLiteDeadlock`,
  `TestUpdateUser_DeactivateAuditRefused_RowIsOwedAndBackfilled`; `server/faultops`
  `TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed` (31 REST/gRPC ops over the
  router, request still succeeds, rows + pending equals an unfaulted run).
  Not covered: the narrowing branch of `UpdateRole` / `UpdateSharePermission` keeps its plain
  best-effort row (inventory "Remaining"); `DecideAccessReviewItem`'s revoke keeps its in-tx
  best-effort sink (#2676); a new revocation that does not use `withOwedAuditMutation` is not
  detected by a static guard.
