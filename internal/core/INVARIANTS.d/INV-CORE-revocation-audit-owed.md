- **INV-CORE-revocation-audit-owed** A revocation (role / group-role / permission / role
  delete, group member removal and delete, project member removal, share revoke / self-removal /
  expiry sweep, secret ACL revoke, machine suspend / revoke / token revoke / role removal, PAT and
  session revoke, user suspend / deactivate / delete, SCIM deactivate / deprovision, break-glass
  revoke, JIT role expiry sweep, invitation revoke, access-request withdraw, risk-exception revoke,
  project delete, environment delete, enabling a project's MFA requirement)
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
  loses nothing: the record committed with the effect.
  The "pending-record write fails too" case (`CreatePendingAuditEvent` refused): the revocation still
  succeeds, the failure is a loud `SECURITY:` log, and the audit row is attempted directly after the
  commit, so the final state equals an unfaulted run (the audit row is written once, nothing is
  queued). The only real loss is when that direct write fails as well: it is logged as `NOT queued
  for backfill (record it by hand)` and is an audit-trail GAP, not an outcome by design; the fuzz
  oracle does not accept it (it reads as "neither an audit row nor a pending row"). Direction-dependent operations choose the
  rule from the change itself (`auditedByDirection`: account state into a blocked state and machine
  suspend/revoke are revocations, back to active is a grant that fails closed).
  Why: Andrei 2026-10-14; before AUDIT-TX-3 these wrote a plain best-effort row after the commit
  with no record, so a refused append or a crash lost the row for good.
  Guard: `internal/core` `TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost` (34 kinds x
  success / append error / effect-then-error / panic / crash at the append / pending-record error
  / pending-record panic, SQLite always, PostgreSQL pg-gated; the backfill completes the trail
  exactly once and the chain verifies), `TestUpdateUser_DeactivateAuditInOwnTransaction_NoSQLiteDeadlock`,
  `TestUpdateUser_DeactivateAuditRefused_RowIsOwedAndBackfilled`; `server/faultops`
  `TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed` (34 REST/gRPC ops over the
  router, request still succeeds, rows + pending equals an unfaulted run); the fuzz oracle's
  owed-audit rule `server/faultops` `owed_audit_oracle_test.go` (oracle (a) accepts a success whose
  diff is confined to {AuditEvent, PendingAuditEvent} only for those ops with a fault on
  LogAuditEvent / ClaimPendingAuditEvent, only when every owed audit row has exactly one matching
  pending record, and only when the backfill then converges to the reference exactly; a
  CreatePendingAuditEvent fault must leave the state equal to the reference), calibrated red/green by
  `TestOwedAuditOracle_Calibration` (regression seed `5012b3d0b086d4a4`; `FuzzOwedAuditRevocations` for
  bursts, `TestOwedAuditOracle_SweepEveryScopedOp` for the exhaustive pass and the hand-pinned
  per-op `owedAuditExpectedOwedTypes`; the SSO callback and the SAML ACS are in the rule's scope,
  they share the group and role reconcile in `sso.go`).
  Not covered: the narrowing branch of `UpdateRole` / `UpdateSharePermission` keeps its plain
  best-effort row (inventory "Remaining"); `DecideAccessReviewItem`'s revoke keeps its in-tx
  best-effort sink (#2676); a new revocation that does not use `withOwedAuditMutation` is not
  detected by a static guard. The oracle rule cannot show from state alone that the pending record
  committed WITH the effect when an op's catalog scenario revokes nothing visible
  (`POST /users/{id}/revoke-sessions` of a user with no session); there the proof is the exact payload
  match plus the `internal/core` test above. The both-writes-fail gap needs two faults and is not
  reachable by the one-fault fuzzer; it is calibrated by hand (`TestOwedAuditOracle_Calibration`, i2).
