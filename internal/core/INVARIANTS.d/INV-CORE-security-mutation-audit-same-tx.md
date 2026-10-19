- **INV-CORE-security-mutation-audit-same-tx** A grant-shaped security mutation
  (one that adds access, a credential, a principal or changes a preventive
  control: every direct, JIT, SSO, baseline and access-request role grant, group
  role grant and membership, permission and role-definition change, break-glass
  activation (whose audit refusal alone commits it degraded with owed records instead,
  INV-CORE-break-glass-never-unrecorded), share create, a share or role UPDATE that widens access (see
  below), secret ACL grant, machine identity create /
  token issue / role grant, PAT create, `CreateUserWithAssignments` and
  `CreateUserAudited`, project/environment create called with
  `WithMutationAuditActor`, SoD policy create/delete) writes its audit row(s)
  through the transaction-scoped store as the LAST statements of its own
  transaction, via `withAuditedMutation` (`mutation_audit_tx.go`). A write that
  does not persist (error or panic) returns `ErrMutationAuditUnavailable` and the
  transaction rolls back; a transaction that wrote no audit row at all is refused
  the same way. Off-box side effects (SIEM, live tail) run only after the commit;
  notifications after that. Revocations are deliberately NOT covered: they are
  never blocked by the audit log and keep their best-effort row after the commit
  (Andrei 2026-10-14). `UpdateRole` and `UpdateSharePermission` go either way
  and are classified per call from what they change inside their transaction
  (`withDirectedAuditedMutation`): any added permission, a higher share
  permission, a later or cleared expiry (mixed changes included) is a grant and
  fails closed; a change that only narrows or changes no access commits and
  audits best-effort after the commit (REVIEW-2 on #3367). The classification
  must hold until the write: `UpdateSharePermission` reads the share with
  `LockShareRecordForUpdate` (PostgreSQL `FOR UPDATE`) in that transaction, so no
  other writer can change it in between (SHARE-CAS-1); `UpdateRole` classifies
  from its own inserts and needs no lock. Why: a crash or refused append between the commit and the
  row left a grant with no audit record (REVIEW-1, AUDIT-TX-2). Inventory:
  `docs/specs/security-mutation-audit-inventory.md`.
  Guard: `internal/core` `TestSecurityMutationAudit_RowExistsIffMutationCommitted`
  (SQLite always, PostgreSQL pg-gated; error, effect-then-error, panic, and a
  goroutine death at the append), `TestWithAuditedMutation_NoRowFailsClosed`,
  `server/faultops` `TestSecurityMutationAuditFailure_FailsClosedChangesNothing`
  (28 REST/gRPC ops, no tolerance; break-glass activation: `TestBreakGlassActivation_AuditFailure_CommitsDegradedWithOwedRecords`), the per-call classification by
  `TestSecurityMutationAudit_UpdateRole_ByDirection`,
  `TestSecurityMutationAudit_UpdateSharePermission_ByDirection` and
  `server/faultops` `TestRoleEditorUpdate_AuditFailure_ByDirection`,
  `TestShareUpdate_AuditFailure_ByDirection`, the locked classification read by
  `TestUpdateSharePermission_ClassifiesFromALockedRead` and (pg-gated, two
  replicas) `TestCTAReview_UpdateSharePermission_NeutralVsConcurrentNarrowing_CrossReplicaPostgres`,
  `_PreservedExpiryVsConcurrentShortening_CrossReplicaPostgres`, `internal/solewriter`
  `TestTracker_GrantWithItsAuditRowIsOneFencedWrite` (pg-gated).
  **Not covered**: the follow-ups listed in the inventory (project/environment
  delete and update, group create/update, user update/restore/reactivate, config
  changes, access-request create/reject, invitations, SCIM); a new grant path
  that does not use `withAuditedMutation` is not detected by a static guard.
