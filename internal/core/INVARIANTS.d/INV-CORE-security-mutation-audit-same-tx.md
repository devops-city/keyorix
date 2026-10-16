- **INV-CORE-security-mutation-audit-same-tx** A grant-shaped security mutation
  (one that adds access, a credential, a principal or changes a preventive
  control: every direct, JIT, SSO, baseline and access-request role grant, group
  role grant and membership, permission and role-definition change, break-glass
  activation, share create/update, secret ACL grant, machine identity create /
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
  (Andrei 2026-10-14). Why: a crash or refused append between the commit and the
  row left a grant with no audit record (REVIEW-1, AUDIT-TX-2). Inventory:
  `docs/specs/security-mutation-audit-inventory.md`.
  Guard: `internal/core` `TestSecurityMutationAudit_RowExistsIffMutationCommitted`
  (SQLite always, PostgreSQL pg-gated; error, effect-then-error, panic, and a
  goroutine death at the append), `TestWithAuditedMutation_NoRowFailsClosed`,
  `server/faultops` `TestSecurityMutationAuditFailure_FailsClosedChangesNothing`
  (32 REST/gRPC ops, no tolerance), `internal/solewriter`
  `TestTracker_GrantWithItsAuditRowIsOneFencedWrite` (pg-gated).
  **Not covered**: the follow-ups listed in the inventory (project/environment
  delete and update, group create/update, user update/restore/reactivate, config
  changes, access-request create/reject, invitations, SCIM); a new grant path
  that does not use `withAuditedMutation` is not detected by a static guard.
