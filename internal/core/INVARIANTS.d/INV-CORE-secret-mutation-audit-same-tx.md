- **INV-CORE-secret-mutation-audit-same-tx** A secret mutation called with
  `WithSecretMutationAudit` (every HTTP and gRPC create, update (both HTTP paths),
  rotate, delete and folder delete) and every `RollbackSecret` writes its audit row
  (`secret.created` / `secret.updated` / `secret.rotated` / `secret.deleted` /
  `secret.rolled_back`, plus the `secret_access_logs` row where it has one) through
  the transaction-scoped store as the LAST statement of the mutation's own
  transaction (`writeMutationAuditTx`). A failed or panicking append returns
  `ErrSecretMutationAuditUnavailable`, the transaction rolls back, and nothing
  changes: no secret row, no version, no audit row, no access log. Off-box side
  effects (SIEM forward, live tail) run only after the commit, from
  `auditForwardSink.Flush`, which recovers a panicking forwarder per event. A
  rotation of a secret with no rotation backend, and every rollback, also commits
  its timestamp in that transaction; a backend-bound rotation keeps the version
  (with its audit row) even when the later timestamp write fails, because the
  upstream credential already changed, and its `secret.rotate_backend_started` row
  is now required before the upstream is called. Why: a mutation must never commit
  without its audit record (AUDIT-MUTATION-TX-1; #3276 had made the append
  synchronous but still separate and log-only).
  Guard: `internal/core` `TestSecretMutationAudit_RowExistsIffMutationCommitted`
  (SQLite always, PostgreSQL pg-gated; error, effect-then-error and panic on the
  append), `TestSecretMutationAudit_StandardDurabilityNeverRelaxesTheMutationCommit`
  (pg-gated), `server/faultops` `TestSecretMutationAuditFailure_FailsClosedChangesNothing`
  (every REST and gRPC mutation op over the real router, no tolerance), and
  `internal/solewriter` `TestTracker_SecretMutationWithItsAuditRowIsOneFencedWrite`
  (pg-gated).
  **Not covered**: a caller that reaches these core methods without
  `WithSecretMutationAudit` writes no mutation row from core (bulk delete, copy,
  bulk rename, the rotation scheduler audit separately and are unchanged), and
  `RestoreSecret` (undelete) still appends `secret.restored` after its commit.
