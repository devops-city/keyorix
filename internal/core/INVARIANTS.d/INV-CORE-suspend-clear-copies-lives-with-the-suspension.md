- **INV-CORE-suspend-clear-copies-lives-with-the-suspension** `SecretNode.SuspendClearSyncedCopies`
  is written only by `SuspendSecretWithOptions` and `ResumeSecret`, through
  `TransitionSecretStatus` (the same conditional write as `Status`, so a racing suspend/resume
  loses loudly and the marker can never outlive or precede its status). Resume always clears it, so
  a later plain suspension never inherits an old choice; a plain suspend of an already-suspended
  secret never downgrades it; suspending again WITH the flag upgrades it and is audited
  (`secret.suspended`, `clear_synced_copies=true`). `SuspendProjectSecretsWithOptions` applies
  the same per-secret path to every secret it affects. With the flag, the status change, the
  marker and the `secret.suspended` row commit in ONE transaction (`storage.WithTransaction` +
  `auditInto`): when the row cannot be written nothing changes and the call returns
  `ErrSuspendAuditUnavailable`, which every transport answers with
  `SuspendWithoutClearingHint` ("suspend without clearing to cut access now"). A plain suspend
  (no flag) writes its status first and its audit row best-effort afterwards: revocation is never
  blocked or delayed by the audit log. Why: SUSPEND-PURGE-1, #3221. Guard:
  `secret_suspend_clear_copies_test.go` (`TestSuspendSecret_ClearSyncedCopies`),
  `server/http/secret_suspend_clear_copies_audit_test.go`
  (`TestSuspendSecret_ClearSyncedCopies_AuditUnavailable_OverTheRouter`: refused with the hint and
  unchanged; a plain suspend still answers 200 and suspends).
