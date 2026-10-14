- **INV-CORE-suspend-clear-copies-lives-with-the-suspension** `SecretNode.SuspendClearSyncedCopies`
  is written only by `SuspendSecretWithOptions` and `ResumeSecret`, through
  `TransitionSecretStatus` (the same conditional write as `Status`, so a racing suspend/resume
  loses loudly and the marker can never outlive or precede its status). Resume always clears it, so
  a later plain suspension never inherits an old choice; a plain suspend of an already-suspended
  secret never downgrades it; suspending again WITH the flag upgrades it and is audited
  (`secret.suspended`, `clear_synced_copies=true`). `SuspendProjectSecretsWithOptions` applies
  the same per-secret path to every secret it affects. Why: SUSPEND-PURGE-1. Guard:
  `secret_suspend_clear_copies_test.go` (`TestSuspendSecret_ClearSyncedCopies`).
