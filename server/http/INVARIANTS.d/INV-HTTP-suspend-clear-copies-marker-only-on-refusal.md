- **INV-HTTP-suspend-clear-copies-marker-only-on-refusal** The per-suspension "also clear synced
  Kubernetes copies" choice reaches a client only through two paths that both run after the
  caller's permission on the secret is established: the `secrets.write`-gated suspend request that
  sets it, and the `SecretSuspended` refusal of a value read the caller may make, which carries it
  as `details.clear_synced_copies` (absent, not `false`, when it was not chosen). The
  `SecretExpired` refusal carries it too, but only when the secret is also suspended with the
  choice (expiry is judged first, so without this the agents would keep the copies; #3215); an
  expired secret that is not suspended never carries it. Guard:
  `internal/core/secret_suspend_clear_copies_expired_test.go`. A caller who
  cannot read the secret gets the same 403/404 as before and never sees the choice. The flag is
  accepted only on the suspend request (the secret-update allowlist rejects `SuspendClearSyncedCopies`)
  and is audited with the suspension. Why: SUSPEND-PURGE-1 (a state oracle would leak that a
  secret is compromised). Guard: `server/http/secret_suspend_clear_copies_test.go`
  (`TestSuspendSecret_ClearSyncedCopies_OverTheRouter`: stored, audited, permission, outsider
  sees nothing, resume removes it), `secret_value_read_refusal_family_test.go` (outsider answers
  unchanged), `handlers/secret_update_diff_test.go` (`TestDiffSecretUpdate_EveryFieldBehavesAsClassified`).
