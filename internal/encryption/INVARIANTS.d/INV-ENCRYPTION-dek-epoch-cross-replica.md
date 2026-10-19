- **INV-ENCRYPTION-dek-epoch-cross-replica** On PostgreSQL no server commits a row under a DEK
  that is not the database's current DEK. The database records its DEK as the DEK epoch
  (`system_metadata["dek.epoch"]`, a fingerprint, `dek_epoch.go`); a server refuses to start
  unless the epoch is its own DEK's fingerprint (seeding an absent epoch only after its DEK
  decrypts the newest encrypted secret version); `Encrypt*` refuse unless an epoch read that
  started at most `dekEpochMaxStaleness` ago matched; `RotateDEKWithSweep` fences the epoch
  (`rotating:<old>`), waits `dekEpochFenceWait` (> `dekEpochMaxStaleness`), holds every swept
  table in SHARE ROW EXCLUSIVE mode for the sweep, and compare-and-sets the epoch to the new DEK in the
  sweep's own transaction, lifting the fence on failure. Decrypt is never fenced. SQLite is
  untouched. Why: #3337 (a replica on another host with the old `dek.key` kept writing under
  the retired DEK). Guard: `dek_epoch_postgres_test.go` (pg-gated:
  `TestDEKEpoch_Postgres_RunningReplicaFencedByRotationElsewhere`, `_FailedRotationLiftsFence`,
  `_StartupLiftsStaleFence`, `_SeedRefusedForStaleDEK`, `_RotateRefusedFromStaleHost`,
  `_FenceLiftedDuringRotation_RollsBack`, `_SweepWaitsForInFlightWriter`), `dek_epoch_test.go`
  (`TestDEKEpoch_SQLiteUnchanged`, `TestDEKEpochWatch_AllowWrite`,
  `TestSweptModels_MatchSweptFields`), end to end
  `server/dek_epoch_cross_replica_postgres_test.go` (pg-gated). **Not covered**: a write
  encrypted before its replica saw the fence whose INSERT starts more than
  `dekEpochFenceWait - dekEpochMaxStaleness` later while the presence guard is also bypassed;
  server binaries predating the epoch.
