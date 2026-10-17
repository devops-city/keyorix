- **INV-STORE-cache-epoch-trigger-fires-for-every-writer** On PostgreSQL the secret-node read
  cache trusts a `cache_epoch` stamp only when the `secret_nodes` cache-epoch trigger is ENABLE
  ALWAYS (`tgenabled = 'A'`) and the reading connection's `session_replication_role` is `'origin'`
  (`pgCacheEpochTriggerFires`, used by `SecretNodeCacheEpochTriggerPresent` and every statement
  built on `nodeTriggerExistsExpr`). The migration (`EnsureSecretNodeCacheEpoch`) installs the
  trigger ENABLE ALWAYS and converges an ordinary one back to it. The server refuses to start
  unless its sessions are in `'origin'` (`internal/storage` `refuseNonOriginReplicationRole`, also
  on the `OpenGormDB` admin path), and the Helm chart refuses `postgresql.settings.session_replication_role`.
  Why: #3361 (REVIEW-1). In `replica` mode an ordinary trigger never fires and the old proof
  (`tgenabled <> 'D'`) still read "present", so a write from such a session left the stamp
  unchanged and a suspended secret read as active; 'R' (ENABLE REPLICA) passed the old proof while
  never firing for ordinary writes. Guard: (pg-gated)
  `secret_node_cache_epoch_replication_role_postgres_test.go`
  (`TestSecretNodeCacheEpoch_ReplicaRoleWriter_StillMovesStamp_Postgres`,
  `..._ProofFailsClosedInReplicaSession_Postgres`, `..._ReplicaOnlyTriggerIsNotTrusted_Postgres`,
  `..._MigrationConvergesToEnableAlways_Postgres`; all red on the base) and `internal/storage`
  `TestCreateStorage_Postgres_RefusesNonOriginReplicationRole` (per-database, per-role-in-database
  and DSN settings); chart: `deploy` `TestHelmPostgresSettings`. Not covered: the
  role-permission generation proof (`rolePermGenerationTriggersPresentExpr`, triggers already
  ENABLE ALWAYS) still accepts `tgenabled = 'R'` and does not read the session's mode.
