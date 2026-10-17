- **INV-STORE-role-permission-generation-trigger-maintained** The role->permission cache
  generation (`system_metadata.role_permissions_generation`) moves on EVERY committed write to
  `role_permissions` or `permissions`, by any writer (direct SQL included): database triggers
  bump it inside the writer's transaction (PostgreSQL: statement-level, INSERT/UPDATE/DELETE/
  TRUNCATE, `ENABLE ALWAYS`; SQLite: per row, INSERT/UPDATE/DELETE), installed by
  `EnsureRolePermissionsGenerationTriggers` on fresh install and upgrade without a trigger-less
  window. Every statement that reads the generation proves in the same statement that the
  triggers exist and fire for every writer (`rolePermGenerationExpr`; on PostgreSQL
  `tgenabled = 'A'` on a connection whose `session_replication_role` is `'origin'`, the same
  `pgTriggerFiresForEveryWriter` condition as the cache-epoch proof); if not, the generation
  reads as NULL and the cache is neither consulted nor filled. A trigger left disabled, ENABLE
  REPLICA or ordinary is converged back to ENABLE ALWAYS by the next migration. `bumpRolePermissionsGenerationTx` stays
  as a second, harmless increment. Why: #3259 (a direct-SQL permission removal kept authorizing
  from every replica's cache until restart). Guard: `TestRolePermissionGeneration_DirectSQLSeenOnNextDecision`,
  `_MissingTriggerBypassesCache`, `_EnsureIsIdempotentAndConverges` (SQLite and Postgres legs);
  `internal/storage` `TestRolePermissionGenerationTriggers_FreshInstallAndUpgrade_{SQLite,Postgres}`,
  `_ConcurrentEnsureOnPostgres`; `server/http` `TestFoldedCredential_CrossReplicaInvalidation`
  (`role-permission-removed-direct-sql`, `permission-renamed-direct-sql`); (pg-gated)
  `TestRolePermissionGeneration_ReplicaOnlyTriggerIsNotTrusted_Postgres`,
  `_OrdinaryTriggerSkippedByReplicaWriter_Postgres`, `_ProofFailsClosedInReplicaSession_Postgres`
  (STORAGE-HARDEN-1: the proof used to accept `tgenabled <> 'D'` and ignore the session's mode,
  so an ENABLE REPLICA trigger or a replica-role writer left a removed permission authorizing
  from a warm cache; all three red on the base).
