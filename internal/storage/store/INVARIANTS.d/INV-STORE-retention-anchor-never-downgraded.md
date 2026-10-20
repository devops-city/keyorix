- **INV-STORE-retention-anchor-never-downgraded** On PostgreSQL, once
  `system_metadata.audit_retention_anchor` holds a v2 value (with the cumulative purged
  count), no update can replace it with another layout: the BEFORE UPDATE trigger
  `trg_system_metadata_retention_anchor_v2` (`EnsureAuditRetentionAnchorTrigger`, ENABLE
  ALWAYS) raises, so a pre-#3258 binary's purge, which deletes and writes a v1 anchor in one
  transaction, rolls back whole and the count is never lost. Why: #3359. Guard:
  `internal/storage/factory_rolling_upgrade_triggers_postgres_test.go:TestAuditRetentionAnchor_OlderLayoutCannotReplaceV2_Postgres`
  (pg-gated), end to end against v0.96.1 `scripts/e2e/mixed_version_test.go:TestMixedVersion_RollingUpgrade_Postgres`
  (e2e tag). ENABLE ALWAYS is re-asserted by every migration, so a trigger left ordinary by
  `pg_restore --disable-triggers`, replica-only or disabled is repaired at the next boot
  (`internal/storage/store/pg_trigger_enable_always_postgres_test.go:TestPGTriggerInstallers_ConvergeToEnableAlways_Postgres`,
  pg-gated; every production PostgreSQL trigger installer must be in its registry,
  `pg_trigger_registry_guard_test.go:TestPGTriggerInstallersAreRegistered`).
