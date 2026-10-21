- **INV-STORE-suspend-marker-only-while-suspended** On PostgreSQL,
  `secret_nodes.suspend_clear_synced_copies` is false on every secret whose status is not
  `suspended`, whichever binary or session writes the row: the BEFORE UPDATE OF status
  trigger `trg_secret_nodes_suspend_marker` (`EnsureSecretSuspendMarkerTrigger`, installed
  by both migration call sites, ENABLE ALWAYS) clears it on every status change away from
  suspended, and the installer clears rows already left stale. So a plain suspend never
  inherits a clear-copies marker from an earlier suspension, even from a pre-#3215 replica
  in a rolling upgrade that writes only status. Why: #3362. Guard:
  `internal/storage/factory_rolling_upgrade_triggers_postgres_test.go:TestSecretSuspendMarker_ClearedByOldBinaryResume_Postgres`
  (pg-gated), end to end against v0.96.1 `scripts/e2e/mixed_version_test.go:TestMixedVersion_RollingUpgrade_Postgres`
  (e2e tag). ENABLE ALWAYS is re-asserted by every migration, so a trigger left ordinary by
  `pg_restore --disable-triggers`, replica-only or disabled is repaired at the next boot
  (`internal/storage/store/pg_trigger_enable_always_postgres_test.go:TestPGTriggerInstallers_ConvergeToEnableAlways_Postgres`,
  pg-gated; every production PostgreSQL trigger installer must be in its registry,
  `pg_trigger_registry_guard_test.go:TestPGTriggerInstallersAreRegistered`).
