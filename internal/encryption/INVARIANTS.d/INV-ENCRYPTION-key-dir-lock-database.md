- **INV-ENCRYPTION-key-dir-lock-database** With `storage.encryption.key_dir_lock: database`
  (PostgreSQL only) every key-directory flock a server relies on has a PostgreSQL counterpart,
  so several replicas can share one key directory (or read-only copies of it) without working
  flock: the server takes no `dek.lock`; rotation crash recovery and first-boot key generation
  run under the key-initialisation advisory lock (a second replica waits, then loads the keys the
  first wrote, instead of generating its own); first-boot generation is refused when the
  database already holds secret versions or a DEK epoch, and the first replica seeds the DEK
  epoch before it releases that lock; key-changing admin commands are kept out by the shared
  server-presence lock every replica holds, and `--force` cannot drop it (nor pass when the
  database's record of the mode cannot be read); the live Postgres
  `admin backup` holds that shared lock for its whole run. INV-ENCRYPTION-01 and
  INV-ENCRYPTION-02 hold through these locks instead of the flock in this mode. The default
  (`flock`) is unchanged. Why: Helm `server.replicas > 1` on a ReadWriteMany volume, where the
  lifetime exclusive flock made a second replica refuse to start (HA-READY-1). Guard:
  `server/key_dir_lock_postgres_test.go` (`TestKeyDirLock_Database_TwoReplicasShareOneFreshKeyDir`,
  `TestKeyDirLock_Database_RefusesNewDEKOverEncryptedData`, `TestKeyDirLock_Database_ReadOnlyKeyDir`,
  `TestKeyDirLock_Database_ConcurrentStartOwnEmptyDirsSeedsEpochUnderLock`),
  `internal/serverguard/keyinit_postgres_test.go:TestPostgres_WithKeyInitLock_SerialisesHolders`,
  `server/admin/admin_test.go:TestAcquireDatabaseLock_ForceRefusedWithDatabaseKeyDirLock`,
  `server/admin/admin_test.go:TestAcquireDatabaseLock_ForceRefusedWhenKeyDirLockRecordUnreadable`,
  `server/admin/key_dir_lock_force_postgres_test.go:TestAcquireDatabaseLock_ForceRefusedWhenKeyDirLockRecordQueryFails`,
  `server/admin/backup_key_dir_lock_postgres_test.go:TestAdminBackup_Postgres_DatabaseKeyDirLock_ExcludesKeyRotation`
  (pg-gated except the two `admin_test.go` `--force` tests).
<!-- section: First-boot / cross-process coordination -->
