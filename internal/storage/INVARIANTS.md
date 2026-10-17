# internal/storage invariants

Read this before changing anything in `internal/storage` (the factory/interface/migration
layer — SQLite vs. Postgres selection, schema epoch, migrations). See
`internal/storage/store/INVARIANTS.md` for the GORM-backed CRUD/locking primitives
underneath, and `internal/storage/models/INVARIANTS.md` notes folded into `store`'s file.

Format: `INV-STORAGE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Schema epoch (ADR-097, ADR-101)

- **INV-STORAGE-01** An older binary refuses to start against a database migrated by a newer
  schema epoch, unless an ADR-101 compatibility floor recorded by that newer migration
  explicitly covers the older binary (INV-STORAGE-04). With no floor recorded, the refusal is
  unconditional. Why: ADR-097, ADR-101. Guard: `TestSchemaEpoch_NewerRecordedEpoch_RefusesToStart`,
  `TestSchemaEpochFloor_RefusesOutsideSupportedRange/db_epoch_above_binary,_no_floor_recorded`.
- **INV-STORAGE-02** `currentSchemaEpoch` (now 3: 2 for `secret_nodes.purge_at`, #3021, floor raised to 2; 3 for the additive `pending_audit_events`, floor stays 2) has not silently bumped without the
  accompanying ADR-101 compatibility-floor work landing — this is a deliberate tripwire, not a
  claim that raising the epoch is wrong. Guard: `schema_epoch_tripwire_test.go:TestCurrentSchemaEpoch_Is3_SeeADR101`.
- **INV-STORAGE-03** A corrupt (non-integer) `schema_epoch` value in `system_metadata` fails
  closed (refuses boot), not proceed silently. Why: ADR-097 "Corrupt value" section. UNGUARDED
  (#issue: no test located beyond the two epoch tests above directly asserting this; likely
  covered incidentally by `checkSchemaEpoch`'s own tests — confirm and cite precisely, or add).
- **INV-STORAGE-04** Rolling back past a recorded `minCompatibleEpoch` floor
  (`system_metadata` key `schema_min_compatible_epoch`, declared by `minCompatibleSchemaEpoch`
  in `factory.go`) must still refuse; an additive-safe migration must NOT raise that floor; a
  recorded epoch or floor is never lowered by an older binary; a corrupt or sub-1 floor fails
  closed. Why: ADR-101 (#2502). Guard: `factory_schema_epoch_floor_test.go`
  (`TestSchemaEpochFloor_RefusesOutsideSupportedRange`, `_StartsInsideSupportedRange`,
  `_AdditiveMigrationDoesNotRaiseFloor`, `_RecordNeverLowersEpochOrFloor`,
  `_FreshInstall_RecordsDeclaredFloor`, `TestMinCompatibleSchemaEpoch_WithinRange`); Postgres
  sibling `factory_schema_epoch_floor_postgres_test.go:TestSchemaEpochFloor_Postgres_RecordAndRefuse`.
  `admin restore` deliberately keeps the strict no-floor rule (`SchemaEpochTooNew`): a backup
  manifest carries no floor. `internal/backupfmt` skips the archived floor row exactly like the
  `schema_epoch` row (guarded by the backup/restore round-trip tests, which fail on a UNIQUE
  violation without the skip).

## AutoMigrate completeness

- **INV-STORAGE-05** Every model struct in `models.go` appears in both
  `models.AllTestModels()` and `storage.AllModels()`/`migrateDatabase`'s AutoMigrate set — no
  model ships with handler code but no table. Why: #2258/#2264 (7, then 6, unmigrated tables
  found late). Guard: `all_models_migration_guard_test.go`
  (`TestAllTestModels_MatchesModelsGoStructSet`, `TestMigrateDatabase_EveryModelGetsATable_Fresh`,
  `_UpgradedInstall`, `_Postgres_Fresh`), `all_models_test.go:TestAllModels_MatchesLiveMigratedTables`.
- **INV-STORAGE-06** The 7 specific previously-unmigrated tables from #2258 exist after
  migration, including on an upgraded (not just fresh) install. Guard:
  `factory_seven_unmigrated_models_test.go` (`TestMigrateDatabase_CreatesAllSevenPreviouslyUnmigratedTables`,
  `_SurviveUpgradeRerun`) — a hand-picked regression pin, superseded in generality by
  INV-STORAGE-05 but kept.
- **INV-STORAGE-07** A full `AutoMigrate` is never run against a table already column-altered
  outside AutoMigrate (poisons the pgx prepared-statement cache, corrupts
  `information_schema` checks). Why: ADR-078, which itself states this is enforced only
  procedurally — by ~15 commented call sites in `factory.go`, not structurally. UNGUARDED by
  design, documented as such; do not add a structural guard without first reading ADR-078's
  own reasoning for why it declined one.

## Composite-key / index migrations

- **INV-STORAGE-08** `Role`'s composite PK is rebuilt to the full 4-column form on SQLite
  upgrade from either legacy 2-column or 3-column shapes, without losing rows mentioned outside
  the PK clause. Guard: `factory_rbac_pk_rebuild_test.go` (`TestRolePKIsComplete_SQLite_*`,
  `TestRebuildRolePKSQLite_*`, `TestRebuildRolePKIfNeeded_SQLite_EndToEnd/_AlreadyComplete`);
  Postgres sibling: `factory_rbac_pk_rebuild_postgres_test.go`.
- **INV-STORAGE-09** Creating a unique index (dynamic-secret-config name, project-membership,
  secret-node name, reminder-notification dedup, email, external-ID, username) fails loud, not
  silently drops rows, if pre-existing duplicate data would violate it. Guard:
  `factory_pre_existing_duplicate_index_test.go`
  (`TestDynamicSecretConfigNameIndex_FailsLoudOnPreExistingDuplicates`, `_FullBootHardFails...`,
  `TestProjectMembershipIndex_FailsLoudOnPreExistingDuplicates`,
  `TestReminderNotificationDedupIndex_FailsLoudOnPreExistingDuplicates/_NoDuplicates_CreatesIndex`);
  `secret_node_name_index_first_boot_test.go:TestEnsureSecretNodeNameIndex_PreExistingDuplicates_FailsLoudWithoutDeletingRows`.
- **INV-STORAGE-10** The secret-node-name unique index exists after a single fresh boot, and a
  concurrent same-name create race on first boot leaves exactly one survivor. Guard:
  `secret_node_name_index_first_boot_test.go`
  (`TestMigrateDatabase_SecretNodeUniqueIndex_ExistsAfterSingleFreshBoot`,
  `TestMigrateDatabase_ConcurrentCreateSecret_SameNameOnFirstBoot_ExactlyOneSurvives`).
- **INV-STORAGE-11** Email and external-ID partial unique indexes exclude soft-deleted rows,
  so a deleted user's email/external ID is reusable. Guard: `factory_identity_index_test.go`
  (`TestEmailPartialUniqueIndex`, `TestExternalIDPartialUniqueIndex`).
- **INV-STORAGE-12** Username partial unique index allows reuse after soft-delete. Guard:
  `factory_username_index_test.go:TestUsernamePartialUniqueIndex_ReuseAfterSoftDelete`.
- **INV-STORAGE-13** The break-glass "one active activation per project+user" partial index is
  created by migration. Guard: `factory_break_glass_index_test.go:TestBreakGlassActiveIndex_CreatedByMigration`.
- **INV-STORAGE-14** Companion/sibling indexes are created on upgrade, not only fresh install.
  Guard: `factory_companion_index_test.go:TestCompanionIndexes_CreatedOnUpgrade`.
- **INV-STORAGE-36** The anomaly hot-path indexes — `idx_anomaly_alerts_dedup` (matching
  `CreateAnomalyAlert`'s dedup predicate), `idx_secret_access_logs_secret_time`,
  `idx_secret_access_logs_access_time` — exist on a fresh install (struct tags) AND converge on
  an upgraded one (`CREATE INDEX IF NOT EXISTS` in `migrateDatabase`), on both dialects. They
  are additive, so no schema-epoch bump. Why: PERF-2 performance study (the dedup count was
  the single most expensive query; per-secret access-log reads full-scanned). Guard:
  `factory_companion_index_test.go:TestCompanionIndexes_CreatedOnUpgrade` (SQLite),
  `factory_anomaly_index_postgres_test.go:TestAnomalyIndexes_Postgres_CreatedOnUpgrade`
  (pg-gated).

## Backfills and fatal-migration discipline

- **INV-STORAGE-15** `AccountState` column values that are blank/NULL/whitespace are backfilled
  to a real enum value, excluding soft-deleted rows, idempotently. Why: #1723 ("don't trade
  loud failure for silent data loss"). Guard: `account_state_backfill_test.go`
  (`TestBackfillBlankAccountState_BackfillsBlankNullAndWhitespace`, `_ExcludesSoftDeletedRows`,
  `_IdempotentOnSecondRunAfterRealBackfill`, `_NoOpWhenNothingBlank`),
  `TestMigrateDatabase_FreshInstallBootsCleanlyWithAccountStateGuards`.
- **INV-STORAGE-16** The set of valid `AccountState` SQL values used by the storage-layer
  guard matches `internal/core`'s own account-state registry — no drift between the two. Guard:
  `account_state_backfill_core_sync_test.go:TestValidAccountStateSQLValues_MatchesCoreRegistry`.
- **INV-STORAGE-17** Every fatal migration step that can fail actually aborts
  `migrateDatabase`/boot on error — no swallowed error lets boot continue. Why: #G54 fail-closed
  discipline. Guard: `account_state_fatal_migration_guard_test.go`
  (`TestMigrateDatabase_AccountStateCallsAbortOnError`,
  `TestAccountStateMigrationScannerDetectsSwallowedErrors` — an AST-based scanner, not just a
  point test).
- **INV-STORAGE-18** A folded/normalized column backfill refuses (never silently merges) when
  two rows would collide after folding; scoped collisions (e.g. per-project) don't cross scope
  boundaries. Why: ADR corpus "normalization boundary design" (#1642). Guard:
  `normalize_backfill_test.go` (`TestBackfillFoldedColumn_RefusesOnCollision`,
  `TestNormalizeColumnInPlace_RefusesOnCollision`, `_ScopedCollision_DifferentProjectsNotAColliding`,
  `_ScopedCollision_SameProjectStillCollides`).

## Crash consistency

- **INV-STORAGE-19** A `migrateDatabase` crash mid-run on a fresh install does not leave the DB
  silently half-migrated on next boot — a retry completes every model's table. Guard:
  `factory_fresh_install_crash_test.go`
  (`TestFreshInstall_InterruptedAutoMigrateLoop_NextBootMustNotSilentlyStayHalfMigrated`,
  `TestFreshInstall_NoCrash_AllModelsPresent`); Postgres sibling:
  `factory_fresh_install_crash_postgres_test.go:TestFreshInstall_InterruptedAutoMigrateLoop_Postgres_NextBootSelfHeals`.
- **INV-STORAGE-20** Postgres migration against a non-public schema produces an identical
  result to the public-schema path. Guard:
  `migrate_postgres_nonpublic_schema_test.go:TestMigrateDatabase_Postgres_NonPublicSchemaMatchesPublic`.

## Path resolution (ADR-095)

- **INV-STORAGE-21** `database.path` resolves to an absolute path anchored at the config
  file's own directory, never process cwd; a `..` traversal in it fails `Load()` outright. Why:
  ADR-095. Guard: `TestLoad_DatabasePathResolvedAbsoluteRegardlessOfCwd`,
  `TestResolveConfigRelativePath_*`, `TestLoad_DatabasePathTraversal_Rejected` — these live in
  `internal/config`, not `internal/storage`, but gate `factory.go`'s `createLocalStorage` input
  directly.
- **INV-STORAGE-22** Opening a missing SQLite path should refuse rather than silently create an
  empty DB. Why: ADR-095 "Task 3". Built as the OPT-IN `database.require_existing_path`
  (#2504): `createLocalStorage` resolves the configured path through `localStorageDBFile` and
  refuses when the file is absent, naming `keyorix system init --database` as the deliberate way
  to create one. In-memory DSNs are exempt by construction (no file to pre-exist); the Postgres
  backend is out of scope. Guard: `factory_local_storage_missing_path_log_test.go`
  (`TestCreateLocalStorage_RequireExistingPath_RefusesMissing` — asserts the EFFECT, that a
  refused boot created neither the file nor its parent directory, not just the returned error —
  plus `_OpensExisting`, `_InMemoryExempt` and `_DSNQuerySuffix_...`, so the refusal cannot be
  satisfied by refusing unconditionally). **The default is still false, i.e. create-if-missing**,
  deliberately: nothing in the supported first-boot paths (`server/entrypoint.sh`,
  `docker-compose.yml`) creates the file before the server starts, so defaulting it on would
  break every containerized first boot. Flipping the default is the deliberate sign-off ADR-095
  Task 3 asks for and is NOT settled here — it needs first boot to run
  `keyorix system init --database` (or equivalent) first.
- **INV-STORAGE-23** Two processes migrating the same SQLite file are serialized by SQLite
  itself: `withMigrationLock` runs the whole migration inside one `BEGIN EXCLUSIVE` transaction
  on a dedicated connection (`withSQLiteInDBMigrationLock`), so it holds however each process
  spells the path (a symlink) and even if the `<db>.migration.lock` sidecar is deleted while
  held; the sidecar flock stays only as the same-path fail-fast. A failed migration rolls back
  completely. Not covered (documented in the test): hard-linked aliases (SQLite's WAL index is
  per path name, so nothing inside SQLite can serialize them) and network filesystems. Why:
  ADR-095 "Task 4.3" (#2505). Guard: `factory_sqlite_migration_lock_indb_test.go`
  (`TestSQLiteMigrationLock_CrossProcess_SerializedBySQLiteItself` — two real OS processes,
  `TestWithSQLiteInDBMigrationLock_HeldElsewhere_FailsCleanlyWithoutMigrating`,
  `TestWithSQLiteInDBMigrationLock_ErrorRollsBackEverything`).

## Connection / transaction hazards — SQLite

- **INV-STORAGE-24** The SQLite DSN sets `_txlock=immediate` (not the driver default
  `deferred`). Guard: `factory_sqlite_txlock_test.go` (`TestSqliteDSN_TxlockImmediate`,
  `TestSqliteDSN_PostgresPathUntouched`).
- **INV-STORAGE-25** `_txlock=immediate` closes the window where a deferred-transaction
  upgrade (read-then-write) fails `SQLITE_BUSY` despite `busy_timeout` being set. Guard:
  `factory_sqlite_deferred_upgrade_busy_test.go`
  (`TestSQLiteDeferredTransaction_UpgradeFailsBusyDespiteBusyTimeout` red control,
  `TestSQLiteImmediateTxlock_ClosesTheDeferredUpgradeBusyWindow` green).
- **INV-STORAGE-26** Required SQLite PRAGMAs (foreign_keys, WAL, etc.) are enabled on every
  fresh connection — GORM connection pooling can open new connections without re-applying
  them — and foreign-key enforcement actually rejects an orphan insert. Guard:
  `factory_sqlite_pragma_test.go` (`TestSQLitePragmas_EnabledOnFreshConnection`,
  `TestSQLiteForeignKeyEnforcement_RejectsOrphanInsert`).

- **INV-STORAGE-37** In-process SQLite write transactions are serialized by a FIFO write gate
  (`openSQLiteGorm`, `sqlite_write_gate.go`) instead of contending inside SQLite's polling busy
  handler, which starves waiters past `busy_timeout` under concurrency (`SQLITE_BUSY`). Every
  production SQLite open goes through the gate; read-only (`mode=ro`) opens are the only,
  allowlisted exceptions. A gate wait is bounded (`sqliteWriteGateMaxWait`, equal to the
  busy_timeout) and fails with `storage.ErrSQLiteWriteContention`, or with the caller's ctx
  error. The error is classified as contention by `internal/storage/store`'s
  `isSQLiteBusyErr` (via `errors.Is`, which is why the sentinel lives in
  `internal/core/storage` — `internal/storage` imports `internal/storage/store`, so the gate's
  own package is unreachable from the classifier), so the audit-chain busy-retry budget covers
  it; `commitAuditBatch` deliberately does NOT bisect on it, because it is batch-global rather
  than item-specific.

  Scope, stated precisely because the earlier wording overclaimed: the gate is
  **per-`*sql.DB` handle**, not per-process — `newSQLiteWriteGate()` is called once per
  `openSQLiteGorm`. A process that opens the same database file through two handles has one
  gate each and they do not serialize against each other; those handles meet SQLite's raw busy
  handler as before. In practice the extra openers are one-shot CLI paths
  (`server/admin/{backup,diagnose,restore}.go`, `internal/encryptionops/*`) that do not run
  concurrently with a serving process, which is why this is a documented limit rather than an
  active bug.

  Also not covered: autocommit writes outside a transaction (none via GORM today: no
  `SkipDefaultTransaction`); and the window between a ctx cancellation releasing the gate
  (`context.AfterFunc(ctx, t.release)`) and `database/sql`'s own rollback completing — a second
  writer can enter during it and meet the raw busy handler. That ordering is deliberate (the
  alternative is wedging the gate on a rollback that never returns) but it is a real gap, and
  it means a future caller that leaks a transaction on a background context would wedge every
  write in the process permanently where it previously degraded to `busy_timeout` retries.

  The gate is held across `BeginTx`'s wait for a free pool connection, bounded only by the
  caller's ctx (an HTTP request ctx often has no deadline). The pool defaults to 8 connections
  (`DefaultSQLiteMaxOpenConns` in `factory.go`, shared with readers), so a writer that cannot get a connection — all 8
  held by readers or by a stuck query — blocks every other writer behind the gate until its ctx
  ends. This is an ACCEPTED tradeoff, not an oversight: bounding the connection wait would
  need a derived ctx, and `database/sql` rolls a transaction back when the ctx passed to
  `BeginTx` is cancelled, so a timeout ctx would end the transaction it just opened. Before
  the gate those writers each waited inside SQLite's busy handler for the same starved
  connections, so the failure mode is unchanged in kind (writes stall until the client
  timeout); it is only now visible as one queue. Recorded for the coordinator to accept or
  reject (#2637 review, Finding 2).

  A gate wait that ends on the caller's ctx deadline (auditWriteTimeout, the gate bound and
  `busy_timeout` are all 10s and the ctx starts first) returns a wrapped `ctx.Err()` rather
  than the sentinel, so `isBatchGlobalContentionErr` also treats `context.DeadlineExceeded` /
  `context.Canceled` as batch-global; matching only the sentinel left the audit path's real
  error bisecting.

  The read-only bypass has no non-test caller today. It is correct as implemented (modernc
  `tx.go` only applies `beginMode` when `!opts.ReadOnly`, so a read-only tx takes a plain
  DEFERRED `BEGIN` and cannot hold the write lock), but SQLite does not ENFORCE read-only at
  the transaction level: a future caller that sets `sql.TxOptions{ReadOnly: true}` and then
  writes would both escape the gate and reopen the deferred-upgrade window INV-STORAGE-25
  closes. The AST guard covers open paths, not `TxOptions`.

  Test-suite scope: the guard allowlists `internal/testhelper` and `internal/testutil`, which
  open SQLite ungated, as does the fuzzworld harness — so production runs gated while most
  handler/core/store tests do not. The gate's own behaviour is covered by its own tests; what
  is NOT covered is the rest of the suite exercising code under the gate.

  Why: #2630 (PERF-2: 2.7–6.4% write failures, p99 at the client
  timeout). Guard: `sqlite_concurrent_write_test.go`
  (`TestSQLite_ConcurrentDistinctSecretWrites_SucceedOrFailFast` green,
  `TestSQLite_ConcurrentDistinctSecretWrites_UngatedControlFails` red control,
  `TestSQLiteWriteGate_FailsFastWithClearError`),
  `sqlite_open_paths_guard_test.go:TestSQLiteOpenPaths_AllGoThroughTheWriteGate` (which proves
  the OPEN path, not the per-process property the earlier wording claimed),
  `store/local_audit_chain_gate_contention_test.go` (the classifier recognises the sentinel,
  and a batch-global contention failure is not bisected).

## Connection / transaction hazards — Postgres

- **INV-STORAGE-27** `CreateStorage`/`OpenGormDB` against Postgres succeed on the happy path,
  and a migration failure during Postgres bootstrap propagates rather than being swallowed.
  Guard: `factory_postgres_bootstrap_test.go` (`TestCreateStorage_Postgres_Success`,
  `TestCreateStorage_Postgres_MigrationFailure_Propagates`, `TestOpenGormDB_Postgres_Success`).
- **INV-STORAGE-28** `pg_advisory_lock`/`pg_try_advisory_lock` is a live-connection primitive
  with zero cwd/filesystem dependency, unaffected by the ADR-095 path-resolution fix. Why:
  ADR-095 Task 2 table. Guard: documented-verified by direct code read in the ADR, not an
  independent test beyond the general Postgres bootstrap tests above.

- **INV-STORAGE-38** The default connection pool is per dialect and measured, not shared:
  `DefaultSQLiteMaxOpenConns` (8) and `DefaultPostgresMaxOpenConns` (25), with idle matching
  the effective open cap; an operator's `max_open_conns` always wins. Harnesses that must mirror
  production's pool reference the exported constants instead of copying a number. A Postgres pool
  larger than the server's usable slots (`max_connections - superuser_reserved_connections`) is
  logged at boot (it fails requests with SQLSTATE 53300). Why: #2631 (PERF-2), measurements in
  `docs/CONFIGURATION.md` "Connection pool". Guard: `pool_defaults_test.go`
  (`TestApplyPoolSettings_DialectDefaults`, `TestPostgresPoolHeadroomWarning`,
  `TestWarnPostgresPoolHeadroom_ReadsTheRealServerLimits` pg-gated); `BenchmarkPoolSize` for
  re-measuring.

## File permissions

- **INV-STORAGE-29** A freshly-created local SQLite database file is always mode 0600,
  regardless of the process's inherited umask. Why: #1647. Guard:
  `factory_local_storage_file_perms_test.go:TestCreateLocalStorage_FreshDatabase_AlwaysSecureModeRegardlessOfUmask`
  (umask 022/000 both exercised).
- **INV-STORAGE-30** A pre-existing SQLite file with lax permissions is tightened on open, not
  left as-is. Guard: `TestCreateLocalStorage_PreExistingLaxPermissions_TightenedOnOpen`.

## Tenancy / RLS (ADR-103) — largest open gap

- **INV-STORAGE-31** Postgres RLS as a second, independent tenancy layer: two DB roles
  (migrator with `BYPASSRLS`+ownership, runtime with neither), `FORCE ROW LEVEL SECURITY` on
  ~30 tables, `SET LOCAL app.current_tenant` per-transaction/per-statement, `WITH CHECK`
  mandatory on every policy, NULL/zero sentinel columns gated to platform-admin only. Why:
  ADR-103 (Accepted — **design only**). UNGUARDED (#issue: confirmed by direct grep — zero
  `ROW LEVEL SECURITY`/`app.current_tenant`/`keyorix_migrator` references anywhere in
  `internal/storage`. This is a ratified design with no implementation and no tests yet; the
  single largest gap found for this package).
- **INV-STORAGE-32** Every exported `LocalStorage`/`storage.Storage` method's first parameter
  is a real, threaded `context.Context` (never `context.Background()`/`context.TODO()`
  substituted) — required for RLS's `SET LOCAL` injection to ever reach the right tenant. Why:
  ADR-103 §1f "Guard". UNGUARDED (#issue: explicitly specified as required-before-ship, not
  built — blocks INV-STORAGE-31).
- **INV-STORAGE-33** SQLite has no RLS and is not protected by this layer at all
  (single-instance/dev only, per ADR-039). Why: ADR-103 §1e. Not a gap — by design.

## CLI / factory boundary (ADR-049, ADR-083)

- **INV-STORAGE-34** CLI commands obtain storage only via the factory (`InitializeStorage`) or
  the sanctioned `storage.OpenGormDB` raw-DB helper — SQLite/Postgres driver imports live only
  inside `internal/storage`. Why: ADR-049. Resolved more strongly than this invariant originally
  asked: since ADR-108's cli-server split, the `cli` module cannot import `internal/storage` (or
  `internal/core`/`internal/config`/`server/`) AT ALL — enforced via `go list -deps`, not source
  grep. Guard: `cli/internal/depguard/depguard_test.go:TestNoServerOrCloudSDKDependencies`. See
  `cli/INVARIANTS.md` INV-CLI-01.
- **INV-STORAGE-35** A process with `server.http.enabled`/`server.grpc.enabled` cannot boot on
  `storage.type: remote`. Why: ADR-083. Guard: `validateRemoteStorageNotServer`, which lives in
  `internal/config`, not `internal/storage` — noted here as an adjacent boundary this package's
  factory depends on, not this package's own test.
