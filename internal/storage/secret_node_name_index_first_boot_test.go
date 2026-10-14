// secret_node_name_index_first_boot_test.go — regression coverage for the
// 2026-09-25 first-boot migration-ordering fix: ensureSecretNodeNameIndex's
// only call site used to be gated on tableExists(db, "secret_nodes"), evaluated
// BEFORE the bulk AutoMigrate loop creates that table on a fresh install, so
// the MT-006 partial unique index was never created on a genuinely first boot
// — only from the second migrateDatabase run onward. Fixed by adding an
// unconditional call in migrateDatabase's tail block, matching every sibling
// ensure*Index call there. See factory.go's own comment at the fix site
// (#STORAGE-FACTORY-MT006-FIRSTBOOT) for the full trace.
package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// firstBootSQLiteDSN returns a fresh, disposable in-memory shared-cache SQLite DSN.
func firstBootSQLiteDSN(t *testing.T) string {
	t.Helper()
	return sqlitetest.DSN("firstboot_")
}

// firstBootPostgresDSN creates a fresh, disposable Postgres database (dropped on
// cleanup) and returns its DSN. Skips the calling test if KEYORIX_TEST_PG_DSN is unset.
func firstBootPostgresDSN(t *testing.T) string {
	t.Helper()
	base := pgTestDSN(t)
	return pgIsolatedDatabaseDSN(t, base)
}

// TestMigrateDatabase_SecretNodeUniqueIndex_ExistsAfterSingleFreshBoot proves the fix:
// exactly ONE CreateStorage call against a brand-new, empty target must produce the full
// production schema, including uniq_secret_nodes_project_env_name_active — on both
// backends. Before the fix this was red on both (HasIndex false after the one boot).
func TestMigrateDatabase_SecretNodeUniqueIndex_ExistsAfterSingleFreshBoot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	t.Run("sqlite", func(t *testing.T) {
		dsn := firstBootSQLiteDSN(t)
		cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dsn}}}
		_, err := NewStorageFactory().CreateStorage(cfg)
		require.NoError(t, err)

		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		assert.True(t, db.Migrator().HasIndex("secret_nodes", "uniq_secret_nodes_project_env_name_active"),
			"a single CreateStorage call on a fresh SQLite DB must create the MT-006 unique index, not defer it to a second run")
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := firstBootPostgresDSN(t)
		cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}
		_, err := NewStorageFactory().CreateStorage(cfg)
		require.NoError(t, err)

		db := pgRawOpen(t, dsn)
		assert.True(t, db.Migrator().HasIndex("secret_nodes", "uniq_secret_nodes_project_env_name_active"),
			"a single CreateStorage call on a fresh Postgres DB must create the MT-006 unique index, not defer it to a second run")
	})
}

// TestMigrateDatabase_ConcurrentCreateSecret_SameNameOnFirstBoot_ExactlyOneSurvives proves
// the index isn't just present but actually enforcing: on a DB that has been through
// exactly one CreateStorage call (first boot), N concurrent LocalStorage.CreateSecret
// calls for the IDENTICAL (project, environment, name) key must leave exactly one row —
// LocalStorage.CreateSecret itself is a raw, unchecked Create with no app-level dedup (by
// design — the DB constraint is the only backstop, see MT-006). Before the fix, a
// first-boot DB had no index at all and every concurrent insert would have survived.
func TestMigrateDatabase_ConcurrentCreateSecret_SameNameOnFirstBoot_ExactlyOneSurvives(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	const concurrency = 8

	t.Run("sqlite", func(t *testing.T) {
		dsn := firstBootSQLiteDSN(t)
		cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dsn}}}
		_, err := NewStorageFactory().CreateStorage(cfg)
		require.NoError(t, err)

		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		runConcurrentCreateSecretRace(t, db, concurrency)
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := firstBootPostgresDSN(t)
		cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}
		_, err := NewStorageFactory().CreateStorage(cfg)
		require.NoError(t, err)

		db := pgRawOpen(t, dsn)
		runConcurrentCreateSecretRace(t, db, concurrency)
	})
}

func runConcurrentCreateSecretRace(t *testing.T, db *gorm.DB, concurrency int) {
	t.Helper()
	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	const projectID, envID, name = 1, 1, "DATABASE_URL"

	var wg sync.WaitGroup
	successes := make([]bool, concurrency)
	for i := range concurrency {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := ls.CreateSecret(ctx, &models.SecretNode{Name: name, ProjectID: projectID, EnvironmentID: envID})
			successes[idx] = err == nil
		}(i)
	}
	wg.Wait()

	won := 0
	for _, ok := range successes {
		if ok {
			won++
		}
	}
	assert.Equal(t, 1, won, "exactly one concurrent CreateSecret for the identical (project, environment, name) key must succeed")

	var count int64
	require.NoError(t, db.Model(&models.SecretNode{}).
		Where("project_id = ? AND environment_id = ? AND name = ? AND deleted_at IS NULL", projectID, envID, name).
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "exactly one row must exist for the contended key after the race")
}

// TestEnsureSecretNodeNameIndex_PreExistingDuplicates_FailsLoudWithoutDeletingRows covers
// the existing warnIfDuplicatesExist protection this fix now also relies on for
// installs that already went through the first-boot gap window with real duplicate
// data written during it: creating the index over pre-existing duplicate rows must fail
// with an actionable error naming the table/key, and must NOT delete or modify either
// row. This mechanism already existed (warnIfDuplicatesExist, factory.go) — this test
// pins it specifically for the call path this fix adds.
func TestEnsureSecretNodeNameIndex_PreExistingDuplicates_FailsLoudWithoutDeletingRows(t *testing.T) {
	db := sqlitetest.OpenWithDialector(t, "firstboot_", sqlite.Open, &gorm.Config{Logger: logger.Discard})
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))

	// Two colliding rows, inserted directly (bypassing any app-level check) — the exact
	// shape a pre-fix first-boot gap window could have produced via two racing
	// LocalStorage.CreateSecret calls with no index yet to stop them.
	require.NoError(t, db.Create(&models.SecretNode{Name: "DUPLICATE", ProjectID: 1, EnvironmentID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{Name: "DUPLICATE", ProjectID: 1, EnvironmentID: 1}).Error)

	err := ensureSecretNodeNameIndex(db)
	require.Error(t, err, "creating the unique index over pre-existing duplicates must fail, not silently pick a winner")
	assert.Contains(t, err.Error(), "pre-existing group(s)", "the error must name the actual problem so an operator can act on it")

	var count int64
	require.NoError(t, db.Model(&models.SecretNode{}).
		Where("project_id = ? AND environment_id = ? AND name = ?", 1, 1, "DUPLICATE").
		Count(&count).Error)
	assert.Equal(t, int64(2), count, "the failed index creation must never delete or modify either colliding row")
}
