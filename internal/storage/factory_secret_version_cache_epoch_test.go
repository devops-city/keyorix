// factory_secret_version_cache_epoch_test.go — the MIGRATION half of
// secret_versions.cache_epoch (store.EnsureSecretVersionCacheEpoch,
// DEK-SWEEP-CACHE-1): the real migration path creates the column on a fresh
// install and on an UPGRADE of a database that already holds versions, on both
// backends, and the DEK sweep's own UPDATE raises it.
//
// No schema-epoch bump, for the reason TestSecretNodeCacheEpoch_NeedsNoSchemaEpochBump
// records for its sibling: the column is additive with DEFAULT 0 and an older
// binary neither reads nor needs to maintain it. The one older-binary hazard is
// an OLD `admin encryption rotate` run against a fleet of NEW servers: it
// rewrites ciphertext without raising the column, which is today's behaviour
// (the new servers' warm entries live at most secretMetaCacheTTL). Run the sweep
// from the same release as the servers.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

func versionCacheEpochOf(t *testing.T, db *gorm.DB, id uint) int64 {
	t.Helper()
	var row struct{ CacheEpoch int64 }
	require.NoError(t, db.Model(&models.SecretVersion{}).Select("cache_epoch").Where("id = ?", id).Take(&row).Error)
	return row.CacheEpoch
}

func assertVersionCacheEpochConverged(t *testing.T, db *gorm.DB, label string) {
	t.Helper()
	require.True(t, db.Migrator().HasColumn("secret_versions", store.SecretVersionCacheEpochColumn),
		"%s: secret_versions.cache_epoch missing — the latest-version cache could not see a DEK sweep", label)
}

func runSecretVersionCacheEpochMigration(t *testing.T, db *gorm.DB, label string) {
	t.Helper()
	f := &DefaultStorageFactory{}

	require.NoError(t, f.migrateDatabase(db))
	assertVersionCacheEpochConverged(t, db, label+" fresh")

	// Stand in for a pre-upgrade database: real rows, column absent.
	var seeded []uint
	for i := range 3 {
		v := models.SecretVersion{SecretNodeID: uint(100 + i), VersionNumber: 1, EncryptedValue: []byte("ct")}
		require.NoError(t, db.Create(&v).Error)
		seeded = append(seeded, v.ID)
	}
	require.NoError(t, db.Exec("ALTER TABLE secret_versions DROP COLUMN cache_epoch").Error)
	require.False(t, db.Migrator().HasColumn("secret_versions", store.SecretVersionCacheEpochColumn),
		"the column must actually be gone, or the upgrade half of this test proves nothing")

	require.NoError(t, f.migrateDatabase(db)) // what a process boot does against an existing database
	assertVersionCacheEpochConverged(t, db, label+" upgrade")
	for _, id := range seeded {
		require.Equal(t, int64(0), versionCacheEpochOf(t, db, id),
			"a pre-existing version must read as epoch 0 after the upgrade, not NULL or an error")
	}

	require.NoError(t, f.migrateDatabase(db)) // idempotent
	assertVersionCacheEpochConverged(t, db, label+" third boot")

	// GORM cannot write it (`<-:false`): a struct Save must leave it alone.
	require.NoError(t, db.Exec("UPDATE secret_versions SET cache_epoch = cache_epoch + 5 WHERE id = ?", seeded[0]).Error)
	var v models.SecretVersion
	require.NoError(t, db.First(&v, seeded[0]).Error)
	v.CacheEpoch = 0
	require.NoError(t, db.Save(&v).Error)
	require.Equal(t, int64(5), versionCacheEpochOf(t, db, seeded[0]), "a struct Save must not be able to reset cache_epoch")
}

func TestSecretVersionCacheEpoch_FreshInstallAndUpgrade_SQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "version-cache-epoch.db"))
	require.NoError(t, err)
	runSecretVersionCacheEpochMigration(t, db, "sqlite")
}

func TestSecretVersionCacheEpoch_FreshInstallAndUpgrade_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres migration form is unverified in this run")
	}
	schema := fmt.Sprintf("version_cache_epoch_%d", os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), gormConfig())
	require.NoError(t, err)
	runSecretVersionCacheEpochMigration(t, db, "postgres")
}
