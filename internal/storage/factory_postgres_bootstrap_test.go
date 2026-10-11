// factory_postgres_bootstrap_test.go — the real-Postgres counterpart to
// TestCreateStorage_Postgres_FailsFast/TestOpenGormDB_Postgres_ConnectFailure
// (storage_s2_test.go). Those only ever drive the connection-refused branch
// of createPostgresStorage/OpenGormDB: gorm.Open never succeeds, so neither
// function ever reaches applyPoolSettings, withMigrationLock, or the final
// success return -- leaving createPostgresStorage at 45.5% coverage (per this
// campaign's survey) despite the function being almost entirely the success
// path plus one error-propagation branch. Uses the same isolated-database
// helpers (pgTestDSN/pgIsolatedDatabaseDSN/pgRawOpen) as
// postgres_pk_rebuild_helpers_test.go, gated on KEYORIX_TEST_PG_DSN so
// go test ./... still passes cleanly with no Postgres available.
package storage

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCreateStorage_Postgres_Success drives createPostgresStorage's entire
// success path against a real, fresh Postgres database: DSN resolves
// non-empty, gorm.Open connects, applyPoolSettings applies pool limits,
// withMigrationLock acquires the advisory lock and runs migrateDatabase, and
// the factory returns a usable store.LocalStorage. This is the first test in
// the repo to reach createPostgresStorage's final `return
// store.NewLocalStorage(db), nil` and withMigrationLock's isPostgres success
// branch (both previously 0%-covered: every other Postgres test either fails
// fast on connect or drives migrateDatabase directly, bypassing the factory
// entirely).
func TestCreateStorage_Postgres_Success(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	cfg.Storage.Database.MaxOpenConns = 5
	cfg.Storage.Database.MaxIdleConns = 2
	cfg.Storage.Database.ConnMaxLifetimeMinutes = 10

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	require.NotNil(t, st)

	// A real migration ran: verify via a table only AutoMigrate/migrateDatabase
	// would have created, and that the schema epoch was recorded (ADR-097).
	db := pgRawOpen(t, dsn)
	assert.True(t, tableExists(db, "users"), "migrateDatabase must have created the users table")
	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
	assert.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value)
}

// TestCreateStorage_Postgres_MigrationFailure_Propagates seeds a
// system_metadata row with a corrupt (unparseable) schema_epoch BEFORE
// calling CreateStorage -- checkSchemaEpoch fails closed (ADR-097), so
// migrateDatabase returns an error, which createPostgresStorage must wrap and
// propagate rather than returning a live (but never-migrated) storage
// instance. This exercises createPostgresStorage's own
// `withMigrationLock(...); err != nil` branch (previously 0%-covered), not
// just checkSchemaEpoch's parse-error branch (already covered against
// SQLite).
func TestCreateStorage_Postgres_MigrationFailure_Propagates(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)

	seed := pgRawOpen(t, dsn)
	require.NoError(t, seed.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, seed.Create(&models.SystemMetadata{
		Key: schemaEpochMetadataKey, Value: "not-a-number",
	}).Error)

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err)
	assert.Nil(t, st)
	assert.Contains(t, err.Error(), "failed to migrate database")
	assert.Contains(t, err.Error(), "not a valid integer")
}

// TestOpenGormDB_Postgres_Success drives OpenGormDB's postgres branch to its
// success return (previously 0%-covered for the same reason as
// createPostgresStorage above: TestOpenGormDB_Postgres_ConnectFailure only
// ever exercises the connection-refused branch). Unlike CreateStorage,
// OpenGormDB deliberately does not migrate -- confirm no tables get created.
func TestOpenGormDB_Postgres_Success(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn

	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	require.NotNil(t, db)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Ping())
	assert.False(t, tableExists(db, "users"), "OpenGormDB must not migrate -- it exists for raw admin access to an already-initialized database")
}
