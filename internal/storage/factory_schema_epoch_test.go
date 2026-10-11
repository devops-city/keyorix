// factory_schema_epoch_test.go — coverage for ADR-097's schema-epoch startup
// guard (checkSchemaEpoch/recordSchemaEpoch), which refuses to let an older
// binary run migrateDatabase against a database a newer binary already
// migrated.
package storage

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemaEpoch_FreshInstall_RecordsCurrentEpoch: a brand-new, empty
// database has nothing to compare against -- migrateDatabase must succeed
// and, having finished, record currentSchemaEpoch for the next run.
func TestSchemaEpoch_FreshInstall_RecordsCurrentEpoch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-fresh.db"))
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
	assert.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value)
}

// TestSchemaEpoch_OlderRecordedEpoch_UpgradesSucceed: the normal upgrade
// case -- the database was last migrated by an OLDER binary (lower epoch).
// migrateDatabase must succeed and advance the recorded epoch.
func TestSchemaEpoch_OlderRecordedEpoch_UpgradeSucceeds(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-older.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: "0"}).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
	assert.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value, "epoch must advance to the current binary's epoch")
}

// TestSchemaEpoch_SameRecordedEpoch_Succeeds: re-running the same binary
// version (epoch already matches) must succeed -- this is the common case
// on every ordinary restart.
func TestSchemaEpoch_SameRecordedEpoch_Succeeds(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-same.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: strconv.Itoa(currentSchemaEpoch)}).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
}

// TestSchemaEpoch_NoRecordedEpoch_PredatesGuard_Succeeds: system_metadata
// exists (this is an established database) but the schema_epoch key was
// never written -- an older binary that predates this guard entirely wrote
// here last. Absence of a recorded epoch cannot itself justify refusing to
// start.
func TestSchemaEpoch_NoRecordedEpoch_PredatesGuard_Succeeds(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-none.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	// system_metadata table exists (via AutoMigrate above) but no schema_epoch row.

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
	assert.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value, "the epoch must be recorded going forward even though none was found")
}

// TestSchemaEpoch_NewerRecordedEpoch_RefusesToStart is the core regression
// this ADR closes: a database already migrated by a NEWER binary (higher
// epoch) must cause migrateDatabase to refuse, not silently proceed.
func TestSchemaEpoch_NewerRecordedEpoch_RefusesToStart(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-newer.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: strconv.Itoa(currentSchemaEpoch + 1)}).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "an older binary must refuse to run against a database migrated by a newer one")
	assert.Contains(t, err.Error(), "newer than this binary's schema epoch")

	// The refusal must be BEFORE any other migration step -- confirm the
	// unrelated additive migration (users.account_state) never ran, i.e. this
	// genuinely short-circuited rather than merely erroring out partway.
	assert.False(t, columnExists(db, "users", "account_state"),
		"checkSchemaEpoch must refuse before any other migration step runs")
}

// TestSchemaEpoch_CorruptRecordedEpoch_FailsClosed: a schema_epoch value that
// doesn't parse as an integer must refuse to start (fail closed), not be
// silently treated as absent or as zero.
func TestSchemaEpoch_CorruptRecordedEpoch_FailsClosed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-corrupt.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: "not-a-number"}).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "a corrupt schema_epoch value must fail closed, not be silently ignored")
	assert.Contains(t, err.Error(), "not a valid integer")
}

// TestCheckSchemaEpoch_ReadQueryError_FailsClosed exercises checkSchemaEpoch's
// third error branch: system_metadata exists (tableExists is true) but the
// query against it fails for a reason OTHER than "no row" -- here, the table
// is missing the very "key" column the WHERE clause references, so the read
// itself errors instead of returning gorm.ErrRecordNotFound. This is
// deliberately NOT the same branch as
// TestSchemaEpoch_CorruptRecordedEpoch_FailsClosed (a value that reads fine
// but fails to parse) -- that test never reaches this one, since a
// successful read short-circuits past it.
func TestCheckSchemaEpoch_ReadQueryError_FailsClosed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-read-error.db"))
	require.NoError(t, err)
	// system_metadata exists (so tableExists is true) but has no "key" column.
	require.NoError(t, db.Exec(`CREATE TABLE system_metadata (id INTEGER PRIMARY KEY, value TEXT)`).Error)

	err = checkSchemaEpoch(db)
	require.Error(t, err, "a genuine query error reading schema_epoch must fail closed, not be treated as absent")
	assert.Contains(t, err.Error(), "failed to read schema epoch")
}

// TestRecordSchemaEpoch_MissingTable_ReturnsError exercises recordSchemaEpoch
// directly (rather than through migrateDatabase, which always AutoMigrates
// system_metadata first and so never reaches this branch): the upsert Create
// call against a database where system_metadata was never created must
// return a wrapped error, not panic or silently no-op.
func TestRecordSchemaEpoch_MissingTable_ReturnsError(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-record-missing-table.db"))
	require.NoError(t, err)

	err = recordSchemaEpoch(db)
	require.Error(t, err, "recordSchemaEpoch against a database with no system_metadata table must return an error")
	assert.Contains(t, err.Error(), "failed to record schema epoch")
}

// TestSchemaEpoch_FailedMigration_DoesNotAdvanceEpoch: if a later migration
// step fails, the epoch must NOT be recorded -- recordSchemaEpoch only runs
// after every other step succeeds, so a crash mid-migration can't advance
// the recorded epoch past what was actually, successfully applied.
func TestSchemaEpoch_FailedMigration_DoesNotAdvanceEpoch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-failed-migration.db"))
	require.NoError(t, err)
	// An incompatible users table (missing columns ensureUserNameIndex needs)
	// reproduces the same failure TestMigrateDatabase_S28_UsersTableIncompatibleSchema
	// exercises, but this test asserts the epoch-specific consequence: no
	// schema_epoch row must exist afterward.
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, display_name TEXT)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err)

	if !tableExists(db, "system_metadata") {
		return // never got far enough to create the table at all -- also correct
	}
	var count int64
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where("key = ?", schemaEpochMetadataKey).Count(&count).Error)
	assert.Zero(t, count, "a failed migration must not record a schema epoch")
}
