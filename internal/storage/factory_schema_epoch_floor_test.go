// factory_schema_epoch_floor_test.go — INV-STORAGE-04 (#2502): ADR-101's
// minCompatibleEpoch compatibility floor.
//
// checkSchemaEpochFor/recordSchemaEpochAs take the binary's epoch (and floor)
// as parameters so these tests can stand in for binaries older and newer
// than this one. The cases below are written relative to currentSchemaEpoch
// (E) so they stay valid when it is bumped.
package storage

import (
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newEpochFloorTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-floor.db"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemMetadata{}))
	return db
}

// stampEpochRows writes schema_epoch and/or the ADR-101 floor directly, as a
// different binary (or a tamperer) would have left them. An empty string
// leaves that key absent.
func stampEpochRows(t *testing.T, db *gorm.DB, epoch, floor string) {
	t.Helper()
	if epoch != "" {
		require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: epoch}).Error)
	}
	if floor != "" {
		require.NoError(t, db.Create(&models.SystemMetadata{Key: schemaMinCompatibleEpochMetadataKey, Value: floor}).Error)
	}
}

func readEpochRow(t *testing.T, db *gorm.DB, key string) string {
	t.Helper()
	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", key).Take(&m).Error)
	return m.Value
}

// TestMinCompatibleSchemaEpoch_WithinRange: the floor this binary declares
// must name a real epoch no newer than its own -- a floor above
// currentSchemaEpoch would make this binary refuse the database it just
// migrated on its next boot; a floor below 1 is not an epoch at all.
func TestMinCompatibleSchemaEpoch_WithinRange(t *testing.T) {
	if minCompatibleSchemaEpoch < 1 || minCompatibleSchemaEpoch > currentSchemaEpoch {
		t.Fatalf("minCompatibleSchemaEpoch = %d must lie within [1, currentSchemaEpoch=%d] (ADR-101)",
			minCompatibleSchemaEpoch, currentSchemaEpoch)
	}
}

// TestSchemaEpochFloor_RefusesOutsideSupportedRange is the INV-STORAGE-04
// refusal matrix, run through the real migrateDatabase entry point with this
// binary's own epoch (E = currentSchemaEpoch). Each case is a database this binary must not
// touch; each must refuse BEFORE any migration step runs.
func TestSchemaEpochFloor_RefusesOutsideSupportedRange(t *testing.T) {
	e := currentSchemaEpoch
	bin := fmt.Sprintf("this binary's schema epoch %d", e)
	cases := []struct {
		name, epoch, floor string
		wantInMsg          []string
	}{
		{
			// The dangerous rollback ADR-101 keeps refusing: a migration
			// declared its schema unsafe for binaries this old.
			name: "binary below recorded floor", epoch: strconv.Itoa(e + 1), floor: strconv.Itoa(e + 1),
			wantInMsg: []string{fmt.Sprintf("minimum compatible schema epoch of %d (database schema epoch %d)", e+1, e+1), bin, "ADR-101"},
		},
		{
			name: "binary below floor lower than db epoch", epoch: strconv.Itoa(e + 3), floor: strconv.Itoa(e + 1),
			wantInMsg: []string{fmt.Sprintf("minimum compatible schema epoch of %d (database schema epoch %d)", e+1, e+3), bin},
		},
		{
			// Stricter reading (ADR-101 is silent on a newer epoch with no
			// floor): with no compatibility claim recorded, ADR-097's original
			// refusal stands.
			name: "db epoch above binary, no floor recorded", epoch: strconv.Itoa(e + 1), floor: "",
			wantInMsg: []string{fmt.Sprintf("database schema epoch %d is newer than %s", e+1, bin), "No minimum compatible schema epoch is recorded"},
		},
		{
			name: "corrupt floor", epoch: "1", floor: "one",
			wantInMsg: []string{`minimum compatible schema epoch "one" is not a valid integer`},
		},
		{
			name: "floor below 1", epoch: "1", floor: "0",
			wantInMsg: []string{"minimum compatible schema epoch 0 is below 1"},
		},
		{
			// A floor refuses on its own, whatever the epoch row says.
			name: "floor above binary, no epoch row", epoch: "", floor: strconv.Itoa(e + 1),
			wantInMsg: []string{fmt.Sprintf("minimum compatible schema epoch of %d", e+1), bin},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := newEpochFloorTestDB(t)
			stampEpochRows(t, db, c.epoch, c.floor)

			err := (&DefaultStorageFactory{}).migrateDatabase(db)
			require.Error(t, err, "migrateDatabase must refuse to start")
			for _, want := range c.wantInMsg {
				assert.Contains(t, err.Error(), want)
			}
			assert.False(t, tableExists(db, "users"),
				"refusal must happen before any migration step touches the schema")
		})
	}
}

// TestSchemaEpochFloor_StartsInsideSupportedRange: the databases this binary
// may run against -- including ADR-101's reason to exist, a NEWER schema
// whose migration declared a floor this binary still satisfies (an old
// replica mid-rollout, or a one-release rollback over an additive
// migration). Running against it must not stamp the database's epoch or
// floor back down to this binary's own.
func TestSchemaEpochFloor_StartsInsideSupportedRange(t *testing.T) {
	e, floor := strconv.Itoa(currentSchemaEpoch), strconv.Itoa(minCompatibleSchemaEpoch)
	next := strconv.Itoa(currentSchemaEpoch + 1)
	cases := []struct {
		name, epoch, floor   string
		wantEpoch, wantFloor string
	}{
		{name: "same epoch, same floor", epoch: e, floor: floor, wantEpoch: e, wantFloor: floor},
		{name: "same epoch, no floor yet (pre-ADR-101 database)", epoch: e, floor: "", wantEpoch: e, wantFloor: floor},
		{name: "newer epoch, floor covers this binary", epoch: next, floor: e, wantEpoch: next, wantFloor: e},
		{name: "much newer epoch, floor covers this binary", epoch: "9", floor: e, wantEpoch: "9", wantFloor: e},
		{name: "previous epoch (normal upgrade)", epoch: "1", floor: "1", wantEpoch: e, wantFloor: floor},
		{name: "older epoch (normal upgrade)", epoch: "0", floor: "", wantEpoch: e, wantFloor: floor},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := newEpochFloorTestDB(t)
			stampEpochRows(t, db, c.epoch, c.floor)

			require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
			assert.True(t, tableExists(db, "users"), "migration must actually have run")
			assert.Equal(t, c.wantEpoch, readEpochRow(t, db, schemaEpochMetadataKey))
			assert.Equal(t, c.wantFloor, readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))
		})
	}
}

// TestSchemaEpochFloor_FreshInstall_RecordsDeclaredFloor: the floor is
// written on first install, from the declared constant.
func TestSchemaEpochFloor_FreshInstall_RecordsDeclaredFloor(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch-floor-fresh.db"))
	require.NoError(t, err)

	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	assert.Equal(t, strconv.Itoa(currentSchemaEpoch), readEpochRow(t, db, schemaEpochMetadataKey))
	assert.Equal(t, strconv.Itoa(minCompatibleSchemaEpoch), readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))
	// And the very next boot of the same binary starts.
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
}

// TestSchemaEpochFloor_AdditiveMigrationDoesNotRaiseFloor is INV-STORAGE-04's
// second half: a future binary (epoch 2) whose migration is additive-safe
// declares the floor unchanged (1). Recording it must advance the epoch but
// leave the floor at 1, so the epoch-1 binary still starts -- while a
// breaking migration (floor 2) makes the epoch-1 binary refuse and the
// epoch-2 binary start.
func TestSchemaEpochFloor_AdditiveMigrationDoesNotRaiseFloor(t *testing.T) {
	db := newEpochFloorTestDB(t)
	require.NoError(t, recordSchemaEpochAs(db, 1, 1))

	// Additive-safe epoch-2 migration.
	require.NoError(t, recordSchemaEpochAs(db, 2, 1))
	assert.Equal(t, "2", readEpochRow(t, db, schemaEpochMetadataKey))
	assert.Equal(t, "1", readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey),
		"an additive-safe migration must not raise the compatibility floor")
	require.NoError(t, checkSchemaEpochFor(db, 1), "epoch-1 binary must still start after an additive-safe migration")
	require.NoError(t, checkSchemaEpochFor(db, 2))

	// Breaking epoch-3 migration raises the floor to itself.
	require.NoError(t, recordSchemaEpochAs(db, 3, 3))
	assert.Equal(t, "3", readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))
	require.Error(t, checkSchemaEpochFor(db, 1), "epoch-1 binary must refuse once a breaking migration raised the floor")
	require.Error(t, checkSchemaEpochFor(db, 2), "epoch-2 binary must refuse: rolling back past the floor")
	require.NoError(t, checkSchemaEpochFor(db, 3))
	require.NoError(t, checkSchemaEpochFor(db, 4))
}

// TestSchemaEpochFloor_RecordNeverLowersEpochOrFloor: an older binary that
// recordSchemaEpoch runs for (because a floor let it start, or a race with a
// sibling replica) must never stamp a newer database's epoch or floor back
// down -- otherwise the next rollback past the real floor would be let
// through.
func TestSchemaEpochFloor_RecordNeverLowersEpochOrFloor(t *testing.T) {
	db := newEpochFloorTestDB(t)
	require.NoError(t, recordSchemaEpochAs(db, 5, 3))

	require.NoError(t, recordSchemaEpochAs(db, 1, 1))
	assert.Equal(t, "5", readEpochRow(t, db, schemaEpochMetadataKey))
	assert.Equal(t, "3", readEpochRow(t, db, schemaMinCompatibleEpochMetadataKey))
	require.Error(t, checkSchemaEpochFor(db, 2), "the floor of 3 must still refuse an epoch-2 binary")

	require.NoError(t, recordSchemaEpochAs(db, 6, 3))
	assert.Equal(t, "6", readEpochRow(t, db, schemaEpochMetadataKey), "a newer epoch must still advance")
}
