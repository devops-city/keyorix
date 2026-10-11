// factory_schema_epoch_upgrade_path_test.go — Gap 2 (ADR-097 conformance):
// migrateDatabase's freshInstallComplete early return (taken on EVERY boot of
// an already-initialized database — which, after the very first boot, is
// every boot there is) used to skip recordSchemaEpoch entirely, since
// recordSchemaEpoch previously lived ONLY at the end of the transactional
// fresh-install tail below that return. An established database's
// schema_epoch row was therefore written once, at first install, and never
// again: a future binary upgrade that bumps currentSchemaEpoch would never
// record the new value against an already-fully-migrated database, freezing
// the stored epoch and silently defeating checkSchemaEpoch's whole
// comparison (a dbEpoch that never advances can never be read as "too new"
// either). Not a corruption risk by itself — checkSchemaEpoch always runs
// first and would still refuse a genuine downgrade using whatever stale value
// is there — but a real ADR-097 conformance gap on the ordinary-restart path.
package storage

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestSchemaEpoch_EstablishedDatabase_EpochRecordsOnEveryBoot is the red
// proof: a database that is ALREADY fully migrated (freshInstallComplete
// would be true) has its schema_epoch row deleted — simulating either a
// pre-ADR-097 database, or (more to the point for this gap) a frozen/stale
// value a future epoch bump never updated — then migrateDatabase runs again.
// Before the fix, the freshInstallComplete early return skips
// recordSchemaEpoch and the row stays absent forever; after the fix, this
// boot (and every subsequent one) records the current epoch.
func TestSchemaEpoch_EstablishedDatabase_EpochRecordsOnEveryBoot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "epoch-established.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	// First boot: a genuinely fresh install, takes the transactional tail,
	// which already records the epoch today — establish that baseline, then
	// remove it to isolate the early-return path's own behavior on the NEXT
	// boot, independent of the first boot's own (already-working) recording.
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, db.Exec("DELETE FROM system_metadata WHERE key = ?", schemaEpochMetadataKey).Error)

	var count int64
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where("key = ?", schemaEpochMetadataKey).Count(&count).Error)
	require.Zero(t, count, "setup: the epoch row must be genuinely absent before the boot under test")

	// Second boot: the database is already fully migrated (freshInstallComplete
	// is true), so this exercises the early-return path, not the transactional
	// fresh-install tail.
	require.NoError(t, f.migrateDatabase(db))

	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error,
		"BUG: the freshInstallComplete early-return path must record the schema epoch "+
			"too, not only the fresh-install transactional tail — otherwise an established "+
			"database's epoch is written once at first install and never updated again")
	require.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value)
}

// TestSchemaEpoch_EstablishedDatabase_StaleEpochCorrectsOnNextBoot is the
// same gap from the other direction: the row EXISTS but holds a stale value
// (as it would after a future currentSchemaEpoch bump against an
// already-fully-migrated database, before this fix) rather than being
// absent. migrateDatabase must correct it forward on the next boot.
func TestSchemaEpoch_EstablishedDatabase_StaleEpochCorrectsOnNextBoot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "epoch-stale.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, db.Model(&models.SystemMetadata{}).
		Where("key = ?", schemaEpochMetadataKey).Update("value", "0").Error)

	require.NoError(t, f.migrateDatabase(db))

	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
	require.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value,
		"BUG: a stale schema_epoch value on an already-fully-migrated database must be "+
			"corrected forward on the next boot via the early-return path, not left frozen")
}
