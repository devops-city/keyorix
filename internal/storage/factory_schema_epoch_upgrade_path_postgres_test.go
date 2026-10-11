// factory_schema_epoch_upgrade_path_postgres_test.go — the real-Postgres
// counterpart to factory_schema_epoch_upgrade_path_test.go's SQLite proof.
// Gated on KEYORIX_TEST_PG_DSN so `go test ./...` still passes cleanly with
// no Postgres available.
package storage

import (
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestSchemaEpoch_Postgres_EstablishedDatabase_EpochRecordsOnEveryBoot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)
	db := pgRawOpen(t, dsn)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, db.Exec("DELETE FROM system_metadata WHERE key = ?", schemaEpochMetadataKey).Error)

	var count int64
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where("key = ?", schemaEpochMetadataKey).Count(&count).Error)
	require.Zero(t, count, "setup: the epoch row must be genuinely absent before the boot under test")

	require.NoError(t, f.migrateDatabase(db))

	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error,
		"BUG: the freshInstallComplete early-return path must record the schema epoch "+
			"too, not only the fresh-install transactional tail")
	require.Equal(t, strconv.Itoa(currentSchemaEpoch), m.Value)
}
