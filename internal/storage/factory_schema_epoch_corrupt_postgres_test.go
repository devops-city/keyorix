// factory_schema_epoch_corrupt_postgres_test.go — the real-Postgres counterpart
// to factory_schema_epoch_corrupt_test.go (INV-STORAGE-03, #2501): a corrupt
// (non-integer) schema_epoch in system_metadata must refuse boot on Postgres
// too, for every value shape a lenient parser could accept, and the refusal
// must leave the database untouched.
//
// TestCreateStorage_Postgres_MigrationFailure_Propagates
// (factory_postgres_bootstrap_test.go) drives one shape ("not-a-number") that
// every plausible parser rejects, so it would stay green if strconv.Atoi were
// swapped for fmt.Sscanf/TrimSpace/ParseFloat. This file reuses the SQLite
// test's corruptSchemaEpochValues table through the real CreateStorage entry
// point, i.e. through withMigrationLock's advisory lock and createPostgresStorage's
// error propagation, which SQLite does not reach.
//
// Gated on KEYORIX_TEST_PG_DSN (pgTestDSN skips without it), so `go test ./...`
// still passes with no Postgres available. NOT covered: a value that parses as
// an integer but is semantically wrong (an older epoch legitimately proceeds).
package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSchemaEpoch_CorruptValue_Postgres_CreateStorageRefusesBoot(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	for _, tc := range corruptSchemaEpochValues {
		t.Run(tc.name, func(t *testing.T) {
			dsn := pgIsolatedDatabaseDSN(t, base)

			seed := pgRawOpen(t, dsn)
			require.NoError(t, seed.AutoMigrate(&models.SystemMetadata{}))
			require.NoError(t, seed.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: tc.value}).Error)

			cfg := &config.Config{}
			cfg.Storage.Type = "postgres"
			cfg.Storage.Database.DSN = dsn

			st, err := NewStorageFactory().CreateStorage(cfg)
			require.Error(t, err, "booting against schema_epoch %q must be refused", tc.value)
			assert.Nil(t, st)
			assert.Contains(t, err.Error(), "not a valid integer")

			// The refused boot ran no later migration step and did not "repair"
			// the corrupt marker with recordSchemaEpoch.
			db := pgRawOpen(t, dsn)
			assert.False(t, tableExists(db, "users"),
				"a refused boot must short-circuit before any other migration step creates tables")
			var m models.SystemMetadata
			require.NoError(t, db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error)
			assert.Equal(t, tc.value, m.Value,
				"the corrupt marker must be left in place for an operator to inspect, not overwritten")
		})
	}
}
