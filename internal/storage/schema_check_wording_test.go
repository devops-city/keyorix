package storage

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BOOT-REFUSALS-1 "Misleading messages" item 6: an epoch or floor refusal was
// wrapped as "failed to migrate database:" although it runs before any
// migration step, so operators looked for a migration error.
func TestCreateStorage_SchemaEpochRefusal_IsNotAMigrationFailure(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	for _, tc := range []struct {
		name, key, value, want string
	}{
		{"newer epoch", schemaEpochMetadataKey, strconv.Itoa(currentSchemaEpoch + 1), "newer than this binary's schema epoch"},
		{"floor above binary", schemaMinCompatibleEpochMetadataKey, strconv.Itoa(currentSchemaEpoch + 1), "database declares a minimum compatible schema epoch of"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "epoch.db")
			seed, err := gormOpenForTest(t, dbPath)
			require.NoError(t, err)
			require.NoError(t, seed.AutoMigrate(&models.SystemMetadata{}))
			require.NoError(t, seed.Create(&models.SystemMetadata{Key: schemaEpochMetadataKey, Value: strconv.Itoa(currentSchemaEpoch)}).Error)
			if tc.key != schemaEpochMetadataKey {
				require.NoError(t, seed.Create(&models.SystemMetadata{Key: tc.key, Value: tc.value}).Error)
			} else {
				require.NoError(t, seed.Model(&models.SystemMetadata{}).Where("key = ?", tc.key).Update("value", tc.value).Error)
			}
			if raw, err := seed.DB(); err == nil {
				_ = raw.Close()
			}

			cfg := &config.Config{}
			cfg.Storage.Type = "local"
			cfg.Storage.Database.Path = dbPath
			_, err = NewStorageFactory().CreateStorage(cfg)
			require.Error(t, err)
			msg := err.Error()
			assert.Contains(t, msg, tc.want, "the page's Match text stays")
			assert.Contains(t, msg, "nothing was migrated")
			assert.NotContains(t, msg, "failed to migrate database")
		})
	}
}
