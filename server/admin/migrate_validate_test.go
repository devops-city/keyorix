package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// #2854: `admin migrate` must refuse a config that `serve` refuses
// (cfg.Validate()) BEFORE it opens the database. The proof is the effect:
// the SQLite file (and so any migration table) must not exist afterwards.
func TestAdminMigrate_RefusesConfigThatValidateRejects(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := fmt.Sprintf(`storage:
  type: local
  database:
    path: %s
server:
  http:
    tls_mode: not-a-real-mode
`, dbPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	configPathFlag = cfgPath

	// Precondition: this is a config Validate itself rejects (what serve runs).
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	cfg.Storage.Type = "local"
	wantErr := cfg.Validate()
	require.Error(t, wantErr, "fixture must be refused by Validate, otherwise this test proves nothing")

	err = runAdminMigrate(migrateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Configuration is invalid")
	assert.Contains(t, err.Error(), wantErr.Error())

	_, statErr := os.Stat(dbPath)
	assert.True(t, os.IsNotExist(statErr), "migrate must not create or touch the database for a refused config (stat err: %v)", statErr)
}

// Green control: a valid config still migrates (the database appears).
func TestAdminMigrate_ValidConfigStillMigrates(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	dir := t.TempDir()
	chdirTest(t, dir)
	dbPath := filepath.Join(dir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, dir, dbPath)

	require.NoError(t, runAdminMigrate(migrateCmd, nil))
	_, statErr := os.Stat(dbPath)
	assert.NoError(t, statErr)
}
