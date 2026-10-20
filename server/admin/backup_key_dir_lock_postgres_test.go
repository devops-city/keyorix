package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/stretchr/testify/require"
)

// With storage.encryption.key_dir_lock: database the default (live) Postgres
// backup holds the shared server-presence lock: it runs next to a live replica,
// and is refused while an admin command (a key rotation) holds the exclusive one,
// without relying on the key-file flocks (docs/multi-replica-keys.md).
func TestAdminBackup_Postgres_DatabaseKeyDirLock_ExcludesKeyRotation(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dir := t.TempDir()
	chdirTest(t, dir)

	require.NoError(t, encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir).Initialize("test-passphrase-1234"))
	configPathFlag = filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPathFlag, []byte(fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: kek.salt
    key_dir_lock: database
`, dsn)), 0o600))
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	backupExclusive = false

	rotation, err := serverguard.AcquireExclusive(cfg)
	require.NoError(t, err)
	backupOutput = filepath.Join(t.TempDir(), "during-rotation.tar.gz")
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err, "backup ran while an admin command held the database exclusively:\n%s", out)
	require.Contains(t, err.Error(), "a key rotation or another admin command holds this database")
	require.NoError(t, rotation.Release())

	replica, err := serverguard.AcquirePresence(cfg)
	require.NoError(t, err)
	defer replica.Release() //nolint:errcheck
	backupOutput = filepath.Join(t.TempDir(), "live.tar.gz")
	out, err = captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "backup next to a live replica:\n%s", out)
}
