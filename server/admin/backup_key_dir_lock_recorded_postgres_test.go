package admin

// A live Postgres backup decides whether it must hold the shared server-presence
// lock from what the replicas recorded in the database (config.KeyDirLockModeMetadataKey),
// as --force does, not only from its own config; an unreadable record refuses the
// backup (HA-READY-1 review). Gated on KEYORIX_TEST_PG_DSN.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// The replicas recorded database mode, but this backup's own config says nothing:
// the backup must still hold the presence lock, so a key rotation (exclusive)
// cannot run beside it, and it must be refused while a rotation holds the database.
func TestAdminBackup_Postgres_RecordedDatabaseKeyDirLock_ExcludesKeyRotation(t *testing.T) {
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
`, dsn)), 0o600)) // no key_dir_lock here
	cfg, err := loadConfig()
	require.NoError(t, err)
	require.False(t, cfg.Storage.Encryption.KeyDirLockIsDatabase())
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	backupExclusive = false

	db := pgAdminRawOpen(t, dsn)
	require.NoError(t, db.Create(&models.SystemMetadata{Key: config.KeyDirLockModeMetadataKey, Value: config.KeyDirLockDatabase}).Error)

	rotation, err := serverguard.AcquireExclusive(cfg)
	require.NoError(t, err)
	backupOutput = filepath.Join(t.TempDir(), "during-rotation.tar.gz")
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err, "backup ran while an admin command held the database exclusively although the replicas recorded key_dir_lock: database:\n%s", out)
	require.Contains(t, err.Error(), "a key rotation or another admin command holds this database")
	require.NoError(t, rotation.Release())
}

func TestAcquireLiveBackupPresence_DecidesFromRecordedMode(t *testing.T) {
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	cfg := &config.Config{} // does not say database
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	if c, ok := st.(interface{ Close() error }); ok {
		defer func() { _ = c.Close() }()
	}

	// Control: nothing recorded, config says nothing -> no lock to hold.
	presence, err := acquireLiveBackupPresence(cfg)
	require.NoError(t, err)
	require.Nil(t, presence, "flock-mode deployment: the live backup takes no presence lock")

	db := pgAdminRawOpen(t, dsn)
	require.NoError(t, db.Create(&models.SystemMetadata{Key: config.KeyDirLockModeMetadataKey, Value: config.KeyDirLockDatabase}).Error)

	presence, err = acquireLiveBackupPresence(cfg)
	require.NoError(t, err)
	require.NotNil(t, presence, "the replicas recorded database mode: the backup must hold the presence lock")
	// While it is held, an admin command cannot take the exclusive lock.
	if ex, xerr := serverguard.AcquireExclusive(cfg); xerr == nil {
		_ = ex.Release()
		t.Fatal("an exclusive admin lock was granted while the backup held the presence lock")
	}
	require.NoError(t, presence.Release())
}

// Fail closed (storage error -> refuse): the record cannot be read (system_metadata
// does not exist in this empty database), so the backup cannot tell whether it
// must hold the presence lock and must not run without it.
func TestAcquireLiveBackupPresence_RefusesWhenRecordQueryFails(t *testing.T) {
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t)) // empty: no schema
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn

	presence, err := acquireLiveBackupPresence(cfg)
	require.Error(t, err, "a live backup went on although the key_dir_lock record could not be read")
	require.Nil(t, presence)
	require.True(t, strings.Contains(err.Error(), "could not be verified") && strings.Contains(err.Error(), "system_metadata"),
		"refusal must name the failed read, got: %v", err)
}

// Fail closed on an unreachable database as well.
func TestAcquireLiveBackupPresence_RefusesWhenDatabaseUnreachable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.Host = "127.0.0.1"
	cfg.Storage.Database.Port = "1" // nothing listens
	cfg.Storage.Database.Name = "keyorix"
	cfg.Storage.Database.User = "keyorix"

	presence, err := acquireLiveBackupPresence(cfg)
	require.Error(t, err)
	require.Nil(t, presence)
	require.Contains(t, err.Error(), "could not be verified")
}
