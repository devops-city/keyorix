// backup_restore_postgres_test.go is the real-Postgres counterpart to
// backup_restore_integration_test.go's TestAdminBackupRestore_RoundTrip --
// design-b3-backup-v2.md §4 (H4, Session H): backup FROM a real Postgres
// source (REPEATABLE READ by default), restore INTO a separate, fresh
// Postgres target, through the real cobra RunE functions. Gated on
// KEYORIX_TEST_PG_DSN (this repo's existing pg-gated convention) so
// `go test ./...` still passes cleanly with no Postgres available.
package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var pgAdminDBCounter atomic.Int64

func pgAdminTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres admin backup/restore test")
	}
	return dsn
}

// pgAdminIsolatedDatabaseDSN creates a fresh, empty database on the real
// Postgres server at base, dropped on test cleanup.
func pgAdminIsolatedDatabaseDSN(t *testing.T, base string) string {
	t.Helper()
	n := pgAdminDBCounter.Add(1)
	dbName := fmt.Sprintf("admin_backup_restore_%d_%d", os.Getpid(), n)

	admin := pgAdminRawOpen(t, base)
	require.NoError(t, admin.Exec("CREATE DATABASE "+dbName).Error) //nolint:gosec // dbName is process-pid+counter generated, not external input
	t.Cleanup(func() {
		cleaner := pgAdminRawOpen(t, base)
		_ = cleaner.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
	})
	return pgdsn.PGReplaceDBName(base, dbName)
}

func pgAdminRawOpen(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func writePostgresBackupRestoreTestConfig(t *testing.T, dir, dsn string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: kek.salt
`, dsn)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	return cfgPath
}

// TestAdminBackupRestore_Postgres_RoundTrip proves design §4's actual
// claims end to end: `admin backup` reads a real Postgres source through
// its default REPEATABLE READ snapshot (no --exclusive), `admin restore`
// loads into a SEPARATE, fresh Postgres target (refuseNonEmptyPostgresTarget,
// the Postgres-specific rollback-protection helpers, LoadArchive's single
// transaction), and the restored data + verify-audit both come out correct.
func TestAdminBackupRestore_Postgres_RoundTrip(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)

	srcDir := t.TempDir()
	chdirTest(t, srcDir)

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))

	configPathFlag = writePostgresBackupRestoreTestConfig(t, srcDir, srcDSN)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg) // creates + migrates the source DB
	require.NoError(t, err)

	seedDB := pgAdminRawOpen(t, srcDSN)
	require.NoError(t, seedDB.Create(&models.Project{Name: "pg-proj"}).Error)
	require.NoError(t, seedDB.Create(&models.User{Username: "pgalice", Email: "pgalice@example.com", PasswordHash: "x"}).Error)

	archivePath := filepath.Join(t.TempDir(), "pg-backup.tar.gz")
	backupOutput = archivePath
	backupExclusive = false // default path: REPEATABLE READ, not the exclusive advisory lock
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

	dekPath := filepath.Join(srcDir, "dek.key")

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID",
		"restore must run verify-audit automatically and report its verdict")

	dstDekPath := filepath.Join(dstDir, "dek.key")
	origDEK, err := os.ReadFile(dekPath)
	require.NoError(t, err)
	gotDEK, err := os.ReadFile(dstDekPath)
	require.NoError(t, err)
	require.Equal(t, origDEK, gotDEK, "restored key material must be byte-identical to the source")

	dstDB := pgAdminRawOpen(t, dstDSN)
	var users []models.User
	require.NoError(t, dstDB.Find(&users).Error)
	require.Len(t, users, 1)
	require.Equal(t, "pgalice", users[0].Username)
	var projects []models.Project
	require.NoError(t, dstDB.Find(&projects).Error)
	require.Len(t, projects, 1)
	require.Equal(t, "pg-proj", projects[0].Name)
}

// TestAdminRestore_Postgres_RefusesNonEmptyTarget is
// refuseNonEmptyPostgresTarget's own proving test: restoring into a
// Postgres database that ALREADY has tables must refuse without
// --overwrite-existing, the same discipline SQLite's refuseNonEmptyExisting
// already enforces.
func TestAdminRestore_Postgres_RefusesNonEmptyTarget(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))
	configPathFlag = writePostgresBackupRestoreTestConfig(t, srcDir, srcDSN)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)

	archivePath := filepath.Join(t.TempDir(), "pg-backup-nonempty.tar.gz")
	backupOutput = archivePath
	_, err = captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err)

	// Pre-migrate the TARGET so it already has tables -- the non-empty case.
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)

	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	err = runAdminRestore(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already has")
}
