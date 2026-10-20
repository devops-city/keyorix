// backup_restore_audit_purge_test.go covers MIGRATE-VERIFY-1: `admin restore`
// verifies the restored audit chain automatically (design-b3 §9), but it did not
// hand the verifier the checkpoint signing key it had just unwrapped. A chain
// that has been through a retention purge has a gap that only that key can
// authenticate, so the restore of every database that had ever been purged
// reported INDETERMINATE ("unauthenticated retention gap") although
// `admin verify-audit --checkpoint-key-file` on the same database says VALID.
//
// Each test drives the real `admin backup` and `admin restore` commands:
// log old and recent chained events, run the real retention purge (which signs
// the re-anchor with the KEK-derived checkpoint key), back up, restore into a
// fresh target. SQLite always; Postgres when KEYORIX_TEST_PG_DSN is set. Not
// t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedPurgedAuditChain logs three events older than the retention window and two
// recent ones, then runs the real retention purge, so the database carries a
// signed retention anchor in front of its surviving chain.
func seedPurgedAuditChain(t *testing.T, st corestorage.Storage, svc *encryption.Service) {
	t.Helper()
	ctx := context.Background()
	key, keyID, ok := svc.AuditCheckpointKey()
	require.True(t, ok, "the KEK-derived audit checkpoint key must be available")
	c := core.NewKeyorixCore(st)
	c.SetAuditCheckpointKey(key, keyID)

	ok2 := true
	log := func(eventType string, at time.Time) {
		require.NoError(t, st.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: eventType, Description: "audit purge restore test", Success: &ok2, EventTime: at,
		}))
	}
	for i := range 3 {
		log("secret.read", time.Now().UTC().AddDate(0, 0, -(40+i)))
	}
	for i := range 2 {
		log("secret.updated", time.Now().UTC().Add(-time.Duration(i+1)*time.Hour))
	}
	res, err := c.PurgeAuditLogs(ctx, core.AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.EqualValues(t, 3, res.DeletedCount, "the three old events must be purged (a signed re-anchor is then written)")
}

// sealSeededAuditCheckpoint turns the generic one-row-per-model seed's audit
// state into one a real database could be in. That seed writes a zero-valued
// audit_checkpoints row with no signature and no high-water mark; the automatic
// verify-audit after a restore now holds the KEK-derived checkpoint key, and with
// it "a checkpoint exists but the anti-rollback mark does not" is BROKEN (it is
// exactly what deleting the mark looks like). The seed's single audit event has no
// entry hash (an unchained legacy row), so the certified chain length is 0.
func sealSeededAuditCheckpoint(t *testing.T, gdb *gorm.DB, svc *encryption.Service) {
	t.Helper()
	key, keyID, ok := svc.AuditCheckpointKey()
	require.True(t, ok, "the KEK-derived audit checkpoint key must be available")
	// The seed also set head_id (a reference-shaped column) to a real event id, so sign
	// what the row actually holds rather than assuming zeros.
	var row models.AuditCheckpoint
	require.NoError(t, gdb.First(&row).Error)
	cp := &auditverify.Checkpoint{
		ChainedEvents: row.ChainedEvents, HeadID: uint64(row.HeadID), HeadHash: row.HeadHash, KeyVersion: keyID,
	}
	sig := auditverify.SignCheckpoint(cp, key)
	require.NoError(t, gdb.Model(&row).Updates(map[string]any{"key_version": keyID, "signature": sig}).Error)
	require.NoError(t, gdb.Create(&models.SystemMetadata{
		Key: "audit_checkpoint_highwater", Value: auditverify.EncodeHighWater(cp, sig), UpdatedAt: propertySeedBaseTime,
	}).Error)
}

func TestAdminRestore_PurgedAuditChain_ReportsValid_SQLite(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := encryption.NewService(encCfg, srcDir)
	require.NoError(t, svc.Initialize("test-passphrase-1234"))
	configPathFlag = writeBackupRestoreTestConfig(t, srcDir, filepath.Join(srcDir, "secrets.db"))
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	seedPurgedAuditChain(t, st, svc)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, filepath.Join(dstDir, "secrets.db"))
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID",
		"a purged-then-restored chain must verify against the restored KEK-derived checkpoint key")
}

func TestAdminRestore_PurgedAuditChain_ReportsValid_Postgres(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := encryption.NewService(encCfg, srcDir)
	require.NoError(t, svc.Initialize("test-passphrase-1234"))
	configPathFlag = writePostgresBackupRestoreTestConfig(t, srcDir, srcDSN)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	seedPurgedAuditChain(t, st, svc)

	archivePath := filepath.Join(t.TempDir(), "pg-backup.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

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
		"a purged-then-restored chain must verify against the restored KEK-derived checkpoint key")
}
