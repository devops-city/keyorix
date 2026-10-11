// backup_restore_purge_test.go covers #3085: `admin restore` refused a backup
// taken after an ordinary secret purge, because the purge left rows that still
// reference the purged secret (and its versions) and backupfmt's mandatory
// dangling-reference check counts every one of them.
//
// Each test drives the real `admin backup` and `admin restore` commands:
// create secrets, give one of them a row in every referencing table, soft-delete
// and PURGE it, back up, restore into a fresh target. SQLite always;
// Postgres when KEYORIX_TEST_PG_DSN is set. Not t.Parallel(): package-level
// cobra flag vars and chdir.
package admin

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// purgeRefsSeed identifies the purged secret and the live one.
type purgeRefsSeed struct {
	purgedID, purgedVersionID, liveID uint
}

// seedSecretWithEveryReference creates a live secret and a secret with one row
// in every table that references a secret or a version (cascade AND historical),
// then soft-deletes and purges the second.
func seedSecretWithEveryReference(t *testing.T, st corestorage.Storage, db *gorm.DB) purgeRefsSeed {
	t.Helper()
	ctx := context.Background()

	user := models.User{Username: "alice", UsernameFolded: "alice", Email: "alice@example.test", IsActive: true}
	require.NoError(t, db.Create(&user).Error)
	project := models.Project{Name: "payments"}
	require.NoError(t, db.Create(&project).Error)
	env := models.Environment{ProjectID: project.ID, Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	tag := models.Tag{Name: "db"}
	require.NoError(t, db.Create(&tag).Error)
	campaign := models.AccessReviewCampaign{ProjectID: project.ID, Name: "q4 review"}
	require.NoError(t, db.Create(&campaign).Error)

	purged, err := st.CreateSecret(ctx, &models.SecretNode{ProjectID: project.ID, EnvironmentID: env.ID, Name: "purge-me", OwnerID: user.ID, IsSecret: true}, "purged-value")
	require.NoError(t, err)
	live, err := st.CreateSecret(ctx, &models.SecretNode{ProjectID: project.ID, EnvironmentID: env.ID, Name: "keep-me", OwnerID: user.ID, IsSecret: true}, "live-value")
	require.NoError(t, err)
	version := models.SecretVersion{SecretNodeID: purged.ID, VersionNumber: 1, EncryptedValue: []byte("ciphertext")}
	require.NoError(t, db.Create(&version).Error)

	sid := purged.ID
	req := models.AccessRequest{ProjectID: project.ID, UserID: user.ID, SecretID: &sid, State: "pending", Reason: "on-call"}
	require.NoError(t, db.Create(&req).Error)
	for _, row := range []any{
		&models.AccessRequestApproval{RequestID: req.ID, ApproverID: user.ID},
		&models.ShareRecord{SecretID: purged.ID, OwnerID: user.ID, RecipientID: user.ID, Permission: "read"},
		&models.SecretACL{SecretID: purged.ID, UserID: user.ID, Permissions: `["secrets.read"]`, GrantedBy: user.ID},
		&models.SecretTag{SecretNodeID: purged.ID, TagID: tag.ID},
		&models.SecretAccessSchedule{SecretNodeID: purged.ID, AllowedDays: "*", EndHour: 24, Timezone: "UTC"},
		&models.SecretMetadataHistory{SecretNodeID: purged.ID},
		&models.SecretVersionComment{VersionID: version.ID, SecretID: purged.ID, UserID: user.ID, Username: "alice", Comment: "rotated"},
		&models.Notification{UserID: user.ID, SecretNodeID: &sid},
		&models.AnomalyAlert{SecretNodeID: purged.ID},
		&models.SecretAccessLog{SecretNodeID: purged.ID, SecretVersionID: version.ID, Action: "read", AccessTime: time.Now()},
		&models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: user.ID, Source: "direct_share",
			AccessLevel: "read", EnvironmentID: env.ID, SecretID: purged.ID, Decision: "pending"},
	} {
		require.NoError(t, db.Create(row).Error)
	}
	// The audit event goes through the store so the hash chain stays valid.
	require.NoError(t, st.LogAuditEvent(ctx, &models.AuditEvent{EventType: "secret.read", SecretNodeID: &sid, UserID: &user.ID}))

	require.NoError(t, st.DeleteSecret(ctx, purged.ID))
	// DeleteSecret freezes the real purge date (now + retention) and a purge never
	// runs before it, whatever cutoff the caller passes. Move that date into the
	// past, as if the retention window had elapsed.
	past := time.Now().Add(-48 * time.Hour)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET deleted_at = ?, purge_at = ? WHERE id = ?", past, past, purged.ID).Error)
	n, err := st.PurgeDeletedSecretsBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "the soft-deleted secret must be purged")
	return purgeRefsSeed{purgedID: purged.ID, purgedVersionID: version.ID, liveID: live.ID}
}

// requirePurgedSecretLeavesOnlyHistory asserts the state a purge must leave in
// db: no cascade row references the purged secret or version, and the
// historical rows are still there, untouched.
func requirePurgedSecretLeavesOnlyHistory(t *testing.T, db *gorm.DB, s purgeRefsSeed) {
	t.Helper()
	for _, c := range store.SecretPurgeCascades() {
		id := s.purgedID
		if c.Parent == store.PurgeParentSecretVersion {
			id = s.purgedVersionID
		}
		var n int64
		require.NoError(t, db.Table(c.Table).Unscoped().Where(c.Column+" = ?", id).Count(&n).Error)
		require.Zero(t, n, "%s.%s still references the purged secret", c.Table, c.Column)
	}
	for _, h := range backupfmt.HistoricalReferences() {
		id := s.purgedID
		if h.Parent == "secret_versions" {
			id = s.purgedVersionID
		}
		var n int64
		require.NoError(t, db.Table(h.Table).Where(h.Column+" = ?", id).Count(&n).Error)
		require.EqualValues(t, 1, n, "%s.%s: the historical row must survive the purge and the restore", h.Table, h.Column)
	}
}

func TestAdminBackupRestore_AfterSecretPurge_SQLite(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))
	configPathFlag = writeBackupRestoreTestConfig(t, srcDir, filepath.Join(srcDir, "secrets.db"))
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	srcDB, err := storage.OpenGormDB(srcCfg)
	require.NoError(t, err)

	seed := seedSecretWithEveryReference(t, st, srcDB)

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
	require.NoError(t, err, "restore must accept a backup taken after a purge; output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")

	dstCfg, err := loadConfig()
	require.NoError(t, err)
	dstDB, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	requirePurgedSecretLeavesOnlyHistory(t, dstDB, seed)
	var live models.SecretNode
	require.NoError(t, dstDB.First(&live, seed.liveID).Error, "the live secret must be restored")
}

func TestAdminBackupRestore_AfterSecretPurge_Postgres(t *testing.T) {
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
	st, err := storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	srcDB := pgAdminRawOpen(t, srcDSN)

	seed := seedSecretWithEveryReference(t, st, srcDB)

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
	require.NoError(t, err, "restore must accept a backup taken after a purge; output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")

	dstDB := pgAdminRawOpen(t, dstDSN)
	requirePurgedSecretLeavesOnlyHistory(t, dstDB, seed)
	var live models.SecretNode
	require.NoError(t, dstDB.First(&live, seed.liveID).Error, "the live secret must be restored")
}
