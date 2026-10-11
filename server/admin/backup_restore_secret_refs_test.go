// backup_restore_secret_refs_test.go covers #3078: backupfmt classified the
// five SecretID columns (share_records, secret_acls, access_requests,
// secret_version_comments, access_review_items) as references to
// mfa_secrets instead of secret_nodes. Restore's mandatory
// dangling-reference check then refused a valid backup holding a share, ACL
// or access request on a real secret, and accepted a reference to a secret
// that does not exist whenever some MFA secret happened to have that id.
//
// Both tests run the real `admin backup` and `admin restore` commands
// (SQLite), like backup_restore_integration_test.go. Not t.Parallel(): they
// set package-level cobra flag vars and chdir.
package admin

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// secretRefsSeed is the parent rows every secret-scoped child row below
// points at. No mfa_secrets rows exist unless a test adds one.
type secretRefsSeed struct {
	userID, projectID, envID, secretID, versionID, campaignID uint
}

// openSecretRefsSource creates, migrates and opens a fresh SQLite source
// deployment in its own directory (the process is chdir'd into it) and
// seeds one user, project, environment, campaign, and three secrets. The
// children reference the third secret, so its id (3) is not the first id of
// any table.
func openSecretRefsSource(t *testing.T) (*gorm.DB, secretRefsSeed) {
	t.Helper()
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
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg) // creates + migrates the source DB
	require.NoError(t, err)
	db, err := storage.OpenGormDB(srcCfg)
	require.NoError(t, err)

	user := models.User{Username: "alice", UsernameFolded: "alice", Email: "alice@example.test", IsActive: true}
	require.NoError(t, db.Create(&user).Error)
	project := models.Project{Name: "payments"}
	require.NoError(t, db.Create(&project).Error)
	env := models.Environment{ProjectID: project.ID, Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	var secret models.SecretNode
	for i := 1; i <= 3; i++ {
		secret = models.SecretNode{ProjectID: project.ID, EnvironmentID: env.ID, Name: fmt.Sprintf("db-password-%d", i), OwnerID: user.ID}
		require.NoError(t, db.Create(&secret).Error)
	}
	version := models.SecretVersion{SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("ciphertext")}
	require.NoError(t, db.Create(&version).Error)
	campaign := models.AccessReviewCampaign{ProjectID: project.ID, Name: "q4 review"}
	require.NoError(t, db.Create(&campaign).Error)

	require.EqualValues(t, 3, secret.ID)
	return db, secretRefsSeed{
		userID: user.ID, projectID: project.ID, envID: env.ID,
		secretID: secret.ID, versionID: version.ID, campaignID: campaign.ID,
	}
}

// secretScopedRows returns one row of each table with a SecretID column,
// all pointing at secretID.
func secretScopedRows(s secretRefsSeed, secretID uint) map[string]any {
	sid := secretID
	return map[string]any{
		"share_records": &models.ShareRecord{SecretID: secretID, OwnerID: s.userID, RecipientID: s.userID + 100, Permission: "read"},
		"secret_acls":   &models.SecretACL{SecretID: secretID, UserID: s.userID, Permissions: `["secrets.read"]`, GrantedBy: s.userID},
		"access_requests": &models.AccessRequest{ProjectID: s.projectID, UserID: s.userID, SecretID: &sid,
			State: "pending", Reason: "on-call"},
		"secret_version_comments": &models.SecretVersionComment{VersionID: s.versionID, SecretID: secretID, UserID: s.userID,
			Username: "alice", Comment: "rotated"},
		"access_review_items": &models.AccessReviewItem{CampaignID: s.campaignID, PrincipalType: "user", PrincipalID: s.userID,
			Source: "direct_share", AccessLevel: "read", EnvironmentID: s.envID, SecretID: secretID, Decision: "pending"},
	}
}

// backupThenRestore runs `admin backup` on the current source config, then
// `admin restore` into a fresh SQLite target, and returns restore's error
// plus the target's config.
func backupThenRestore(t *testing.T) (*config.Config, error) {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "backup output:\n%s", out)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, filepath.Join(dstDir, "secrets.db"))
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	if err != nil {
		return nil, fmt.Errorf("%w (restore output:\n%s)", err, out)
	}
	dstCfg, cfgErr := loadConfig()
	require.NoError(t, cfgErr)
	return dstCfg, nil
}

// TestAdminBackupRestore_SecretScopedRowsRestore: a backup holding a share,
// an ACL, a secret-scoped access request, a version comment and an access
// review item, each on a real secret, restores, and every row comes back
// pointing at the same secret. There are no MFA secrets, so before #3078's
// fix restore refused this with "share_records.secret_id references missing
// mfa_secrets.id=3".
func TestAdminBackupRestore_SecretScopedRowsRestore(t *testing.T) {
	db, seed := openSecretRefsSource(t)
	rows := secretScopedRows(seed, seed.secretID)
	for table, row := range rows {
		require.NoError(t, db.Create(row).Error, "seed %s", table)
	}
	var mfaSecrets int64
	require.NoError(t, db.Model(&models.MFASecret{}).Count(&mfaSecrets).Error)
	require.Zero(t, mfaSecrets)

	dstCfg, err := backupThenRestore(t)
	require.NoError(t, err)

	dst, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	for table := range rows {
		var got []uint
		require.NoError(t, dst.Table(table).Pluck("secret_id", &got).Error)
		require.Equal(t, []uint{seed.secretID}, got, "%s.secret_id after restore", table)
	}
}

// TestAdminBackupRestore_RefusesDanglingSecretReference: for each table
// with a SecretID column, a row pointing at a secret that does not exist
// makes restore refuse, naming the table and secret_nodes. An MFA secret
// with that same id exists, which is what made restore accept these rows
// before #3078's fix.
func TestAdminBackupRestore_RefusesDanglingSecretReference(t *testing.T) {
	const missingSecretID = 999
	for _, table := range []string{
		"share_records", "secret_acls", "access_requests", "secret_version_comments", "access_review_items",
	} {
		t.Run(table, func(t *testing.T) {
			db, seed := openSecretRefsSource(t)
			require.NoError(t, db.Create(&models.MFASecret{ID: missingSecretID, UserID: seed.userID,
				SecretEnc: []byte("not-a-real-totp-seed"), CreatedAt: time.Now()}).Error)
			require.NoError(t, db.Create(secretScopedRows(seed, missingSecretID)[table]).Error)

			_, err := backupThenRestore(t)
			require.Error(t, err, "restore must refuse a %s row whose secret does not exist", table)
			require.Contains(t, err.Error(), "restore refuses: 1 dangling reference(s)")
			require.Contains(t, err.Error(), fmt.Sprintf(`table %q column "secret_id"`, table))
			require.Contains(t, err.Error(), fmt.Sprintf("references missing secret_nodes.id=%d", missingSecretID))
		})
	}
}
