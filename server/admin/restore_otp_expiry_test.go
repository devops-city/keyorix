package admin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// OTP-EXPIRY-1 / restore: a pre-expiry archive loaded into the fresh (already
// migrated) target must not bring back password_reset_required credentials that
// never expire.

func usersManifest(columns ...string) backupfmt.Manifest {
	return backupfmt.Manifest{Tables: []backupfmt.TableEntry{{Name: "users", Columns: columns}}}
}

func restoredUsersDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	// As LoadArchive leaves them: rows with NO expiry.
	for i, state := range []string{"password_reset_required", "active", "pending_first_login"} {
		require.NoError(t, db.Create(&models.User{
			ID: uint(i + 1), Username: state, UsernameFolded: state, AccountState: state,
		}).Error)
	}
	return db
}

func expiryOf(t *testing.T, db *gorm.DB, id uint) *time.Time {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, id).Error)
	return u.OneTimePasswordExpiresAt
}

func TestRestore_OlderArchiveGetsTheLegacyOTPExpiryBackfill(t *testing.T) {
	db := restoredUsersDB(t)
	before := time.Now()

	require.NoError(t, backfillOTPExpiryForOlderArchive(db, usersManifest("id", "username", "account_state")))

	got := expiryOf(t, db, 1)
	require.NotNil(t, got, "a restored pre-expiry password_reset_required account must not keep a never-expiring credential")
	assert.WithinDuration(t, before.Add(storage.LegacyOneTimePasswordGrace), *got, time.Minute)
	assert.Nil(t, expiryOf(t, db, 2), "an active account is untouched")
	assert.Nil(t, expiryOf(t, db, 3), "a pending_first_login account is untouched (its credential is a setup link)")
}

func TestRestore_ArchiveWithTheColumnIsLoadedAsIs(t *testing.T) {
	db := restoredUsersDB(t)

	require.NoError(t, backfillOTPExpiryForOlderArchive(db, usersManifest("id", "username", "account_state", otpExpiryColumn)))

	assert.Nil(t, expiryOf(t, db, 1), "a NULL expiry in an archive that has the column is real data, not a legacy row")
}

func TestArchiveLacksOTPExpiry(t *testing.T) {
	assert.True(t, archiveLacksOTPExpiry(usersManifest("id")))
	assert.False(t, archiveLacksOTPExpiry(usersManifest("id", otpExpiryColumn)))
	assert.False(t, archiveLacksOTPExpiry(backfillNoUsersManifest()), "no users table: nothing to stamp")
}

func backfillNoUsersManifest() backupfmt.Manifest {
	return backupfmt.Manifest{Tables: []backupfmt.TableEntry{{Name: "projects", Columns: []string{"id"}}}}
}
