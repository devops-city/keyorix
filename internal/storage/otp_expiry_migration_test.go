package storage

// otp_expiry_migration_test.go — OTP-EXPIRY-1: the upgrade path of
// users.one_time_password_expires_at on SQLite and (KEYORIX_TEST_PG_DSN) Postgres.
//
// The rule under test (see backfillLegacyOneTimePasswordExpiry): when the column
// is added to an existing database, every live password_reset_required account
// gets upgrade-time + LegacyOneTimePasswordGrace; no other account is touched;
// and the backfill never runs again on a later boot.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func otpMigrationUser(name, state string) *models.User {
	return &models.User{
		Username: name, UsernameFolded: name,
		Email: name + "@example.com", EmailFolded: name + "@example.com",
		DisplayName: name, PasswordHash: "x", IsActive: true, AccountState: state,
	}
}

func otpExpiryOf(t *testing.T, db *gorm.DB, username string) *time.Time {
	t.Helper()
	// Read through the model, the way the login path does, so the stored encoding of
	// the backfilled value is proven readable by production code.
	var u models.User
	require.NoError(t, db.Unscoped().Where("username = ?", username).First(&u).Error)
	return u.OneTimePasswordExpiresAt
}

func TestMigrateDatabase_OneTimePasswordExpiry_UpgradeBackfill(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	backends := map[string]func(t *testing.T) (cfg *config.Config, open func(t *testing.T) *gorm.DB){
		"sqlite": func(t *testing.T) (*config.Config, func(t *testing.T) *gorm.DB) {
			path := filepath.Join(t.TempDir(), "otp.db")
			cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: path}}}
			return cfg, func(t *testing.T) *gorm.DB {
				db, err := openSQLiteGorm(path)
				require.NoError(t, err)
				return db
			}
		},
		"postgres": func(t *testing.T) (*config.Config, func(t *testing.T) *gorm.DB) {
			dsn := firstBootPostgresDSN(t)
			cfg := &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}
			return cfg, func(t *testing.T) *gorm.DB { return pgRawOpen(t, dsn) }
		},
	}

	for name, setup := range backends {
		t.Run(name, func(t *testing.T) {
			cfg, open := setup(t)

			// Boot 1: a database as the previous release left it. Create the full
			// schema, add the legacy users, then take the new column away again.
			_, err := NewStorageFactory().CreateStorage(cfg)
			require.NoError(t, err)
			db := open(t)
			for _, u := range []*models.User{
				otpMigrationUser("legacy_otp", "password_reset_required"),
				otpMigrationUser("plain_active", "active"),
				otpMigrationUser("pending_setup", "pending_first_login"),
				otpMigrationUser("deleted_reset", "password_reset_required"),
			} {
				require.NoError(t, db.Create(u).Error)
			}
			require.NoError(t, db.Where("username = ?", "deleted_reset").Delete(&models.User{}).Error)
			require.NoError(t, db.Migrator().DropColumn(&models.User{}, "OneTimePasswordExpiresAt"))
			require.False(t, db.Migrator().HasColumn(&models.User{}, "OneTimePasswordExpiresAt"))

			// Boot 2: the upgrade.
			before := time.Now().UTC()
			_, err = NewStorageFactory().CreateStorage(cfg)
			require.NoError(t, err)
			after := time.Now().UTC()
			db = open(t)
			require.True(t, db.Migrator().HasColumn(&models.User{}, "OneTimePasswordExpiresAt"))

			got := otpExpiryOf(t, db, "legacy_otp")
			require.NotNil(t, got, "a pre-upgrade password_reset_required account must be given an expiry")
			assert.False(t, got.Before(before.Add(LegacyOneTimePasswordGrace).Add(-time.Second)), "expiry = upgrade time + grace, got %s", got)
			assert.False(t, got.After(after.Add(LegacyOneTimePasswordGrace).Add(time.Second)), "expiry = upgrade time + grace, got %s", got)
			assert.Nil(t, otpExpiryOf(t, db, "plain_active"), "an active account is not touched")
			assert.Nil(t, otpExpiryOf(t, db, "pending_setup"), "a setup-link account is not touched")
			assert.Nil(t, otpExpiryOf(t, db, "deleted_reset"), "a deleted account is not touched")

			// Boot 3: an account forced into a reset AFTER the upgrade (admin
			// force-reset, expired-password gate) keeps its own, non-expiring
			// password. The backfill must not run again and stamp it.
			require.NoError(t, db.Create(otpMigrationUser("forced_later", "password_reset_required")).Error)
			_, err = NewStorageFactory().CreateStorage(cfg)
			require.NoError(t, err)
			db = open(t)
			assert.Nil(t, otpExpiryOf(t, db, "forced_later"), "the legacy backfill is one-shot: a later boot must not expire a post-upgrade forced reset")
			again := otpExpiryOf(t, db, "legacy_otp")
			require.NotNil(t, again)
			assert.True(t, again.Equal(*got), "a later boot must not move an existing expiry")
		})
	}
}
