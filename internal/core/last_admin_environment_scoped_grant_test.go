package core_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestSuspendUser_EnvironmentScopedAdminGrantIsNotAGlobalAdminBackup (#2857):
// an admin-role grant at {ProjectID: 0, EnvironmentID: X} resolves only inside
// environment X, never at global scope, so it must not count as a surviving
// global administrator. Before the fix the core-side guards
// (guardLastAdminDeactivation here) counted it, and the install's only real
// global admin could be suspended: the lockout direction INV-CORE-15 forbids.
// The storage-side guard (RemoveGlobalAdminRoleGuarded) already refused it.
func TestSuspendUser_EnvironmentScopedAdminGrantIsNotAGlobalAdminBackup(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "admin.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.User{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.Session{}, &models.PersonalAccessToken{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 5, ProjectID: 2, Name: "e5"}).Error)
	for _, u := range []struct {
		id   uint
		name string
	}{{100, "globaladmin"}, {101, "envadmin"}} {
		require.NoError(t, db.Create(&models.User{
			ID: u.id, Username: u.name, UsernameFolded: u.name,
			Email: u.name + "@example.com", EmailFolded: u.name + "@example.com",
			IsActive: true, AccountState: "active",
		}).Error)
	}
	// The install's ONLY global administrator.
	require.NoError(t, db.Create(&models.UserRole{UserID: 100, RoleID: 1}).Error)
	// admin at {0, env 5}: the shape POST /api/v1/user-roles accepts.
	require.NoError(t, db.Create(&models.UserRole{UserID: 101, RoleID: 1, ProjectID: 0, EnvironmentID: 5}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	// Precondition: the grant applies inside environment 5 and NOT at global scope,
	// so a fixture that failed to create it cannot make this pass vacuously.
	inEnv, err := c.Storage().GetUserRoleIDsAt(ctx, 101, storage.Scope{ProjectID: 2, EnvironmentID: 5})
	require.NoError(t, err)
	require.Contains(t, inEnv, uint(1), "fixture precondition: user 101 holds admin inside environment 5")
	atGlobal, err := c.Storage().GetUserRoleIDsAt(ctx, 101, storage.Scope{})
	require.NoError(t, err)
	require.NotContains(t, atGlobal, uint(1), "fixture precondition: that grant does not resolve at global scope")

	// Self-suspension, so the admin-rank ceiling (which refuses a non-admin
	// actor before the guard runs) cannot be what refuses it.
	err = c.SuspendUser(ctx, 100, 100)
	require.ErrorContains(t, err, "refusing to deactivate the last install administrator",
		"#2857: the last real global admin was suspended because a {0, env 5} grant counted as a backup")

	var u models.User
	require.NoError(t, db.First(&u, 100).Error)
	require.Equal(t, core.AccountActive, u.AccountState)

	// Calibration: a real global grant for user 101 IS a backup, and the suspend goes through.
	require.NoError(t, db.Create(&models.UserRole{UserID: 101, RoleID: 1}).Error)
	require.NoError(t, c.SuspendUser(ctx, 100, 100))
}
