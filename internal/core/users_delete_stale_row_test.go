package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newDeleteUserTestCore is newMFATestCore plus the tables DeleteUser's
// credential sweep and last-admin guard read.
func newDeleteUserTestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	c, db, _ := newMFATestCore(t)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.Project{}, &models.Environment{},
		&models.Group{}, &models.GroupRole{}, &models.UserGroup{}))
	return c, db
}

// TestDeleteUser_KeepsConcurrentPasswordChange (#2677): DeleteUser must not
// write back the user row it read before taking the lock. Before the fix it
// persisted that stale row with a full-row Save, reverting a password change
// that committed in between, and RestoreUser later let the OLD password in.
func TestDeleteUser_KeepsConcurrentPasswordChange(t *testing.T) {
	c, gdb := newDeleteUserTestCore(t)
	ctx := context.Background()
	c.storage = &afterFirstGetUser{Storage: c.storage, hook: func() {
		require.NoError(t, gdb.Model(&models.User{}).Where("id = 1").Updates(map[string]any{
			"password_hash": "NEW-HASH-from-concurrent-change", "mfa_enabled": true,
		}).Error)
	}}
	require.NoError(t, c.DeleteUser(ctx, 1, 1))

	var u models.User
	require.NoError(t, gdb.Unscoped().Where("id = 1").First(&u).Error)
	require.True(t, u.DeletedAt.Valid, "the user must be soft-deleted")
	require.False(t, u.IsActive)
	require.Equal(t, AccountDeprovisioned, u.AccountState)
	require.Equal(t, "NEW-HASH-from-concurrent-change", u.PasswordHash, "#2677: DeleteUser reverted the concurrent password change")
	require.True(t, u.MFAEnabled, "#2677: DeleteUser reverted a concurrent MFA enable")
}

// TestDeleteUser_KeepsConcurrentSuspension: the account_state DeleteUser writes
// is derived from the row it reads UNDER the lock, so a suspension committing
// after the pre-read is kept (a suspended account stays suspended, as it does
// when it was already suspended before the delete started).
func TestDeleteUser_KeepsConcurrentSuspension(t *testing.T) {
	c, gdb := newDeleteUserTestCore(t)
	ctx := context.Background()
	c.storage = &afterFirstGetUser{Storage: c.storage, hook: func() {
		require.NoError(t, gdb.Model(&models.User{}).Where("id = 1").Update("account_state", AccountSuspended).Error)
	}}
	require.NoError(t, c.DeleteUser(ctx, 1, 1))

	var u models.User
	require.NoError(t, gdb.Unscoped().Where("id = 1").First(&u).Error)
	require.True(t, u.DeletedAt.Valid)
	require.False(t, u.IsActive)
	require.Equal(t, AccountSuspended, u.AccountState, "a suspension committed after the pre-read must not be overwritten")
}
