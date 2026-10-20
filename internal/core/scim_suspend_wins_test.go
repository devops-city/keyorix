package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newSCIMStateCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
		&models.UserRole{}, &models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
	return c, db
}

// An admin security suspension must survive routine SCIM activation. The IdP re-sends
// active=true for every active user, so without a distinct deprovisioned state that
// sync would silently undo an incident-response lockout.
func TestUpdateSCIMUser_AdminSuspensionSurvivesReactivation(t *testing.T) {
	t.Parallel()
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes := true

	require.NoError(t, c.SuspendUser(ctx, 99, 1)) // admin incident response

	updated, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes) // IdP sync
	require.NoError(t, err)
	assert.Equal(t, AccountSuspended, updated.AccountState, "SCIM activation must not clear an admin suspension")
	assert.True(t, AccountLoginBlocked(updated.ID, updated.AccountState), "the account stays login-blocked")
}

// The legitimate SCIM lifecycle still works: deactivation blocks login (deprovisioned),
// and a later reactivation restores access.
func TestUpdateSCIMUser_DeactivateThenReactivate(t *testing.T) {
	t.Parallel()
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes, no := true, false

	off, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)
	assert.Equal(t, AccountDeprovisioned, off.AccountState)
	assert.False(t, off.IsActive)
	assert.True(t, AccountLoginBlocked(off.ID, off.AccountState), "a SCIM-deactivated account is login-blocked")

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	assert.Equal(t, AccountActive, on.AccountState, "reactivation clears its own deactivation")
	assert.True(t, on.IsActive)
	assert.False(t, AccountLoginBlocked(on.ID, on.AccountState))
}

// An admin-forced credential reset (password_reset_required) must survive a routine
// SCIM deactivate→reactivate cycle. The restricted state confines the user to the
// password-change flow; if SCIM downgraded it to deprovisioned and then cleared that
// to active, the forced reset would be silently lifted (the same class as the
// admin-suspension case, for the other sticky admin state).
func TestUpdateSCIMUser_ForcedResetSurvivesDeactivateReactivate(t *testing.T) {
	t.Parallel()
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes, no := true, false

	require.NoError(t, c.RequirePasswordReset(ctx, 99, 1)) // admin forces a reset

	off, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)
	assert.Equal(t, AccountPasswordResetRequired, off.AccountState, "SCIM deactivation must not downgrade a forced reset")
	assert.False(t, off.IsActive, "but login is still blocked while deactivated (IsActive=false)")

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	assert.Equal(t, AccountPasswordResetRequired, on.AccountState, "reactivation must not clear the forced reset")
	assert.True(t, AccountRestricted(on.AccountState), "the user is still confined to the password-change flow")
}

// Deactivating an already admin-suspended user must not downgrade the suspension to a
// deprovisioned state (which a later reactivation could then clear).
func TestUpdateSCIMUser_DeactivateKeepsAdminSuspension(t *testing.T) {
	t.Parallel()
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes, no := true, false
	require.NoError(t, c.SuspendUser(ctx, 99, 1))

	off, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)
	assert.Equal(t, AccountSuspended, off.AccountState, "an admin suspension is not downgraded by SCIM deactivation")

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	assert.Equal(t, AccountSuspended, on.AccountState, "and reactivation still cannot revive it")
}
