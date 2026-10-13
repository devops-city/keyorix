// reauth_grant_suspend_failure_test.go — failure-path and sibling-path coverage
// for the re-auth grant purge (#3227 coordinator review): a storage fault in the
// use-time account re-read, a fault in the purge itself, and the SCIM /
// UpdateUser account-disabling paths.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A GetUser fault in userStillActiveForGrant: the password matched, only the
// account re-read failed. The grant is not spent, the action is refused with the
// generic message, and the audit is mfa.error (not mfa.failed) -- #2888.
func TestRequireReauth_ActiveRecheckGetUserFault_AuditedAsMFAError(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	mintReauthGrantFor(t, db, 1, fixed)

	base := c.storage
	// Call 1 is RegenerateMFARecoveryCodes' own read; call 2 is the re-check.
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "GetUser", NthCall: 2, Kind: faultstorage.KindError,
		Err: errors.New("injected: GetUser"),
	})
	c.storage = fs
	_, err := c.RegenerateMFARecoveryCodes(context.Background(), 1, mfaTestPassword)
	c.storage = base

	require.True(t, fs.Fired(), "the use-time GetUser must have been reached")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid code or password", "client response must stay the generic refusal")
	assert.EqualValues(t, 1, countGrantsFor(t, db, 1), "a faulted re-check must not spend the grant")

	var failed, errored int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.failed", uint(1)).Count(&failed).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", "mfa.error", uint(1)).Count(&errored).Error)
	assert.Zero(t, failed, "a storage fault after a matched password must not be audited as a wrong credential")
	assert.EqualValues(t, 1, errored)
}

// The purge itself faults: the suspension still succeeds (the purge is
// best-effort after commit) and the surviving grant is refused at use time.
func TestSuspendUser_PurgeFault_SuspendSucceedsGrantRefusedAtUse(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	mintReauthGrantFor(t, db, 1, fixed)

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "DeleteMFAStepUpGrantsFor", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: DeleteMFAStepUpGrantsFor"),
	})
	c.storage = fs
	require.NoError(t, c.SuspendUser(context.Background(), 0, 1), "a failed purge must not fail the suspension")
	c.storage = base

	require.True(t, fs.Fired(), "the purge must have been attempted")
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.True(t, AccountLoginBlocked(u.ID, u.AccountState), "the account must be suspended")
	assert.EqualValues(t, 1, countGrantsFor(t, db, 1), "the faulted purge left the grant behind")
	requireStepUpActionRefused(t, c, 1)
}

// UpdateUser(IsActive=false) purges the target's grants.
func TestUpdateUser_Deactivate_PurgesReauthGrants(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob", Email: "b@b.com",
		EmailFolded: "b@b.com", PasswordHash: "x", IsActive: true, AccountState: "active"}).Error)
	mintReauthGrantFor(t, db, 2, fixed)
	no := false

	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 2, ActorID: 1, IsActive: &no})
	require.NoError(t, err)

	assert.EqualValues(t, 0, countGrantsFor(t, db, 2), "deactivating via UpdateUser must purge the user's grants")
}

// SCIM update with active=false purges.
func TestUpdateSCIMUser_Deactivate_PurgesReauthGrants(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.MFAStepUpGrant{}))
	mintReauthGrantFor(t, db, 1, c.authEffectiveNow())
	no := false

	_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
	require.NoError(t, err)

	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "SCIM deactivation must purge the user's grants")
}

// SCIM DELETE (deprovision) purges.
func TestDeprovisionSCIMUser_PurgesReauthGrants(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.Role{}, &models.MFAStepUpGrant{}))
	mintReauthGrantFor(t, db, 1, c.authEffectiveNow())

	require.NoError(t, c.DeprovisionSCIMUser(context.Background(), 2, 1))

	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "SCIM deprovision must purge the user's grants")
}
