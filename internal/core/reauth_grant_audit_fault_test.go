// reauth_grant_audit_fault_test.go — REAUTH-GRANT-TESTS-1 (#3227 review leftovers).
//
// Revocations must never be blocked by an audit failure: every account-disabling
// path purges the user's step-up grants, and a LogAuditEvent fault (before or
// after the purge) must neither stop the disable nor leave a grant behind. Also
// pins the GetUser-fault behaviour of the suspend path and that the use-time
// account re-check fault counts toward the lockout.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func auditFault() *faultstorage.FaultSpec {
	return &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: LogAuditEvent"),
	}
}

func TestSuspendUser_AuditWriteFault_StillSuspendsAndPurgesGrants(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	mintReauthGrantFor(t, db, 1, fixed)

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, auditFault())
	c.storage = fs
	err := c.SuspendUser(context.Background(), 0, 1)
	c.storage = base

	require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
	require.NoError(t, err, "an audit failure must not fail the suspension")
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.True(t, AccountLoginBlocked(u.ID, u.AccountState), "the account must be suspended")
	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "the purge must not depend on the audit write")
	requireStepUpActionRefused(t, c, 1)
}

func TestUpdateUser_Deactivate_AuditWriteFault_StillPurgesGrants(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob", Email: "b@b.com",
		EmailFolded: "b@b.com", PasswordHash: "x", IsActive: true, AccountState: "active"}).Error)
	mintReauthGrantFor(t, db, 2, fixed)
	no := false

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, auditFault())
	c.storage = fs
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 2, ActorID: 1, IsActive: &no})
	c.storage = base

	require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
	require.NoError(t, err)
	var u models.User
	require.NoError(t, db.First(&u, 2).Error)
	assert.False(t, u.IsActive)
	assert.EqualValues(t, 0, countGrantsFor(t, db, 2), "the purge must not depend on the audit write")
}

func TestUpdateSCIMUser_Deactivate_AuditWriteFault_StillPurgesGrants(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.MFAStepUpGrant{}))
	mintReauthGrantFor(t, db, 1, c.authEffectiveNow())
	no := false

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, auditFault())
	c.storage = fs
	_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
	c.storage = base

	require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
	require.NoError(t, err)
	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "the purge must not depend on the audit write")
}

func TestDeprovisionSCIMUser_AuditWriteFault_StillPurgesGrants(t *testing.T) {
	t.Parallel()
	c, db := newSCIMStateCore(t)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.Role{}, &models.MFAStepUpGrant{}))
	mintReauthGrantFor(t, db, 1, c.authEffectiveNow())

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, auditFault())
	c.storage = fs
	err := c.DeprovisionSCIMUser(context.Background(), 2, 1)
	c.storage = base

	require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
	require.NoError(t, err)
	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "the purge must not depend on the audit write")
}

// A GetUser fault during SuspendUser. Its only GetUser read is setAccountState's
// cosmetic audit-description lookup (auditRef), which runs after the disable
// commits and swallows the error: the suspension must still succeed and purge.
func TestSuspendUser_GetUserFault_StillSuspendsAndPurgesGrants(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	mintReauthGrantFor(t, db, 1, fixed)

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: GetUser"),
	})
	c.storage = fs
	err := c.SuspendUser(context.Background(), 0, 1)
	c.storage = base

	require.True(t, fs.Fired(), "SuspendUser must have reached GetUser")
	require.NoError(t, err, "a GetUser fault must not fail the suspension")
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.True(t, AccountLoginBlocked(u.ID, u.AccountState), "the account must be suspended")
	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "a GetUser fault must not stop the purge")
	requireStepUpActionRefused(t, c, 1)
}

// Item 1 (#3227 review): the userStillActiveForGrant read error reaches
// postVerdictErr, i.e. it counts toward the lockout exactly like a failed grant
// consumption does (mfa.error audit, generic client response -- the latter two
// are pinned by TestRequireReauth_ActiveRecheckGetUserFault_AuditedAsMFAError).
func TestRequireReauth_ActiveRecheckGetUserFault_CountsTowardLockout(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	mintReauthGrantFor(t, db, 1, fixed)

	base := c.storage
	for i := range 3 {
		// A fresh one-shot fault per attempt: call 1 is RegenerateMFARecoveryCodes'
		// own read, call 2 is the use-time re-check.
		fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
			Method: "GetUser", NthCall: 2, Kind: faultstorage.KindError,
			Err: errors.New("injected: GetUser"),
		})
		c.storage = fs
		_, err := c.RegenerateMFARecoveryCodes(context.Background(), 1, mfaTestPassword)
		require.True(t, fs.Fired(), "attempt %d: the re-check must have faulted", i)
		require.Error(t, err, "attempt %d", i)
		assert.Contains(t, err.Error(), "invalid code or password")
	}
	c.storage = base

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	// (FailedLoginAttempts itself resets to 0 when the lock trips, so the lock is the signal.)
	assert.NotNil(t, u.LoginLockedUntil, "MaxAttempts matched-password-but-faulted-re-check attempts must lock the account, like wrong guesses")
	assert.EqualValues(t, 1, countGrantsFor(t, db, 1), "the grant is not spent by a faulted re-check")
}
