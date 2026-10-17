package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// TestUpdateUser_Deactivation_RevokesSessionsAndPATs verifies that setting
// IsActive=false via UpdateUser immediately terminates the user's active
// sessions and PATs and evicts them from the auth cache (#r124-M).
// Prior to the fix, UpdateUser only updated the is_active column and left
// live sessions/PATs intact, so the user could keep authenticating until
// their credentials expired naturally.
func TestUpdateUser_Deactivation_RevokesSessionsAndPATs(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	db := sqlitetest.OpenWithDialector(t, "kx_update_user_deactivation_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.PersonalAccessToken{},
		&models.AuditEvent{},
		&models.UserRole{},
		&models.Role{},
		// Group/UserGroup/GroupRole/Project/Environment are needed by
		// guardLastAdminDeactivation (#G02), which UpdateUser's deactivating
		// path now calls — without them the role lookup fails on a missing
		// table and the guard fails closed, refusing every deactivation.
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
	))

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	// Seed: an active user with one session and one PAT.
	active := true
	u := &models.User{
		ID:       42,
		Username: "alice",
		Email:    "alice@example.com",
		IsActive: true,
	}
	require.NoError(t, db.Create(u).Error)
	require.NoError(t, db.Create(&models.Session{
		ID:           100,
		UserID:       42,
		SessionToken: "sess-hash-abc",
		CreatedAt:    time.Now(),
	}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{
		ID:        200,
		UserID:    42,
		Name:      "ci-token",
		TokenHash: "pat-hash-xyz",
	}).Error)

	// Track auth-cache evictions.
	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	// Deactivate via UpdateUser.
	updated, err := c.UpdateUser(ctx, &UpdateUserRequest{
		ID:       42,
		IsActive: &[]bool{false}[0],
	})
	require.NoError(t, err)
	assert.False(t, updated.IsActive, "user must be marked inactive")

	// Session must be deleted.
	var sessions []models.Session
	require.NoError(t, db.Where("user_id = ?", 42).Find(&sessions).Error)
	assert.Empty(t, sessions, "deactivation must delete all user sessions")

	// PAT must be revoked.
	var pat models.PersonalAccessToken
	require.NoError(t, db.First(&pat, 200).Error)
	assert.True(t, pat.Revoked, "deactivation must revoke all user PATs")

	// Auth cache must be evicted for both tokens.
	assert.Contains(t, evicted, "sess-hash-abc", "session hash must be evicted from auth cache")
	assert.Contains(t, evicted, "pat-hash-xyz", "PAT hash must be evicted from auth cache")

	// Re-activating should NOT revoke anything new.
	evicted = nil
	_, err = c.UpdateUser(ctx, &UpdateUserRequest{
		ID:       42,
		IsActive: &active,
	})
	require.NoError(t, err)
	assert.Empty(t, evicted, "re-activation must not evict any tokens")
}

// TestUpdateUser_NoRevocation_WhenAlreadyInactive verifies that calling
// UpdateUser on a user who is already inactive does not trigger redundant
// session/PAT revocations (the deactivating transition only fires once).
func TestUpdateUser_NoRevocation_WhenAlreadyInactive(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	db := sqlitetest.OpenWithDialector(t, "kx_update_user_deactivation_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.PersonalAccessToken{},
		&models.AuditEvent{},
		&models.UserRole{},
		&models.Role{},
		// Group/UserGroup/GroupRole/Project/Environment are needed by
		// guardLastAdminDeactivation (#G02), which UpdateUser's deactivating
		// path now calls — without them the role lookup fails on a missing
		// table and the guard fails closed, refusing every deactivation.
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
	))

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	// Seed: a user who is already inactive.
	u := &models.User{
		ID:       43,
		Username: "bob",
		Email:    "bob@example.com",
		IsActive: false,
	}
	require.NoError(t, db.Create(u).Error)

	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	// UpdateUser with IsActive=false on an already-inactive user.
	inactive := false
	_, err := c.UpdateUser(ctx, &UpdateUserRequest{
		ID:       43,
		IsActive: &inactive,
	})
	require.NoError(t, err)
	assert.Empty(t, evicted, "no evictions when user was already inactive")
}

// TestUpdateUser_Deactivation_SucceedsDespiteSessionRevocationFailure is the
// G80 residual fix's own regression test: a DeleteSessionsForUserExcept
// failure must NOT fail the whole deactivating UpdateUser call. Before this
// fix, DeleteSessionsForUserExcept's error was the WithTransaction closure's
// return value, so it propagated and UpdateUser reported total failure even
// though the conditional write (UpdateUserIfActiveStateMatches) had already
// matched and applied -- the deactivation itself durably succeeded, but the
// caller was told it hadn't. This mattered most over storage.type: remote,
// where DeleteSessionsForUserExcept/RevokeAllPersonalAccessTokensForUser were
// BOTH hard-stubbed to errUnsupportedRemote until this fix, meaning EVERY
// remote deactivation failed outright. Uses MockStorage (not a real SQLite
// DB) specifically so DeleteSessionsForUserExcept can be made to fail in
// isolation while the conditional write still succeeds -- not reproducible
// against LocalStorage without a fault-injection seam.
func TestUpdateUser_Deactivation_SucceedsDespiteSessionRevocationFailure(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 44, Username: "carol", Email: "carol@example.com", IsActive: true}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs first
	// (ActorID unset -> 0, target 44) -- the fixture target holds no role
	// scopes, so it passes trivially through to the rest of this test.
	ms.On("GetUserRoleScopes", mock.Anything, uint(44)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(44)).Return(original, nil)
	// guardLastAdminDeactivation: target holds no roles anywhere -> not a
	// global admin -> the lockout guard returns nil immediately, same mocking
	// shape as the #1529 authority tests in sod_external_test.go/risk_exceptions_test.go.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(44), Scope{}).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(44), Scope{}).Return([]uint{}, nil)
	ms.On("ListSessionTokenHashesForUser", mock.Anything, uint(44)).Return([]string{"sess-hash-1"}, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), true).Return(true, nil)
	ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, uint(44)).Return([]string{"pat-hash-1"}, nil)
	// The failure under test: a real error (e.g. errUnsupportedRemote over
	// storage.type: remote, or a transient HTTP failure) from the session
	// deletion sub-call.
	ms.On("DeleteSessionsForUserExcept", mock.Anything, uint(44), uint(0)).Return(errors.New("simulated: session deletion transport failure"))
	// Discoverability: a failed revocation must still be audited (Success=false)
	// even though it doesn't fail the call -- see EventUserDeactivationCleanupFailed's
	// doc in users.go.
	var audited *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventUserDeactivationCleanupFailed {
			audited = ev
			return true
		}
		return false
	})).Return(nil)

	c := NewKeyorixCore(ms)
	updated, err := c.UpdateUser(context.Background(), &UpdateUserRequest{
		ID:       44,
		IsActive: &[]bool{false}[0],
	})
	require.NoError(t, err, "the deactivation must succeed even though session deletion failed")
	require.NotNil(t, updated)
	assert.False(t, updated.IsActive, "the user must still be marked inactive")
	require.NotNil(t, audited, "the revocation failure must be audited for discoverability")
	require.NotNil(t, audited.Success)
	assert.False(t, *audited.Success)
	assert.Contains(t, audited.Description, "session deletion transport failure")
}
