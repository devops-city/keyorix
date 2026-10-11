// core_s26_test.go — sprint-26 coverage blitz:
// users.go (UpdateUser branches, RestoreUser, validateCreateUserRequest, CreateUser),
// versions.go (GetSecretVersionsWithPermissionCheck success, GetSecretVersionWithPermissionCheck success,
//
//	GetLatestSecretVersionWithPermissionCheck success),
//
// setup_consume.go (expireInvitationIfOverdue, localPart, displayNameFromEmail),
// sharing_validation.go (validateUpdateShareRequest branches),
// audit_checkpoint.go (SeedAuditWatermark no-key, advanceAuditHighWater),
// access_review_revoke.go (verifyAccessReviewGrantExists more branches),
// permissions.go (CheckSecretPermission with direct share, no permission),
// service.go (HealthCheck nil-storage edge).
package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── users.go — validateCreateUserRequest branches ────────────────────────────

// testPassword satisfies the default password policy (MinLength=16, requires
// uppercase, lowercase, digit, and special character).
const testPassword = "Secret#Passw0rd!"

func TestValidateCreateUserRequest_MissingEmail(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	req := &CreateUserRequest{Username: "alice", Password: testPassword}
	// Email is empty → validation error from buildUserForCreate
	_, err := c.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Validation")
}

func TestValidateCreateUserRequest_MissingPassword(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	req := &CreateUserRequest{Username: "alice", Email: "a@x.com"}
	_, err := c.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Validation")
}

func TestValidateCreateUserRequest_MissingUsername(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	req := &CreateUserRequest{Email: "a@x.com", Password: testPassword}
	_, err := c.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Validation")
}

// ── users.go — CreateUser success path ──────────────────────────────────────

func TestCreateUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByUsername", mock.Anything, "alice").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(nil, storage.ErrUserNotFound)
	created := &models.User{ID: 10, Username: "alice", Email: "alice@x.com"}
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(created, nil)
	// HistoryCount=5 in default policy → AddPasswordHistory is called (best-effort).
	ms.On("AddPasswordHistory", mock.Anything, uint(10), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	// system_viewer role assignment — best-effort, non-fatal
	ms.On("GetRoleByName", mock.Anything, "system_viewer").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	u, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Username: "alice",
		Email:    "alice@x.com",
		Password: testPassword,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(10), u.ID)
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByUsername", mock.Anything, "alice").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "dup@x.com").Return(nil, storage.ErrUserNotFound)
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, storage.ErrDuplicateEmail)
	c := NewKeyorixCore(ms)
	_, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Username: "alice",
		Email:    "dup@x.com",
		Password: testPassword,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserAlreadyExists), "expected ErrUserAlreadyExists, got: %v", err)
}

func TestCreateUser_UsernameConflict(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByUsername", mock.Anything, "taken").Return(&models.User{ID: 99}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Username: "taken",
		Email:    "someone@x.com",
		Password: testPassword,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserAlreadyExists))
}

// ── users.go — UpdateUser branches ──────────────────────────────────────────

func TestUpdateUser_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestUpdateUser_UserNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser is ever reached.
	ms.On("GetUserRoleScopes", mock.Anything, uint(42)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(42)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 42})
	require.Error(t, err)
}

func TestUpdateUser_UsernameAlreadyExists(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	// Someone else already has username "bob"
	ms.On("GetUserByUsername", mock.Anything, "bob").Return(&models.User{ID: 2, Username: "bob"}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, Username: "bob"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserAlreadyExists))
}

func TestUpdateUser_EmailAlreadyExists(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	// Username unchanged, so GetUserByUsername is NOT called for it.
	// Email "bob@x.com" already taken by a different user (ID=2).
	ms.On("GetUserByEmail", mock.Anything, "bob@x.com").Return(&models.User{ID: 2, Email: "bob@x.com"}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, Email: "bob@x.com"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserAlreadyExists))
}

func TestUpdateUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), false).Return(true, nil)
	c := NewKeyorixCore(ms)
	u, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, DisplayName: "Alice Smith"})
	require.NoError(t, err)
	assert.Equal(t, "Alice Smith", u.DisplayName)
}

func TestUpdateUser_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), false).Return(false, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, DisplayName: "X"})
	require.Error(t, err)
}

// ── users.go — UpdateUser IsActive TOCTOU (the StateTransitionMissingCAS fix) ──
//
// Every UpdateUser call is a check-then-act (GetUser, mutate in memory, write
// back) racing any concurrent write to the same row, so every branch routes
// the final persist through storage.Storage.UpdateUserIfActiveStateMatches
// (asserting the wasActive value observed at the top of the call) instead of
// a plain unconditional UpdateUser/Save — including a plain field-only edit
// that never touches IsActive in the request. These tests prove (a) all three
// branches (deactivating, non-deactivating IsActive assertion, and the
// default no-IsActive-in-request case) route through the conditional write,
// (b) a lost race (matched=false) surfaces as ErrUserActiveStateConflict
// rather than being silently retried or ignored, and — mirroring #388's
// "second racing transition" test — (c) losing the race skips the
// deactivating branch's session/PAT revocation side effects.

// TestUpdateUser_Reactivate_UsesConditionalPath verifies a non-deactivating
// IsActive assertion (re-activating an inactive user) is routed through
// UpdateUserIfActiveStateMatches, not the plain UpdateUser.
func TestUpdateUser_Reactivate_UsesConditionalPath(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", IsActive: false}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 1 && u.IsActive
	}), false).Return(true, nil)
	c := NewKeyorixCore(ms)
	active := true
	u, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, IsActive: &active})
	require.NoError(t, err)
	assert.True(t, u.IsActive)
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// TestUpdateUser_RedundantSameValueAssertion_UsesConditionalPath verifies that
// even a "set to the same value it already is" IsActive assertion (wasActive
// == the requested value, so deactivating is false) still routes through the
// conditional path — the caller explicitly cares about this field either way.
func TestUpdateUser_RedundantSameValueAssertion_UsesConditionalPath(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", IsActive: true}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 1 && u.IsActive
	}), true).Return(true, nil)
	c := NewKeyorixCore(ms)
	active := true
	u, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, IsActive: &active})
	require.NoError(t, err)
	assert.True(t, u.IsActive)
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// TestUpdateUser_Reactivate_LostRace_ReturnsConflictError proves the
// non-deactivating branch's race is closed: a concurrent write that already
// moved is_active away from the value this call observed must surface as
// ErrUserActiveStateConflict, not be silently retried or dropped.
func TestUpdateUser_Reactivate_LostRace_ReturnsConflictError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", IsActive: false}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 1 && u.IsActive
	}), false).Return(false, nil)
	c := NewKeyorixCore(ms)
	active := true
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, IsActive: &active})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserActiveStateConflict), "expected ErrUserActiveStateConflict, got: %v", err)
}

// TestUpdateUser_Deactivate_LostRace_ReturnsConflictError proves the
// deactivating branch (inside WithTransaction) closes the same race, and that
// losing it skips PAT revocation / session deletion — the loser must not
// apply any part of its write, not just IsActive.
func TestUpdateUser_Deactivate_LostRace_ReturnsConflictError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", IsActive: true}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	// guardLastAdminDeactivation (#G02) runs first — fixture user holds no
	// roles, so IsGlobalAdmin resolves false and the guard is a no-op.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(1), Scope{}).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(1), Scope{}).Return([]uint{}, nil)
	ms.On("ListSessionTokenHashesForUser", mock.Anything, uint(1)).Return([]string{}, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 1 && !u.IsActive
	}), true).Return(false, nil)
	c := NewKeyorixCore(ms)
	inactive := false
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, IsActive: &inactive})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserActiveStateConflict), "expected ErrUserActiveStateConflict, got: %v", err)
	ms.AssertNotCalled(t, "RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything)
	ms.AssertNotCalled(t, "DeleteSessionsForUserExcept", mock.Anything, mock.Anything, mock.Anything)
}

// TestUpdateUser_PlainFieldUpdate_DoesNotUseActiveStateConditionalPath proves
// a plain field-only update (no IsActive in the request) is completely
// unaffected by this fix: it still persists via the unconditional plain
// UpdateUser, exactly as before, and never touches
// UpdateUserIfActiveStateMatches — so it cannot be spuriously rejected by an
// unrelated concurrent is_active change on the same row.
// TestUpdateUser_PlainFieldUpdate_UsesActiveStateConditionalPath verifies a
// request that never touches IsActive still routes its persist through
// UpdateUserIfActiveStateMatches (asserting the unchanged wasActive value) —
// a plain unconditional UpdateUser/Save here would be exactly the check-then-act
// race this fix closes, since GetUser's read and this write are not atomic.
func TestUpdateUser_PlainFieldUpdate_UsesActiveStateConditionalPath(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", IsActive: true}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 1 && u.DisplayName == "Alice Renamed"
	}), true).Return(true, nil)
	c := NewKeyorixCore(ms)
	u, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, DisplayName: "Alice Renamed"})
	require.NoError(t, err)
	assert.Equal(t, "Alice Renamed", u.DisplayName)
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// TestUpdateUser_PlainFieldUpdate_LostRace_ReturnsConflictError verifies that
// when the conditional write's precondition (is_active unchanged since
// GetUser) no longer holds at write time, a plain field-only update also
// surfaces ErrUserActiveStateConflict rather than silently overwriting a
// concurrent IsActive flip.
func TestUpdateUser_PlainFieldUpdate_LostRace_ReturnsConflictError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", IsActive: true}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser -- the fixture target holds no role scopes, so it passes
	// trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), true).Return(false, nil)
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, DisplayName: "Alice Renamed"})
	require.ErrorIs(t, err, ErrUserActiveStateConflict)
}

// ── users.go — RestoreUser ───────────────────────────────────────────────────

func TestRestoreUser_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RestoreUser(context.Background(), 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestRestoreUser_NotFoundErr(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs first.
	ms.On("GetUserRoleScopes", mock.Anything, uint(7)).Return([]Scope{}, nil)
	// storage.IsUserNotFound recognises ErrUserNotFound
	ms.On("RestoreUser", mock.Anything, uint(7)).Return(storage.ErrUserNotFound)
	c := NewKeyorixCore(ms)
	err := c.RestoreUser(context.Background(), 0, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found or not deleted")
}

func TestRestoreUser_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs first.
	ms.On("GetUserRoleScopes", mock.Anything, uint(7)).Return([]Scope{}, nil)
	ms.On("RestoreUser", mock.Anything, uint(7)).Return(errors.New("db exploded"))
	c := NewKeyorixCore(ms)
	err := c.RestoreUser(context.Background(), 0, 7)
	require.Error(t, err)
	// Non-not-found errors surface as storage failure.
}

func TestRestoreUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// S1 (CLI-split inventory #2012): RestoreUser now calls the admin-rank
	// ceiling first (actor 1 != target 5) — the fixture target holds no role
	// scopes, so it passes trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(5)).Return([]Scope{}, nil)
	ms.On("RestoreUser", mock.Anything, uint(5)).Return(nil)
	restored := &models.User{ID: 5, Username: "alice", AccountState: "active"}
	ms.On("GetUser", mock.Anything, uint(5)).Return(restored, nil)
	ms.On("UpdateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(restored, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.RestoreUser(context.Background(), 1, 5)
	require.NoError(t, err)
}

// ── versions.go — permission-check success paths ─────────────────────────────
//
// The owner path: GetSecret returns OwnerID == userID → permission granted
// without calling ListSharesBySecret at all.

func TestGetSecretVersionsWithPermissionCheck_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 10, OwnerID: 1}
	ms.On("GetSecret", mock.Anything, uint(10)).Return(secret, nil)
	ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
	versions := []*models.SecretVersion{{ID: 1, SecretNodeID: 10, VersionNumber: 1}}
	ms.On("GetSecretVersions", mock.Anything, uint(10)).Return(versions, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetSecretVersionsWithPermissionCheck(context.Background(), 10, 1)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestGetSecretVersionWithPermissionCheck_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 10, OwnerID: 1}
	ms.On("GetSecret", mock.Anything, uint(10)).Return(secret, nil)
	ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
	versions := []*models.SecretVersion{{ID: 1, SecretNodeID: 10, VersionNumber: 2}}
	ms.On("GetSecretVersions", mock.Anything, uint(10)).Return(versions, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetSecretVersionWithPermissionCheck(context.Background(), 10, 1, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, got.VersionNumber)
}

func TestGetLatestSecretVersionWithPermissionCheck_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 10, OwnerID: 1}
	ms.On("GetSecret", mock.Anything, uint(10)).Return(secret, nil)
	ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
	// GetLatestSecretVersion calls storage.GetSecretVersions (not GetLatestSecretVersion).
	latest := []*models.SecretVersion{{ID: 3, SecretNodeID: 10, VersionNumber: 1}}
	ms.On("GetSecretVersions", mock.Anything, uint(10)).Return(latest, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetLatestSecretVersionWithPermissionCheck(context.Background(), 10, 1)
	require.NoError(t, err)
	assert.Equal(t, uint(3), got.ID)
}

// ── CheckSecretPermission — direct-share and no-permission paths ─────────────

func TestCheckSecretPermission_DirectShare(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// Secret owned by user 99 (not user 1).
	secret := &models.SecretNode{ID: 5, OwnerID: 99}
	ms.On("GetSecret", mock.Anything, uint(5)).Return(secret, nil)
	shareID := uint(7)
	shares := []*models.ShareRecord{{
		ID:          shareID,
		SecretID:    5,
		RecipientID: 1,
		Permission:  "read",
		IsGroup:     false,
	}}
	ms.On("ListSharesBySecret", mock.Anything, uint(5)).Return(shares, nil)
	// #2941: a share applies only to a live member of the secret's project.
	ms.On("IsProjectMember", mock.Anything, uint(1), uint(0)).Return(true, nil)
	c := NewKeyorixCore(ms)
	pctx, err := c.CheckSecretPermission(context.Background(), 5, 1, PermissionRead)
	require.NoError(t, err)
	assert.Equal(t, "direct_share", pctx.Source)
}

func TestCheckSecretPermission_Denied(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 5, OwnerID: 99}
	ms.On("GetSecret", mock.Anything, uint(5)).Return(secret, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(5)).Return([]*models.ShareRecord{}, nil)
	// CheckGroupPermissions calls GetUserGroupsAt
	ms.On("GetUserGroupsAt", mock.Anything, uint(1), mock.Anything).Return([]*models.Group{}, nil)
	// ACL fallback (r140): no direct grant, and no ancestor folder grant either → deny.
	ms.On("GetSecretACL", mock.Anything, uint(5), uint(1)).Return(nil, errors.New("record not found"))
	ms.On("GetSecretAncestors", mock.Anything, uint(5)).Return([]uint{}, nil)
	// RBAC fallback (r124): no roles → deny.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(1), mock.Anything).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(1), mock.Anything).Return([]uint{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.CheckSecretPermission(context.Background(), 5, 1, PermissionRead)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}

// ── setup_consume.go — helpers ───────────────────────────────────────────────

func TestLocalPart_WithAt(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "alice", localPart("alice@example.com"))
}

func TestLocalPart_NoAt(t *testing.T) {
	t.Parallel()
	// When no '@' exists the whole string is returned.
	assert.Equal(t, "noatsign", localPart("noatsign"))
}

func TestDisplayNameFromEmail_NormalEmail(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "bob", displayNameFromEmail("bob@example.com"))
}

func TestDisplayNameFromEmail_NoAt(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "bob", displayNameFromEmail("bob"))
}

func TestExpireInvitationIfOverdue_NotExpired(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	future := time.Now().Add(time.Hour)
	inv := &models.ProjectInvitation{State: InvitationPending, ExpiresAt: &future}
	// Should not call UpdateProjectInvitation — nothing changes.
	c.expireInvitationIfOverdue(context.Background(), inv)
	assert.Equal(t, InvitationPending, inv.State)
}

func TestExpireInvitationIfOverdue_PastExpiry(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	past := time.Now().Add(-time.Hour)
	inv := &models.ProjectInvitation{ID: 1, State: InvitationPending, ExpiresAt: &past}
	ms.On("UpdateProjectInvitation", mock.Anything, inv).Return(true, nil)
	c := NewKeyorixCore(ms)
	c.expireInvitationIfOverdue(context.Background(), inv)
	assert.Equal(t, InvitationExpired, inv.State)
}

func TestExpireInvitationIfOverdue_AlreadyAccepted(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	past := time.Now().Add(-time.Hour)
	inv := &models.ProjectInvitation{State: InvitationAccepted, ExpiresAt: &past}
	// Not pending → no call to storage.
	c.expireInvitationIfOverdue(context.Background(), inv)
	assert.Equal(t, InvitationAccepted, inv.State)
}

func TestExpireInvitationIfOverdue_NoExpiry(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	inv := &models.ProjectInvitation{State: InvitationPending, ExpiresAt: nil}
	c.expireInvitationIfOverdue(context.Background(), inv)
	assert.Equal(t, InvitationPending, inv.State)
}

// ── sharing_validation.go — validateUpdateShareRequest ───────────────────────

func TestValidateUpdateShareRequest_Nil(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateUpdateShareRequest(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestValidateUpdateShareRequest_ZeroShareID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateUpdateShareRequest(&UpdateShareRequest{ShareID: 0, Permission: "read", UpdatedBy: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "share ID is required")
}

func TestValidateUpdateShareRequest_InvalidPermission(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateUpdateShareRequest(&UpdateShareRequest{ShareID: 1, Permission: "admin", UpdatedBy: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}

func TestValidateUpdateShareRequest_ZeroUpdatedBy(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateUpdateShareRequest(&UpdateShareRequest{ShareID: 1, Permission: "read", UpdatedBy: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "updatedBy is required")
}

func TestValidateUpdateShareRequest_Valid(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateUpdateShareRequest(&UpdateShareRequest{ShareID: 1, Permission: "write", UpdatedBy: 2})
	require.NoError(t, err)
}

// ── audit_checkpoint.go — SeedAuditWatermark no-key branch ──────────────────

func TestSeedAuditWatermark_NoKey(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// No audit checkpoint key set → AuditCheckpointsAvailable() is false → early return.
	c.SeedAuditWatermark(context.Background())
	// Must not panic; watermark stays 0.
	assert.Equal(t, int64(0), c.watermark())
}

func TestSeedAuditWatermark_WithKey_NoMark(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return("", false, nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	c.SeedAuditWatermark(context.Background())
	assert.Equal(t, int64(0), c.watermark())
}

// ── audit_checkpoint.go — advanceAuditHighWater ──────────────────────────────

func TestAdvanceAuditHighWater_WritesMetadata(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return("", false, nil)
	ms.On("SetSystemMetadata", mock.Anything, auditHighWaterKey, mock.AnythingOfType("string")).Return(nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	cp := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 1, HeadHash: "abc", KeyVersion: "v1"}
	c.advanceAuditHighWater(context.Background(), cp)
	assert.Equal(t, int64(5), c.watermark())
}

func TestAdvanceAuditHighWater_DoesNotLowerMark(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// Existing persisted mark at 100 events.
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	c.bumpWatermark(100)
	// Build a valid high-water value for 100 events so GetSystemMetadata returns it.
	bigCP := &models.AuditCheckpoint{ChainedEvents: 100, HeadID: 0, HeadHash: "", KeyVersion: "v1"}
	bigVal := auditHighWaterValue(bigCP, c.signCheckpoint(bigCP))
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return(bigVal, true, nil)
	// Trying to advance to 3 events (lower) must be a no-op write.
	cp := &models.AuditCheckpoint{ChainedEvents: 3, HeadID: 1, HeadHash: "xyz", KeyVersion: "v1"}
	c.advanceAuditHighWater(context.Background(), cp)
	// Watermark must remain at 100, not drop to 3.
	assert.Equal(t, int64(100), c.watermark())
}

// TestAdvanceAuditHighWater_WritesWitnessFile proves design-b3-backup-v2.md
// §6.3's wiring: once SetAuditHighWaterWitnessPath is set, every checkpoint
// write mirrors the persisted high-water mark to the witness file `admin
// restore` later compares an archive against.
func TestAdvanceAuditHighWater_WritesWitnessFile(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return("", false, nil)
	ms.On("SetSystemMetadata", mock.Anything, auditHighWaterKey, mock.AnythingOfType("string")).Return(nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")

	witnessPath := filepath.Join(t.TempDir(), auditverify.AuditHighWaterWitnessFileName)
	c.SetAuditHighWaterWitnessPath(witnessPath)

	cp := &models.AuditCheckpoint{ChainedEvents: 7, HeadID: 1, HeadHash: "abc", KeyVersion: "v1"}
	c.advanceAuditHighWater(context.Background(), cp)

	parsedCP, _, found, err := auditverify.ReadWitness(witnessPath)
	require.NoError(t, err)
	require.True(t, found, "witness file must exist after a checkpoint write with the path set")
	assert.Equal(t, int64(7), parsedCP.ChainedEvents)
}

// TestAdvanceAuditHighWater_NoWitnessPathIsANoop proves the default
// (auditHighWaterWitnessPath unset) does not attempt to write anything —
// the common case for any deployment `admin backup`/`admin restore` don't
// support, and every existing test core that never calls the setter.
func TestAdvanceAuditHighWater_NoWitnessPathIsANoop(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return("", false, nil)
	ms.On("SetSystemMetadata", mock.Anything, auditHighWaterKey, mock.AnythingOfType("string")).Return(nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")

	cp := &models.AuditCheckpoint{ChainedEvents: 7, HeadID: 1, HeadHash: "abc", KeyVersion: "v1"}
	require.NotPanics(t, func() { c.advanceAuditHighWater(context.Background(), cp) })
}

// ── access_review_revoke.go — verifyAccessReviewGrantExists branches ─────────

func TestVerifyAccessReviewGrantExists_RoleSource_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListProjectRoleAssignments", mock.Anything, uint(1)).Return([]storage.RoleAssignment{}, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "role",
		PrincipalID: 5,
		RoleID:      3,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
}

func TestVerifyAccessReviewGrantExists_RoleSource_Found(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	assignments := []storage.RoleAssignment{
		{PrincipalType: "user", PrincipalID: 5, RoleID: 3, EnvironmentID: 0},
	}
	ms.On("ListProjectRoleAssignments", mock.Anything, uint(1)).Return(assignments, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:        "role",
		PrincipalType: "user",
		PrincipalID:   5,
		RoleID:        3,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.NoError(t, err)
}

// TestVerifyAccessReviewGrantExists_RoleSource_Machine is #G51: a
// machine-identity role grant is queried from ListProjectMachineRoleAssignments,
// a separate storage call from the user/group path — and must NOT fall through
// to ListProjectRoleAssignments at all (it would never match there).
func TestVerifyAccessReviewGrantExists_RoleSource_Machine(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	assignments := []storage.RoleAssignment{
		{PrincipalType: "machine", PrincipalID: 50, RoleID: 3, EnvironmentID: 0},
	}
	ms.On("ListProjectMachineRoleAssignments", mock.Anything, uint(1)).Return(assignments, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:        "role",
		PrincipalType: "machine",
		PrincipalID:   50,
		RoleID:        3,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.NoError(t, err)
	ms.AssertNotCalled(t, "ListProjectRoleAssignments", mock.Anything, mock.Anything)
}

func TestVerifyAccessReviewGrantExists_DirectShare_Found(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(10)).Return(&models.SecretNode{ID: 10, ProjectID: 1}, nil)
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 10, RecipientID: 5, IsGroup: false},
	}
	ms.On("ListSharesBySecret", mock.Anything, uint(10)).Return(shares, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "direct_share",
		SecretID:    10,
		PrincipalID: 5,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.NoError(t, err)
}

// TestVerifyAccessReviewGrantExists_DirectShare_CrossProjectRefused is #G51: a
// share on a secret belonging to a DIFFERENT project must be refused even
// though the recipient/isGroup match — the secret's own project must gate the
// share lookup.
func TestVerifyAccessReviewGrantExists_DirectShare_CrossProjectRefused(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(10)).Return(&models.SecretNode{ID: 10, ProjectID: 2}, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "direct_share",
		SecretID:    10,
		PrincipalID: 5,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
	ms.AssertNotCalled(t, "ListSharesBySecret", mock.Anything, mock.Anything)
}

func TestVerifyAccessReviewGrantExists_DirectShare_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(10)).Return(&models.SecretNode{ID: 10, ProjectID: 1}, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(10)).Return([]*models.ShareRecord{}, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "direct_share",
		SecretID:    10,
		PrincipalID: 5,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
}

func TestVerifyAccessReviewGrantExists_Owner_Found(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(10)).Return(&models.SecretNode{ID: 10, ProjectID: 1, OwnerID: 5}, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "owner",
		SecretID:    10,
		PrincipalID: 5,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.NoError(t, err)
}

func TestVerifyAccessReviewGrantExists_Owner_WrongOwner(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(10)).Return(&models.SecretNode{ID: 10, ProjectID: 1, OwnerID: 99}, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "owner",
		SecretID:    10,
		PrincipalID: 5, // != 99
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
}

// TestVerifyAccessReviewGrantExists_Owner_CrossProjectRefused is #G51: a
// secret's ownership grant in a DIFFERENT project must be refused even when
// the owner ID matches, exactly mirroring the direct_share cross-project case.
func TestVerifyAccessReviewGrantExists_Owner_CrossProjectRefused(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(10)).Return(&models.SecretNode{ID: 10, ProjectID: 2, OwnerID: 5}, nil)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{
		Source:      "owner",
		SecretID:    10,
		PrincipalID: 5,
	}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
}

func TestVerifyAccessReviewGrantExists_Owner_MissingIDs(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{Source: "owner", SecretID: 0, PrincipalID: 0}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "principal_id and secret_id are required")
}

func TestVerifyAccessReviewGrantExists_UnknownSource(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{Source: "bogus"}
	err := c.verifyAccessReviewGrantExists(context.Background(), 1, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown access-review source")
}

// ── audit_checkpoint.go — parseAuditHighWater helper ─────────────────────────

func TestParseAuditHighWater_ValidValue(t *testing.T) {
	t.Parallel()
	cp := &models.AuditCheckpoint{ChainedEvents: 42, HeadID: 7, HeadHash: "deadbeef", KeyVersion: "v1"}
	val := auditHighWaterValue(cp, "sig123")
	parsed, sig, ok := parseAuditHighWater(val)
	require.True(t, ok)
	assert.Equal(t, int64(42), parsed.ChainedEvents)
	assert.Equal(t, uint(7), parsed.HeadID)
	assert.Equal(t, "deadbeef", parsed.HeadHash)
	assert.Equal(t, "sig123", sig)
}

func TestParseAuditHighWater_InvalidValue(t *testing.T) {
	t.Parallel()
	_, _, ok := parseAuditHighWater("not_valid")
	assert.False(t, ok)
}

func TestParseAuditHighWater_WrongVersion(t *testing.T) {
	t.Parallel()
	// Replace "v1" prefix with "v2" → wrong version
	val := "v2\x1f42\x1f7\x1fdeadbeef\x1fv1\x1fsig"
	_, _, ok := parseAuditHighWater(val)
	assert.False(t, ok)
}

// ── audit_checkpoint.go — checkpointCanonical / signCheckpoint ───────────────

func TestCheckpointCanonical_Format(t *testing.T) {
	t.Parallel()
	cp := &models.AuditCheckpoint{ChainedEvents: 10, HeadID: 3, HeadHash: "abc", KeyVersion: "kv1"}
	canon := checkpointCanonical(cp)
	assert.Contains(t, canon, "v1\x00")
	assert.Contains(t, canon, "abc")
}

func TestCheckpointSignatureValid_Roundtrip(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("testkeywithenoughbytes1234567890"), "v1")
	cp := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 1, HeadHash: "hash1", KeyVersion: "v1"}
	cp.Signature = c.signCheckpoint(cp)
	assert.True(t, c.checkpointSignatureValid(cp))
}

func TestCheckpointSignatureValid_TamperedData(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("testkeywithenoughbytes1234567890"), "v1")
	cp := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 1, HeadHash: "hash1", KeyVersion: "v1"}
	cp.Signature = c.signCheckpoint(cp)
	// Tamper with data after signing.
	cp.ChainedEvents = 4
	assert.False(t, c.checkpointSignatureValid(cp))
}

// ── validateShareSecretRequest — self-share path (sharing_validation.go) ─────

func TestValidateShareSecretRequest_SelfShare(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateShareSecretRequest(&ShareSecretRequest{
		SecretID:    1,
		RecipientID: 5,
		Permission:  "read",
		SharedBy:    5, // same as RecipientID
		IsGroup:     false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot share a secret with yourself")
}

func TestValidateShareSecretRequest_GroupSelfShareAllowed(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// IsGroup=true: RecipientID is a group ID, so same numeric value as SharedBy is fine.
	err := c.validateShareSecretRequest(&ShareSecretRequest{
		SecretID:    1,
		RecipientID: 5,
		Permission:  "read",
		SharedBy:    5,
		IsGroup:     true,
	})
	require.NoError(t, err)
}

// ── RevokeAccessReviewGrant — validation branches ────────────────────────────

func TestRevokeAccessReviewGrant_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RevokeAccessReviewGrant(context.Background(), 1, 0, AccessReviewDecision{Source: "role"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

func TestRevokeAccessReviewGrant_OwnerSource(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RevokeAccessReviewGrant(context.Background(), 1, 1, AccessReviewDecision{Source: "owner"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ownership cannot be revoked")
}

func TestRevokeAccessReviewGrant_UnknownSource(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RevokeAccessReviewGrant(context.Background(), 1, 1, AccessReviewDecision{Source: "mystery"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown access-review source")
}

func TestRevokeAccessReviewGrant_RoleMissingIDs(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RevokeAccessReviewGrant(context.Background(), 1, 1, AccessReviewDecision{
		Source:      "role",
		PrincipalID: 0, // missing
		RoleID:      0, // missing
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "principal_id and role_id are required")
}

// ── AttestAccessReviewGrant — basic validation ───────────────────────────────

func TestAttestAccessReviewGrant_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.AttestAccessReviewGrant(context.Background(), 1, 0, AccessReviewDecision{Source: "role"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

func TestAttestAccessReviewGrant_EmptySource(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.AttestAccessReviewGrant(context.Background(), 1, 1, AccessReviewDecision{Source: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source is required")
}
