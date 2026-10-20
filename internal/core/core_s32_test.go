// core_s32_test.go — sprint-32 coverage blitz:
// membership_lifecycle.go (wrapCreateMembershipError),
// rbac_management.go (RemovePermissionFromRole, assignUserRoleSystemGrant),
// pat.go (ListOwnPATs),
// project_members.go (SetProjectMemberRole),
// scim_groups.go (applyGroupMembershipChanges),
// rotation_policies.go (CreateRotationPolicy),
// login_lockout.go (UnlockUser extra branches).
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── membership_lifecycle.go — wrapCreateMembershipError ──────────────────

func TestWrapCreateMembershipError_Duplicate(t *testing.T) {
	t.Parallel()
	err := wrapCreateMembershipError(storage.ErrDuplicateActiveMembership)
	assert.Contains(t, err.Error(), "already has a membership")
}

func TestWrapCreateMembershipError_Other(t *testing.T) {
	t.Parallel()
	other := errors.New("generic error")
	err := wrapCreateMembershipError(other)
	assert.Contains(t, err.Error(), "failed to create membership")
}

// ── pat.go — ListOwnPATs ──────────────────────────────────────────────────

func TestListOwnPATs_ZeroUserID(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	_, err := c.ListOwnPATs(context.Background(), 0)
	require.Error(t, err)
}

func TestListOwnPATs_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	tokens := []*models.PersonalAccessToken{{ID: 1, UserID: 5, Name: "mytoken"}}
	ms.On("ListPersonalAccessTokensByUser", mock.Anything, uint(5)).Return(tokens, nil)
	c := NewKeyorixCore(ms)
	result, err := c.ListOwnPATs(context.Background(), 5)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListOwnPATs_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListPersonalAccessTokensByUser", mock.Anything, uint(5)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.ListOwnPATs(context.Background(), 5)
	require.Error(t, err)
}

// ── rbac_management.go — RemovePermissionFromRole ─────────────────────────

func TestRemovePermissionFromRole_Success_s32(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	role := &models.Role{ID: 1, Name: "myrole"}
	ms.On("GetRole", mock.Anything, uint(1)).Return(role, nil)
	// RemovePermissionFromRole on MockStorage is a hardcoded stub returning nil.
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.RemovePermissionFromRole(context.Background(), 0, 1, 2)
	require.NoError(t, err)
}

func TestRemovePermissionFromRole_RoleNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.RemovePermissionFromRole(context.Background(), 0, 99, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── scim_groups.go — applyGroupMembershipChanges ──────────────────────────

func TestApplyGroupMembershipChanges_RemoveAndAdd(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// guardLastGlobalAdminMembership (#G02) precheck for user 1's removal — no
	// admin roles seeded in this fixture, so it's a no-op. #2496: the admin-role
	// set is now resolved structurally (MockStorage.ListAdminBypassRoleIDs
	// returns none) rather than by three GetRoleByName name lookups, so there is
	// nothing left to stub here.
	// guardLastProjectAdminGroupMembership (core-project-members.json#3) precheck
	// for user 1's removal — no group role assignments in this fixture, so it's a
	// no-op too.
	ms.On("ListGroupRoleAssignments", mock.Anything, uint(10)).Return([]storage.RoleAssignment{}, nil)
	// user 1 is in current but NOT in want → RemoveUserFromGroup (global: projectID=0).
	ms.On("RemoveUserFromGroup", mock.Anything, uint(1), uint(10), uint(0)).Return(nil)
	// user 2 is in current AND in want → no-op.
	// user 3 is in toAdd → AddUserToGroup (global: projectID=0).
	ms.On("AddUserToGroup", mock.Anything, uint(3), uint(10), uint(0)).Return(nil)
	// MERGE-FIX-3482G: removing user 1 (a member, read under the guard locks) and
	// adding user 3 is a mixed request, so two commits: the removal first, its row
	// owed (recorded, then appended and claimed), then the add, its row written in
	// that transaction (fail closed).
	ms.On("ListGroupMembers", mock.Anything, uint(10)).Return([]*models.User{{ID: 1}, {ID: 2}}, nil)
	ms.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil)
	ms.On("ClaimPendingAuditEvent", mock.Anything, mock.Anything).Return(true, nil).Maybe() // the mock assigns no pending id
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	want := map[uint]bool{2: true}
	current := []*models.User{{ID: 1}, {ID: 2}}
	toAdd := []uint{3}
	audit := func(tgt auditTarget) {
		c.writeAuditEventFullOn(context.Background(), tgt, EventSCIMGroupUpdated, nil, nil, nil, "", "test")
	}
	require.NoError(t, c.applyGroupMembershipChanges(context.Background(), 10, want, current, toAdd, nil, audit, audit))
	ms.AssertExpectations(t)
}

// ── project_members.go — SetProjectMemberRole ─────────────────────────────
// Signature: (ctx, actorID, projectID, userID uint, roleName string)

func TestSetProjectMemberRole_RoleNotFound_s32(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRoleByName", mock.Anything, "nonexistent").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	// actorID=0, projectID=1, userID=1, roleName="nonexistent"
	err := c.SetProjectMemberRole(context.Background(), 0, 1, 1, "nonexistent", false)
	require.Error(t, err)
}

// ── rotation_policies.go — CreateRotationPolicy ───────────────────────────

func TestCreateRotationPolicy_MissingEnvID(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	req := &CreateRotationPolicyRequest{
		Name:          "my-policy",
		Scope:         "environment",
		IntervalDays:  30,
		EnvironmentID: nil, // missing → error
	}
	_, err := c.CreateRotationPolicy(context.Background(), 1, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment_id")
}

func TestCreateRotationPolicy_AlertDaysGEInterval(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	projID := uint(1)
	req := &CreateRotationPolicyRequest{
		Name:            "my-policy",
		Scope:           "project",
		IntervalDays:    10,
		AlertDaysBefore: 10, // must be < interval_days → error
		ProjectID:       &projID,
	}
	_, err := c.CreateRotationPolicy(context.Background(), 1, req)
	require.Error(t, err)
}

// ── rbac_management.go — assignUserRoleSystemGrant ───────────────────────

func TestAssignUserRoleSystemGrant_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// requireNoSoDViolation: ListSoDPolicies is a smart stub returning nil policies → OK.
	// AssignRole must be mocked.
	ms.On("AssignRole", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.assignUserRoleSystemGrant(context.Background(), 0, 1, 2, Scope{})
	require.NoError(t, err)
}

func TestAssignUserRoleSystemGrant_AssignRoleError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("AssignRole", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope")).Return(errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.assignUserRoleSystemGrant(context.Background(), 0, 1, 2, Scope{})
	require.Error(t, err)
}

// ── login_lockout.go — UnlockUser ────────────────────────────────────────

func TestUnlockUser_ZeroID(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	err := c.UnlockUser(context.Background(), 0, 0)
	require.Error(t, err)
}

func TestUnlockUser_UserNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.UnlockUser(context.Background(), 0, 5)
	require.Error(t, err)
}
