package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestInviteGlobal_ValidatesAndSnapshotsAssignments(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()

	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline at EACH grant's own scope -- system role (global), plus each
	// project assignment below.
	for _, scope := range []Scope{{}, {ProjectID: 1}, {ProjectID: 2}} {
		store.On("GetUserRoleIDsAt", ctx, uint(9), scope).Return([]uint{100}, nil)
		store.On("GetUserGroupRoleIDsAt", ctx, uint(9), scope).Return([]uint{}, nil)
	}
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	// GetProject is a fixed stub in the mock (always resolves), so only roles are
	// asserted here.
	store.On("GetRoleByName", ctx, "system_auditor").Return(&models.Role{ID: 3, Name: "system_auditor"}, nil)
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5}, nil)
	store.On("GetRoleByName", ctx, "project_viewer").Return(&models.Role{ID: 6}, nil)
	store.On("CreateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		// Global invite: no project scope, system role set, assignments snapshotted.
		if inv.ProjectID != 0 || inv.Role != "" || inv.SystemRole != "system_auditor" || inv.State != InvitationPending {
			return false
		}
		var got []ProjectAssignment
		if err := json.Unmarshal([]byte(inv.AssignmentsJSON), &got); err != nil {
			return false
		}
		return len(got) == 2 // 3 in → one deduped
	})).Return(&models.ProjectInvitation{ID: 12, State: InvitationPending}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "invitation.created"
	})).Return(nil)

	inv, err := c.InviteGlobal(ctx, "carol@acme.io", "system_auditor", []ProjectAssignment{
		{ProjectID: 1, Role: "project_developer"},
		{ProjectID: 2, Role: "project_viewer"},
		{ProjectID: 1, Role: "project_viewer"}, // duplicate project — deduped
	}, 9, 0)

	require.NoError(t, err)
	assert.Equal(t, InvitationPending, inv.State)
	store.AssertExpectations(t)
}

func TestInviteGlobal_RejectsUnknownRole(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "system_viewer").Return(&models.Role{ID: 1}, nil)
	store.On("GetRoleByName", ctx, "bogus_role").Return(nil, assertNotFoundErr())
	// F6 sweep (2026-09-22): the roles.assign baseline does NOT apply here --
	// systemRole is left empty (the mandatory, non-discretionary system_viewer
	// default) -- see invitations.go's InviteGlobal comment for the full reasoning.

	_, err := c.InviteGlobal(ctx, "carol@acme.io", "", []ProjectAssignment{
		{ProjectID: 1, Role: "bogus_role"},
	}, 9, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown role")
	// Nothing persisted on a validation failure.
	store.AssertNotCalled(t, "CreateProjectInvitation", mock.Anything, mock.Anything)
}

// ADR-022: domain allowlist applies to global invites the same way it does to
// project-scoped invites (TestInviteToProject_RejectsDisallowedDomain).
func TestInviteGlobal_RejectsDisallowedDomain(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	c.SetMembershipDomainAllowlist([]string{"acme.com"})
	ctx := context.Background()

	_, err := c.InviteGlobal(ctx, "carol@evil.example", "", nil, 9, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")
	store.AssertNotCalled(t, "CreateProjectInvitation", mock.Anything, mock.Anything)
}

func TestInviteGlobal_RejectsAssignmentMissingRole(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "system_viewer").Return(&models.Role{ID: 1}, nil)
	// F6 sweep (2026-09-22): the roles.assign baseline does NOT apply here --
	// systemRole is left empty (the mandatory, non-discretionary system_viewer
	// default) -- see invitations.go's InviteGlobal comment for the full reasoning.

	_, err := c.InviteGlobal(ctx, "carol@acme.io", "", []ProjectAssignment{
		{ProjectID: 1, Role: ""},
	}, 9, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a project_id and a role")
	store.AssertNotCalled(t, "CreateProjectInvitation", mock.Anything, mock.Anything)
}

// #231: InviteGlobal must refuse to let a non-admin actor mint a global admin
// system role, mirroring the ceiling check InviteToProject already applies to
// its own role parameter. Uses real storage since the check goes through
// GetUserRoleIDsAt, not a mockable single call.
func TestInviteGlobal_RejectsNonAdminGrantingGlobalAdminRole(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// A non-admin actor holding only roles.write-adjacent permissions (project_developer,
	// no admin-tier role anywhere) must not be able to mint an "admin" invitation.
	nonAdminID := seedUserWithRole(t, st, "non-admin-inviter", "project_developer", storage.Scope{})

	_, err := c.InviteGlobal(ctx, "mallory@acme.io", "admin", nil, nonAdminID, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not hold permission")
}

// #231: the per-project assignments bundled into a global invite must be
// individually ceiling-checked too — a non-admin actor shouldn't be able to
// smuggle an admin-conferring project assignment into an otherwise-plain
// global invite.
func TestInviteGlobal_RejectsNonAdminGrantingProjectAdminAssignment(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	nonAdminID := seedUserWithRole(t, st, "non-admin-inviter-2", "project_developer", storage.Scope{})
	proj, err := st.CreateProject(ctx, &models.Project{Name: "target-project"})
	require.NoError(t, err)

	_, err = c.InviteGlobal(ctx, "mallory2@acme.io", "system_viewer", []ProjectAssignment{
		{ProjectID: proj.ID, Role: "project_admin"},
	}, nonAdminID, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not hold permission")
}

func TestInviteGlobal_DefaultsSystemViewer(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "system_viewer").Return(&models.Role{ID: 1, Name: "system_viewer"}, nil)
	// F6 sweep (2026-09-22): the roles.assign baseline does NOT apply here --
	// systemRole is left empty (the mandatory, non-discretionary system_viewer
	// default), so InviteGlobal calls requireGranterHoldsRolePermissionsNoBaseline
	// instead. See that call site's comment (invitations.go) for the full
	// reasoning; this is this test's own documented invariant too (its name).
	store.On("CreateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.SystemRole == "system_viewer" && inv.AssignmentsJSON == ""
	})).Return(&models.ProjectInvitation{ID: 13, State: InvitationPending}, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

	_, err := c.InviteGlobal(ctx, "dave@acme.io", "", nil, 9, 0)
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// applyInvitationGrants on a global invite must grant the system role at scope 0
// plus one membership per assignment.
func TestApplyInvitationGrants_GlobalInvite(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	anyAudit(store)
	ctx := context.Background()

	assignments, _ := json.Marshal([]ProjectAssignment{
		{ProjectID: 1, Role: "project_developer"},
		{ProjectID: 2, Role: "project_viewer"},
	})
	inv := &models.ProjectInvitation{
		ID: 12, ProjectID: 0, Email: "carol@acme.io", InvitedBy: 9,
		SystemRole: "system_auditor", AssignmentsJSON: string(assignments),
		ValidationModeAtInvite: ValidationModeOpen,
	}

	// F6 sweep (2026-09-22): granting ANY role now ALSO requires the granter
	// (the inviter, 9) hold roles.assign as a baseline, at EACH grant's own
	// scope -- system role (global), plus each project assignment below.
	for _, scope := range []storage.Scope{{ProjectID: 0}, {ProjectID: 1}, {ProjectID: 2}} {
		store.On("GetUserRoleIDsAt", ctx, uint(9), Scope(scope)).Return([]uint{100}, nil)
		store.On("GetUserGroupRoleIDsAt", ctx, uint(9), Scope(scope)).Return([]uint{}, nil)
	}
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	// System role grant at scope 0.
	store.On("GetRoleByName", ctx, "system_auditor").Return(&models.Role{ID: 3}, nil)
	store.On("GetRole", ctx, uint(3)).Return(&models.Role{ID: 3, Name: "system_auditor"}, nil) // #3546 role-scope check
	store.On("AssignRole", ctx, uint(20), uint(3), storage.Scope{ProjectID: 0}).Return(nil)
	// One membership per assignment (open mode → active → role granted).
	for _, a := range []struct {
		pid    uint
		role   string
		roleID uint
	}{{1, "project_developer", 5}, {2, "project_viewer", 6}} {
		store.On("GetRoleByName", ctx, a.role).Return(&models.Role{ID: a.roleID, Name: a.role}, nil)
		store.On("GetActiveProjectMembership", ctx, a.pid, uint(20)).Return(nil, assertNotFoundErr())
		store.On("CreateProjectMembership", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
			return m.ProjectID == a.pid && m.UserID == 20
		})).Return(&models.ProjectMembership{ProjectID: a.pid, UserID: 20, Role: a.role, State: MembershipActive}, nil)
		store.On("GetRole", ctx, a.roleID).Return(&models.Role{ID: a.roleID, Name: a.role}, nil) // #3546 role-scope check
		store.On("AssignRole", ctx, uint(20), a.roleID, storage.Scope{ProjectID: a.pid}).Return(nil)
	}

	err := c.applyInvitationGrants(ctx, inv, 20)
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// The system-role grant on global-invitation acceptance is the moment of privilege
// (up to and including super_admin) — it must land in the RBAC audit trail like every
// other grant path, not vanish with zero trace (#299). Uses real storage so
// ListRBACAuditLogs is exercised end to end.
func TestApplyInvitationGrants_SystemRoleIsRBACAudited(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// #93/#107/#141: the inviter must themselves hold every permission of the
	// role they're granting (system_auditor here) — give them "admin" so the
	// ceiling check's admin bypass applies, same as a real install where only an
	// admin can invite someone into a system_auditor-or-richer role.
	inviterID := seedUserWithRole(t, st, "admin-inviter", "admin", storage.Scope{})
	invitee, err := st.CreateUser(ctx, foldedTestUser(t, "carol", "carol@example.com"))
	require.NoError(t, err)

	inv := &models.ProjectInvitation{
		ID: 1, ProjectID: 0, Email: invitee.Email, InvitedBy: inviterID,
		SystemRole: "system_auditor",
	}

	require.NoError(t, c.applyInvitationGrants(ctx, inv, invitee.ID))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var assigned *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleAssigned {
			assigned = e
		}
	}
	require.NotNil(t, assigned, "global-invitation system-role grant must appear in the RBAC audit trail")
	require.NotNil(t, assigned.ActorUserID)
	assert.Equal(t, inviterID, *assigned.ActorUserID)
	require.NotNil(t, assigned.TargetUserID)
	assert.Equal(t, invitee.ID, *assigned.TargetUserID)
}
