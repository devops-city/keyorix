package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newInviteCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

func TestInviteToProject(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline before the (here vacuous, since GetRolePermissions defaults to
	// nil/no-mock) per-role escalation-by-proxy check.
	store.On("GetUserRoleIDsAt", ctx, uint(9), Scope{ProjectID: 1}).Return([]uint{100}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	store.On("CreateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.State == InvitationPending && inv.Email == "a@b.com" && inv.ProjectID == 1 && inv.ExpiresAt != nil
	})).Return(&models.ProjectInvitation{ID: 7, State: InvitationPending}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "invitation.created"
	})).Return(nil)

	inv, err := c.InviteToProject(ctx, 1, "a@b.com", "project_developer", 9, 0)
	require.NoError(t, err)
	assert.Equal(t, InvitationPending, inv.State)
	store.AssertExpectations(t)
}

// #1573: a machine identity holding project-scoped roles.assign can invite a
// project member. invitedBy (0, ADR-030) alone loses which machine did it;
// InvitedByMachineIdentityID must carry it through to the persisted row.
func TestInviteToProject_RecordsActingMachineIdentity(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	// mock.Anything for ctx, not the exact ctx value: PART2-CONT-6's fix tags
	// ctx with WithSelfMachineGranter for a real machine inviter
	// (invitedByMachineID != 0, as this test's own name says) before the
	// storage calls below, which legitimately changes ctx's identity --
	// that's the fix working as intended, not something this test should
	// pin down.
	store.On("GetRoleByName", mock.Anything, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline -- machine 42 resolves via AuthorizePrincipal's machine branch.
	store.On("GetMachineRoleIDsAt", mock.Anything, uint(42), Scope{ProjectID: 1}).Return([]uint{200}, nil)
	store.On("RoleSetHasPermission", mock.Anything, []uint{200}, "roles.assign").Return(true, nil)
	store.On("CreateProjectInvitation", mock.Anything, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.InvitedBy == 0 && inv.InvitedByMachineIdentityID == 42
	})).Return(&models.ProjectInvitation{ID: 8, State: InvitationPending}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	_, err := c.InviteToProject(ctx, 1, "a@b.com", "project_developer", 0, 42)
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// ADR-022: domain allowlist. Default (no allowlist configured) imposes no
// restriction — covered implicitly by TestInviteToProject above, which
// succeeds with no allowlist set.

func TestInviteToProject_RejectsDisallowedDomain(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	c.SetMembershipDomainAllowlist([]string{"acme.com"})
	ctx := context.Background()

	_, err := c.InviteToProject(ctx, 1, "a@evil.example", "project_developer", 9, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")
	store.AssertNotCalled(t, "CreateProjectInvitation", mock.Anything, mock.Anything)
}

func TestInviteToProject_AllowsAllowlistedDomain(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	c.SetMembershipDomainAllowlist([]string{"acme.com"})
	ctx := context.Background()
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline before the domain-allowlist logic (this test's actual subject) runs.
	store.On("GetUserRoleIDsAt", ctx, uint(9), Scope{ProjectID: 1}).Return([]uint{100}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	store.On("CreateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.State == InvitationPending && inv.Email == "a@acme.com"
	})).Return(&models.ProjectInvitation{ID: 8, State: InvitationPending}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "invitation.created"
	})).Return(nil)

	inv, err := c.InviteToProject(ctx, 1, "a@acme.com", "project_developer", 9, 0)

	require.NoError(t, err)
	assert.Equal(t, InvitationPending, inv.State)
	store.AssertExpectations(t)
}

func TestRevokeInvitation_RejectsNonPending(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetProjectInvitation", ctx, uint(7)).Return(&models.ProjectInvitation{ID: 7, ProjectID: 1, State: InvitationAccepted}, nil)

	err := c.RevokeInvitation(ctx, 1, 7, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
	store.AssertNotCalled(t, "UpdateProjectInvitation", mock.Anything, mock.Anything)
}

// Cross-project guard: revoking an invitation in project 2 while authorized for
// project 1 must be rejected.
func TestRevokeInvitation_RejectsOtherProject(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetProjectInvitation", ctx, uint(7)).Return(&models.ProjectInvitation{ID: 7, ProjectID: 2, State: InvitationPending}, nil)

	err := c.RevokeInvitation(ctx, 1, 7, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "UpdateProjectInvitation", mock.Anything, mock.Anything)
}

func TestApproveAccessRequest_GrantsRole(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: AccessRequestPending,
	}, nil)
	store.On("GetProject", ctx, uint(1)).Return(&models.Project{ID: 1}, nil)
	// F6 sweep (2026-09-22): approving now ALSO requires roles.assign as a
	// baseline before the role-upgrade grant (this test's actual subject) runs.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{100}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	// Admin upgrades the grant to developer.
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	store.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "test-role-5"}, nil).Maybe() // #3546 role-scope check
	store.On("AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("UpdateAccessRequest", ctx, mock.MatchedBy(func(r *models.AccessRequest) bool {
		return r.State == AccessRequestApproved && r.GrantedRole == "project_developer" && r.ResolvedBy == 9
	})).Return(true, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "access_request.approved"
	})).Return(nil)
	// The grant now also routes through the audited RBAC choke point (#298), which
	// records its own structured role.assigned event alongside the generic one above.
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleAssigned
	})).Return(nil)
	store.On("ListAccessRequestApprovals", ctx, uint(3)).Return([]*models.AccessRequestApproval{}, nil)
	store.On("CreateAccessRequestApproval", ctx, mock.Anything).Return(nil)

	allowNotifications(store) // best-effort outcome notification to the requester
	out, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "project_developer", 0)
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, out.State)
	store.AssertCalled(t, "AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1})
	store.AssertCalled(t, "LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleAssigned
	}))
}

func TestApproveAccessRequest_FallsBackToSuggestedRole(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: AccessRequestPending,
	}, nil)
	store.On("GetProject", ctx, uint(1)).Return(&models.Project{ID: 1}, nil)
	store.On("GetRoleByName", ctx, "project_viewer").Return(&models.Role{ID: 6, Name: "project_viewer"}, nil)
	// F6 sweep (2026-09-22): approving now ALSO requires roles.assign as a
	// baseline before the suggested-role fallback logic (this test's actual
	// subject) runs.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{100}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	store.On("GetRole", mock.Anything, uint(6)).Return(&models.Role{ID: 6, Name: "test-role-6"}, nil).Maybe() // #3546 role-scope check
	store.On("AssignRole", ctx, uint(2), uint(6), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("UpdateAccessRequest", ctx, mock.Anything).Return(true, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)
	store.On("ListAccessRequestApprovals", ctx, uint(3)).Return([]*models.AccessRequestApproval{}, nil)
	store.On("CreateAccessRequestApproval", ctx, mock.Anything).Return(nil)

	allowNotifications(store) // best-effort outcome notification to the requester
	// Empty grantedRole → uses the suggested role.
	out, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "project_viewer", out.GrantedRole)
}

// stubAdminRoleLookups registers the admin role names so roleSetContainsAdmin can
// resolve them; super_admin=1, admin=2, system_admin=3, project_admin=4.
func stubAdminRoleLookups(store *MockStorage, ctx context.Context) {
	store.On("GetRoleByName", ctx, "super_admin").Return(&models.Role{ID: 1}, nil)
	store.On("GetRoleByName", ctx, "admin").Return(&models.Role{ID: 2}, nil)
	store.On("GetRoleByName", ctx, "system_admin").Return(&models.Role{ID: 3}, nil)
	store.On("GetRoleByName", ctx, "project_admin").Return(&models.Role{ID: 4}, nil)
}

// The same admin-role ceiling applies to project invitations: a non-admin inviter
// (roles.assign but not admin) cannot invite someone as an admin role — escalation-by-
// proxy. A non-admin role invite still works.
func TestInviteToProject_EnforcesAdminCeiling(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	stubAdminRoleLookups(store, ctx)
	// Inviter 9 holds only a non-admin role (id 6) at the project.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{6}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{6}).Return(false, nil)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline -- role 6 DOES carry it (this test's inviter is meant to be an
	// ordinary authorized inviter, just not admin-tier), used by both invite
	// calls below.
	store.On("RoleSetHasPermission", ctx, []uint{6}, "roles.assign").Return(true, nil)
	// FIX-1: the ceiling now derives from project_admin's own bundled
	// permissions rather than its name, so the mock must resolve them —
	// and the inviter's own role (6) must not carry that permission either.
	store.On("GetRolePermissions", ctx, uint(4)).Return([]*models.Permission{{ID: 50, Name: "projects.admin"}}, nil)
	store.On("RoleSetHasPermission", ctx, []uint{6}, "projects.admin").Return(false, nil)
	// project_developer (role 6) itself bundles no permissions relevant to this
	// test, so the second invite below (inviting AS project_developer) hits the
	// ceiling check for role 6 too.
	store.On("GetRolePermissions", ctx, uint(6)).Return([]*models.Permission{}, nil)

	// Inviting as project_admin → refused before any invitation is created.
	_, err := c.InviteToProject(ctx, 1, "a@b.io", "project_admin", 9, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not hold permission")
	store.AssertNotCalled(t, "CreateProjectInvitation", mock.Anything, mock.Anything)

	// Inviting as a non-admin role is allowed (isAdminRoleName false → no ceiling).
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 6, Name: "project_developer"}, nil)
	store.On("CreateProjectInvitation", ctx, mock.Anything).Return(&models.ProjectInvitation{ID: 1}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	_, err = c.InviteToProject(ctx, 1, "c@d.io", "project_developer", 9, 0)
	require.NoError(t, err)
}

// Privilege ceiling: a non-admin approver cannot sign off a request that grants an
// admin role — that would mint a principal more powerful than the approver.
func TestApproveAccessRequest_RejectsAdminGrantByNonAdmin(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "admin", State: AccessRequestPending,
	}, nil)
	store.On("GetProject", ctx, uint(1)).Return(&models.Project{ID: 1}, nil)
	stubAdminRoleLookups(store, ctx)
	// Approver 9 holds only a non-admin role (id 6) at the project.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{6}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{6}).Return(false, nil)
	// F6 sweep (2026-09-22): granting ANY role now ALSO requires roles.assign
	// as a baseline -- role 6 doesn't carry that either, so the baseline
	// check itself now refuses this approver first (same "do not hold
	// permission" error shape the original system.admin-specific denial
	// below asserted on).
	store.On("RoleSetHasPermission", ctx, []uint{6}, "roles.assign").Return(false, nil)
	// FIX-1: the ceiling now derives from admin's own bundled permissions
	// rather than its name, so the mock must resolve them — and the
	// approver's own role (6) must not carry that permission either.
	store.On("GetRolePermissions", ctx, uint(2)).Return([]*models.Permission{{ID: 51, Name: "system.admin"}}, nil)
	store.On("RoleSetHasPermission", ctx, []uint{6}, "system.admin").Return(false, nil)

	_, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "admin", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not hold permission")
	// The grant was refused before any role assignment or approval record.
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "CreateAccessRequestApproval", mock.Anything, mock.Anything)
}

// An admin approver may grant an admin role — the ceiling permits an equal-or-higher
// authority to sign off.
func TestApproveAccessRequest_AdminApproverMayGrantAdmin(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "admin", State: AccessRequestPending,
	}, nil)
	store.On("GetProject", ctx, uint(1)).Return(&models.Project{ID: 1}, nil)
	stubAdminRoleLookups(store, ctx)
	// Approver 9 holds the admin role (id 2) at the project.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{2}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{2}).Return(true, nil)
	store.On("GetRole", mock.Anything, uint(2)).Return(&models.Role{ID: 2, Name: "test-role-2"}, nil).Maybe() // #3546 role-scope check
	store.On("AssignRole", ctx, uint(2), uint(2), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("UpdateAccessRequest", ctx, mock.Anything).Return(true, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)
	store.On("ListAccessRequestApprovals", ctx, uint(3)).Return([]*models.AccessRequestApproval{}, nil)
	store.On("CreateAccessRequestApproval", ctx, mock.Anything).Return(nil)
	allowNotifications(store)

	out, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "admin", 0)
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, out.State)
}

// A request whose TTL has elapsed is refused on the approve path (lazy expiry), not
// only on the list path — GetAccessRequest returns the stored record verbatim.
func TestApproveAccessRequest_RejectsExpired(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	past := time.Date(2026, 6, 5, 11, 0, 0, 0, time.UTC) // before the fixed clock (12:00)
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: AccessRequestPending, ExpiresAt: &past,
	}, nil)
	store.On("GetProject", ctx, uint(1)).Return(&models.Project{ID: 1}, nil)
	store.On("UpdateAccessRequest", ctx, mock.MatchedBy(func(r *models.AccessRequest) bool {
		return r.State == AccessRequestExpired
	})).Return(true, nil)

	_, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestApproveAccessRequest_RejectsNonPending(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{ID: 3, ProjectID: 1, State: AccessRequestApproved}, nil)

	_, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "project_viewer", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Cross-project guard: approving a request that belongs to project 2 while the
// caller is authorized for project 1 must be rejected — otherwise the role grant
// lands in a project the caller has no rights over (privilege escalation).
func TestApproveAccessRequest_RejectsOtherProject(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 2, UserID: 2, SuggestedRole: "project_admin", State: AccessRequestPending,
	}, nil)

	_, err := c.ApproveAccessRequestWithExpiry(ctx, 1, 3, 9, 0, "project_admin", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// #371: a request against a project that no longer exists (never created, or already
// soft-deleted) must be refused at creation time — otherwise it could sit pending
// against a project retired specifically to shut off further access, waiting to be
// approved (and go live) whenever the project is restored.
func TestRequestProjectAccess_RejectsUnknownProject(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetProject", ctx, uint(404)).Return(nil, fmt.Errorf("project not found"))

	_, err := c.RequestProjectAccess(ctx, 404, 2, "", "please")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "CreateAccessRequest", mock.Anything, mock.Anything)
}

// #371: RequestProjectAccess must refuse a soft-deleted project the same way it refuses
// an unknown one — GetProject's default soft-delete scope makes this the same check.
func TestRequestProjectAccess_RejectsSoftDeletedProject(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester", "requester@example.com"))
	require.NoError(t, err)
	proj, err := st.CreateProject(ctx, &models.Project{Name: "retiring"})
	require.NoError(t, err)
	require.NoError(t, st.DeleteProject(ctx, proj.ID))

	_, err = c.RequestProjectAccess(ctx, proj.ID, requester.ID, "project_viewer", "please")
	require.Error(t, err, "requesting access to a soft-deleted project must be refused")
}

// TestRequestProjectAccess_RefusesDuplicatePending is #G82: an authenticated
// user must not be able to flood a project with unbounded pending access
// requests (and the admin notification each one fires) by calling this
// endpoint repeatedly — a second request while the first is still pending
// must be refused.
func TestRequestProjectAccess_RefusesDuplicatePending(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester", "requester@example.com"))
	require.NoError(t, err)
	proj, err := st.CreateProject(ctx, &models.Project{Name: "flood-target"})
	require.NoError(t, err)

	first, err := c.RequestProjectAccess(ctx, proj.ID, requester.ID, "", "please")
	require.NoError(t, err)
	require.Equal(t, AccessRequestPending, first.State)

	_, err = c.RequestProjectAccess(ctx, proj.ID, requester.ID, "", "please again")
	require.Error(t, err, "a second request while the first is still pending must be refused")
	assert.Contains(t, err.Error(), "already have a pending")

	requests, err := c.ListAccessRequests(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, requests, 1, "the flood attempt must not have created a second row")
}

// #371: ApproveAccessRequestWithExpiry must refuse to approve a request whose target
// project has been soft-deleted in the meantime — DeleteProject never touches
// access_requests, so without this check a stale pending request could be approved
// after the fact and go live the moment the project is later restored, against
// potentially-stale intent and with no re-review.
func TestApproveAccessRequestWithExpiry_RejectsSoftDeletedProject(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	approver, err := st.CreateUser(ctx, foldedTestUser(t, "approver2", "approver2@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, approver.ID, adminRole.ID, storage.Scope{}))
	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester2", "requester2@example.com"))
	require.NoError(t, err)

	proj, err := st.CreateProject(ctx, &models.Project{Name: "retiring2"})
	require.NoError(t, err)
	req, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: proj.ID, UserID: requester.ID, SuggestedRole: "project_viewer", State: AccessRequestPending,
	})
	require.NoError(t, err)

	// The project is soft-deleted AFTER the request was filed, but before it's approved.
	require.NoError(t, st.DeleteProject(ctx, proj.ID))

	_, err = c.ApproveAccessRequestWithExpiry(ctx, proj.ID, req.ID, approver.ID, 0, "", 0)
	require.Error(t, err, "approving a request against a soft-deleted project must be refused")
	assert.Contains(t, err.Error(), "no longer exists")

	// No role grant landed.
	ids, err := st.GetUserRoleIDsAt(ctx, requester.ID, storage.Scope{ProjectID: proj.ID})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestWithdrawAccessRequest_OwnershipChecked(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{ID: 3, UserID: 2, State: AccessRequestPending}, nil)

	// A different user cannot withdraw it. #G14: the denial is the same generic
	// "not found" a nonexistent request ID gets, not a distinct ownership message.
	err := c.WithdrawAccessRequest(ctx, 3, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "UpdateAccessRequest", mock.Anything, mock.Anything)
}

func TestListProjectInvitations_LazyExpire(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	past := c.now().Add(-1 * time.Hour)
	store.On("ListProjectInvitations", ctx, uint(1)).Return([]*models.ProjectInvitation{
		{ID: 1, State: InvitationPending, ExpiresAt: &past},
	}, nil)
	// The expired pending invite is persisted as expired.
	store.On("UpdateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.State == InvitationExpired
	})).Return(true, nil)

	out, err := c.ListProjectInvitations(ctx, 1)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, InvitationExpired, out[0].State)
}

// #345: InviteToProjectWithLink used to call the unthrottled provisionSetupLink
// directly, so a principal with only project-scoped roles.assign could loop-call the
// invite endpoint for the same target email to fire unbounded real SMTP sends. It must
// now hit the same per-(purpose, email) min-interval throttle ResendInvitationLink
// already enforces (#183).
func TestInviteToProjectWithLink_ThrottlesRepeatedInitialInvites(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)
	ctx := context.Background()
	fixed := c.now()
	anyAudit(store)

	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline, before the resend-throttle logic (this test's actual subject) runs.
	store.On("GetUserRoleIDsAt", ctx, uint(9), Scope{ProjectID: 1}).Return([]uint{100}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(9), Scope{ProjectID: 1}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{100}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{100}, "roles.assign").Return(true, nil)
	store.On("CreateProjectInvitation", ctx, mock.AnythingOfType("*models.ProjectInvitation")).
		Return(&models.ProjectInvitation{ID: 7, State: InvitationPending}, nil)
	store.On("SupersedeActiveSetupTokens", ctx, SetupPurposeInvitationAccept, "a@b.com", ptr(uint(1))).Return(nil)
	store.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

	// First invite: a zero prior count on both windows, so it succeeds and mints a
	// token — this is the send that a same-email loop must now be throttled against.
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "a@b.com", fixed.Add(-24*time.Hour)).Return(int64(0), nil).Once()
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "a@b.com", fixed.Add(-resendMinInterval)).Return(int64(0), nil).Once()

	inv1, prov1, err := c.InviteToProjectWithLink(ctx, 1, "a@b.com", "project_developer", 9, 0)
	require.NoError(t, err)
	require.NotNil(t, inv1)
	require.NotNil(t, prov1)
	assert.True(t, prov1.Delivered)

	// Second call for the SAME target email, immediately after. Pre-fix this looped
	// straight through to a second real SMTP send with no check at all.
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "a@b.com", fixed.Add(-24*time.Hour)).Return(int64(1), nil).Once()
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "a@b.com", fixed.Add(-resendMinInterval)).Return(int64(1), nil).Once()

	inv2, prov2, err := c.InviteToProjectWithLink(ctx, 1, "a@b.com", "project_developer", 9, 0)
	require.Error(t, err, "the second same-email invite must be throttled, not delivered")
	assert.Contains(t, err.Error(), "wait")
	assert.Nil(t, prov2)
	// The invitation row itself still exists (same contract as a base_url-unset
	// failure) — only the link/email send is throttled, so the caller can resend once
	// the window passes rather than losing the invite.
	require.NotNil(t, inv2)
	store.AssertNumberOfCalls(t, "CreateSetupToken", 1)
}

// #1573: a machine identity inviting a project member also mints the setup
// token via InviteToProjectWithLink. createdBy (0, ADR-030) alone loses which
// machine did it; SetupToken.CreatedByMachineIdentityID must carry it through.
func TestInviteToProjectWithLink_RecordsActingMachineIdentityOnSetupToken(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)
	ctx := context.Background()
	fixed := c.now()
	anyAudit(store)

	// mock.Anything for CreateProjectInvitation's ctx, not the exact ctx
	// value: PART2-CONT-6's fix tags ctx with WithSelfMachineGranter inside
	// InviteToProject (called by InviteToProjectWithLink below) for a real
	// machine inviter (invitedByMachineID != 0) -- that tagged ctx is local
	// to InviteToProject's own call to CreateProjectInvitation and does not
	// propagate back to this test's ctx variable, so every OTHER call below
	// still legitimately matches the exact original ctx.
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	// F6 sweep (2026-09-22): inviting now ALSO requires roles.assign as a
	// baseline -- machine 42 is tagged via WithSelfMachineGranter (a real
	// machine inviter), so this baseline check resolves against ITS OWN
	// permissions via AuthorizePrincipal's machine branch.
	store.On("GetMachineRoleIDsAt", mock.Anything, uint(42), Scope{ProjectID: 1}).Return([]uint{200}, nil)
	store.On("RoleSetHasPermission", mock.Anything, []uint{200}, "roles.assign").Return(true, nil)
	store.On("CreateProjectInvitation", mock.Anything, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.InvitedBy == 0 && inv.InvitedByMachineIdentityID == 42
	})).Return(&models.ProjectInvitation{ID: 7, State: InvitationPending}, nil)
	store.On("SupersedeActiveSetupTokens", ctx, SetupPurposeInvitationAccept, "a@b.com", ptr(uint(1))).Return(nil)
	store.On("CreateSetupToken", ctx, mock.MatchedBy(func(tok *models.SetupToken) bool {
		return tok.CreatedBy == 0 && tok.CreatedByMachineIdentityID == 42
	})).Return(&models.SetupToken{ID: 1}, nil)
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "a@b.com", fixed.Add(-24*time.Hour)).Return(int64(0), nil).Once()
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "a@b.com", fixed.Add(-resendMinInterval)).Return(int64(0), nil).Once()

	_, prov, err := c.InviteToProjectWithLink(ctx, 1, "a@b.com", "project_developer", 0, 42)
	require.NoError(t, err)
	assert.True(t, prov.Delivered)
	store.AssertExpectations(t)
}

// #345: InviteGlobalWithLink has the same unthrottled-initial-send shape as
// InviteToProjectWithLink, reachable via the users.write-gated global-invite endpoint.
func TestInviteGlobalWithLink_ThrottlesRepeatedInitialInvites(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newInviteCore(store)
	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)
	ctx := context.Background()
	fixed := c.now()
	anyAudit(store)

	store.On("GetRoleByName", ctx, "system_viewer").Return(&models.Role{ID: 2}, nil)
	store.On("CreateProjectInvitation", ctx, mock.AnythingOfType("*models.ProjectInvitation")).
		Return(&models.ProjectInvitation{ID: 8, State: InvitationPending}, nil)
	store.On("SupersedeActiveSetupTokens", ctx, SetupPurposeInvitationAccept, "c@d.com", (*uint)(nil)).Return(nil)
	store.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "c@d.com", fixed.Add(-24*time.Hour)).Return(int64(0), nil).Once()
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "c@d.com", fixed.Add(-resendMinInterval)).Return(int64(0), nil).Once()

	// F6 sweep (2026-09-22): requireGranterHoldsRolePermissions now checks a
	// roles.assign baseline before the per-permission loop this test's
	// throttling behavior actually exercises.
	stubAuthorizedPrincipal(store, 9, Scope{}, "roles.assign")

	inv1, prov1, err := c.InviteGlobalWithLink(ctx, "c@d.com", "", nil, 9, 0)
	require.NoError(t, err)
	require.NotNil(t, inv1)
	require.NotNil(t, prov1)

	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "c@d.com", fixed.Add(-24*time.Hour)).Return(int64(1), nil).Once()
	store.On("CountSetupTokensSince", ctx, SetupPurposeInvitationAccept, "c@d.com", fixed.Add(-resendMinInterval)).Return(int64(1), nil).Once()

	inv2, prov2, err := c.InviteGlobalWithLink(ctx, "c@d.com", "", nil, 9, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wait")
	assert.Nil(t, prov2)
	require.NotNil(t, inv2)
	store.AssertNumberOfCalls(t, "CreateSetupToken", 1)
}

// Access-request approval grants a real role, so both the immediate and TTL-bound
// grant branches must land in the RBAC audit trail with a structured RoleID — not
// just the generic access_request.approved event (#298). Uses real storage so
// ListRBACAuditLogs is exercised end to end.
func TestApproveAccessRequestWithExpiry_IsRBACAudited(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	approver, err := st.CreateUser(ctx, foldedTestUser(t, "approver", "approver@example.com"))
	require.NoError(t, err)
	// #93/#107/#141: the approver must themselves hold every permission of the
	// role being granted — grant "admin" globally so the ceiling check's admin
	// bypass applies.
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, approver.ID, adminRole.ID, storage.Scope{}))
	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester", "requester@example.com"))
	require.NoError(t, err)
	req, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: requester.ID, SuggestedRole: "project_viewer", State: AccessRequestPending,
	})
	require.NoError(t, err)

	_, err = c.ApproveAccessRequestWithExpiry(ctx, 1, req.ID, approver.ID, 0, "", 0)
	require.NoError(t, err)

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var assigned *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleAssigned {
			assigned = e
		}
	}
	require.NotNil(t, assigned, "access-request approval grant must appear in the RBAC audit trail")
	require.NotNil(t, assigned.ActorUserID)
	assert.Equal(t, approver.ID, *assigned.ActorUserID)
	require.NotNil(t, assigned.TargetUserID)
	assert.Equal(t, requester.ID, *assigned.TargetUserID)

	// Time-bound (TTL) grant branch is audited the same way.
	req2, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: requester.ID, SuggestedRole: "project_developer", State: AccessRequestPending,
	})
	require.NoError(t, err)
	_, err = c.ApproveAccessRequestWithExpiry(ctx, 1, req2.ID, approver.ID, 0, "", time.Hour)
	require.NoError(t, err)

	entries, _, err = c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var count int
	for _, e := range entries {
		if e.Action == EventRoleAssigned && e.TargetUserID != nil && *e.TargetUserID == requester.ID {
			count++
		}
	}
	assert.Equal(t, 2, count, "both the immediate and TTL-bound grants are RBAC-audited")
}
