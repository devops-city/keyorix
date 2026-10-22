// last_admin_primitive_test.go — regression coverage for FIX-2 (adversarial
// review run 2): the last-project-admin guard sat on entry points
// (SetProjectMemberRole, RemoveProjectMember), not on the shared primitives
// (RemoveUserRole, RemoveRoleFromGroup) those entry points funnel through.
// Any OTHER caller reaching a primitive directly — the plain /user-roles HTTP
// route, the gRPC RemoveRole RPC, the /system RemoveRoleGrantProxy, or
// RemoveRoleFromGroup's own callers — bypassed project-admin protection
// entirely. These tests exercise the primitives DIRECTLY, the same way those
// bypassing entry points do, proving the guard now holds regardless of which
// caller reaches it.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoveUserRole_RefusesLastProjectAdminAtThePrimitive proves the fix's
// core claim: calling RemoveUserRole DIRECTLY at project scope (as the plain
// /user-roles HTTP route, the gRPC RemoveRole RPC, and the /system
// RemoveRoleGrantProxy all do — none of them route through
// SetProjectMemberRole/RemoveProjectMember) refuses to strip a project of its
// last roles.assign holder, even though NEITHER of those entry-point guards
// is anywhere in this call path.
func TestRemoveUserRole_RefusesLastProjectAdminAtThePrimitive(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, foldedTestUser(t, "priya", "priya@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_admin", false))

	// Bypass SetProjectMemberRole/RemoveProjectMember entirely — call the
	// shared primitive the way an entry point with no guard of its own would.
	err = c.RemoveUserRole(ctx, actor, u.ID, adminRole.ID, Scope{ProjectID: proj})
	require.Error(t, err, "must refuse to strip project 7's last roles.assign holder")
	assert.Contains(t, err.Error(), "last administrator")

	ids, err := st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.Contains(t, ids, adminRole.ID, "the grant must survive when the guard refuses")
}

// TestRemoveUserRole_AllowsProjectAdminRemovalWhenAnotherSurvives is the
// positive control: the guard only bites on the LAST holder, not every
// project-admin removal.
func TestRemoveUserRole_AllowsProjectAdminRemovalWhenAnotherSurvives(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, foldedTestUser(t, "priya", "priya@example.com"))
	require.NoError(t, err)
	other, err := st.CreateUser(ctx, foldedTestUser(t, "raj", "raj@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_admin", false))
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, other.ID, "project_admin", false))

	err = c.RemoveUserRole(ctx, actor, u.ID, adminRole.ID, Scope{ProjectID: proj})
	require.NoError(t, err, "removal is fine while another project admin survives")
}

// TestRemoveUserRole_EnvironmentScopeUnaffected confirms the new guard is
// scoped to project-level grants only (environment_id = 0), matching
// guardLastProjectAdmin/resolveProjectAdminHolders' existing convention that
// an environment-scoped role never independently confers project-admin
// authority (RemoveProjectMember's own doc comment: it removes environment-
// scoped grants too, without additional guarding). An environment-scoped
// removal must proceed even when it's the user's only grant.
func TestRemoveUserRole_EnvironmentScopeUnaffected(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	// A real project/environment pair: the #3546 role-scope check refuses an
	// environment that does not belong to the grant's project.
	p, err := c.CreateProject(ctx, "env-scope-unaffected", "")
	require.NoError(t, err)
	e, err := c.CreateEnvironment(ctx, p.ID, "env-scope-unaffected-env")
	require.NoError(t, err)
	proj, env := p.ID, e.ID
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, foldedTestUser(t, "priya", "priya@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, c.AssignUserRole(ctx, actor, u.ID, adminRole.ID, Scope{ProjectID: proj, EnvironmentID: env}, false))

	err = c.RemoveUserRole(ctx, actor, u.ID, adminRole.ID, Scope{ProjectID: proj, EnvironmentID: env})
	require.NoError(t, err, "an environment-scoped grant never independently conferred project-admin authority")
}

// TestRemoveRoleFromGroup_RefusesLastProjectAdmin proves the third of the
// three sibling gaps: a group's project-admin-conferring role grant is the
// third way (alongside group deletion and membership removal, both already
// guarded — TestDeleteGroup_RefusesLastProjectAdmin /
// TestRemoveUserFromGroup_RefusesLastProjectAdminMember in
// project_scoped_group_admin_guard_test.go) a group can stop conferring
// project-admin authority, and had no guard at all.
func TestRemoveRoleFromGroup_RefusesLastProjectAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))

	err = c.RemoveRoleFromGroup(ctx, actor, group.ID, adminRole.ID, Scope{ProjectID: proj})
	require.Error(t, err, "must refuse to remove project 7's last roles.assign grant from the group holding it")
	assert.Contains(t, err.Error(), "last administrative role grant")

	roles, err := st.GetGroupRoles(ctx, group.ID)
	require.NoError(t, err)
	found := false
	for _, r := range roles {
		if r.ID == adminRole.ID {
			found = true
		}
	}
	assert.True(t, found, "the grant must survive when the guard refuses")
}

// TestRemoveRoleFromGroup_AllowsWhenAnotherProjectAdminExists is the positive
// control.
func TestRemoveRoleFromGroup_AllowsWhenAnotherProjectAdminExists(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	other, err := st.CreateUser(ctx, foldedTestUser(t, "raj", "raj@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	// An independent, direct project_admin grant at the same project survives
	// the group's role removal.
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, other.ID, "project_admin", false))

	err = c.RemoveRoleFromGroup(ctx, actor, group.ID, adminRole.ID, Scope{ProjectID: proj})
	require.NoError(t, err, "removal is fine while another project admin survives")
}

// TestRemoveRoleFromGroup_AllowsNonAdminRole confirms the new guard only
// bites on a roles.assign-bearing role — removing an ordinary role from a
// group must never be blocked, regardless of the project's admin count.
func TestRemoveRoleFromGroup_AllowsNonAdminRole(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-viewers"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, viewerRole.ID, storage.Scope{ProjectID: proj}))

	err = c.RemoveRoleFromGroup(ctx, actor, group.ID, viewerRole.ID, Scope{ProjectID: proj})
	require.NoError(t, err, "a non-admin role grant must never be blocked by the last-admin guard")
}

// TestReconcileSSOGroups_RefusesStrandingLastProjectAdmin proves the third
// FIX-2 gap: SSO group-membership de-provisioning (an IdP that stops
// asserting a user's admin-conferring group) previously called
// storage.RemoveUserFromGroup directly, bypassing every core-layer guard.
// This drives the same reconciliation path used on every SSO login and
// confirms the user's membership in a group holding a project's last
// roles.assign grant survives when the IdP stops asserting it.
func TestReconcileSSOGroups_RefusesStrandingLastProjectAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, foldedTestUser(t, "priya", "priya@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, false, u.ID, group.ID, 0))

	// The IdP no longer asserts "proj7-admins" for this user (desired is
	// empty) — reconcileSSOGroupRemovals must refuse the removal rather than
	// silently stranding project 7.
	rep := &ssoReconcileReport{}
	c.reconcileSSOGroupRemovals(ctx, u.ID, map[uint]bool{}, map[uint]bool{group.ID: true}, map[uint]string{group.ID: group.Name}, rep)
	removed, err := rep.removed, rep.err()
	assert.Equal(t, 0, removed, "the last-admin-conferring group membership must not have been removed")
	// #2839 item 1: the refusal is now REPORTED rather than swallowed, so
	// CompleteSAML can refuse the login instead of minting a session over a
	// membership the IdP has revoked but which is still in place. The membership
	// surviving (asserted below) and the caller being told are both required —
	// the guard protects the project, and the error protects the session.
	require.Error(t, err, "a refused removal must be surfaced, not swallowed")
	assert.ErrorIs(t, err, ErrSSOReconcileIncomplete)

	groups, err := st.GetUserGroups(ctx, u.ID)
	require.NoError(t, err)
	found := false
	for _, g := range groups {
		if g.ID == group.ID {
			found = true
		}
	}
	assert.True(t, found, "the group membership must survive when the guard refuses")
}
