//go:build e2e

package e2e

import (
	"fmt"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// groupUsersRolesRBAC creates a second user, a custom role, assigns it via
// the user-roles endpoints, then sweeps the per-user read-only report
// endpoints (memberships, permissions, roles, shared-secrets) and the
// lifecycle actions that don't destroy the account (reactivate/suspend/
// unlock/require-password-reset/revoke-sessions/resend-setup-link) --
// deliberately NOT delete, which runs last in groupAdminAndSystem's cleanup
// so every earlier group can still reference ctx.userID.
func groupUsersRolesRBAC(ctx *smokeCtx) {
	c := ctx.c

	created := c.callExpect("POST", "POST /api/v1/users", "/api/v1/users", map[string]interface{}{
		"username": "e2esmokeuser", "email": "e2esmokeuser@smoke.local",
		"display_name": "E2E Smoke User", "password": harness.SmokeUserPassword,
	}, 201)
	var user idOnly
	c.unmarshalData(created, &user, "create user")
	ctx.userID = user.ID
	u := fmt.Sprintf("/api/v1/users/%d", ctx.userID)

	c.callExpect("GET", "GET /api/v1/users", "/api/v1/users", nil, 200)
	c.callExpect("GET", "GET /api/v1/users/{id}", u, nil, 200)
	c.callExpect("GET", "GET /api/v1/users/by-username", "/api/v1/users/by-username?username=e2esmokeuser", nil, 200)
	c.callExpect("GET", "GET /api/v1/users/by-email", "/api/v1/users/by-email?email=e2esmokeuser@smoke.local", nil, 200)
	c.callExpect("GET", "GET /api/v1/users/by-external-id", "/api/v1/users/by-external-id?external_id=nonexistent", nil, 200, 404)
	c.callExpect("GET", "GET /api/v1/users/search", "/api/v1/users/search?q=e2esmoke", nil, 200)
	c.callExpect("GET", "GET /api/v1/users/stale", "/api/v1/users/stale", nil, 200)
	c.callExpect("PUT", "PUT /api/v1/users/{id}", u, map[string]string{"display_name": "E2E Smoke User (updated)"}, 200)
	c.callExpect("GET", "GET /api/v1/users/{id}/memberships", u+"/memberships", nil, 200)
	c.callExpect("GET", "GET /api/v1/users/{id}/permissions", u+"/permissions", nil, 200)
	c.callExpect("GET", "GET /api/v1/users/{id}/shared-secrets", u+"/shared-secrets", nil, 200)
	c.callExpect("POST", "POST /api/v1/users/{id}/require-password-reset", u+"/require-password-reset", nil, 200)
	c.callExpect("POST", "POST /api/v1/users/{id}/resend-setup-link", u+"/resend-setup-link", nil, 200, 400)
	c.callExpect("POST", "POST /api/v1/users/{id}/suspend", u+"/suspend", map[string]string{"reason": "e2e smoke"}, 200)
	c.callExpect("POST", "POST /api/v1/users/{id}/unlock", u+"/unlock", nil, 200)
	c.callExpect("POST", "POST /api/v1/users/{id}/reactivate", u+"/reactivate", nil, 200)
	c.callExpect("POST", "POST /api/v1/users/{id}/revoke-sessions", u+"/revoke-sessions", nil, 200)

	// Roles: create a custom role bundling a permission the bootstrap admin
	// already holds (secrets.read), assign it to the new user via the
	// user-roles endpoints, then read it back both ways
	// (GET /users/{id}/roles and GET /user-roles/user/{userId}).
	roleCreated := c.callExpect("POST", "POST /api/v1/roles", "/api/v1/roles", map[string]interface{}{
		"name": "e2e-smoke-role", "description": "SESSION-I smoke role", "permissions": []string{"secrets.read"},
	}, 201)
	var roleEnv struct {
		Role idOnly `json:"role"`
	}
	c.unmarshalData(roleCreated, &roleEnv, "create role")
	ctx.roleID = roleEnv.Role.ID
	r := fmt.Sprintf("/api/v1/roles/%d", ctx.roleID)

	c.callExpect("GET", "GET /api/v1/roles", "/api/v1/roles", nil, 200)
	c.callExpect("GET", "GET /api/v1/roles/{id}", r, nil, 200)
	c.callExpect("GET", "GET /api/v1/roles/by-name", "/api/v1/roles/by-name?name=e2e-smoke-role", nil, 200)
	c.callExpect("PUT", "PUT /api/v1/roles/{id}", r, map[string]interface{}{
		"name": "e2e-smoke-role", "description": "SESSION-I smoke role (updated)", "permissions": []string{"secrets.read"},
	}, 200)
	c.callExpect("GET", "GET /api/v1/roles/{id}/permissions", r+"/permissions", nil, 200)
	// Best-effort: exact body contract not individually confirmed (see
	// groups_catalog.go's identical note) -- permission_id=1 is whatever
	// the seeded permission table's first row happens to be, which is
	// enough to prove the route doesn't 5xx even if it 400s on a mismatch.
	c.call("POST", "POST /api/v1/roles/{id}/permissions", r+"/permissions", map[string]interface{}{"permission_id": 1})

	if ctx.userID != 0 && ctx.roleID != 0 {
		c.callExpect("POST", "POST /api/v1/user-roles", "/api/v1/user-roles", map[string]interface{}{
			"user_id": ctx.userID, "role_id": ctx.roleID, "project_id": 0, "environment_id": 0,
		}, 201)
		c.callExpect("GET", "GET /api/v1/user-roles/user/{userId}", fmt.Sprintf("/api/v1/user-roles/user/%d", ctx.userID), nil, 200)
		c.callExpect("GET", "GET /api/v1/users/{id}/roles", u+"/roles", nil, 200)
		c.callExpect("PUT", "PUT /api/v1/users/{id}/roles", u+"/roles", map[string]interface{}{
			"role_ids": []uint{ctx.roleID},
		}, 200, 400)
		c.callExpect("DELETE", "DELETE /api/v1/user-roles", "/api/v1/user-roles", map[string]interface{}{
			"user_id": ctx.userID, "role_id": ctx.roleID, "project_id": 0, "environment_id": 0,
		}, 200, 204)
	}

	// Project membership: add the new user to the smoke project via both
	// the /members and /memberships routes (router.go registers both as
	// distinct paths), then update/remove through /members.
	p := fmt.Sprintf("/api/v1/projects/%d", ctx.projectID)
	c.callExpect("POST", "POST /api/v1/projects/{id}/members", p+"/members",
		map[string]interface{}{"user_id": ctx.userID, "role": "project_viewer"}, 200, 201)
	c.callExpect("GET", "GET /api/v1/projects/{id}/members", p+"/members", nil, 200)
	// Share-dialog recipient search (SHARE-2): the bootstrap admin holds global
	// users.read, so it may search any project.
	c.callExpect("GET", "GET /api/v1/projects/{id}/share-recipients", p+"/share-recipients?q=a&page_size=5", nil, 200)
	c.callExpect("PUT", "PUT /api/v1/projects/{id}/members/{userId}", fmt.Sprintf("%s/members/%d", p, ctx.userID),
		map[string]string{"role": "project_viewer"}, 200)

	// InviteMember (the real handler behind POST /memberships) takes
	// {"user_id", "role": <role NAME, not id>} -- best-effort since ctx.userID
	// may already be an active member via POST /members above (InviteMember
	// would then correctly refuse a second active membership for the same
	// user; either outcome is fine here, only a 5xx would fail the test).
	c.call("POST", "POST /api/v1/projects/{id}/memberships", p+"/memberships",
		map[string]interface{}{"user_id": ctx.userID, "role": "project_viewer"})
	membershipsGet := c.callExpect("GET", "GET /api/v1/projects/{id}/memberships", p+"/memberships", nil, 200)
	var memberships struct {
		Memberships []idOnly `json:"memberships"`
	}
	c.unmarshalData(membershipsGet, &memberships, "list memberships")
	if len(memberships.Memberships) > 0 {
		c.call("PUT", "PUT /api/v1/projects/{id}/memberships/{membershipId}",
			fmt.Sprintf("%s/memberships/%d", p, memberships.Memberships[0].ID),
			map[string]string{"action": "approve"})
	} else {
		c.skip("PUT /api/v1/projects/{id}/memberships/{membershipId}")
	}
}

// groupGroups exercises user-group create/list/get/update, membership
// add/list/remove, and role grant/list/revoke on the group (a group can
// hold roles the same way a user can), plus the shared-secrets/shares
// report endpoints and soft-delete restore.
func groupGroups(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/groups", "/api/v1/groups",
		map[string]string{"name": "e2e-smoke-group", "description": "SESSION-I smoke"}, 201)
	var group idOnly
	c.unmarshalData(created, &group, "create group")
	g := fmt.Sprintf("/api/v1/groups/%d", group.ID)

	c.callExpect("GET", "GET /api/v1/groups", "/api/v1/groups", nil, 200)
	c.callExpect("GET", "GET /api/v1/groups/{id}", g, nil, 200)
	c.callExpect("PUT", "PUT /api/v1/groups/{id}", g, map[string]string{"name": "e2e-smoke-group", "description": "updated"}, 200)

	c.callExpect("POST", "POST /api/v1/groups/{id}/members", g+"/members", map[string]interface{}{"user_id": ctx.userID}, 200, 201)
	c.callExpect("GET", "GET /api/v1/groups/{id}/members", g+"/members", nil, 200)

	roleForGroup := c.callExpect("POST", "POST /api/v1/roles", "/api/v1/roles", map[string]interface{}{
		"name": "e2e-smoke-group-role", "description": "SESSION-I smoke", "permissions": []string{"secrets.read"},
	}, 201)
	var groupRoleEnv struct {
		Role idOnly `json:"role"`
	}
	c.unmarshalData(roleForGroup, &groupRoleEnv, "create group role")
	c.callExpect("POST", "POST /api/v1/groups/{id}/roles", g+"/roles", map[string]interface{}{"role_id": groupRoleEnv.Role.ID}, 200, 201)
	c.callExpect("GET", "GET /api/v1/groups/{id}/roles", g+"/roles", nil, 200)
	c.callExpect("DELETE", "DELETE /api/v1/groups/{id}/roles/{roleId}", fmt.Sprintf("%s/roles/%d", g, groupRoleEnv.Role.ID), nil, 200, 204)
	c.callExpect("DELETE", "DELETE /api/v1/roles/{id}/permissions/{permissionId}", fmt.Sprintf("/api/v1/roles/%d/permissions/1", groupRoleEnv.Role.ID), nil, 200, 204, 404)
	c.callExpect("DELETE", "DELETE /api/v1/roles/{id}", fmt.Sprintf("/api/v1/roles/%d", groupRoleEnv.Role.ID), nil, 200, 204)

	c.callExpect("GET", "GET /api/v1/groups/{id}/shared-secrets", g+"/shared-secrets", nil, 200)
	c.callExpect("GET", "GET /api/v1/groups/{id}/shares", g+"/shares", nil, 200)

	c.callExpect("DELETE", "DELETE /api/v1/groups/{id}/members/{userId}", fmt.Sprintf("%s/members/%d", g, ctx.userID), nil, 200, 204)
	c.callExpect("DELETE", "DELETE /api/v1/groups/{id}", g, nil, 200, 204)
	c.callExpect("POST", "POST /api/v1/groups/{id}/restore", g+"/restore", nil, 200, 400, 404)
}

// groupPermissions is read-only: list + get-one, using role permission id 1
// (secrets.read is always seeded first by auth_bootstrap.go's permission
// seeding, but this driver doesn't depend on that exact ordering -- a 404 is
// an acceptable, non-5xx outcome for the get-one probe).
func groupPermissions(ctx *smokeCtx) {
	c := ctx.c
	listResp := c.callExpect("GET", "GET /api/v1/permissions", "/api/v1/permissions", nil, 200)
	var perms struct {
		Permissions []idOnly `json:"permissions"`
	}
	c.unmarshalData(listResp, &perms, "list permissions")
	id := uint(1)
	if len(perms.Permissions) > 0 {
		id = perms.Permissions[0].ID
	}
	c.callExpect("GET", "GET /api/v1/permissions/{id}", fmt.Sprintf("/api/v1/permissions/%d", id), nil, 200, 404)
}
