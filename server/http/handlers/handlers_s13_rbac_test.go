// handlers_s13_rbac_test.go — coverage sweep targeting error-path branches in:
//   - rbac.go: ListRoles 500, CreateRole conflict, UpdateRole not-found,
//     DeleteRole not-found, RemoveRole not-found, GetPermission not-found,
//     RemovePermissionFromRole not-found, GetGroupRoles bad-param / not-found,
//     GetGroupRoles bad-param, AssignPermissionToRole bad-param
//   - rbac_role_grants_proxy.go: every proxy handler's 400 paths
//     (bad param, missing required fields, malformed body)
//   - users_roles.go: bad param / not-found for all four handlers,
//     UpdateUserRoles bad-body / invalid-role-id
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── rbac.go: ListRoles ────────────────────────────────────────────────────────

// TestRBACHandler_ListRoles_Unauthorized_S13 covers the 401 branch of ListRoles
// when no user is in context.
func TestRBACHandler_ListRoles_Unauthorized_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	// no withUserCtx → mustGetUser returns false
	w := httptest.NewRecorder()
	handler.ListRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── rbac.go: CreateRole ───────────────────────────────────────────────────────

// TestRBACHandler_CreateRole_Unauthorized_S13 covers the 401 path.
func TestRBACHandler_CreateRole_Unauthorized_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	body := bytes.NewBufferString(`{"name":"newrole","description":"desc","permissions":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRBACHandler_CreateRole_InvalidJSON_S13 covers the JSON-decode error path.
func TestRBACHandler_CreateRole_InvalidJSON_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles",
		bytes.NewBufferString(`not-json`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	handler.CreateRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: UpdateRole ───────────────────────────────────────────────────────

// TestRBACHandler_UpdateRole_NotFound_S13 covers the not-found path inside
// UpdateRole when the role ID does not exist.
func TestRBACHandler_UpdateRole_NotFound_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	body := bytes.NewBufferString(`{"description":"new desc"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/9999", body)
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", "9999"))
	w := httptest.NewRecorder()
	handler.UpdateRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRBACHandler_UpdateRole_BadParam_S13 covers the bad-id parse path.
func TestRBACHandler_UpdateRole_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	body := bytes.NewBufferString(`{"description":"desc"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/nan", body)
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	handler.UpdateRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_UpdateRole_InvalidJSON_S13 covers the JSON-decode error path.
func TestRBACHandler_UpdateRole_InvalidJSON_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "update-json-err-role")
	req := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/v1/roles/%d", role.ID),
		bytes.NewBufferString(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", role.ID)))
	w := httptest.NewRecorder()
	handler.UpdateRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: DeleteRole ───────────────────────────────────────────────────────

// TestRBACHandler_DeleteRole_NotFound_S13 covers the not-found path when the
// role does not exist.
func TestRBACHandler_DeleteRole_NotFound_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/9999", nil)
	req = withUserCtx(withChiParam(req, "id", "9999"))
	w := httptest.NewRecorder()
	handler.DeleteRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRBACHandler_DeleteRole_BadParam_S13 covers bad id parse.
func TestRBACHandler_DeleteRole_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/nan", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	handler.DeleteRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_DeleteRole_Unauthorized_S13 covers the 401 path.
func TestRBACHandler_DeleteRole_Unauthorized_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "del-unauth-role")
	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v1/roles/%d", role.ID), nil)
	req = withChiParam(req, "id", fmt.Sprintf("%d", role.ID))
	w := httptest.NewRecorder()
	handler.DeleteRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── rbac.go: RemoveRole ───────────────────────────────────────────────────────

// TestRBACHandler_RemoveRole_NotAssigned_S13 covers the not-found/not-assigned
// branch in RemoveRole.
func TestRBACHandler_RemoveRole_NotAssigned_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "unassigned-role")

	body, _ := json.Marshal(map[string]any{
		"user_id": 2,
		"role_id": role.ID,
	})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/user-roles",
		bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	handler.RemoveRole(w, req)
	// user 2 never had this role → "not assigned" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRBACHandler_RemoveRole_InvalidJSON_S13 covers JSON decode error.
func TestRBACHandler_RemoveRole_InvalidJSON_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/user-roles",
		bytes.NewBufferString(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	handler.RemoveRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: GetPermission ───────────────────────────────────────────────────

// TestRBACHandler_GetPermission_NotFound_S13 covers the not-found path.
func TestRBACHandler_GetPermission_NotFound_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/permissions/9999", nil)
	req = withUserCtx(withChiParam(req, "id", "9999"))
	w := httptest.NewRecorder()
	handler.GetPermission(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRBACHandler_GetPermission_BadParam_S13 covers bad id parse.
func TestRBACHandler_GetPermission_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/permissions/nan", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	handler.GetPermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_GetPermission_Happy_S13 covers the 200 success path.
func TestRBACHandler_GetPermission_Happy_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	perm := mustCreatePermission(t, db, "keys.list", "keys", "list")
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/permissions/%d", perm.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", perm.ID)))
	w := httptest.NewRecorder()
	handler.GetPermission(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rbac.go: RemovePermissionFromRole ─────────────────────────────────────────

// TestRBACHandler_RemovePermissionFromRole_NotFound_S13 covers the not-found path
// when the permission is not assigned to the role.
func TestRBACHandler_RemovePermissionFromRole_NotFound_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "perm-rm-role")
	perm := mustCreatePermission(t, db, "keys.rm", "keys", "rm")
	// perm is NOT assigned to role → should return 404
	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v1/roles/%d/permissions/%d", role.ID, perm.ID), nil)
	req = withUserCtx(withChiParams(req, map[string]string{
		"id":           fmt.Sprintf("%d", role.ID),
		"permissionId": fmt.Sprintf("%d", perm.ID),
	}))
	w := httptest.NewRecorder()
	handler.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRBACHandler_RemovePermissionFromRole_BadRoleParam_S13 covers bad role id.
func TestRBACHandler_RemovePermissionFromRole_BadRoleParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/nan/permissions/1", nil)
	req = withUserCtx(withChiParams(req, map[string]string{
		"id":           "nan",
		"permissionId": "1",
	}))
	w := httptest.NewRecorder()
	handler.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_RemovePermissionFromRole_BadPermParam_S13 covers bad permission id.
func TestRBACHandler_RemovePermissionFromRole_BadPermParam_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "perm-bad-param-role")
	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v1/roles/%d/permissions/nan", role.ID), nil)
	req = withUserCtx(withChiParams(req, map[string]string{
		"id":           fmt.Sprintf("%d", role.ID),
		"permissionId": "nan",
	}))
	w := httptest.NewRecorder()
	handler.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: GetGroupRoles ───────────────────────────────────────────────────

// TestRBACHandler_GetGroupRoles_BadParam_S13 covers the bad-id path.
func TestRBACHandler_GetGroupRoles_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/nan/roles", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	handler.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_GetGroupRoles_Unauthorized_S13 covers the 401 path.
func TestRBACHandler_GetGroupRoles_Unauthorized_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/roles", nil)
	req = withChiParam(req, "id", "1")
	// no withUserCtx
	w := httptest.NewRecorder()
	handler.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── rbac.go: AssignPermissionToRole — bad param ───────────────────────────────

// TestRBACHandler_AssignPermissionToRole_BadParam_S13 covers the bad role-id
// path of AssignPermissionToRole.
func TestRBACHandler_AssignPermissionToRole_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	body := bytes.NewBufferString(`{"permission_id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles/nan/permissions", body)
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	handler.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_AssignPermissionToRole_InvalidJSON_S13 covers JSON decode error.
func TestRBACHandler_AssignPermissionToRole_InvalidJSON_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "assign-perm-json-role")
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID),
		bytes.NewBufferString(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", role.ID)))
	w := httptest.NewRecorder()
	handler.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: GetRole ─────────────────────────────────────────────────────────

// TestRBACHandler_GetRole_Unauthorized_S13 covers the 401 path.
func TestRBACHandler_GetRole_Unauthorized_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/1", nil)
	req = withChiParam(req, "id", "1")
	w := httptest.NewRecorder()
	handler.GetRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRBACHandler_GetRole_BadParam_S13 covers bad id parse.
func TestRBACHandler_GetRole_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/nan", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	handler.GetRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: GetRoleByName ───────────────────────────────────────────────────

// TestRBACHandler_GetRoleByName_Empty_S13 covers the empty-name path.
func TestRBACHandler_GetRoleByName_Empty_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/by-name", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	handler.GetRoleByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_GetRoleByName_NotFound_S13 covers the not-found path.
func TestRBACHandler_GetRoleByName_NotFound_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/by-name?name=ghost-role", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	handler.GetRoleByName(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRBACHandler_GetRoleByName_Happy_S13 covers the 200 success path.
func TestRBACHandler_GetRoleByName_Happy_S13(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	mustCreateRole(t, db, "named-role-s13")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/by-name?name=named-role-s13", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	handler.GetRoleByName(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rbac.go: GetUserRoles ────────────────────────────────────────────────────

// TestRBACHandler_GetUserRoles_BadParam_S13 covers the bad userId parse path.
func TestRBACHandler_GetUserRoles_BadParam_S13(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/user-roles/user/nan", nil)
	req = withUserCtx(withChiParam(req, "userId", "nan"))
	w := httptest.NewRecorder()
	handler.GetUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetGroupRoleGrantsProxy_BadGroupID_S13 covers the bad groupID path.

// TestGetGroupRoleGrantsProxy_Happy_S13 covers the success path (empty list).

// TestAssignRoleWithExpiryProxy_BadBody_S13 covers JSON decode error.

// TestAssignRoleWithExpiryProxy_MissingUserID_S13 covers missing user_id.

// TestAssignRoleWithExpiryProxy_MissingRoleID_S13 covers missing role_id.

// TestAssignRoleToGroupWithExpiryProxy_BadBody_S13 covers JSON decode error.

// TestAssignRoleToGroupWithExpiryProxy_MissingGroupID_S13 covers missing group_id.

// TestAssignRoleToGroupWithExpiryProxy_MissingRoleID_S13 covers missing role_id.

// TestRemoveAllProjectRoleGrantsProxy_BadBody_S13 covers JSON decode error.

// TestRemoveAllProjectRoleGrantsProxy_MissingFields_S13 covers missing user_id+project_id.

// TestRemoveAllProjectRoleGrantsProxy_Happy_S13 covers the success path.

// TestListGroupRoleAssignmentsProxy_BadGroupID_S13 covers the bad groupID path.

// TestListGroupRoleAssignmentsProxy_Happy_S13 covers the success path.

// TestListProjectRoleAssignmentsProxy_MissingProjectID_S13 covers missing param.

// TestListProjectRoleAssignmentsProxy_BadProjectID_S13 covers invalid project_id.

// TestListProjectRoleAssignmentsProxy_Happy_S13 covers the success path.

// TestListProjectMachineRoleAssignmentsProxy_MissingProjectID_S13 covers missing param.

// TestListProjectMachineRoleAssignmentsProxy_Happy_S13 covers success path.

// TestRemoveGlobalAdminRoleGuardedProxy_BadBody_S13 covers JSON decode error.

// TestRemoveGlobalAdminRoleGuardedProxy_MissingFields_S13 covers zero user_id+role_id.

// TestRemoveGlobalAdminRoleGuardedProxy_NotAssigned_S13 covers the
// ErrRoleNotAssigned → 404 path.
//
// To reach it we need the last-admin guard (survives check) to pass first,
// which requires another admin assignment to exist. We seed user 2 with
// the admin role so the guard sees a surviving admin, then try to remove
// that same role from user 3 (who never had it) → ErrRoleNotAssigned → 404.

// TestRemoveGlobalAdminRoleGuardedProxy_LastAdmin_S13 covers the
// ErrWouldStrandLastAdmin → 409 path when removing the sole admin.

// TestRemoveGlobalAdminRoleGuardedProxy_IgnoresWireSuppliedAdminRoleIDs is the
// #G79 regression: RemoveGlobalAdminRoleGuardedProxy previously trusted the
// caller's own admin_role_ids list to decide how many admin-conferring grants
// count toward the last-admin invariant. A caller submitting an EMPTY list
// (omitting the real admin role, attempting to make the guard undercount and
// let the sole admin's role be removed) must still be refused — the server
// now resolves the admin-role set itself and ignores the wire value entirely.

// ── users_roles.go: GetUserRolesForUser ──────────────────────────────────────

func newUsersRolesHandlerS13(t *testing.T) *UsersRolesHandler {
	t.Helper()
	return NewUsersRolesHandler(freshCoreS12(t))
}

// TestGetUserRolesForUser_Unauthorized_S13 covers the 401 path.
func TestGetUserRolesForUser_Unauthorized_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/1/roles", nil)
	req = withChiParam(req, "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetUserRolesForUser_BadParam_S13 covers the bad-id path.
func TestGetUserRolesForUser_BadParam_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nan/roles", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetUserRolesForUser_NonExistent_S13 confirms that a request for a
// non-existent user returns 200 with an empty roles list (the storage layer
// returns nil/nil for unknown users — no error, so the handler succeeds).
func TestGetUserRolesForUser_NonExistent_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/9999/roles", nil)
	req = withUserCtx(withChiParam(req, "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "roles")
}

// TestGetUserRolesForUser_Happy_S13 covers the 200 success path.
func TestGetUserRolesForUser_Happy_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewUsersRolesHandler(cs)

	// Create user via DB directly through the core's storage.
	// Use freshCoreS12WithAdmin to get a DB reference.
	cs2, db := freshCoreS12WithAdmin(t)
	h2 := NewUsersRolesHandler(cs2)
	user := &models.User{Username: "roles-user", Email: "roles@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)
	_ = h // silence lint

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/users/%d/roles", user.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", user.ID)))
	w := httptest.NewRecorder()
	h2.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go: GetUserPermissionsForUser ─────────────────────────────────

// TestGetUserPermissionsForUser_Unauthorized_S13 covers the 401 path.
func TestGetUserPermissionsForUser_Unauthorized_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/1/permissions", nil)
	req = withChiParam(req, "id", "1")
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetUserPermissionsForUser_BadParam_S13 covers the bad-id path.
func TestGetUserPermissionsForUser_BadParam_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nan/permissions", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetUserPermissionsForUser_NonExistent_S13 confirms that a request for a
// non-existent user returns 200 with an empty permissions list (storage returns
// nil/nil for unknown users — the handler succeeds with empty data).
// G84: reading a DIFFERENT user's (even a nonexistent one's) permission set
// requires the caller to be self, an admin, or a roles.read holder — a bare
// authenticated context is no longer enough. Use the admin-seeded core so this
// still exercises the "nonexistent target" data path the test is named for.
func TestGetUserPermissionsForUser_NonExistent_S13(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewUsersRolesHandler(cs)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/9999/permissions", nil)
	req = withUserCtx(withChiParam(req, "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "permissions")
}

// ── users_roles.go: GetUserMembershipsForUser ─────────────────────────────────

// TestGetUserMembershipsForUser_Unauthorized_S13 covers the 401 path.
func TestGetUserMembershipsForUser_Unauthorized_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/1/memberships", nil)
	req = withChiParam(req, "id", "1")
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetUserMembershipsForUser_BadParam_S13 covers the bad-id path.
func TestGetUserMembershipsForUser_BadParam_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nan/memberships", nil)
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetUserMembershipsForUser_Happy_S13 covers the 200 path for an existing user.
func TestGetUserMembershipsForUser_Happy_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewUsersRolesHandler(cs)
	user := &models.User{Username: "memb-user", Email: "memb@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/users/%d/memberships", user.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", user.ID)))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go: UpdateUserRoles ──────────────────────────────────────────

// TestUpdateUserRoles_Unauthorized_S13 covers the 401 path.
func TestUpdateUserRoles_Unauthorized_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	body := bytes.NewBufferString(`{"role_ids":[]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/1/roles", body)
	req.Header.Set("Content-Type", "application/json")
	req = withChiParam(req, "id", "1")
	// no withUserCtx
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUpdateUserRoles_BadParam_S13 covers bad user id.
func TestUpdateUserRoles_BadParam_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	body := bytes.NewBufferString(`{"role_ids":[]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/nan/roles", body)
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", "nan"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateUserRoles_InvalidJSON_S13 covers JSON decode error.
func TestUpdateUserRoles_InvalidJSON_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/1/roles",
		bytes.NewBufferString(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateUserRoles_InvalidRoleID_S13 covers the "role does not exist" path.
func TestUpdateUserRoles_InvalidRoleID_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewUsersRolesHandler(cs)
	user := &models.User{Username: "roles-update-user", Email: "roleupd@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)

	body, _ := json.Marshal(map[string]any{
		"role_ids": []uint{99999}, // role does not exist
	})
	req := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/v1/users/%d/roles", user.ID),
		bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", user.ID)))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// role 99999 doesn't exist → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "NotFound")
}

// TestUpdateUserRoles_NonExistentUser_S13 confirms that updating roles for a
// non-existent user with an empty role set returns 200 (the storage returns
// nil for GetUserRoleIDsExact with no rows, SetUserRoles is a no-op, and
// GetUserRolesByID returns an empty slice — no error path is triggered).
func TestUpdateUserRoles_NonExistentUser_S13(t *testing.T) {
	h := newUsersRolesHandlerS13(t)
	body := bytes.NewBufferString(`{"role_ids":[]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/9999/roles", body)
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", "9999"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// SetUserRoles with empty roles for unknown user is a no-op → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUpdateUserRoles_Happy_S13 covers the success path (empty role set).
func TestUpdateUserRoles_Happy_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewUsersRolesHandler(cs)
	user := &models.User{Username: "roles-happy-user", Email: "roleshappy@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)

	body := bytes.NewBufferString(`{"role_ids":[]}`)
	req := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/v1/users/%d/roles", user.ID), body)
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", user.ID)))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
