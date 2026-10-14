// openapi_contract_apihygiene_rbac_test.go — proving tests for the 7
// operationIds backfilled with a real response schema by the API-hygiene
// casing campaign's PR C3 (rbac: Roles/Permissions): createRole, getRole,
// getRoleByName, updateRole, listPermissions, getPermission,
// getUserRoleAssignment. See rbac_wire.go and checks_test.go's
// TestEnforcedSetMatchesADR074 comment for the same set.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractAPIHygiene_CreateRole(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	// An unknown permission name is silently skipped (resolveAndAuthorizePermissions'
	// documented convention) -- no permission seeding needed for a 201.
	body, _ := json.Marshal(map[string]any{
		"name": "contract-ah-createrole", "description": "d",
		"permissions": []string{"contract-ah-unknown-permission"},
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestContractAPIHygiene_GetRole(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	role := &models.Role{Name: "contract-ah-getrole", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/roles/1", nil),
		"id", fmt.Sprintf("%d", role.ID),
	))
	w := httptest.NewRecorder()
	h.GetRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestContractAPIHygiene_GetRoleByName(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	require.NoError(t, db.Create(&models.Role{Name: "contract-ah-getrolebyname", Description: "d"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/roles/by-name?name=contract-ah-getrolebyname", nil))
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestContractAPIHygiene_UpdateRole(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	role := &models.Role{Name: "contract-ah-updaterole", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]any{"description": "updated"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/roles/1", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", role.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestContractAPIHygiene_ListPermissions(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/permissions", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestContractAPIHygiene_GetUserRoleAssignment(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	u := &models.User{Username: "contract-ah-userroleassign", Email: "contract-ah-userroleassign@example.test", DisplayName: "U"}
	require.NoError(t, db.Create(u).Error)
	role := &models.Role{Name: "contract-ah-userroleassign-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: role.ID}).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/user-roles/user/1", nil),
		"userId", fmt.Sprintf("%d", u.ID),
	))
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestContractAPIHygiene_GetPermission(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	perm := &models.Permission{Name: "contract-ah-getpermission", Resource: "contract-ah", Action: "read"}
	require.NoError(t, db.Create(perm).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/permissions/1", nil),
		"id", fmt.Sprintf("%d", perm.ID),
	))
	w := httptest.NewRecorder()
	h.GetPermission(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
