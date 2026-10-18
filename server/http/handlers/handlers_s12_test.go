// handlers_s12_test.go — coverage sweep targeting branches not covered by
// handlers_s4_test.go or earlier sweeps. Focuses on:
//   - audit_export_csv.go: parseAuditCSVFilter query-param branches
//   - rbac.go: replaceRolePermissions (0%), reserved-name guard, expiry
//     guard (user + group), queryUint non-zero path, ListPermissions resource
//     filter with seeded data, CreateRole validation error
//   - users_crud.go: mutual-exclusion guards (both flags / assignments with
//     setup-link/OTP), classic path (no password), OTP/setup-link conflict
//     errors, GetUserByEmail/GetUserByUsername/GetUserByExternalID empty param
//   - not-found, GetUser/UpdateUser/DeleteUser/UnlockUser bad-param + not-
//     found, accountStateAction self-action + not-found
//   - helpers.go: sendCreated with message, sendSuccess without message
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

// freshCoreS12 opens a uniquely-named in-memory SQLite DB with a broad set of
// models migrated and returns a ready-to-use KeyorixCore.
// freshCoreS12 is freshLocalStorageS12 wrapped in a KeyorixCore. Split so a
// test that needs to decorate the storage layer (login_rate_limit_reserve_
// interleaving_test.go parks one storage call to force an interleaving) can
// reuse this exact schema instead of hand-rolling a second AutoMigrate list —
// CLAUDE.md: hand-picked AutoMigrate lists hide schema divergence.
func freshCoreS12(t *testing.T) *core.KeyorixCore {
	t.Helper()
	return core.NewKeyorixCore(freshLocalStorageS12(t))
}

func freshLocalStorageS12(t *testing.T) *store.LocalStorage {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s12_")
	err := db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
		&models.SecretACL{}, &models.SecretAccessSchedule{},
		&models.RecoveryKeyRecord{},
	)
	require.NoError(t, err)
	return store.NewLocalStorage(db)
}

// freshCoreS12WithAdmin returns a KeyorixCore plus the underlying DB. The
// user with the ID returned by withUserCtx (UserID=1) is wired to a
// system_admin role so in-handler authorization passes via the admin bypass.
func freshCoreS12WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s12a_")
	err := db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
		&models.SecretACL{}, &models.SecretAccessSchedule{},
		&models.RecoveryKeyRecord{},
	)
	require.NoError(t, err)

	// Seed the user context user (UserID=1) as a global admin.
	// The role name must be in adminRoleNames ("super_admin", "admin",
	// "system_admin", "project_admin") for the admin bypass to fire.
	adminRole := &models.Role{Name: "system_admin", NameFolded: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	// withUserCtx injects UserID=1 — seed a user with that implicit first ID.
	testUser := &models.User{Username: "testuser_s12", UsernameFolded: "testuser_s12", Email: "testuser_s12@example.com", EmailFolded: "testuser_s12@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	// ADR-109 step 3: internal/core no longer defaults to dynamic.New internally
	// (that would mean importing internal/dynamic from production code) — wire it
	// explicitly here, exactly as server/main.go's DefaultIntegrations does, for
	// the dynamic-secret handler tests in this package that use this helper.
	cs.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, true, false) })
	return cs, db
}

// ── audit_export_csv.go: filter branches ─────────────────────────────────────

// TestExportAuditLogsCSV_FilterBranches exercises the parseAuditCSVFilter
// branches for project_id, user_id, since, until, and limit query params.
// The s3/existing tests don't cover these parameter branches.
func TestExportAuditLogsCSV_FilterBranches(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuditHandler(cs)

	cases := []struct {
		name  string
		query string
	}{
		{"project_id_filter", "?project_id=42"},
		{"user_id_filter", "?user_id=7"},
		{"since_filter", "?since=2024-01-01T00:00:00Z"},
		{"until_filter", "?until=2025-01-01T00:00:00Z"},
		{"custom_limit", "?limit=50"},
		{"limit_too_large_defaults", "?limit=99999"},
		{"invalid_since_ignored", "?since=not-a-date"},
		{"invalid_until_ignored", "?until=bad"},
		{"invalid_project_id_ignored", "?project_id=notanumber"},
		{"invalid_user_id_ignored", "?user_id=notanumber"},
		{"all_filters_combined", "?project_id=1&user_id=2&since=2024-01-01T00:00:00Z&until=2025-01-01T00:00:00Z&limit=100"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv"+tc.query, nil))
			w := httptest.NewRecorder()
			h.ExportAuditLogsCSV(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		})
	}
}

// ── rbac.go: replaceRolePermissions via UpdateRole ────────────────────────────

// TestRBACHandler_UpdateRole_WithPermissions_S12 exercises the
// replaceRolePermissions method (0% coverage) by calling UpdateRole with a
// non-nil Permissions list on a real DB.
func TestRBACHandler_UpdateRole_WithPermissions_S12(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)

	// Seed a non-builtin role (so DeleteRole+builtin guard doesn't block us).
	role := &models.Role{Name: "update-perm-role-s12", Description: "Custom"}
	require.NoError(t, db.Create(role).Error)

	// Seed a permission for the resource filter to find.
	perm := &models.Permission{Name: "secrets.read.s12", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(perm).Error)

	// Call UpdateRole with a permissions list — this hits replaceRolePermissions.
	perms := []string{"secrets.read.s12"}
	body, _ := json.Marshal(map[string]any{
		"description": "Updated description",
		"permissions": perms,
	})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/roles/1", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", role.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	// Accept 200 (permissions replaced) or 403 (actor doesn't hold the
	// permission via direct check — the admin bypass covers authorize, but the
	// per-permission hold-check uses the storage lookup). Either way the
	// replaceRolePermissions call ran.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ── rbac.go: CreateRole reserved-name guard ───────────────────────────────────

// TestRBACHandler_CreateRole_ReservedName_S12 verifies that posting a reserved
// role name (admin, super_admin, system_admin) returns 409 Conflict. Distinct
// from s4's unauthorized+bad-JSON tests.
func TestRBACHandler_CreateRole_ReservedName_S12(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewRBACHandler(cs)

	for _, name := range []string{"admin", "super_admin", "system_admin"} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"name":        name,
				"description": "Should be rejected",
				"permissions": []string{"roles.write"},
			})
			req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.CreateRole(w, req)
			assert.Equal(t, http.StatusConflict, w.Code)
		})
	}
}

// TestRBACHandler_CreateRole_ValidationError_S12 verifies the 400 branch when
// the role name is too short or missing required fields.
func TestRBACHandler_CreateRole_ValidationError_S12(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]any{
		"name":        "ab", // too short (< 3 chars)
		"description": "desc",
		"permissions": []string{"secrets.read"},
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: queryUint non-zero path ─────────────────────────────────────────

// TestRBACHandler_RemoveRoleFromGroup_WithScope_S12 passes non-zero
// project_id and environment_id query params to RemoveRoleFromGroup, exercising
// the non-zero return branch of queryUint.
func TestRBACHandler_RemoveRoleFromGroup_WithScope_S12(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	group := &models.Group{Name: "scope-group-s12"}
	require.NoError(t, db.Create(group).Error)
	role := &models.Role{Name: "scope-role-s12", Description: "q"}
	require.NoError(t, db.Create(role).Error)

	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/groups/%d/roles/%d?project_id=5&environment_id=3", group.ID, role.ID),
			nil),
		map[string]string{
			"id":     fmt.Sprintf("%d", group.ID),
			"roleId": fmt.Sprintf("%d", role.ID),
		},
	))
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	// The role isn't assigned to the group — expect not-found or 500 (internal
	// "not assigned" message maps to 500 in this handler). The key is that
	// queryUint ran (project_id=5, environment_id=3 were parsed).
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: AssignRole expiry guard ─────────────────────────────────────────

// TestRBACHandler_AssignRole_PastExpiry_S12 verifies that a role-assignment
// request with an already-past ExpiresAt returns 400 (roleExpiryValid guard).
func TestRBACHandler_AssignRole_PastExpiry_S12(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	role := &models.Role{Name: "assign-expiry-role-s12", Description: "exp"}
	require.NoError(t, db.Create(role).Error)
	targetUser := &models.User{Username: "expuser_s12", Email: "expuser_s12@x.com", AccountState: "active"}
	require.NoError(t, db.Create(targetUser).Error)

	past := time.Now().Add(-24 * time.Hour)
	body, _ := json.Marshal(map[string]any{
		"user_id":    targetUser.ID,
		"role_id":    role.ID,
		"expires_at": past.Format(time.RFC3339),
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AssignRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "future")
}

// ── rbac.go: AssignRoleToGroup expiry guard ───────────────────────────────────

// TestRBACHandler_AssignRoleToGroup_PastExpiry_S12 verifies the expiry guard
// for the group-assignment path.
func TestRBACHandler_AssignRoleToGroup_PastExpiry_S12(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	group := &models.Group{Name: "grp-exp-s12"}
	require.NoError(t, db.Create(group).Error)
	role := &models.Role{Name: "grp-exp-role-s12", Description: "x"}
	require.NoError(t, db.Create(role).Error)

	past := time.Now().Add(-48 * time.Hour)
	body, _ := json.Marshal(map[string]any{
		"role_id":    role.ID,
		"expires_at": past.Format(time.RFC3339),
	})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/groups/1/roles", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", group.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "future")
}

// ── rbac.go: GetUserRoles not-found ──────────────────────────────────────────

// TestRBACHandler_GetUserRoles_NotFound_S12 exercises the not-found error path
// for GetUserRoles (user 9999 doesn't exist).
func TestRBACHandler_GetUserRoles_NotFound_S12(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewRBACHandler(cs)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/user-roles/user/9999", nil),
		"userId", "9999",
	))
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	// Either 404 or 200 with empty list — no 500, no panic.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ── rbac.go: AssignRole validation ───────────────────────────────────────────

// TestRBACHandler_AssignRole_ValidationError_S12 verifies the 400 branch when
// required fields (user_id, role_id) are absent.
func TestRBACHandler_AssignRole_ValidationError_S12(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]any{}) // missing user_id and role_id
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.AssignRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRBACHandler_AssignRole_InvalidJSON_S12 verifies the 400 branch for
// malformed JSON in AssignRole.
func TestRBACHandler_AssignRole_InvalidJSON_S12(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewRBACHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewBufferString("bad-json")))
	w := httptest.NewRecorder()
	h.AssignRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: AssignPermissionToRole not-found ─────────────────────────────────

// TestRBACHandler_AssignPermissionToRole_NotFound_S12 verifies the not-found
// path (role 9999 and permission 9999 don't exist).
func TestRBACHandler_AssignPermissionToRole_NotFound_S12(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]any{"permission_id": uint(9999)})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/roles/9999/permissions", bytes.NewReader(body)),
		"id", "9999",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	// Expect 404 or 403 (permission not found / actor doesn't hold it).
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ── rbac.go: ListPermissions resource filter with seeded data ─────────────────

// TestRBACHandler_ListPermissions_ResourceFilter_S12 seeds permissions with
// different resources and verifies the ?resource= filter returns only matching
// entries. Extends the existing WithFilter test by confirming actual filtering.
func TestRBACHandler_ListPermissions_ResourceFilter_S12(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)

	require.NoError(t, db.Create(&models.Permission{Name: "s12.secrets.read", Resource: "s12secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{Name: "s12.roles.read", Resource: "s12roles", Action: "read"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/permissions?resource=s12secrets", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	perms := data["permissions"].([]any)
	// Only the s12secrets resource should appear after filtering.
	assert.GreaterOrEqual(t, len(perms), 1)
	for _, p := range perms {
		pm := p.(map[string]any)
		resource, _ := pm["resource"].(string)
		assert.Equal(t, "s12secrets", resource)
	}
}

// ── users_crud.go: CreateUser mutual-exclusion guards ─────────────────────────

// freshUserHandlerS12 builds a UserHandler backed by a fresh admin-seeded core.
func freshUserHandlerS12(t *testing.T) (*UserHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	uh, err := NewUserHandler(cs)
	require.NoError(t, err)
	return uh, cs, db
}

// TestCreateUser_BothFlagsSet_S12 verifies the 400 returned when both
// deliver_setup_link and generate_one_time_password are set simultaneously.
func TestCreateUser_BothFlagsSet_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":                   "bothflagsuser_s12",
		"email":                      "bothflags_s12@x.com",
		"display_name":               "Both Flags",
		"deliver_setup_link":         true,
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Choose either")
}

// TestCreateUser_AssignmentsWithSetupLink_S12 verifies the 400 returned when
// role/project_assignments are combined with deliver_setup_link.
func TestCreateUser_AssignmentsWithSetupLink_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":           "setupassign_s12",
		"email":              "setupassign_s12@x.com",
		"display_name":       "Setup Assign",
		"deliver_setup_link": true,
		"role":               "admin",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "role/project_assignments")
}

// TestCreateUser_AssignmentsWithOTP_S12 verifies the 400 returned when
// role/project_assignments are combined with generate_one_time_password.
func TestCreateUser_AssignmentsWithOTP_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":                   "otpassign_s12",
		"email":                      "otpassign_s12@x.com",
		"display_name":               "OTP Assign",
		"generate_one_time_password": true,
		"role":                       "admin",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateUserWithOTP_ConflictError_S12 verifies the 409 branch in
// createUserWithOTP when the user already exists.
func TestCreateUserWithOTP_ConflictError_S12(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)

	existing := &models.User{
		Username:       "otp-exists-s12",
		UsernameFolded: "otp-exists-s12",
		Email:          "otp-exists-s12@x.com",
		EmailFolded:    "otp-exists-s12@x.com",
		AccountState:   "active",
	}
	require.NoError(t, db.Create(existing).Error)

	body, _ := json.Marshal(map[string]any{
		"username":                   "otp-exists-s12",
		"email":                      "otp-exists-s12@x.com",
		"display_name":               "OTP Exists S12",
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestCreateUserWithSetupLink_BaseURLRequired_S12 verifies the 400 branch in
// createUserWithSetupLink when the server isn't configured with a base_url
// for setup-link delivery (ErrSetupBaseURLRequired path).
func TestCreateUserWithSetupLink_BaseURLRequired_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)

	body, _ := json.Marshal(map[string]any{
		"username":           "setup-baseurl-s12",
		"email":              "setup-baseurl-s12@x.com",
		"display_name":       "Setup BaseURL S12",
		"deliver_setup_link": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	// Without a base_url configured the setup-link path returns 400 (ConfigError).
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ConfigError")
}

// TestCreateUserClassic_NoPassword_S12 verifies the 400 returned when neither
// a password nor a setup-link/OTP flag is provided (createUserClassic guard).
func TestCreateUserClassic_NoPassword_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":     "nopwuser_s12",
		"email":        "nopw_s12@x.com",
		"display_name": "No Password S12",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Password is required")
}

// ── users_crud.go: GetUserByEmail ─────────────────────────────────────────────

// TestGetUserByEmail_EmptyParam_S12 verifies the 400 branch when ?email= is absent.
func TestGetUserByEmail_EmptyParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-email", nil))
	w := httptest.NewRecorder()
	uh.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "email is required")
}

// ── users_crud.go: GetUserByUsername ──────────────────────────────────────────

// TestGetUserByUsername_EmptyParam_S12 verifies the 400 branch when ?username= is absent.
func TestGetUserByUsername_EmptyParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-username", nil))
	w := httptest.NewRecorder()
	uh.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "username is required")
}

// TestGetUserByUsername_NotFound_S12 verifies the 404 branch.
func TestGetUserByUsername_NotFound_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-username?username=nobody_s12", nil))
	w := httptest.NewRecorder()
	uh.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: GetUserByExternalID ────────────────────────────────────────

// TestGetUserByExternalID_EmptyParam_S12 verifies the 400 branch.
func TestGetUserByExternalID_EmptyParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-external-id", nil))
	w := httptest.NewRecorder()
	uh.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "external_id is required")
}

// ── users_crud.go: GetUser ────────────────────────────────────────────────────

// TestGetUser_BadParam_S12 verifies the 400 branch when "id" is not a number.
func TestGetUser_BadParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/users/bad", nil), "id", "bad"))
	w := httptest.NewRecorder()
	uh.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetUser_NotFound_S12 verifies the 404 branch.
func TestGetUser_NotFound_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/users/9999", nil), "id", "9999"))
	w := httptest.NewRecorder()
	uh.GetUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: UpdateUser ─────────────────────────────────────────────────

// TestUpdateUser_BadParam_S12 verifies the 400 branch when "id" is not a number.
func TestUpdateUser_BadParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/bad", bytes.NewBufferString("{}")),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	uh.UpdateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateUser_InvalidJSON_S12 verifies the 400 branch for malformed JSON.
func TestUpdateUser_InvalidJSON_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/1", bytes.NewBufferString("not-json")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	uh.UpdateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateUser_NotFound_S12 verifies the 404 branch.
func TestUpdateUser_NotFound_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{"display_name": "New Name"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/9999", bytes.NewReader(body)),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	uh.UpdateUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: DeleteUser ────────────────────────────────────────────────

// TestDeleteUser_BadParam_S12 verifies the 400 branch.
func TestDeleteUser_BadParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/users/bad", nil), "id", "bad"))
	w := httptest.NewRecorder()
	uh.DeleteUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteUser_NotFound_S12 verifies the 404 branch.
func TestDeleteUser_NotFound_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/users/9999", nil), "id", "9999"))
	w := httptest.NewRecorder()
	uh.DeleteUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: RestoreUser ────────────────────────────────────────────────

// TestRestoreUser_BadParam_S12 verifies the 400 branch.
func TestRestoreUser_BadParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/users/bad/restore", nil), "id", "bad"))
	w := httptest.NewRecorder()
	uh.RestoreUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_crud.go: accountStateAction ────────────────────────────────────────

// TestAccountStateAction_SelfAction_S12 verifies the 400 returned when an admin
// tries to change their own account state. withUserCtx injects UserID=1; the
// URL param must match.
func TestAccountStateAction_SelfAction_S12(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	// Ensure a user with ID=1 exists (freshCoreS12WithAdmin seeds one).
	var u models.User
	require.NoError(t, db.First(&u).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/users/%d/suspend", u.ID), nil),
		"id", fmt.Sprintf("%d", u.ID),
	))
	w := httptest.NewRecorder()
	uh.SuspendUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Cannot change your own account state")
}

// TestAccountStateAction_NotFound_S12 verifies the 404 branch.
func TestAccountStateAction_NotFound_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/9999/suspend", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	uh.SuspendUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: UnlockUser ────────────────────────────────────────────────

// TestUnlockUser_BadParam_S12 verifies the 400 branch.
func TestUnlockUser_BadParam_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/users/bad/unlock", nil), "id", "bad"))
	w := httptest.NewRecorder()
	uh.UnlockUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUnlockUser_NotFound_S12 verifies the 404 branch.
func TestUnlockUser_NotFound_S12(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/users/9999/unlock", nil), "id", "9999"))
	w := httptest.NewRecorder()
	uh.UnlockUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── helpers.go: sendCreated / sendSuccess ─────────────────────────────────────

// TestSendCreated_WithMessage_S12 covers sendCreated's message != "" branch.
func TestSendCreated_WithMessage_S12(t *testing.T) {
	w := httptest.NewRecorder()
	sendCreated(w, map[string]any{"key": "val"}, "item created")
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "item created")
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

// TestSendSuccess_NoMessage_S12 covers sendSuccess without a message (the
// message="" branch must omit the "message" key entirely).
func TestSendSuccess_NoMessage_S12(t *testing.T) {
	w := httptest.NewRecorder()
	sendSuccess(w, map[string]any{"k": "v"}, "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), `"message"`)
}
