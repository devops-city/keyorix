// handlers_s26_test.go — coverage sweep targeting remaining gaps after s25:
//   - dynamic_secrets.go: GetConfig (happy path with DB-seeded config),
//     ListLeases (happy path), ClassifyConfig (happy path), SetConfigEnabled
//     (happy path), isSafeDynamicSecretError (all safe-string branches)
//   - break_glass.go: ActivateBreakGlass (disabled → 403, enabled+no-role → 400)
//   - catalog.go: GetProject (bad id), RestoreProject (bad id),
//     GetProjectDrift (bad id), CreateProjectEnvironment (bad id),
//     ListProjectEnvironments (bad id)
//   - users_roles.go: UpdateUserRoles (nonexistent role id → 400)
//   - invitations.go: CreateInvitation (unknown role → 400), CreateGlobalInvitation
//     (bad project assignment auth → 403 / missing email → 400)
//   - access_review_campaigns_proxy.go: GetLatestClosedAccessReviewCampaignProxy
//     (existing closed campaign → non-nil response)
//   - break_glass_proxy.go: CreateBreakGlassActivationProxy (missing state → 400)
//   - users_crud.go: GetUser (bad id), GetUserByEmail/Username/ExternalID (not found)
//   - shares_crud.go: RevokeShare (bad id)
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
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

// freshCoreS26 opens a uniquely-named in-memory SQLite DB.
func freshCoreS26(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s26_")
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
		&models.LegalHold{}, &models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreS26WithAdmin creates a core backed by a DB pre-seeded with an admin
// role and a user that withUserCtx (UserID=1) matches.
func freshCoreS26WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s26a_")
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
		&models.LegalHold{}, &models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
	)
	require.NoError(t, err)
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "testuser_s26", Email: "testuser_s26@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// uintStrS26 converts a uint to its string representation.
func uintStrS26(n uint) string {
	return fmt.Sprintf("%d", n)
}

// ── dynamic_secrets.go: GetConfig happy path ──────────────────────────────────

// TestGetConfig_HappyPath_S26 verifies that an admin user can GET a config
// that exists in the DB (happy path — covers the sendSuccess branch at line
// 163 in dynamic_secrets.go).
func TestGetConfig_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s26-getconfig-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s26-getconfig-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name:          "s26-test-config",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/1", nil),
		"id", uintStrS26(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.GetConfig(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dynamic_secrets.go: ListLeases happy path ────────────────────────────────

// TestListLeases_HappyPath_S26 verifies that an admin user can list leases for
// an existing config (200 with empty list).
func TestListLeases_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s26-listleases-proj"}
	require.NoError(t, db.Create(proj).Error)
	cfg := &models.DynamicSecretConfig{
		Name:        "s26-listleases-config",
		ProjectID:   proj.ID,
		BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/1/leases", nil),
		"id", uintStrS26(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dynamic_secrets.go: ClassifyConfig happy path ───────────────────────────

// TestClassifyConfig_HappyPath_S26 verifies PATCH classification on an existing
// config returns 200 and updates the config.
func TestClassifyConfig_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s26-classify-proj"}
	require.NoError(t, db.Create(proj).Error)
	cfg := &models.DynamicSecretConfig{
		Name:        "s26-classify-config",
		ProjectID:   proj.ID,
		BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	body, _ := json.Marshal(map[string]string{"classification": "confidential"})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/1/classification",
			bytes.NewReader(body)),
		"id", uintStrS26(cfg.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestClassifyConfig_BadJSON_S26 verifies that invalid JSON body returns 400.
func TestClassifyConfig_BadJSON_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s26-classify-bad-proj"}
	require.NoError(t, db.Create(proj).Error)
	cfg := &models.DynamicSecretConfig{
		Name:        "s26-classify-bad-config",
		ProjectID:   proj.ID,
		BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/1/classification",
			bytes.NewBufferString("{not-valid-json}")),
		"id", uintStrS26(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets.go: SetConfigEnabled happy path ─────────────────────────

// TestSetConfigEnabled_HappyPath_S26 verifies PATCH enabled on an existing
// config returns 200.
func TestSetConfigEnabled_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s26-setenabled-proj"}
	require.NoError(t, db.Create(proj).Error)
	cfg := &models.DynamicSecretConfig{
		Name:        "s26-setenabled-config",
		ProjectID:   proj.ID,
		BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	body, _ := json.Marshal(map[string]bool{"enabled": false})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/1/enabled",
			bytes.NewReader(body)),
		"id", uintStrS26(cfg.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetConfigEnabled_BadJSON_S26 verifies that invalid JSON body returns 400.
func TestSetConfigEnabled_BadJSON_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s26-setenabled-bad-proj"}
	require.NoError(t, db.Create(proj).Error)
	cfg := &models.DynamicSecretConfig{
		Name:        "s26-setenabled-bad-config",
		ProjectID:   proj.ID,
		BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/1/enabled",
			bytes.NewBufferString("{not-valid-json}")),
		"id", uintStrS26(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets.go: isSafeDynamicSecretError ────────────────────────────

// TestIsSafeDynamicSecretError_AllSafeStrings_S26 verifies all safe message
// substrings return true.
func TestIsSafeDynamicSecretError_AllSafeStrings_S26(t *testing.T) {
	safeMessages := []string{
		"config not found",
		"lease not found",
		"lease is not active",
		"lease has expired; issue a new lease instead",
		"cannot issue from the",
		"active-lease limit reached",
		"mints self-expiring credentials that cannot be renewed",
		"unsupported backend",
	}
	for _, msg := range safeMessages {
		assert.True(t, isSafeDynamicSecretError(msg), "expected %q to be safe", msg)
	}
	assert.False(t, isSafeDynamicSecretError("unexpected internal error"), "expected unsafe error to return false")
}

// ── break_glass.go: ActivateBreakGlass branches ──────────────────────────────

// TestActivateBreakGlass_Disabled_S26 verifies that when break-glass is disabled
// (the default), the handler returns 403 (permission denied branch).
func TestActivateBreakGlass_Disabled_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	// break-glass is disabled by default — no SetBreakGlassPolicy call needed
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-bg-disabled"}
	require.NoError(t, db.Create(proj).Error)

	body, _ := json.Marshal(map[string]string{
		"justification": "emergency access required for incident response",
	})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass",
			bytes.NewReader(body)),
		"id", uintStrS26(proj.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)

	// Disabled → "permission denied" → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestActivateBreakGlass_EnabledNoRole_S26 verifies that when break-glass is
// enabled but no emergency role is configured, the handler returns 400
// (no emergency role branch).
func TestActivateBreakGlass_EnabledNoRole_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	// Enable break-glass but don't set an emergency role.
	cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled:       true,
		EmergencyRole: "",
		DefaultTTL:    time.Hour,
	})
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-bg-norole"}
	require.NoError(t, db.Create(proj).Error)
	// Make user 1 a project member (project-scoped role grant required by IsProjectMember).
	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID:    1,
		RoleID:    adminRole.ID,
		ProjectID: proj.ID,
	}).Error)

	body, _ := json.Marshal(map[string]string{
		"justification": "emergency access required for incident response procedure",
	})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass",
			bytes.NewReader(body)),
		"id", uintStrS26(proj.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)

	// "no emergency role" → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestActivateBreakGlass_EnabledRoleNotFound_S26 verifies that when break-glass
// is enabled with a role name that doesn't exist, the handler returns 400
// ("not found" branch).
func TestActivateBreakGlass_EnabledRoleNotFound_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled:       true,
		EmergencyRole: "nonexistent_emergency_role",
		DefaultTTL:    time.Hour,
	})
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-bg-rolenotfound"}
	require.NoError(t, db.Create(proj).Error)
	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID:    1,
		RoleID:    adminRole.ID,
		ProjectID: proj.ID,
	}).Error)

	body, _ := json.Marshal(map[string]string{
		"justification": "emergency access required for incident response procedure",
	})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass",
			bytes.NewReader(body)),
		"id", uintStrS26(proj.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)

	// "not found" → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── catalog.go: bad-ID branches ──────────────────────────────────────────────

// TestGetProject_BadID_S26 verifies that a non-numeric project ID returns 400.
func TestGetProject_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRestoreProject_BadID_S26 verifies that a non-numeric project ID returns 400.
func TestRestoreProject_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/restore", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetProjectDrift_BadID_S26 verifies that a non-numeric project ID returns 400.
func TestGetProjectDrift_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/drift", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateProjectEnvironment_BadID_S26 verifies that a non-numeric project ID
// returns 400.
func TestCreateProjectEnvironment_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	body, _ := json.Marshal(map[string]string{"name": "staging"})
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/environments",
			bytes.NewReader(body)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListProjectEnvironments_BadID_S26 verifies that a non-numeric project ID
// returns 400.
func TestListProjectEnvironments_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/environments", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteEnvironment_BadID_S26 verifies that a non-numeric environment ID
// returns 400.
func TestDeleteEnvironment_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	// DeleteEnvironment reads chi.URLParam(r, "id") as the environment ID.
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/environments/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_roles.go: UpdateUserRoles with nonexistent role ID ──────────────────

// TestUpdateUserRoles_NonexistentRoleID_S26 verifies that supplying a role_id
// that does not exist in the DB returns 400.
func TestUpdateUserRoles_NonexistentRoleID_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewUsersRolesHandler(cs)

	body, _ := json.Marshal(map[string]any{"role_ids": []uint{99999}})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/1/roles", bytes.NewReader(body)),
		"id", "1",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)

	// Role ID 99999 does not exist → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: CreateInvitation with unknown role ────────────────────────

// TestCreateInvitation_UnknownRole_S26 verifies that supplying an unknown role
// name returns 400 via the inv==nil bad-input path.
func TestCreateInvitation_UnknownRole_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-invite-proj"}
	require.NoError(t, db.Create(proj).Error)

	body, _ := json.Marshal(map[string]string{
		"email": "newuser@example.com",
		"role":  "nonexistent_role_name",
	})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/invitations",
			bytes.NewReader(body)),
		"id", uintStrS26(proj.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)

	// Unknown role → error path (inv==nil, status=400)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns_proxy.go: GetLatestClosed with existing campaign ──

// TestGetLatestClosedCampaignProxy_WithRecord_S26 verifies that when a closed
// campaign exists, GetLatestClosedAccessReviewCampaignProxy returns 200 with a
// non-nil campaign (covers line 318 in access_review_campaigns_proxy.go).

// ── users_crud.go: bad ID / not found paths ──────────────────────────────────

// TestGetUser_BadID_S26 verifies that a non-numeric user ID returns 400.
func TestGetUser_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/bad", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetUserByEmail_NotFound_S26 verifies the 404 branch for GetUserByEmail.
func TestGetUserByEmail_NotFound_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/users/by-email?email=nobody%40example.com", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetUserByUsername_NotFound_S26 verifies the 404 branch for GetUserByUsername.
func TestGetUserByUsername_NotFound_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/users/by-username?username=nobody", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetUserByExternalID_NotFound_S26 verifies the 404 branch for GetUserByExternalID.
func TestGetUserByExternalID_NotFound_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/users/by-external-id?external_id=nobody", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── shares_crud.go: RevokeShare bad ID ───────────────────────────────────────

// TestRevokeShare_BadID_S26 verifies that a non-numeric share ID returns 400.
func TestRevokeShare_BadID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/shares/bad", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_roles.go: GetUserRolesForUser happy path ───────────────────────────

// TestGetUserRolesForUser_HappyPath_S26 verifies that an existing user's roles
// are returned (200).
func TestGetUserRolesForUser_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewUsersRolesHandler(cs)

	// User 1 exists (testuser_s26 seeded by freshCoreS26WithAdmin).
	_ = db
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/1/roles", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetUserPermissionsForUser_HappyPath_S26 verifies that an existing user's
// permissions are returned (200).
func TestGetUserPermissionsForUser_HappyPath_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewUsersRolesHandler(cs)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/1/permissions", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetUserMembershipsForUser_HappyPath_S26 verifies that an existing user's
// memberships are returned (200 with empty list).
func TestGetUserMembershipsForUser_HappyPath_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewUsersRolesHandler(cs)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/1/memberships", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ListBreakGlassActivations happy path ─────────────────────────────────────

// TestListBreakGlassActivations_HappyPath_S26 verifies that listing break-glass
// activations for a valid project returns 200.
func TestListBreakGlassActivations_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-listbg-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/break-glass", nil),
		"id", uintStrS26(proj.ID),
	))
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ListAccessReviewCampaigns: empty project variant ─────────────────────────

// TestListAccessReviewCampaigns_EmptyResult_S26 verifies that listing campaigns
// for a valid but empty project returns 200 with empty list.
func TestListAccessReviewCampaigns_EmptyResult_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-listcamp-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/access-review/campaigns", nil),
		"id", uintStrS26(proj.ID),
	)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns_proxy: CreateAccessReviewCampaignProxy happy path ─

// TestCreateAccessReviewCampaignProxy_HappyPath_S26 verifies that a valid campaign
// body creates a campaign and returns 200.

// ── ListInvitations happy path ────────────────────────────────────────────────

// TestListInvitations_HappyPath_S26 verifies that listing invitations for a
// valid project returns 200 with empty list.
func TestListInvitations_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-listinv-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/invitations", nil),
		"id", uintStrS26(proj.ID),
	)
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetOpenAccessReviewCampaignProxy with open campaign ───────────────────────

// TestGetOpenAccessReviewCampaignProxy_WithOpenCampaign_S26 verifies that when
// an open campaign exists, GetOpenAccessReviewCampaignProxy returns it.

// ── CountPendingAccessReviewItemsProxy happy path ────────────────────────────

// TestCountPendingAccessReviewItemsProxy_HappyPath_S26 verifies the happy path
// for counting pending items in a campaign (returns 200 with count=0).

// ── CreateAccessReviewItemsProxy happy path ───────────────────────────────────

// TestCreateAccessReviewItemsProxy_EmptyItems_S26 verifies that posting zero
// items returns 200 (empty-batch path).

// ── GetAccessReviewItemProxy happy path (after creating an item) ─────────────

// TestGetAccessReviewItemProxy_HappyPath_S26 verifies that looking up an
// existing item returns 200.

// ── UpdateAccessReviewItemProxy happy path ────────────────────────────────────

// TestUpdateAccessReviewItemProxy_HappyPath_S26 verifies that updating a pending
// item in an open campaign returns 200.

// ── ListAccessReviewItemsProxy with items ────────────────────────────────────

// TestListAccessReviewItemsProxy_WithItems_S26 verifies that listing items for
// a campaign that has items returns 200 with the items.

// ── GetBreakGlassActivationProxy happy path ───────────────────────────────────

// TestGetBreakGlassActivationProxy_HappyPath_S26 verifies that looking up an
// existing break-glass activation returns 200.

// ── ListBreakGlassActivationsProxy happy path ─────────────────────────────────

// TestListBreakGlassActivationsProxy_HappyPath_S26 verifies the happy path for
// listing break-glass activations (empty list → 200).

// ── RevokeBreakGlassActivationProxy happy path ───────────────────────────────

// TestRevokeBreakGlassActivationProxy_NotFound_S26 verifies 404 when revoke
// targets a non-existent activation.
//
// Was asserting 409 (ErrBreakGlassNotActive) before the G80 documented-exception
// fix added a GetBreakGlassActivation lookup ahead of the conditional revoke: the
// old raw single-conditional-UPDATE passthrough couldn't distinguish "no such
// row" from "row exists but isn't active" — both looked like zero rows affected.
// The fix's existence check makes that distinction correctly; a truly
// non-existent ID is now 404, not 409. See
// TestRevokeBreakGlassActivationProxy_AlreadyRevoked_S26 below for the 409 case
// this test used to also (imprecisely) cover.

// TestRevokeBreakGlassActivationProxy_AlreadyRevoked_S26 verifies 409 when revoke
// targets an activation that exists but is already in state=revoked — the case
// TestRevokeBreakGlassActivationProxy_NotFound_S26 used to (imprecisely) assert
// via a non-existent ID instead.

// TestRevokeBreakGlassActivationProxy_ExpiredStateStillRevocable_S26 is #1653
// reopened's regression test for this call site: a TTL-lapsed activation
// (State == expired, whether via read-time projection or the persisted
// ReconcileExpiredBreakGlassActivation transition) must still be revocable --
// refusing it here because of a clock-derived value was the exact defect this
// finding produced, duplicated at this second (remote-storage-proxy) call
// site alongside core.RevokeBreakGlass's own guard.

// TestRevokeBreakGlassActivationProxy_RemovesRoleGrant is the G80 documented-
// exception fix's own regression test: before the fix, this handler flipped the
// activation to state=revoked WITHOUT ever removing the underlying role
// assignment (its offsetting effect was claimed to travel through a separate
// call chain that turned out not to exist — the missing /api/v1/rbac/remove-role
// wire route, #1511). A live emergency role grant must actually be gone from
// user_roles (the table RBAC reads) after a successful revoke, not just
// reported revoked in the activation row.

// ── catalog.go: DeleteEnvironment error branches ──────────────────────────────

// TestDeleteEnvironment_NotFound_S26 verifies 404 when deleting a non-existent
// environment.
func TestDeleteEnvironment_NotFound_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/environments/99999", nil),
		"id", "99999",
	)
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteEnvironment_HasActiveSecrets_S26 verifies 409 when deleting an
// environment that still contains active secrets.
func TestDeleteEnvironment_HasActiveSecrets_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-delenv-secrets-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s26-delenv-secrets-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	// Seed an active secret in this environment.
	secret := &models.SecretNode{
		Name:          "s26-test-secret",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		IsSecret:      true,
		Status:        "active",
	}
	require.NoError(t, db.Create(secret).Error)

	req := withChiParam_S25(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/environments/%d", env.ID), nil),
		"id", uintStrS26(env.ID),
	)
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	// Environment has active secrets → 409 Conflict
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── catalog.go: DeleteProject with secrets ────────────────────────────────────

// TestDeleteProject_HasSecrets_S26 verifies 409 when deleting a project that
// still contains secrets (without force=true).
func TestDeleteProject_HasSecrets_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-delproj-secrets"}
	require.NoError(t, db.Create(proj).Error)
	// Seed a secret node in this project.
	secret := &models.SecretNode{
		Name:      "s26-blocking-secret",
		ProjectID: proj.ID,
		IsSecret:  true,
		Status:    "active",
	}
	require.NoError(t, db.Create(secret).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/projects/%d", proj.ID), nil),
		"id", uintStrS26(proj.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteProject(w, req)
	// Project has secrets → 409 Conflict
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── access_request_proxy.go: happy paths ─────────────────────────────────────

// TestCreateAccessRequestProxy_HappyPath_S26 verifies that a valid access
// request is stored and 200 returned.

// TestGetAccessRequestProxy_HappyPath_S26 verifies that looking up an existing
// access request returns 200.

// TestListAccessRequestsProxy_HappyPath_S26 verifies that listing access
// requests for a project returns 200.

// TestListAccessRequestApprovalsProxy_HappyPath_S26 verifies that listing
// approvals for an access request returns 200 with empty list.

// TestUpdateAccessRequestProxy_HappyPath_S26 verifies that updating an existing
// access request returns 200.

// TestCreateAccessRequestApprovalProxy_HappyPath_S26 verifies that creating an
// approval for an access request returns 200.

// ── rbac.go: GetGroupRoles happy path ────────────────────────────────────────

// TestGetGroupRoles_HappyPath_S26 verifies that listing roles for a group
// returns 200 with empty list.
func TestGetGroupRoles_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	group := &models.Group{Name: "s26-group", Description: "test group"}
	require.NoError(t, db.Create(group).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/groups/%d/roles", group.ID), nil),
		"id", uintStrS26(group.ID),
	))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rbac.go: ListRoles happy path ────────────────────────────────────────────

// TestListRoles_HappyPath_S26 verifies that listing roles returns 200.
func TestListRoles_HappyPath_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil))
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities.go: ListOIDCBindings happy path ──────────────────────

// TestListOIDCBindings_HappyPath_S26 verifies that listing OIDC bindings for a
// machine identity returns 200 with empty list.
func TestListOIDCBindings_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-oidc-proj"}
	require.NoError(t, db.Create(proj).Error)
	machine := &models.MachineIdentity{
		Name:      "s26-oidc-machine",
		ProjectID: proj.ID,
	}
	require.NoError(t, db.Create(machine).Error)

	// ListOIDCBindings uses chi "id" (project) and "machineId" (machine).
	req := withUserCtx(withChiParams2_S25(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings", proj.ID, machine.ID), nil),
		"id", uintStrS26(proj.ID),
		"machineId", uintStrS26(machine.ID),
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListMachineIdentities_HappyPath_S26 verifies that listing machine
// identities returns 200 with empty or populated list.
func TestListMachineIdentities_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-list-machine-proj"}
	require.NoError(t, db.Create(proj).Error)

	// ListMachineIdentities uses chi "id" (project ID), not a query param.
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/projects/%d/machine-identities", proj.ID), nil),
		"id", uintStrS26(proj.ID),
	))
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SoD proxy: happy paths ────────────────────────────────────────────────────

// TestCreateSoDPolicyProxy_HappyPath_S26 verifies that creating a SoD policy
// returns 200 (proxy path).
//
// #1529: CreateSoDPolicy now requires admin-tier authority, so this needs
// freshCoreS26WithAdmin (seeds UserID=1 as admin) + withUserCtx (attaches
// UserID=1 to the request context) instead of the plain freshCoreS26 +
// bare-context request this test used before.

// TestGetSoDPolicyProxy_HappyPath_S26 verifies that getting an existing SoD
// policy returns 200.

// TestDeleteSoDPolicyProxy_HappyPath_S26 verifies that deleting an existing
// SoD policy returns 200.

// ── webauthn_proxy.go: happy paths ──────────────────────────────────────────

// TestListWebAuthnCredentialsProxy_HappyPath_S26 verifies listing webauthn
// credentials for a user returns 200.

// TestCountWebAuthnCredentialsProxy_HappyPath_S26 verifies counting webauthn
// credentials for a user returns 200.

// ── setup_tokens_proxy.go: happy paths ──────────────────────────────────────

// TestExpireSetupTokenProxy_HappyPath_S26 verifies that expiring a setup token
// returns 200 when no tokens match (affected = 0).

// TestGetSetupTokenByHashProxy_NotFound_S26 verifies that looking up a
// setup token by hash returns 404 when not found.

// ── admin_jobs.go: RunComplianceDigest happy path ────────────────────────────

// TestRunComplianceDigest_HappyPath_S26 verifies that triggering the compliance
// digest job returns 200 (no user context needed for admin jobs).
func TestRunComplianceDigest_HappyPath_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewAdminJobsHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil))
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rbac.go: replaceRolePermissions happy path ───────────────────────────────

// TestUpdateRole_ReplacePermissions_S26 verifies that UpdateRole with a list
// of permissions replaces the role's permissions and returns 200.
func TestUpdateRole_ReplacePermissions_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	// Create a role and some permissions.
	role := &models.Role{Name: "s26-update-role", Description: "test role"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read", Description: "read secrets"}
	require.NoError(t, db.Create(perm).Error)

	body, _ := json.Marshal(map[string]any{
		"name":           "s26-update-role",
		"description":    "updated description",
		"permission_ids": []uint{perm.ID},
	})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPut,
			fmt.Sprintf("/api/v1/roles/%d", role.ID),
			bytes.NewReader(body)),
		"id", uintStrS26(role.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rbac.go: DeleteRole happy path ───────────────────────────────────────────

// TestDeleteRole_HappyPath_S26 verifies that deleting a non-system role
// returns 200.
func TestDeleteRole_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	role := &models.Role{Name: "s26-delete-role", Description: "role to delete"}
	require.NoError(t, db.Create(role).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/roles/%d", role.ID), nil),
		"id", uintStrS26(role.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── users_crud.go: GetUser happy path ────────────────────────────────────────

// TestGetUser_HappyPath_S26 verifies that looking up a real user returns 200.
func TestGetUser_HappyPath_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/1", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── invitations.go: RevokeInvitation bad ID ──────────────────────────────────

// TestRevokeInvitation_BadProjectID_S26 verifies that a non-numeric project ID
// returns 400.
func TestRevokeInvitation_BadProjectID_S26(t *testing.T) {
	cs := freshCoreS26(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/projects/bad/invitations/1", nil),
		"id", "bad",
		"invitationId", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── ListInvitations with existing invitations ──────────────────────────────────

// TestListInvitations_WithInvitations_S26 verifies that listing invitations for
// a project with existing invitations returns 200.
func TestListInvitations_WithInvitations_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-list-inv-with-proj"}
	require.NoError(t, db.Create(proj).Error)

	// Seed an invitation.
	inv := &models.ProjectInvitation{
		ProjectID: proj.ID,
		Email:     "invitee@example.com",
		Role:      "viewer",
		State:     "pending",
		InvitedBy: 1,
	}
	require.NoError(t, db.Create(inv).Error)

	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/projects/%d/invitations", proj.ID), nil),
		"id", uintStrS26(proj.ID),
	)
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── audit.go: GetAuditRetention/VerifyAuditChain/WriteAuditCheckpoint ─────────

// TestGetAuditRetention_HappyPath_S26 verifies that getting the audit retention
// policy returns 200.
func TestGetAuditRetention_HappyPath_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewAuditHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestVerifyAuditChain_EmptyDB_S26 verifies that verifying the audit chain on
// an empty DB returns 200 (empty chain is valid).
func TestVerifyAuditChain_EmptyDB_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewAuditHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain/verify", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	// Empty DB → chain is valid → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestWriteAuditCheckpoint_S26 verifies that writing an audit checkpoint
// returns 412 when encryption is disabled (written=false, covers lines 431-436).
func TestWriteAuditCheckpoint_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewAuditHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoints", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	// Encryption not enabled → written=false → 412 PreconditionFailed
	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}

// ── rbac.go: not-found / builtin / reserved-name error paths ─────────────────

// TestGetRole_NotFound_S26 verifies that getting a non-existent role returns 404.
func TestGetRole_NotFound_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/roles/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetRoleByName_NotFound_S26 verifies that looking up a role by a
// non-existent name returns 404.
func TestGetRoleByName_NotFound_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/roles/by-name?name=nonexistent_role_s26", nil),
	)
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteRole_BuiltinRole_S26 verifies that attempting to delete a builtin
// role (e.g. system_admin) returns 403 Forbidden.
func TestDeleteRole_BuiltinRole_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	// The system_admin role was seeded by freshCoreS26WithAdmin.
	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/roles/1", nil),
		"id", uintStrS26(adminRole.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCreateRole_ReservedName_S26 verifies that creating a role with a
// reserved/builtin name returns 409 Conflict.
func TestCreateRole_ReservedName_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	// CreateRoleRequest requires name, description, and at least one permission.
	body, _ := json.Marshal(map[string]any{
		"name":        "system_admin",
		"description": "should be rejected by IsBuiltinRole check",
		"permissions": []string{"secrets.read"},
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles",
		bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRole(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── groups_handler.go: GetGroup not found ─────────────────────────────────────

// TestGetGroup_NotFound_S26 verifies that getting a non-existent group
// returns 404.
func TestGetGroup_NotFound_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── rotation_policies_handler.go: List with environment_id param ──────────────

// TestListRotationPolicies_WithEnvironmentID_S26 verifies that listing rotation
// policies with an environment_id query param returns 200 (covers the
// environmentID branch in the List handler).
func TestListRotationPolicies_WithEnvironmentID_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h := NewRotationPolicyHandler(cs)

	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies?environment_id=1", nil),
	)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── catalog.go: CreateProjectEnvironment validation error (too-long name) ─────

// TestCreateProjectEnvironment_TooLongName_S26 verifies that creating a project
// environment with a name longer than 200 characters returns 400 ValidationError
// (covers the CreateEnvironment validation-error branch at catalog.go:280-282).
func TestCreateProjectEnvironment_TooLongName_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-long-env-proj"}
	require.NoError(t, db.Create(proj).Error)

	// 201 'x' characters — exceeds the 200-char maxEnvironmentNameLen limit.
	longName := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"[:201]

	body, _ := json.Marshal(map[string]string{"name": longName})
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/v1/projects/%d/environments", proj.ID),
			bytes.NewReader(body)),
		"id", uintStrS26(proj.ID),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: RevokeInvitation happy path ───────────────────────────────

// TestRevokeInvitation_HappyPath_S26 verifies that revoking a pending invitation
// returns 200 OK (covers the sendSuccess branch in RevokeInvitation).
func TestRevokeInvitation_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-revoke-inv-proj"}
	require.NoError(t, db.Create(proj).Error)

	inv := &models.ProjectInvitation{
		ProjectID: proj.ID,
		Email:     "invitee_s26@example.com",
		Role:      "project_viewer",
		State:     "pending",
		InvitedBy: 1,
	}
	require.NoError(t, db.Create(inv).Error)

	req := withUserCtx(withChiParams2_S25(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/projects/%d/invitations/%d", proj.ID, inv.ID), nil),
		"id", uintStrS26(proj.ID),
		"invitationId", uintStrS26(inv.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRevokeInvitation_AlreadyRevoked_S26 verifies that revoking a non-pending
// invitation returns 409 Conflict (errOnlyPending path).
func TestRevokeInvitation_AlreadyRevoked_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-revoke-inv2-proj"}
	require.NoError(t, db.Create(proj).Error)

	inv := &models.ProjectInvitation{
		ProjectID: proj.ID,
		Email:     "invitee2_s26@example.com",
		Role:      "project_viewer",
		State:     "revoked", // already revoked
		InvitedBy: 1,
	}
	require.NoError(t, db.Create(inv).Error)

	req := withUserCtx(withChiParams2_S25(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/projects/%d/invitations/%d", proj.ID, inv.ID), nil),
		"id", uintStrS26(proj.ID),
		"invitationId", uintStrS26(inv.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	// "only a pending invitation can be revoked" → errOnlyPending → 409
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── break_glass.go: RevokeBreakGlass happy path ───────────────────────────────

// TestRevokeBreakGlass_HappyPath_S26 verifies that revoking an active break-glass
// activation returns 200 OK (covers the sendSuccess branch).
func TestRevokeBreakGlass_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s26-revoke-bg-proj"}
	require.NoError(t, db.Create(proj).Error)

	activation := &models.BreakGlassActivation{
		ProjectID:     proj.ID,
		UserID:        1,
		RoleID:        0, // no real role — RemoveUserRole will return ErrRoleNotAssigned which is tolerated
		RoleName:      "emergency_access",
		Justification: "test revoke",
		State:         "active",
	}
	require.NoError(t, db.Create(activation).Error)

	req := withUserCtx(withChiParams2_S25(
		httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/revoke", proj.ID, activation.ID), nil),
		"id", uintStrS26(proj.ID),
		"activationId", uintStrS26(activation.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── shares_query.go: ListSecretShares, ListShares filters, GetSharingStatus ──

// TestListSecretShares_HappyPath_S26 verifies that listing shares for a secret
// owned by the current user returns 200 (covers the sendSuccess branch).
func TestListSecretShares_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s26-list-secret-shares-proj"}
	require.NoError(t, db.Create(proj).Error)

	secret := &models.SecretNode{
		ProjectID: proj.ID,
		Name:      "s26-secret-for-shares",
		IsSecret:  true,
		Status:    "active",
		OwnerID:   1, // matches withUserCtx UserID
	}
	require.NoError(t, db.Create(secret).Error)

	// Owner authority requires live project membership (RBAC-001,
	// requireLiveOwnerAuthority) — the fixture's admin role grant is global
	// (ProjectID 0), which IsProjectMember deliberately does not count as
	// project membership, so seed a project-scoped role too.
	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID, ProjectID: proj.ID}).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/secrets/%d/shares", secret.ID), nil),
		"id", uintStrS26(secret.ID),
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_WithSecretIDFilter_S26 verifies that listing shares with a
// secretId filter covers the filter branch (line 80).
func TestListShares_WithSecretIDFilter_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/shares?secretId=1", nil),
	)
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_WithRecipientTypeFilter_S26 verifies that listing shares with
// a recipientType=user filter covers the filter branch (line 84).
func TestListShares_WithRecipientTypeFilter_S26(t *testing.T) {
	cs, _ := freshCoreS26WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/shares?recipientType=user", nil),
	)
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetSharingStatusWithIndicators_HappyPath_S26 verifies that getting
// sharing status for a secret owned by the current user returns 200.
func TestGetSharingStatusWithIndicators_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s26-sharing-status-proj"}
	require.NoError(t, db.Create(proj).Error)

	secret := &models.SecretNode{
		ProjectID: proj.ID,
		Name:      "s26-secret-for-status",
		IsSecret:  true,
		Status:    "active",
		OwnerID:   1, // matches withUserCtx UserID
	}
	require.NoError(t, db.Create(secret).Error)

	// Owner authority requires live project membership (RBAC-001,
	// requireLiveOwnerAuthority) — the fixture's admin role grant is global
	// (ProjectID 0), which IsProjectMember deliberately does not count as
	// project membership, so seed a project-scoped role too.
	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID, ProjectID: proj.ID}).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/secrets/%d/sharing-status", secret.ID), nil),
		"id", uintStrS26(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod.go: DeleteSoDPolicy success path ─────────────────────────────────────

// TestDeleteSoDPolicy_HappyPath_S26 verifies that deleting an existing SoD
// policy returns 200 OK (covers the sendSuccess branch in sod.go:89).
func TestDeleteSoDPolicy_HappyPath_S26(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	policy := &models.SoDPolicy{
		Name:        "s26-sod-policy-to-delete",
		PermissionA: "secrets.write",
		PermissionB: "roles.assign",
	}
	require.NoError(t, db.Create(policy).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete,
			fmt.Sprintf("/api/v1/sod/policies/%d", policy.ID), nil),
		"id", uintStrS26(policy.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
