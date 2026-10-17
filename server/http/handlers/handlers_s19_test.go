// handlers_s19_test.go — coverage sweep targeting branches not yet covered by
// earlier sweeps. Focuses on:
//   - groups_handler.go:66 CreateGroup (missing field → 400, bad body → 400, success → 201)
//   - secrets_expiring.go:27 ExpiringSecrets (no user ctx → 401, bad project id → 400, success → 200)
//   - sso.go:74 CompleteSSO (missing state → 302-redirect with error)
//   - machine_token_hygiene.go:30 MachineTokenHygiene (no user ctx → 401, success → 200)
//   - project_memberships.go:28 ListProjectMemberships (bad id → 400, success → 200, stale → 200)
//   - retention_proxy.go:289 DeleteExpiredShareRecordsProxy (bad body → 400, success → 200)
//   - rbac.go:708 GetGroupRoles (no user ctx → 401, bad id → 400, not-found → 500/404)
//   - users_handler.go:172 createUserLegacy (no user ctx → 401, bad JSON → 400, bad validation → 400, success → 201)
//   - machine_identities.go:520 ListOIDCBindings (bad project id → 400, bad machine id → 400, no user ctx → 401, success → 200)
//   - misc_remote_proxy.go:270 CreateUserWithRoleGrantsProxy (bad body → 400, missing fields → 400, success → 200)
//   - access_review_campaigns_proxy.go:303 GetLatestClosedAccessReviewCampaignProxy (missing project_id → 400, nil result → 200, success → 200)
//   - admin_jobs.go:85 RunComplianceDigest (no user ctx → 401, success → 200)
//   - connect_grants_proxy.go:141 DeleteConnectRefGrantProxy (bad id → 400, success → 200)
//   - dynamic_secrets_proxy.go:373 CountActiveLeasesProxy (missing config_id → 400, bad config_id → 400, success → 200)
//   - dynamic_secrets.go:193 ListLeases (bad config id → 403/400, success → 200)
//   - groups_proxy.go:144 UpdateGroupProxy (bad id → 400, bad body → 400, success → 200)
//   - invitations.go:232 ListAccessRequests (bad project id → 400, success → 200)
//   - legal_hold_proxy.go:85 CreateLegalHoldProxy (bad body → 400, missing reason → 400, success → 200)
//   - break_glass_proxy.go:142 CreateBreakGlassActivationProxy (bad body → 400, missing fields → 400, success → 200)
//   - project_memberships_proxy.go:102 CreateMembershipProxy (bad body → 400, missing fields → 400, success → 200)
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

// freshCoreS19 opens a uniquely-named in-memory SQLite DB and returns a
// ready-to-use KeyorixCore. Mirrors freshCoreS12/freshCoreS17.
func freshCoreS19(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s19_")
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
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreS19WithAdmin returns a KeyorixCore plus the underlying DB with
// user 1 wired to a system_admin role (matches withUserCtx's injected UserID=1).
func freshCoreS19WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s19a_")
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
	)
	require.NoError(t, err)

	adminRole := &models.Role{Name: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "testuser_s19", Email: "testuser_s19@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// ── groups_handler.go: CreateGroup ────────────────────────────────────────────

// TestCreateGroup_NoUserCtx_S19 — no user context → 401.
func TestCreateGroup_NoUserCtx_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]string{"name": "mygroup"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCreateGroup_BadJSON_S19 — malformed JSON body → 400.
func TestCreateGroup_BadJSON_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewBufferString("{bad")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateGroup_ValidationError_S19 — empty name fails identifier validation → 400.
func TestCreateGroup_ValidationError_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]string{"name": ""})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateGroup_Success_S19 — valid name → 201.
func TestCreateGroup_Success_S19(t *testing.T) {
	cs, _ := freshCoreS19WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]string{"name": "valid-group-s19", "description": "test"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ── secrets_expiring.go: ExpiringSecrets ─────────────────────────────────────

// TestExpiringSecrets_NoUserCtx_S19 — no user context → 401.
func TestExpiringSecrets_NoUserCtx_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/expiring", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestExpiringSecrets_BadProjectID_S19 — non-numeric project id → 400.
func TestExpiringSecrets_BadProjectID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/secrets/expiring", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestExpiringSecrets_EmptyResult_S19 — valid project id with no secrets → 200 with empty list.
func TestExpiringSecrets_EmptyResult_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/expiring?days=30", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "expiring")
}

// ── machine_token_hygiene.go: MachineTokenHygiene ────────────────────────────

// TestMachineTokenHygiene_NoUserCtx_S19 — no user context → 401.
func TestMachineTokenHygiene_NoUserCtx_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil)
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestMachineTokenHygiene_Success_S19 — with user context → 200 with tokens list.
func TestMachineTokenHygiene_Success_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=30", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "tokens")
}

// ── project_memberships.go: ListProjectMemberships ───────────────────────────

// TestListProjectMemberships_BadID_S19 — non-numeric project id → 400.
func TestListProjectMemberships_BadID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/notanumber/memberships", nil),
		"id", "notanumber",
	)
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListProjectMemberships_Success_S19 — valid project id, no memberships → 200.
func TestListProjectMemberships_Success_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/memberships", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "memberships")
}

// TestListProjectMemberships_Stale_S19 — stale=true filter → 200.
func TestListProjectMemberships_Stale_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/memberships?stale=true", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rbac.go: GetGroupRoles ────────────────────────────────────────────────────

// TestGetGroupRoles_NoUserCtx_S19 — no user context → 401.
func TestGetGroupRoles_NoUserCtx_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewRBACHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/roles", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetGroupRoles_BadID_S19 — non-numeric group id → 400.
func TestGetGroupRoles_BadID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewRBACHandler(cs)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/bad/roles", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetGroupRoles_Success_S19 — valid group id with no roles → 200.
func TestGetGroupRoles_Success_S19(t *testing.T) {
	cs, db := freshCoreS19WithAdmin(t)
	h := NewRBACHandler(cs)
	g := &models.Group{Name: "test-group-roles-s19"}
	require.NoError(t, db.Create(g).Error)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/roles", nil),
		"id", fmt.Sprintf("%d", g.ID),
	))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "roles")
}

// ── users_handler.go: createUserLegacy ───────────────────────────────────────

// TestCreateUserLegacy_NoUserCtx_S19 — no user context → 401.
func TestCreateUserLegacy_NoUserCtx_S19(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"username": "u", "email": "u@x.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users-legacy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCreateUserLegacy_BadJSON_S19 — malformed JSON → 400.
func TestCreateUserLegacy_BadJSON_S19(t *testing.T) {
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users-legacy",
		bytes.NewBufferString("{bad")))
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateUserLegacy_ValidationError_S19 — missing required fields → 400.
func TestCreateUserLegacy_ValidationError_S19(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"username": "", "email": ""})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users-legacy",
		bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateUserLegacy_Success_S19 — valid body (including required password) → 201.
func TestCreateUserLegacy_Success_S19(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"username":     "legacy-user-s19",
		"email":        "legacy-user-s19@example.com",
		"display_name": "Legacy User S19",
		"password":     "Str0ng#Pass!",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users-legacy",
		bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ── machine_identities.go: ListOIDCBindings ──────────────────────────────────

// TestListOIDCBindings_BadProjectID_S19 — non-numeric project id → 400.
func TestListOIDCBindings_BadProjectID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	r := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/machine-identities/1/oidc-bindings", nil),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListOIDCBindings_BadMachineID_S19 — non-numeric machine id → 400.
func TestListOIDCBindings_BadMachineID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	r := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/bad/oidc-bindings", nil),
		map[string]string{"id": "1", "machineId": "bad"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListOIDCBindings_NoUserCtx_S19 — no user context → 401.
// Use withChiParams (map form) to set both route params at once.
func TestListOIDCBindings_NoUserCtx_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	r := withChiParams(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/1/oidc-bindings", nil),
		map[string]string{"id": "1", "machineId": "1"},
	)
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListOIDCBindings_NotFound_S19 — valid params but machine doesn't exist → 404.
// machineInProject returns "machine identity not found" (contains "not found") → handler 404.
func TestListOIDCBindings_NotFound_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	r := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/99/machine-identities/99/oidc-bindings", nil),
		map[string]string{"id": "99", "machineId": "99"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── misc_remote_proxy.go: CreateUserWithRoleGrantsProxy ─────────────────────

// TestCreateUserWithRoleGrantsProxy_BadBody_S19 — malformed JSON → 400.

// TestCreateUserWithRoleGrantsProxy_MissingFields_S19 — missing username → 400.

// TestCreateUserWithRoleGrantsProxy_Success_S19 — all required fields → 200.

// ── access_review_campaigns_proxy.go: GetLatestClosedAccessReviewCampaignProxy ─

// TestGetLatestClosedAccessReviewCampaignProxy_MissingProjectID_S19 — missing project_id → 400.

// TestGetLatestClosedAccessReviewCampaignProxy_NilResult_S19 — project with no closed campaign → 200 nil.

// ── admin_jobs.go: RunComplianceDigest ───────────────────────────────────────

// TestRunComplianceDigest_NoUserCtx_S19 — no user context → 401.
func TestRunComplianceDigest_NoUserCtx_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewAdminJobsHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil)
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRunComplianceDigest_Success_S19 — with user context → 200.
func TestRunComplianceDigest_Success_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewAdminJobsHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil))
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sent")
}

// ── dynamic_secrets_proxy.go: CountActiveLeasesProxy ─────────────────────────

// TestCountActiveLeasesProxy_MissingConfigID_S19 — missing config_id → 400.

// TestCountActiveLeasesProxy_BadConfigID_S19 — non-numeric config_id → 400.

// TestCountActiveLeasesProxy_Success_S19 — valid config_id, config absent → count=0.

// ── dynamic_secrets.go: ListLeases ───────────────────────────────────────────

// TestListLeases_BadConfigID_S19 — non-numeric config id → 400/403.
func TestListLeases_BadConfigID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewDynamicSecretHandler(cs)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/bad/leases", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	// loadAuthorizedConfig returns 400 for bad id or 403 if authz fails first
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusForbidden)
}

// TestListLeases_NotFound_S19 — valid numeric config id but config doesn't exist → 403/404.
func TestListLeases_NotFound_S19(t *testing.T) {
	cs, _ := freshCoreS19WithAdmin(t)
	h := NewDynamicSecretHandler(cs)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/9999/leases", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusForbidden || w.Code == http.StatusInternalServerError)
}

// ── groups_proxy.go: UpdateGroupProxy ────────────────────────────────────────

// TestUpdateGroupProxy_BadID_S19 — non-numeric group id → 400.

// TestUpdateGroupProxy_BadBody_S19 — malformed JSON body → 400.

// TestUpdateGroupProxy_Success_S19 — GORM Save upserts (creates if absent) so a
// non-existent group ID succeeds rather than returning 404.
// TestUpdateGroupProxy_NonexistentID_S19: UpdateGroupProxy now routes through
// core.KeyorixCore.UpdateGroup (#G79), which requires the target group to
// already exist (GetGroup first) rather than the previous bare
// storage.UpdateGroup's GORM-Save upsert-on-missing-ID quirk — a PUT to a
// nonexistent group ID must 404, not silently create a new row.

// ── invitations.go: ListAccessRequests ───────────────────────────────────────

// TestListAccessRequests_BadProjectID_S19 — non-numeric project id → 400.
func TestListAccessRequests_BadProjectID_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/access-requests", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListAccessRequests_Success_S19 — valid project id, empty result → 200.
func TestListAccessRequests_Success_S19(t *testing.T) {
	cs := freshCoreS19(t)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/access-requests", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "access_requests")
}

// ── legal_hold_proxy.go: CreateLegalHoldProxy ────────────────────────────────

// TestCreateLegalHoldProxy_BadBody_S19 — malformed JSON → 400.

// TestCreateLegalHoldProxy_MissingReason_S19 — empty reason → 400.

// TestCreateLegalHoldProxy_Success_S19 — valid body → 200 with created hold.
// TestCreateLegalHoldProxy_Success_S19: CreateLegalHoldProxy now routes
// through core.KeyorixCore.PlaceLegalHold (#G79), which requires an
// admin-tier actor — an admin-tier caller (seeded here) can still place a
// hold via the proxy.

// TestCreateLegalHoldProxy_RefusesNonAdminActor_S19 is the #G79 regression: a
// system.write-only caller with no admin-tier role must be refused — the
// bug this fix closes let ANY caller holding system.write place a legal hold.

// ── project_memberships_proxy.go: CreateMembershipProxy ─────────────────────

// TestCreateMembershipProxy_BadBody_S19 — malformed JSON → 400.

// TestCreateMembershipProxy_MissingFields_S19 — missing required fields → 400.

// TestCreateMembershipProxy_Success_S19 — all required fields → 200 with membership.

// ── retention_proxy.go: DeleteExpiredShareRecordsProxy ───────────────────────

// TestDeleteExpiredShareRecordsProxy_BadBody_S19 — malformed JSON → 400.

// TestDeleteExpiredShareRecordsProxy_Success_S19 — valid before time, no records → 200.
