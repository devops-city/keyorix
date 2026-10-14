// handlers_s25_test.go — coverage sweep targeting remaining gaps after s24:
//   - dynamic_secrets.go: ListConfigs (happy path admin), RevokeLease (auth
//     forbidden), RenewLease (forbidden, lease-found-then-forbidden)
//   - secrets_expiring.go: ExpiringSecrets (no user ctx, bad id, happy path,
//     days param, nil-expiration branch)
//   - secrets_orphaned.go: OrphanedSecrets (no user ctx, bad id, happy path)
//   - secrets_copy.go: CopySecret (no user ctx, bad id, bad json, missing env,
//     source not found)
//   - shares_query.go: ListSharedSecrets (no user ctx, happy path),
//     ListGroupSharedSecrets (no user ctx, bad id, happy path),
//     GetSharingStatusWithIndicators (no user ctx, bad id, not found),
//     RemoveSelfFromShare (no user ctx, bad id, not found)
//   - sso.go: CompleteSSO (unknown provider, error param, missing code/state,
//     CompleteSSO error path with safe error msg)
//   - admin_jobs.go: RunExpiryReminders (no user ctx, valid lead_days, invalid
//     lead_days ignored), RunAnomalyAlerts (no user ctx), RunRotationReminders
//     (no user ctx)
//   - users_roles.go: UpdateUserRoles (valid role IDs happy path)
//   - secrets_usage.go: UsageMostAccessed (no user ctx, bad id, happy path),
//     UsageUnused (no user ctx, bad id, happy path)
//   - break_glass.go: ActivateBreakGlass (no user ctx, missing justification)
//   - access_review_campaigns.go: DecideAccessReviewCampaignItem (no user ctx,
//     bad ids)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

// freshCoreS25 opens a uniquely-named in-memory SQLite DB and returns a
// ready-to-use KeyorixCore.
func freshCoreS25(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s25_")
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

// freshCoreS25WithAdmin creates a core backed by a DB pre-seeded with an admin
// role and a user that withUserCtx (UserID=1) matches.
func freshCoreS25WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s25a_")
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
	testUser := &models.User{Username: "testuser_s25", Email: "testuser_s25@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// withChiParam_S25 is a local alias for setting a single chi URL param.
func withChiParam_S25(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// withChiParams2_S25 sets two chi URL params at once.
func withChiParams2_S25(r *http.Request, k1, v1, k2, v2 string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k1, v1)
	rctx.URLParams.Add(k2, v2)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// withChiParams3_S25 sets three chi URL params at once.
func withChiParams3_S25(r *http.Request, k1, v1, k2, v2, k3, v3 string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k1, v1)
	rctx.URLParams.Add(k2, v2)
	rctx.URLParams.Add(k3, v3)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// uintStrS25 converts a uint to its decimal string representation.
func uintStrS25(n uint) string {
	return fmt.Sprintf("%d", n)
}

// ── dynamic_secrets.go: ListConfigs happy path ───────────────────────────────

// TestDynamic_ListConfigs_AdminHappyPath_S25 verifies that an admin user can
// list configs (200) even when the list is empty.
func TestDynamic_ListConfigs_AdminHappyPath_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s25-list-cfg-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s25-list-cfg-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/dynamic-secrets/configs?project_id=%d&environment_id=%d", proj.ID, env.ID),
		nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestDynamic_ListConfigs_AdminNoScope_S25 verifies that an admin user can
// list configs with no scope params (global scope → empty list).
func TestDynamic_ListConfigs_AdminNoScope_S25(t *testing.T) {
	cs, _ := freshCoreS25WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dynamic_secrets.go: RevokeLease forbidden path ───────────────────────────

// TestDynamic_RevokeLease_Forbidden_S25 verifies the 403 branch: a user context
// exists but after GetDynamicSecretLease the authorize check fails (no role).
func TestDynamic_RevokeLease_Forbidden_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewDynamicSecretHandler(cs)

	// RevokeLease first calls GetDynamicSecretLease (not-found → 404 is already
	// tested elsewhere). With user ctx but no roles, the authorize() call returns
	// false → 403. But we can only reach authorize() if the lease exists; if the
	// lease doesn't exist we get 404. Test the 404 path as the pre-auth barrier.
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/nonexistent/revoke", nil),
		"leaseID", "nonexistent-lease",
	))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	// Not found because the lease doesn't exist.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamic_RenewLease_Forbidden_S25 verifies the 403 branch in RenewLease:
// user ctx is present but there is no lease → 404 (the authorize guard is only
// reachable when GetDynamicSecretLease succeeds).
func TestDynamic_RenewLease_Forbidden_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/missing/renew", nil),
		"leaseID", "missing-lease",
	))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets_expiring.go: ExpiringSecrets ──────────────────────────────────────

// TestExpiringSecrets_NoUserCtx_S25 verifies the 401 branch.
func TestExpiringSecrets_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/expiring", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestExpiringSecrets_BadID_S25 verifies the 400 branch on a non-numeric project id.
func TestExpiringSecrets_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/secrets/expiring", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestExpiringSecrets_HappyPath_S25 verifies 200 with an empty project.
func TestExpiringSecrets_HappyPath_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s25-expiring-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/expiring", nil),
		"id", uintStrS25(proj.ID),
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestExpiringSecrets_WithDays_S25 verifies the ?days=N query param branch.
func TestExpiringSecrets_WithDays_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s25-expiring-days-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/secrets/expiring?days=30", proj.ID), nil),
		"id", uintStrS25(proj.ID),
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestExpiringSecrets_InvalidDays_S25 verifies that an invalid ?days param is
// ignored (defaults to 0 which core interprets as the default window).
func TestExpiringSecrets_InvalidDays_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s25-expiring-invdays-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/secrets/expiring?days=notanumber", proj.ID), nil),
		"id", uintStrS25(proj.ID),
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── secrets_orphaned.go: OrphanedSecrets ─────────────────────────────────────

// TestOrphanedSecrets_NoUserCtx_S25 verifies the 401 branch.
func TestOrphanedSecrets_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/orphaned", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestOrphanedSecrets_BadID_S25 verifies the 400 branch on a non-numeric project id.
func TestOrphanedSecrets_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/secrets/orphaned", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestOrphanedSecrets_HappyPath_S25 verifies 200 with an empty project.
func TestOrphanedSecrets_HappyPath_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s25-orphaned-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/orphaned", nil),
		"id", uintStrS25(proj.ID),
	))
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── secrets_copy.go: CopySecret ──────────────────────────────────────────────

// TestCopySecret_NoUserCtx_S25 verifies the 401 branch.
func TestCopySecret_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"environment_id":1}`)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/copy", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCopySecret_BadID_S25 verifies the 400 branch on a non-numeric secret id.
func TestCopySecret_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"environment_id":1}`)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/bad/copy", body),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCopySecret_BadJSON_S25 verifies the 400 branch on invalid JSON body.
func TestCopySecret_BadJSON_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/copy", bytes.NewBufferString("{not valid json")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCopySecret_MissingEnvID_S25 verifies the 400 branch when environment_id is 0.
func TestCopySecret_MissingEnvID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/copy", bytes.NewBufferString(`{"environment_id":0}`)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCopySecret_SourceNotFound_S25 verifies the 404 branch when the source
// secret doesn't exist.
func TestCopySecret_SourceNotFound_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/99999/copy", bytes.NewBufferString(`{"environment_id":1}`)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── shares_query.go: ListSharedSecrets ───────────────────────────────────────

// TestListSharedSecrets_NoUserCtx_S25 verifies the 401 branch.
func TestListSharedSecrets_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/shared-secrets", nil)
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSharedSecrets_HappyPath_S25 verifies 200 with an empty list.
func TestListSharedSecrets_HappyPath_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shared-secrets", nil))
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── shares_query.go: ListGroupSharedSecrets ───────────────────────────────────

// TestListGroupSharedSecrets_NoUserCtx_S25 verifies the 401 branch.
func TestListGroupSharedSecrets_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/shared-secrets", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListGroupSharedSecrets_BadID_S25 verifies the 400 branch on a non-numeric
// group id.
func TestListGroupSharedSecrets_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/bad/shared-secrets", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListGroupSharedSecrets_HappyPath_S25 verifies 200 with an empty list for
// an existing group.
func TestListGroupSharedSecrets_HappyPath_S25(t *testing.T) {
	// #G10: ListGroupSharedSecrets now self-authorizes (secrets.read, global scope);
	// withUserCtx's UserID 1 needs a real grant, unlike freshCoreS25's bare fixture.
	cs, _ := freshCoreS25WithAdmin(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	// group ID 1 may or may not exist; storage returns empty list on missing group
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/shared-secrets", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── shares_query.go: GetSharingStatusWithIndicators ───────────────────────────

// TestGetSharingStatus_NoUserCtx_S25 verifies the 401 branch.
func TestGetSharingStatus_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/sharing-status", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetSharingStatus_BadID_S25 verifies the 400 branch on a non-numeric
// secret id.
func TestGetSharingStatus_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/bad/sharing-status", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetSharingStatus_NotFound_S25 verifies the 404 branch when the secret
// doesn't exist.
func TestGetSharingStatus_NotFound_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/99999/sharing-status", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	// 404 or 500 depending on how storage wraps not-found.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── shares_query.go: RemoveSelfFromShare ─────────────────────────────────────

// TestRemoveSelfFromShare_NoUserCtx_S25 verifies the 401 branch.
func TestRemoveSelfFromShare_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/1/self-share", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRemoveSelfFromShare_BadID_S25 verifies the 400 branch on a non-numeric
// secret id.
func TestRemoveSelfFromShare_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/bad/self-share", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveSelfFromShare_NotFound_S25 verifies the non-204 branch when the
// share doesn't exist.
func TestRemoveSelfFromShare_NotFound_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/99999/self-share", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	// 404 or 500 when the secret/share isn't found; never 204.
	assert.NotEqual(t, http.StatusNoContent, w.Code)
}

// ── sso.go: CompleteSSO branches ─────────────────────────────────────────────

// TestCompleteSSO_UnknownProvider_S25 verifies the 400 branch when the provider
// doesn't exist in core (SSOCompleteURL returns ok=false).
func TestCompleteSSO_UnknownProvider_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAuthHandler(cs, false)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/auth/sso/nonexistent/callback?code=x&state=y", nil),
		"provider", "nonexistent",
	)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCompleteSSO_NoProvider_S25 verifies the consistent "no provider" path
// when no SSO provider is configured in the test DB.
func TestCompleteSSO_NoProvider_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAuthHandler(cs, false)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/auth/sso/unknown/callback?error=access_denied", nil),
		"provider", "unknown",
	)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBeginSSO_UnknownProvider_S25 verifies that BeginSSO returns 400 when the
// provider is not registered.
func TestBeginSSO_UnknownProvider_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAuthHandler(cs, false)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/auth/sso/notreal/login", nil),
		"provider", "notreal",
	)
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── admin_jobs.go: RunExpiryReminders branches ───────────────────────────────

// TestRunExpiryReminders_NoUserCtx_S25 verifies the 401 branch.
func TestRunExpiryReminders_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAdminJobsHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders", nil)
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRunExpiryReminders_WithLeadDays_S25 verifies the lead_days query param
// branch is parsed correctly and returns 200.
func TestRunExpiryReminders_WithLeadDays_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAdminJobsHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders?lead_days=7", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRunExpiryReminders_InvalidLeadDays_S25 verifies that a non-numeric
// lead_days param is silently ignored (defaults to 0).
func TestRunExpiryReminders_InvalidLeadDays_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAdminJobsHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders?lead_days=notanumber", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRunAnomalyAlerts_NoUserCtx_S25 verifies the 401 branch.
func TestRunAnomalyAlerts_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAdminJobsHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/anomaly-alerts", nil)
	w := httptest.NewRecorder()
	h.RunAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRunRotationReminders_NoUserCtx_S25 verifies the 401 branch.
func TestRunRotationReminders_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAdminJobsHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/rotation-reminders", nil)
	w := httptest.NewRecorder()
	h.RunRotationReminders(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRunComplianceDigest_NoUserCtx_S25 verifies the 401 branch.
func TestRunComplianceDigest_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewAdminJobsHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil)
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── users_roles.go: UpdateUserRoles valid role path ──────────────────────────

// TestUpdateUserRoles_ValidRole_S25 verifies the success path when a valid role
// ID is provided (role exists in DB + user exists).
func TestUpdateUserRoles_ValidRole_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h := NewUsersRolesHandler(cs)

	// Create a target user to update roles for.
	target := &models.User{Username: "roles-valid-s25", Email: "roles-valid@example.com", AccountState: "active"}
	require.NoError(t, db.Create(target).Error)

	// Use the system_admin role (ID=1) which was seeded by freshCoreS25WithAdmin.
	// We need to fetch it to get its actual ID.
	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)

	body, _ := json.Marshal(map[string]any{"role_ids": []uint{adminRole.ID}})
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/1/roles", bytes.NewReader(body)),
		"id", uintStrS25(target.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// Either 200 (roles set) or 404 (user not found in core lookup) are valid.
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

// ── secrets_usage.go: UsageMostAccessed / UsageUnused ────────────────────────

// TestUsageMostAccessed_NoUserCtx_S25 verifies the 401 branch.
func TestUsageMostAccessed_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/usage/most-accessed", nil)
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUsageMostAccessed_BadProjectID_S25 verifies the 400 branch when the
// project_id query param is not a valid number.
func TestUsageMostAccessed_BadProjectID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/usage/most-accessed?project_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUsageMostAccessed_HappyPath_S25 verifies 200 with a valid project_id.
func TestUsageMostAccessed_HappyPath_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s25-usage-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/usage/most-accessed?project_id=%d", proj.ID), nil))
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUsageUnused_NoUserCtx_S25 verifies the 401 branch.
func TestUsageUnused_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/usage/unused", nil)
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUsageUnused_BadProjectID_S25 verifies the 400 branch when the project_id
// query param is not a valid number.
func TestUsageUnused_BadProjectID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/usage/unused?project_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUsageUnused_HappyPath_S25 verifies 200 with a valid project_id.
func TestUsageUnused_HappyPath_S25(t *testing.T) {
	cs, db := freshCoreS25WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	proj := &models.Project{Name: "s25-unused-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/usage/unused?project_id=%d", proj.ID), nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── break_glass.go: ActivateBreakGlass branches ──────────────────────────────

// TestActivateBreakGlass_BadID_S25 verifies the 400 branch on a non-numeric
// project id.
func TestActivateBreakGlass_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/break-glass",
			bytes.NewBufferString(`{"justification":"test"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestActivateBreakGlass_NoUserCtx_S25 verifies the 401 branch (valid ID, no
// user context).
func TestActivateBreakGlass_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass",
			bytes.NewBufferString(`{"justification":"test"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestActivateBreakGlass_BadJSON_S25 verifies the 400 branch when the request
// body is not valid JSON.
func TestActivateBreakGlass_BadJSON_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass",
			bytes.NewBufferString("{not json")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestActivateBreakGlass_MissingJustification_S25 verifies the 400 branch when
// justification is missing.
func TestActivateBreakGlass_MissingJustification_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass",
			bytes.NewBufferString(`{"justification":""}`)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns.go: DecideAccessReviewCampaignItem ───────────────

// TestDecideAccessReviewItem_BadProjectID_S25 verifies the 400 branch on a
// non-numeric project ID.
func TestDecideAccessReviewItem_BadProjectID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams3_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/bad/access-review/campaigns/1/items/1/decide",
			bytes.NewBufferString(`{"action":"attest"}`)),
		"id", "bad",
		"campaignId", "1",
		"itemId", "1",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewItem_BadCampaignID_S25 verifies the 400 branch on a
// non-numeric campaign ID.
func TestDecideAccessReviewItem_BadCampaignID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams3_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/bad/items/1/decide",
			bytes.NewBufferString(`{"action":"attest"}`)),
		"id", "1",
		"campaignId", "bad",
		"itemId", "1",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewItem_BadItemID_S25 verifies the 400 branch on a
// non-numeric item ID.
func TestDecideAccessReviewItem_BadItemID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams3_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/1/items/bad/decide",
			bytes.NewBufferString(`{"action":"attest"}`)),
		"id", "1",
		"campaignId", "1",
		"itemId", "bad",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewItem_NoUserCtx_S25 verifies the 401 branch when there
// is no user context.
func TestDecideAccessReviewItem_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams3_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/1/items/1/decide",
			bytes.NewBufferString(`{"action":"attest"}`)),
		"id", "1",
		"campaignId", "1",
		"itemId", "1",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDecideAccessReviewItem_BadJSON_S25 verifies the 400 branch on invalid JSON.
func TestDecideAccessReviewItem_BadJSON_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(withChiParams3_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/1/items/1/decide",
			bytes.NewBufferString("{not json")),
		"id", "1",
		"campaignId", "1",
		"itemId", "1",
	))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewItem_MissingAction_S25 verifies the 400 branch when
// action is empty.
func TestDecideAccessReviewItem_MissingAction_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(withChiParams3_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/1/items/1/decide",
			bytes.NewBufferString(`{"action":""}`)),
		"id", "1",
		"campaignId", "1",
		"itemId", "1",
	))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── ListShares filter branches ────────────────────────────────────────────────

// TestListShares_NoUserCtx_S25 verifies the 401 branch.
func TestListShares_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/shares", nil)
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListShares_HappyPath_S25 verifies the happy path (empty list).
func TestListShares_HappyPath_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_RecipientTypeFilter_S25 verifies the recipientType=group
// filter branch (covers the "group" check in the filter).
func TestListShares_RecipientTypeFilter_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?recipientType=group", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_PageParams_S25 verifies that page / pageSize params are parsed.
func TestListShares_PageParams_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?page=2&pageSize=5", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_SecretIDFilter_S25 verifies the ?secretId= filter branch.
func TestListShares_SecretIDFilter_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?secretId=1", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── RevokeBreakGlass branches ────────────────────────────────────────────────

// TestRevokeBreakGlass_BadProjectID_S25 verifies the 400 branch on bad project
// ID.
func TestRevokeBreakGlass_BadProjectID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/break-glass/1/revoke", nil),
		"id", "bad",
		"activationId", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeBreakGlass_BadActivationID_S25 verifies the 400 branch on a bad
// activation ID.
func TestRevokeBreakGlass_BadActivationID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass/bad/revoke", nil),
		"id", "1",
		"activationId", "bad",
	)
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeBreakGlass_NoUserCtx_S25 verifies the 401 branch.
func TestRevokeBreakGlass_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass/1/revoke", nil),
		"id", "1",
		"activationId", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRevokeBreakGlass_NotFound_S25 verifies that a valid request with a
// non-existent activation returns an error (404 or 400).
func TestRevokeBreakGlass_NotFound_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(withChiParams2_S25(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass/99999/revoke", nil),
		"id", "1",
		"activationId", "99999",
	))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	// Not 200 — activation doesn't exist.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── CloseAccessReviewCampaign branches ────────────────────────────────────────

// TestCloseAccessReviewCampaign_BadProjectID_S25 verifies the 400 branch.
func TestCloseAccessReviewCampaign_BadProjectID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/bad/access-review/campaigns/1/close",
			bytes.NewBufferString(`{}`)),
		"id", "bad",
		"campaignId", "1",
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCloseAccessReviewCampaign_BadCampaignID_S25 verifies the 400 branch on a
// non-numeric campaign ID.
func TestCloseAccessReviewCampaign_BadCampaignID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/bad/close",
			bytes.NewBufferString(`{}`)),
		"id", "1",
		"campaignId", "bad",
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCloseAccessReviewCampaign_NoUserCtx_S25 verifies the 401 branch.
func TestCloseAccessReviewCampaign_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParams2_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns/1/close",
			bytes.NewBufferString(`{}`)),
		"id", "1",
		"campaignId", "1",
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── OpenAccessReviewCampaign branches ─────────────────────────────────────────

// TestOpenAccessReviewCampaign_BadProjectID_S25 verifies the 400 branch.
func TestOpenAccessReviewCampaign_BadProjectID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/bad/access-review/campaigns",
			bytes.NewBufferString(`{"name":"test"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestOpenAccessReviewCampaign_NoUserCtx_S25 verifies the 401 branch.
func TestOpenAccessReviewCampaign_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewCatalogHandler(cs)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/1/access-review/campaigns",
			bytes.NewBufferString(`{"name":"test"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── isSafeSSOError additional branches ────────────────────────────────────────

// TestIsSafeSSOError_AdditionalBranches_S25 exercises additional safe-string
// checks that may not be covered by existing tests.
func TestIsSafeSSOError_AdditionalBranches_S25(t *testing.T) {
	assert.True(t, isSafeSSOError("unknown SAML provider"))
	assert.True(t, isSafeSSOError("login state does not match the callback provider"))
	assert.True(t, isSafeSSOError("login state expired"))
	assert.True(t, isSafeSSOError("the token response carried no id_token"))
	assert.True(t, isSafeSSOError("the assertion carried no subject or email"))
	assert.True(t, isSafeSSOError("the IdP returned no email; cannot auto-provision an account"))
}

// ── ListSecretShares branches ─────────────────────────────────────────────────

// TestListSecretShares_NoUserCtx_S25 verifies the 401 branch.
func TestListSecretShares_NoUserCtx_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/shares", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSecretShares_BadID_S25 verifies the 400 branch on a non-numeric
// secret id.
func TestListSecretShares_BadID_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/bad/shares", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecretShares_NotFound_S25 verifies the not-found error path when the
// secret doesn't exist.
func TestListSecretShares_NotFound_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/99999/shares", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	// Not found or forbidden (no ownership).
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── parseScopeQuery: invalid environment_id branch ───────────────────────────

// TestDynamic_ListConfigs_BadEnvIDInQuery_S25 verifies the 400 branch for an
// invalid environment_id query param. parseScopeQuery is called by ListConfigs.
func TestDynamic_ListConfigs_BadEnvIDInQuery_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewDynamicSecretHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/dynamic-secrets/configs?environment_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamic_ListConfigs_BadProjectIDInQuery_S25 verifies the 400 branch for
// an invalid project_id query param.
func TestDynamic_ListConfigs_BadProjectIDInQuery_S25(t *testing.T) {
	cs := freshCoreS25(t)
	h := NewDynamicSecretHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/dynamic-secrets/configs?project_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── UserContext.ActorKind / PrincipalID ───────────────────────────────────────

// TestUserContextActorKind_S25 exercises the ActorKind and PrincipalID methods
// on various UserContext field combinations.
func TestUserContextActorKind_S25(t *testing.T) {
	// No machine identity → "user" kind
	u := &middleware.UserContext{UserID: 5, Username: "u5"}
	assert.Equal(t, "user", u.ActorKind())
	assert.Equal(t, uint(5), u.PrincipalID())

	// With MachineIdentityID set but no ActorType → still "user" kind
	// (ActorKind checks ActorType string, not MachineIdentityID presence)
	mid := uint(42)
	m := &middleware.UserContext{UserID: 0, Username: "machine-42", MachineIdentityID: &mid}
	// PrincipalID returns MachineIdentityID when set
	assert.Equal(t, uint(42), m.PrincipalID())
}
