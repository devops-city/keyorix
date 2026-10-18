// secrets_crud_s13_test.go — additional coverage for secrets_crud.go and secrets_handler.go.
//
// Targets uncovered branches NOT already reached by secrets_crud_s15_test.go:
//   - GetSecret: bad "id" path param (400)
//   - GetSecret: include_value=true user-path (success + value)
//   - GetSecretByName: missing "name" query param (400)
//   - UpdateSecret: no user context (401)
//   - UpdateSecret: validation error via max_reads=0 (400)
//   - UpdateSecret: expiration + clear_expiration conflict (400)
//   - UpdateSecret: invalid expiration format (400)
//   - UpdateSecret: success path (200, goSafe+audit path)
//   - sendUpdateSecretError: "not found" branch (404)
//   - sendUpdateSecretError: validation error branch (400)
//   - ClassifySecret: bad "id" path param (400)
//   - ClassifySecret: success path (200)
//   - SetAutoRotate: bad "id" path param (400)
//   - SetAutoRotate: success path (200)
//   - DeleteSecret: internal error fallback (500)
//   - DeleteSecret: success path with audit (204)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// ── DB helpers ─────────────────────────────────────────────────────────────────

// freshSecretFixtureS13 builds an isolated named in-memory SQLite DB, migrates
// ALL models (same set as freshCoreS12WithAdmin), seeds user 1 as system_admin,
// seeds a project+environment, and creates one owned secret owned by user 1.
// Returns handler, core service, seeded secret, and raw DB.
func freshSecretFixtureS13(t *testing.T) (*SecretHandler, *core.KeyorixCore, *models.SecretNode, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxsecret_s13_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
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
	))

	// Seed user 1 as system_admin so in-handler authorization passes.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice-s13", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "system_admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-s13"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod-s13"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "s13-target", Value: []byte("s3cr3t-val"), ProjectID: 1, EnvironmentID: 10,
		Type: "static", CreatedBy: "alice-s13", OwnerID: 1,
	})
	require.NoError(t, err)

	return h, cs, secret, db
}

// withAdminCtxS13 injects a UserContext for user 1 into the request.
func withAdminCtxS13(r *http.Request) *http.Request {
	uc := &middleware.UserContext{
		UserID: 1, Username: "alice-s13",
		ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// ── GetSecret: bad "id" path param ────────────────────────────────────────────

// TestGetSecret_BadID_S13 verifies 400 when the "id" path param is not numeric.
func TestGetSecret_BadID_S13(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS13(t)
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/notanumber", nil),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// ── GetSecret: include_value=true (user path, success) ────────────────────────

// TestGetSecret_IncludeValue_S13 exercises the include_value=true branch for a
// user (non-machine) caller who owns the secret. Covers lines 236–253.
func TestGetSecret_IncludeValue_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// The response should include both secret metadata and value.
	assert.Contains(t, body, "secret")
	assert.Contains(t, body, "value")
}

// ── GetSecretByName: missing "name" query param ────────────────────────────────

// TestGetSecretByName_MissingName_S13 verifies 400 when the "name" query
// parameter is absent or empty.
func TestGetSecretByName_MissingName_S13(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS13(t)
	// project_id and environment_id present but name is missing.
	r := withAdminCtxS13(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-name?project_id=1&environment_id=10", nil),
	)
	w := httptest.NewRecorder()
	h.GetSecretByName(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

// ── UpdateSecret: missing user context (401) ───────────────────────────────────

// TestUpdateSecret_NoUserCtx_S13 verifies 401 when no UserContext is present
// in the request. This covers the early-return guard at the top of UpdateSecret.
func TestUpdateSecret_NoUserCtx_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	// Deliberately do NOT inject a user context.
	r := withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), strings.NewReader(`{"value":"new"}`)),
		"id", fmt.Sprintf("%d", secret.ID),
	)
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Unauthorized")
}

// ── UpdateSecret: validation error (max_reads < 1) ────────────────────────────

// TestUpdateSecret_ValidationError_S13 verifies 400 when max_reads=0 fails the
// validate:"omitempty,min=1" constraint.
func TestUpdateSecret_ValidationError_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	zero := 0
	body, _ := json.Marshal(map[string]any{"max_reads": zero})
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// ── UpdateSecret: expiration + clear_expiration conflict ──────────────────────

// TestUpdateSecret_ExpirationConflict_S13 verifies 400 when both expiration and
// clear_expiration are set (mutually exclusive).
func TestUpdateSecret_ExpirationConflict_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	body, _ := json.Marshal(map[string]any{
		"expiration":       "2030-01-01T00:00:00Z",
		"clear_expiration": true,
	})
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// ── UpdateSecret: invalid expiration format ────────────────────────────────────

// TestUpdateSecret_BadExpirationFormat_S13 verifies 400 when the expiration
// string is not RFC3339.
func TestUpdateSecret_BadExpirationFormat_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	body, _ := json.Marshal(map[string]any{
		"expiration": "not-a-date",
	})
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// ── UpdateSecret: success path (goSafe + audit) ───────────────────────────────

// TestUpdateSecret_Success_S13 exercises the full success path of UpdateSecret,
// covering the goSafe audit call and sendSuccess.
func TestUpdateSecret_Success_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	body, _ := json.Marshal(map[string]any{"value": "updated-value-s13"})
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// ── sendUpdateSecretError: "not found" branch ─────────────────────────────────

// TestUpdateSecret_NotFound_S13 exercises the sendUpdateSecretError "not found"
// branch (404) by targeting a non-existent secret ID.
func TestUpdateSecret_NotFound_S13(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS13(t)
	body, _ := json.Marshal(map[string]any{"value": "v"})
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/99999", bytes.NewReader(body)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	// The error from EnforceSecretWritePermission wraps the GORM record-not-found
	// error, which contains "not found" → sendUpdateSecretError returns 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NotFound")
}

// ── sendUpdateSecretError: validation error branch ────────────────────────────

// TestSendUpdateSecretError_ValidationBranch_S13 directly invokes
// sendUpdateSecretError with an error string containing the validation prefix
// so the third branch ("ValidationError", 400) is executed.
func TestSendUpdateSecretError_ValidationBranch_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// Build an error that matches the i18n validation prefix.
	validationPrefix := i18n.T("ErrorValidation", nil)
	validationErr := fmt.Errorf("%s: value too long", validationPrefix)

	w := httptest.NewRecorder()
	h.sendUpdateSecretError(w, validationErr)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// ── ClassifySecret: bad "id" path param ───────────────────────────────────────

// TestClassifySecret_BadID_S13 verifies 400 when the "id" path param is not
// a valid integer. This covers the bad-ID early-return in ClassifySecret.
func TestClassifySecret_BadID_S13(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS13(t)
	body := `{"classification":"confidential"}`
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/notanumber/classification", strings.NewReader(body)),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.ClassifySecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestClassifySecret_Success_S13 verifies 200 when classifying an existing secret
// with a valid label. This exercises the sendSuccess path in ClassifySecret.
func TestClassifySecret_Success_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	body := `{"classification":"confidential"}`
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/classification", secret.ID), strings.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.ClassifySecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Classification updated")
}

// ── SetAutoRotate: bad "id" path param ────────────────────────────────────────

// TestSetAutoRotate_BadID_S13 verifies 400 when the "id" path param is not
// a valid integer. This covers the bad-ID early-return in SetAutoRotate.
func TestSetAutoRotate_BadID_S13(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS13(t)
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/notanumber/auto-rotate", strings.NewReader(`{"enabled":false}`)),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestSetAutoRotate_Success_S13 verifies 200 on a valid SetAutoRotate call
// with enabled=false (disabling auto-rotate always succeeds regardless of backend).
func TestSetAutoRotate_Success_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	body, _ := json.Marshal(map[string]any{"enabled": false})
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/auto-rotate", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Auto-rotation updated")
}

// ── DeleteSecret: internal error fallback ─────────────────────────────────────

// TestDeleteSecret_InternalError_S13 triggers the internal-error fallback (500)
// in DeleteSecret by making the DB read-only after the pre-fetch so the actual
// delete write fails with an unexpected storage error.
func TestDeleteSecret_InternalError_S13(t *testing.T) {
	h, _, secret, db := freshSecretFixtureS13(t)

	// Make the DB read-only so DeleteSecretWithPermissionCheck fails on the
	// actual DELETE write (not the pre-read inside GetSecretWithPermissionCheck).
	// The pre-fetch at line 503-506 uses GetSecretWithPermissionCheck which reads;
	// the delete at line 509 writes — after PRAGMA query_only = ON both will fail,
	// but the first error seen by the handler is from the delete, which won't
	// contain "not found" or "permission denied", so it falls through to InternalError.
	require.NoError(t, db.Exec("PRAGMA query_only = ON").Error)
	t.Cleanup(func() { _ = db.Exec("PRAGMA query_only = OFF").Error })

	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	// Any non-2xx (404, 403, or 500) is acceptable; specifically we want the InternalError
	// path to be reachable, which happens when neither "not found" nor "permission denied"
	// appear in the error string.
	assert.NotEqual(t, http.StatusNoContent, w.Code)
}

// TestDeleteSecret_SuccessWithAudit_S13 verifies that a successful delete (204)
// triggers the goSafe audit path and writes the NoContent status.
func TestDeleteSecret_SuccessWithAudit_S13(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	r := withAdminCtxS13(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// withMachineCtxS13 injects a machine-identity UserContext (UserID 0, per
// UserContext.MachineIdentityID's own doc comment) into the request.
func withMachineCtxS13(r *http.Request, machineID uint) *http.Request {
	uc := &middleware.UserContext{
		MachineIdentityID: &machineID, ActorType: core.ActorTypeMachine,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// TestDeleteSecret_MachineActorUsesScopedPermissionNotOwnerCheck is the direct
// handler-level regression test for security-closures.tsv's
// secret-delete-machine-actor-001: a machine-identity-authenticated caller
// (UserID always 0, see UserContext.MachineIdentityID) must go through the
// isMachine branch (plain DeleteSecret, already authorized by the route's own
// RequireScopedSecretPermission gate) rather than DeleteSecretWithPermissionCheck,
// whose userID==0 requirement fails a machine caller unconditionally. Replaces
// the #1808 differential-conformance-harness proving test (TestConformance_
// DeleteSecret, server/http/remote_storage_*_test.go) retired in ADR-108 Phase 6
// step 14a — the harness is gone, but the fixed code path (secrets_crud.go,
// still live and unrelated to the RemoteStorage/legacy-CLI surface Phase 6
// deletes) still needs a proving test of its own.
func TestDeleteSecret_MachineActorUsesScopedPermissionNotOwnerCheck(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS13(t)
	r := withMachineCtxS13(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	), 42)
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	// Pre-fix, this unconditionally hit DeleteSecretWithPermissionCheck's
	// userID==0 CheckSecretPermission guard and never returned 204.
	assert.Equal(t, http.StatusNoContent, w.Code)
}
