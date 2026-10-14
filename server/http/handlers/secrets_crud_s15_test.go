// secrets_crud_s15_test.go — coverage sweep for secrets_crud.go and secrets_handler.go.
// Targets uncovered branches in:
//   - CreateSecret: malformed JSON, conflict error, env-not-belong (422), internal error
//   - GetSecret: user permission-denied, user not-found (exact 404)
//   - GetSecretByName: missing project_id / env_id, not-found, permission-denied
//   - UpdateSecret: bad ID, malformed JSON, sendUpdateSecretError branches
//   - DeleteSecret: bad ID, not-found, permission-denied, success (204)
//   - ClassifySecret: bad JSON, invalid label (400), not-found (404)
//   - SetAutoRotate: bad JSON, not-found (404), unknown charset (400), backend-without-ref (400)
//   - sendUpdateSecretError: permission denied, internal error fallback
//   - sendSuccess / sendError: envelope correctness
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

// ── DB helpers ────────────────────────────────────────────────────────────────

// freshSecretFixtureS15 builds an isolated named in-memory SQLite DB, migrates
// all required schemas, seeds user 1 as system_admin, seeds a project and
// environment, and creates one owned secret. Returns the handler, core service,
// the seeded SecretNode, and the underlying *gorm.DB.
func freshSecretFixtureS15(t *testing.T) (*SecretHandler, *core.KeyorixCore, *models.SecretNode, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s15_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.SecretVersion{}, &models.SecretAccessLog{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.SecretAccessSchedule{},
	))

	// Seed the user context user (UserID=1) as a global admin bypass.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice-s15", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "system_admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-s15"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod-s15"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "s15-target", Value: []byte("s3cr3t"), ProjectID: 1, EnvironmentID: 10,
		Type: "static", CreatedBy: "alice-s15", OwnerID: 1,
	})
	require.NoError(t, err)

	return h, cs, secret, db
}

// adminCtxS15 returns a *middleware.UserContext for user 1 (the admin seeded by freshSecretFixtureS15).
func adminCtxS15() *middleware.UserContext {
	return &middleware.UserContext{UserID: 1, Username: "alice-s15", ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
}

// withAdminCtxS15 injects adminCtxS15() into the request context.
func withAdminCtxS15(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), adminCtxS15()))
}

// ── CreateSecret: malformed JSON → 400 ────────────────────────────────────────

func TestCreateSecret_MalformedJSON_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", strings.NewReader("{not-json")))
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidJSON")
}

// TestCreateSecret_ValidationError_S15 verifies 400 when required fields are absent.
func TestCreateSecret_ValidationError_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	body, _ := json.Marshal(map[string]any{
		// "name" intentionally omitted → validate:"required,min=1" fires
		"value": "v", "project_id": 1, "environment_id": 10, "type": "static",
	})
	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// TestCreateSecret_ConflictError_S15 verifies 409 when the secret name already
// exists in the same project/environment.
func TestCreateSecret_ConflictError_S15(t *testing.T) {
	h, _, existing, _ := freshSecretFixtureS15(t)
	body, _ := json.Marshal(map[string]any{
		"name": existing.Name, "value": "v2", "project_id": uint(1),
		"environment_id": uint(10), "type": "static",
	})
	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "ConflictError")
}

// TestCreateSecret_EnvNotBelongError_S15 verifies 422 when the given environment
// belongs to a different project than the specified project_id.
func TestCreateSecret_EnvNotBelongError_S15(t *testing.T) {
	h, _, _, db := freshSecretFixtureS15(t)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "other-proj-s15"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "other-env-s15"}).Error)

	body, _ := json.Marshal(map[string]any{
		"name": "env-mismatch-s15", "value": "v", "project_id": uint(1),
		"environment_id": uint(20), "type": "static",
	})
	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)
	// Core returns "does not belong to project" → 422
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// ── GetSecret: exact status codes for user path ───────────────────────────────

// TestGetSecret_UserNotFound_S15 verifies 404 when the user's own lookup returns not-found.
func TestGetSecret_UserNotFound_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetSecret_UserFound_S15 verifies 200 when the owner fetches their own secret.
func TestGetSecret_UserFound_S15(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetSecret_UserPermissionDenied_S15 verifies 403 when a non-owner, non-admin
// user attempts to fetch a secret they have no access to.
func TestGetSecret_UserPermissionDenied_S15(t *testing.T) {
	_, cs, secret, db := freshSecretFixtureS15(t)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob-s15", AccountState: "active"}).Error)

	h2, err := NewSecretHandler(cs)
	require.NoError(t, err)

	user2Ctx := &middleware.UserContext{UserID: 2, Username: "bob-s15", ActorType: core.ActorTypeUser, SessionAuth: true}
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), user2Ctx))
	r = withChiParam(r, "id", fmt.Sprintf("%d", secret.ID))
	w := httptest.NewRecorder()
	h2.GetSecret(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── GetSecretByName: missing params / not-found / permission-denied ───────────

// TestGetSecretByName_MissingProjectID_S15 verifies 400 when project_id is absent.
func TestGetSecretByName_MissingProjectID_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-name?name=foo&environment_id=10", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id is required")
}

// TestGetSecretByName_MissingEnvironmentID_S15 verifies 400 when environment_id is absent.
func TestGetSecretByName_MissingEnvironmentID_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-name?name=foo&project_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "environment_id is required")
}

// TestGetSecretByName_NotFound_S15 verifies 404 when no secret matches the name.
func TestGetSecretByName_NotFound_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(httptest.NewRequest(http.MethodGet,
		"/api/v1/secrets/by-name?name=does-not-exist-s15&project_id=1&environment_id=10", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NotFound")
}

// TestGetSecretByName_PermissionDenied_S15 verifies 403 when a non-owner, non-admin
// user requests a secret by name that they have no access to.
func TestGetSecretByName_PermissionDenied_S15(t *testing.T) {
	_, cs, secret, db := freshSecretFixtureS15(t)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "carol-s15", AccountState: "active"}).Error)

	h3, err := NewSecretHandler(cs)
	require.NoError(t, err)

	user3Ctx := &middleware.UserContext{UserID: 3, Username: "carol-s15", ActorType: core.ActorTypeUser, SessionAuth: true}
	url := fmt.Sprintf("/api/v1/secrets/by-name?name=%s&project_id=1&environment_id=10", secret.Name)
	r := httptest.NewRequest(http.MethodGet, url, nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), user3Ctx))
	w := httptest.NewRecorder()
	h3.GetSecretByName(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── UpdateSecret: bad ID / malformed JSON ─────────────────────────────────────

// TestUpdateSecret_BadID_S15 verifies 400 when the path param is not numeric.
func TestUpdateSecret_BadID_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/notanumber", strings.NewReader("{}")),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestUpdateSecret_MalformedJSON_S15 verifies 400 when the body is invalid JSON.
func TestUpdateSecret_MalformedJSON_S15(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), strings.NewReader("{bad json")),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidJSON")
}

// ── sendUpdateSecretError: permission-denied and internal-error branches ───────

// TestSendUpdateSecretError_PermissionDenied_S15 exercises the "permission denied"
// branch (403) of sendUpdateSecretError by calling UpdateSecret as a non-owner user.
func TestSendUpdateSecretError_PermissionDenied_S15(t *testing.T) {
	_, cs, secret, db := freshSecretFixtureS15(t)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "dave-s15", AccountState: "active"}).Error)

	h4, err := NewSecretHandler(cs)
	require.NoError(t, err)

	user4Ctx := &middleware.UserContext{UserID: 4, Username: "dave-s15", ActorType: core.ActorTypeUser, SessionAuth: true}
	body, _ := json.Marshal(map[string]any{"value": "new"})
	r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), user4Ctx))
	r = withChiParam(r, "id", fmt.Sprintf("%d", secret.ID))
	w := httptest.NewRecorder()
	h4.UpdateSecret(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Forbidden")
}

// TestSendUpdateSecretError_InternalError_S15 exercises the internal-error fallback (500)
// of sendUpdateSecretError by making the DB read-only so the write fails with
// a storage error that matches neither "not found" nor "permission denied".
func TestSendUpdateSecretError_InternalError_S15(t *testing.T) {
	h, _, secret, db := freshSecretFixtureS15(t)

	require.NoError(t, db.Exec("PRAGMA query_only = ON").Error)
	t.Cleanup(func() { _ = db.Exec("PRAGMA query_only = OFF").Error })

	body, _ := json.Marshal(map[string]any{"value": "new"})
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}

// ── DeleteSecret: bad ID / not-found / permission-denied / success ────────────

// TestDeleteSecret_BadID_S15 verifies 400 when the path param is not numeric.
func TestDeleteSecret_BadID_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/badid", nil),
		"id", "badid",
	))
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestDeleteSecret_NotFound_S15 verifies 404 when the secret ID does not exist.
func TestDeleteSecret_NotFound_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NotFound")
}

// TestDeleteSecret_PermissionDenied_S15 verifies 403 when a non-owner, non-admin
// user attempts to delete a secret they have no access to.
func TestDeleteSecret_PermissionDenied_S15(t *testing.T) {
	_, cs, secret, db := freshSecretFixtureS15(t)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "eve-s15", AccountState: "active"}).Error)

	h5, err := NewSecretHandler(cs)
	require.NoError(t, err)

	user5Ctx := &middleware.UserContext{UserID: 5, Username: "eve-s15", ActorType: core.ActorTypeUser, SessionAuth: true}
	r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), user5Ctx))
	r = withChiParam(r, "id", fmt.Sprintf("%d", secret.ID))
	w := httptest.NewRecorder()
	h5.DeleteSecret(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Forbidden")
}

// TestDeleteSecret_Success_S15 verifies 204 on successful deletion.
func TestDeleteSecret_Success_S15(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── ClassifySecret: bad JSON / invalid label / not-found ─────────────────────

// TestClassifySecret_BadJSON_S15 verifies 400 on malformed request body.
func TestClassifySecret_BadJSON_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/classification", strings.NewReader("{bad")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ClassifySecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidJSON")
}

// TestClassifySecret_InvalidLabel_S15 verifies 400 when core rejects an unknown
// classification label ("classification must be" error).
func TestClassifySecret_InvalidLabel_S15(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS15(t)
	body := `{"classification":"not-a-real-label"}`
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/classification", secret.ID), strings.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.ClassifySecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestClassifySecret_NotFound_S15 verifies 404 when classifying a non-existent secret.
func TestClassifySecret_NotFound_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	body := `{"classification":"confidential"}`
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/99999/classification", strings.NewReader(body)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.ClassifySecret(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── SetAutoRotate: bad JSON / not-found / invalid params ──────────────────────

// TestSetAutoRotate_BadJSON_S15 verifies 400 on malformed request body.
func TestSetAutoRotate_BadJSON_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/auto-rotate", strings.NewReader("{bad")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidJSON")
}

// TestSetAutoRotate_NotFound_S15 verifies 404 when the secret does not exist.
func TestSetAutoRotate_NotFound_S15(t *testing.T) {
	h, _, _, _ := freshSecretFixtureS15(t)
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/99999/auto-rotate", strings.NewReader(`{"enabled":true}`)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestSetAutoRotate_UnknownCharset_S15 verifies 400 on an unknown charset value.
func TestSetAutoRotate_UnknownCharset_S15(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS15(t)
	body, _ := json.Marshal(map[string]any{"enabled": true, "charset": "emoji-only-s15"})
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/auto-rotate", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetAutoRotate_BackendWithoutRef_S15 verifies 400 when backend is set but
// ref is empty ("must be set together" error).
func TestSetAutoRotate_BackendWithoutRef_S15(t *testing.T) {
	h, _, secret, _ := freshSecretFixtureS15(t)
	body, _ := json.Marshal(map[string]any{"enabled": true, "backend": "aws-secrets-manager", "ref": ""})
	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/auto-rotate", secret.ID), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, r)
	// "must be set together" or "unknown rotation backend" → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sendSuccess / sendError: envelope correctness ─────────────────────────────

// TestSendSuccess_Envelope_S15 verifies that sendSuccess writes a JSON envelope
// with Success=true, the supplied data, and the supplied message.
func TestSendSuccess_Envelope_S15(t *testing.T) {
	cs := freshCoreS12(t) // lightweight helper from handlers_s12_test.go
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	h.sendSuccess(w, map[string]string{"k": "v"}, "all good s15")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	var resp SuccessResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.Equal(t, "all good s15", resp.Message)
}

// TestSendError_Envelope_S15 verifies that sendError writes a JSON envelope with
// Success=false, the supplied error type, message, and status code.
func TestSendError_Envelope_S15(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	h.sendError(w, "TestError", "oops", http.StatusTeapot, map[string]string{"field": "x"})
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
	assert.Equal(t, "TestError", resp.Error)
	assert.Equal(t, "oops", resp.Message)
	assert.Equal(t, http.StatusTeapot, resp.Code)
}
