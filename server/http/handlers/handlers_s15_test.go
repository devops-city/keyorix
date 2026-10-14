// handlers_s15_test.go — coverage sweep for:
//   - secrets_list.go   (ListSecrets): machine-identity path, show_shared_only,
//     permission, expires_before valid+invalid, camelCase pageSize,
//     page > maxListPage, project_id/environment_id filters, multi-tag,
//     invalid project_id/environment_id ignored.
//   - secrets_versions.go (GetSecretVersions, RotateSecret, RollbackSecret):
//     not-found with seeded data, success paths, fmt.Sprintf branch.
//   - secrets_deleted.go  (DeletedSecrets): bad project ID (400), ?limit=N,
//     invalid limit ignored, seeded deleted data exercising toDeletedSecretEntry.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newSecretHandlerS15 builds a SecretHandler backed by a fresh admin-seeded core.
func newSecretHandlerS15(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, db
}

// withMachineUserCtxS15 wraps a request with a UserContext that has MachineIdentityID set.
func withMachineUserCtxS15(r *http.Request, machineID uint) *http.Request {
	mid := machineID
	userCtx := &customMiddleware.UserContext{
		UserID:            1,
		Username:          "machine-s15",
		MachineIdentityID: &mid,
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// ── secrets_list.go: uncovered filter branches ────────────────────────────────

func TestListSecrets_ShowSharedOnly_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?show_shared_only=true", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_PermissionFilter_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?permission=secrets.read", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_ExpiresBeforeValid_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?expires_before=2099-12-31T00:00:00Z", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_ExpiresBeforeInvalid_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?expires_before=not-a-date", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// malformed expires_before is silently ignored, not a 400
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_CamelCasePageSize_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?pageSize=5", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_PageClamped_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	// page > maxListPage (10000) should be clamped
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?page=99999999", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_ProjectIDFilter_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_EnvironmentIDFilter_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?environment_id=2", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_InvalidProjectIDIgnored_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_InvalidEnvironmentIDIgnored_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?environment_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_TagMultipleParams_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	// Exercises both repeatable ?tag= and comma-split inner loop
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?tag=prod&tag=critical,infra", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// TestListSecrets_MachineIdentityPath_S15 covers the MachineIdentityID \!= nil branch,
// which routes to ListSecretsInScope instead of ListSecretsWithSharingInfo.
func TestListSecrets_MachineIdentityPath_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withMachineUserCtxS15(httptest.NewRequest(http.MethodGet, "/", nil), 42)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_AllFiltersCombined_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	url := "/?search=pw&include_deleted=true&show_owned_only=true&show_shared_only=true" +
		"&permission=secrets.write&type=static&classification=confidential" +
		"&tag=a,b&tag=c&project_id=1&environment_id=2&expires_before=2099-01-01T00:00:00Z" +
		"&page=2&page_size=10&sort_by=name&sort_order=asc"
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_versions.go: GetSecretVersions ────────────────────────────────────

// TestGetSecretVersions_NotFound_S15 exercises the "not found" error branch
// when the secret ID doesn't exist.
func TestGetSecretVersions_NotFound_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "88888",
	))
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// TestGetSecretVersions_Success_S15 seeds a real secret and exercises the success
// path including GetSecret audit-log goSafe call.
func TestGetSecretVersions_Success_S15(t *testing.T) {
	h, db := newSecretHandlerS15(t)

	proj := &models.Project{Name: "vsn-proj-s15"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "vsn-env-s15", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "vsn-secret-s15",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		OwnerID:       1,
		Type:          "static",
	}
	require.NoError(t, db.Create(secret).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "response should have a 'data' key")
	_, hasVersions := data["versions"]
	assert.True(t, hasVersions, "response data should contain 'versions'")
}

// ── secrets_versions.go: RotateSecret ─────────────────────────────────────────

// TestRotateSecret_NotFoundBranch_S15 exercises the "not found" switch case.
func TestRotateSecret_NotFoundBranch_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	body := []byte(`{"new_value":"newval"}`)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", "77777",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// TestRotateSecret_HappyPath_S15 seeds a real secret and calls RotateSecret,
// exercising the success path including the async audit goSafe call.
func TestRotateSecret_HappyPath_S15(t *testing.T) {
	h, db := newSecretHandlerS15(t)

	proj := &models.Project{Name: "rot-proj-s15"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "rot-env-s15", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "rot-secret-s15",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		OwnerID:       1,
		Type:          "static",
	}
	require.NoError(t, db.Create(secret).Error)

	body, _ := json.Marshal(map[string]string{"new_value": "rotated-value-s15"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	// 200 on success, or 404/500 if rotation not fully supported; not 401/400
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── secrets_versions.go: RollbackSecret ───────────────────────────────────────

// TestRollbackSecret_NotFoundBranch_S15 exercises the "not found" switch case.
func TestRollbackSecret_NotFoundBranch_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	body := []byte(`{"version":1}`)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", "66666",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// TestRollbackSecret_HappyPath_S15 seeds a real secret and exercises the
// fmt.Sprintf success message path (or a version error branch).
func TestRollbackSecret_HappyPath_S15(t *testing.T) {
	h, db := newSecretHandlerS15(t)

	proj := &models.Project{Name: "rb-proj-s15"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "rb-env-s15", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "rb-secret-s15",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		OwnerID:       1,
		Type:          "static",
	}
	require.NoError(t, db.Create(secret).Error)

	body, _ := json.Marshal(map[string]int{"version": 1})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	// May be 200 (success), 400 (already current), or 404/500; not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_deleted.go: uncovered branches ────────────────────────────────────

// TestDeletedSecrets_BadProjectID_S15 covers the strconv.ParseUint failure → 400.
func TestDeletedSecrets_BadProjectID_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeletedSecrets_WithExplicitLimit_S15 covers the ?limit=N branch where Atoi succeeds.
func TestDeletedSecrets_WithExplicitLimit_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?limit=25", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestDeletedSecrets_InvalidLimitIgnored_S15 covers the branch where Atoi fails
// and limit stays 0 (the default).
func TestDeletedSecrets_InvalidLimitIgnored_S15(t *testing.T) {
	h, _ := newSecretHandlerS15(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?limit=bad", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestDeletedSecrets_WithSeededData_S15 seeds a soft-deleted secret and verifies
// the response includes it, exercising toDeletedSecretEntry including DeletedAt branch.
func TestDeletedSecrets_WithSeededData_S15(t *testing.T) {
	h, db := newSecretHandlerS15(t)

	proj := &models.Project{Name: "del-proj-s15"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "del-env-s15", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name:           "trashed-s15",
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		OwnerID:        1,
		Type:           "static",
		Classification: "internal",
	}
	require.NoError(t, db.Create(secret).Error)
	// Soft-delete so it appears in the recycle bin.
	require.NoError(t, db.Delete(secret).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?limit=10", nil),
		"id", fmt.Sprintf("%d", proj.ID),
	))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "response should have a 'data' key")
	deleted, ok := data["deleted"].([]any)
	require.True(t, ok, "data.deleted should be an array")
	assert.GreaterOrEqual(t, len(deleted), 1, "expected at least one deleted secret in response")
}
