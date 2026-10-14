// shares_s13_test.go — coverage sweep targeting uncovered branches in:
//   - shares_crud.go:  ShareSecret, UpdateSharePermission, RevokeShare
//   - shares_query.go: ListSecretShares, ListShares, ListSharedSecrets,
//     ListGroupSharedSecrets, GetSharingStatusWithIndicators, RemoveSelfFromShare
//   - shares_handler.go: sendSuccess, sendError
//
// Focuses on: bad param (400), missing user context (401), not-found core errors
// (404), validation failures (400), and query filter branches.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newShareHandlerS13(t *testing.T) *ShareHandler {
	t.Helper()
	cs := freshCoreS12(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	return h
}

func decodeShareResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// ── ShareSecret ───────────────────────────────────────────────────────────────

// TestShareSecret_NoUserCtx_S13 hits the unauthenticated branch → 401.
func TestShareSecret_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/share", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "Unauthorized", resp["error"])
}

// TestShareSecret_BadID_S13 passes a non-numeric secret ID → 400.
func TestShareSecret_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/not-a-number/share", strings.NewReader(`{}`)),
		"id", "not-a-number",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestShareSecret_BadJSON_S13 passes malformed JSON → 400.
func TestShareSecret_BadJSON_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/share", strings.NewReader(`{bad json`)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidJSON", resp["error"])
}

// TestShareSecret_ValidationError_S13 passes valid JSON but fails validation
// (missing required fields) → 400 ValidationError.
func TestShareSecret_ValidationError_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	// recipient_id and permission are required; omit them.
	body := `{"is_group": false}`
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/share", strings.NewReader(body)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "ValidationError", resp["error"])
}

// TestShareSecret_NotFound_S13 triggers the not-found branch by sharing a
// non-existent secret → 404.
func TestShareSecret_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	body := `{"recipient_id": 2, "permission": "read"}`
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/9999/share", strings.NewReader(body)),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "NotFound", resp["error"])
}

// TestShareSecret_GroupShare_NotFound_S13 exercises the IsGroup=true code path
// with a non-existent secret → 404 (covers the group branch in ShareSecret).
func TestShareSecret_GroupShare_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	body := `{"recipient_id": 5, "is_group": true, "permission": "read"}`
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/9999/share", strings.NewReader(body)),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	// Secret doesn't exist → core returns not-found → 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestShareSecret_ExpiryInPast_S13 triggers the "expiry must be in the future"
// error branch → 400 ValidationError.
func TestShareSecret_ExpiryInPast_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// r137 Sprint 1: ShareSecret checks IsProjectMember(recipient, secret.ProjectID).
	// Seed a project, put the recipient (ID=2) in it, and assign the secret that project.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	// Wave 6: ShareSecret now also gates the owner on live project membership
	// (RBAC-001, requireLiveOwnerAuthority) — user 1 (owner) must be a member too.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	// Seed a secret owned by user 1.
	require.NoError(t, db.Create(&models.SecretNode{ID: 101, Name: "expiry-test", IsSecret: true, OwnerID: 1, ProjectID: 1}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"recipient_id": 2, "permission": "read", "expires_at": "` + past + `"}`
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/101/share", strings.NewReader(body)),
		"id", "101",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "ValidationError", resp["error"])
}

// ── UpdateSharePermission ─────────────────────────────────────────────────────

// TestUpdateSharePermission_NoUserCtx_S13 → 401.
func TestUpdateSharePermission_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/1", strings.NewReader(`{}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUpdateSharePermission_BadID_S13 → 400 InvalidParameter.
func TestUpdateSharePermission_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/bad", strings.NewReader(`{}`)),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestUpdateSharePermission_BadJSON_S13 → 400 InvalidJSON.
func TestUpdateSharePermission_BadJSON_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/1", strings.NewReader(`{oops`)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidJSON", resp["error"])
}

// TestUpdateSharePermission_ValidationError_S13 — missing permission field → 400.
func TestUpdateSharePermission_ValidationError_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/1", strings.NewReader(`{}`)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "ValidationError", resp["error"])
}

// TestUpdateSharePermission_NotFound_S13 → 404 for non-existent share.
func TestUpdateSharePermission_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	body := `{"permission": "read"}`
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/9999", strings.NewReader(body)),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "NotFound", resp["error"])
}

// TestUpdateSharePermission_ExpiryInPast_S13 — expiry error branch → 400.
func TestUpdateSharePermission_ExpiryInPast_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// Wave 6: UpdateSharePermission now also gates the owner on live project
	// membership (RBAC-001, requireLiveOwnerAuthority) — needs a real project.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 102, Name: "upd-expiry", IsSecret: true, OwnerID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{ID: 50, SecretID: 102, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	past := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"permission": "write", "expires_at": "` + past + `"}`
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/50", strings.NewReader(body)),
		"id", "50",
	))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "ValidationError", resp["error"])
}

// ── RevokeShare ───────────────────────────────────────────────────────────────

// TestRevokeShare_NoUserCtx_S13 → 401.
func TestRevokeShare_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/shares/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRevokeShare_BadID_S13 → 400 InvalidParameter.
func TestRevokeShare_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/shares/bad", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestRevokeShare_NotFound_S13 → 404 for non-existent share.
func TestRevokeShare_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/shares/9999", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "NotFound", resp["error"])
}

// ── ListSecretShares ──────────────────────────────────────────────────────────

// TestListSecretShares_NoUserCtx_S13 → 401.
func TestListSecretShares_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/shares", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSecretShares_BadID_S13 → 400 InvalidParameter.
func TestListSecretShares_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/xyz/shares", nil),
		"id", "xyz",
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestListSecretShares_NotFound_S13 — non-existent secret → 404 or 403.
// (The permission-checked variant may return not-found or forbidden depending
// on whether the secret exists at all.)
func TestListSecretShares_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/9999/shares", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)

	// core returns not-found or forbidden for a non-existent secret.
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusForbidden,
		"expected 404 or 403, got %d", w.Code)
}

// ── ListShares ────────────────────────────────────────────────────────────────

// TestListShares_NoUserCtx_S13 → 401.
func TestListShares_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/shares", nil)
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListShares_SecretIDFilter_S13 exercises the ?secretId= query filter.
func TestListShares_SecretIDFilter_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?secretId=42", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	// No shares in DB → empty list with 200.
	assert.Equal(t, http.StatusOK, w.Code)
	// sendSuccess wraps payload in {"success":true, "data": <payload>}
	// The handler puts pagination info into the payload, so response is:
	// {"success":true, "data": {"data": [...], "total":0, "page":1, ...}}
	outer := decodeShareResponse(t, w)
	inner, ok := outer["data"].(map[string]any)
	require.True(t, ok, "outer data should be an object")
	items, ok := inner["data"].([]any)
	require.True(t, ok, "inner data should be an array")
	assert.Empty(t, items)
}

// TestListShares_RecipientTypeFilter_User_S13 exercises the ?recipientType=user filter.
func TestListShares_RecipientTypeFilter_User_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?recipientType=user", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_RecipientTypeFilter_Group_S13 exercises the ?recipientType=group filter.
func TestListShares_RecipientTypeFilter_Group_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?recipientType=group", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_UnrecognizedRecipientType_S13 — unknown recipientType is
// ignored (no filter applied). Should still return 200.
func TestListShares_UnrecognizedRecipientType_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?recipientType=machine", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_InvalidSecretIDFilter_S13 — non-numeric ?secretId is ignored.
func TestListShares_InvalidSecretIDFilter_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?secretId=not-a-number", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	// Invalid secretId is silently ignored → 200.
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListShares_Pagination_S13 — exercises page/pageSize params and ensures
// totalPages is computed and paging slice doesn't go out-of-bounds on empty DB.
func TestListShares_Pagination_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?page=2&pageSize=5", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	outer := decodeShareResponse(t, w)
	inner, ok := outer["data"].(map[string]any)
	require.True(t, ok, "outer data should be an object")
	assert.Equal(t, float64(2), inner["page"])
	assert.Equal(t, float64(5), inner["pageSize"])
}

// TestListShares_PageSizeClamp_S13 — oversized pageSize is clamped to 20.
func TestListShares_PageSizeClamp_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?pageSize=9999", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	outer := decodeShareResponse(t, w)
	inner, ok := outer["data"].(map[string]any)
	require.True(t, ok, "outer data should be an object")
	assert.Equal(t, float64(20), inner["pageSize"])
}

// TestListShares_PageSizeZero_S13 — zero pageSize is clamped to 20.
func TestListShares_PageSizeZero_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?pageSize=0", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	outer := decodeShareResponse(t, w)
	inner, ok := outer["data"].(map[string]any)
	require.True(t, ok, "outer data should be an object")
	assert.Equal(t, float64(20), inner["pageSize"])
}

// TestListShares_PageBelowOne_S13 — page=0 is normalised to 1.
func TestListShares_PageBelowOne_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shares?page=0", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	outer := decodeShareResponse(t, w)
	inner, ok := outer["data"].(map[string]any)
	require.True(t, ok, "outer data should be an object")
	assert.Equal(t, float64(1), inner["page"])
}

// ── ListSharedSecrets ─────────────────────────────────────────────────────────

// TestListSharedSecrets_NoUserCtx_S13 → 401.
func TestListSharedSecrets_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/shared-secrets", nil)
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSharedSecrets_EmptyDB_S13 — happy path with no secrets shared → 200
// with empty list (nil → [] normalisation).
func TestListSharedSecrets_EmptyDB_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shared-secrets", nil))
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	secrets, ok := data["secrets"].([]any)
	require.True(t, ok, "secrets field should be an array")
	assert.Empty(t, secrets)
}

// ── ListGroupSharedSecrets ────────────────────────────────────────────────────

// TestListGroupSharedSecrets_BadID_S13 → 400 for non-numeric group ID.
func TestListGroupSharedSecrets_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/abc/shared-secrets", nil),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestListGroupSharedSecrets_NoUserCtx_S13 → 401.
func TestListGroupSharedSecrets_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/shared-secrets", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── GetSharingStatusWithIndicators ───────────────────────────────────────────

// TestGetSharingStatusWithIndicators_NoUserCtx_S13 → 401.
func TestGetSharingStatusWithIndicators_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/sharing-status", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetSharingStatusWithIndicators_BadID_S13 → 400.
func TestGetSharingStatusWithIndicators_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/bad/sharing-status", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestGetSharingStatusWithIndicators_NotFound_S13 — non-existent secret → 404.
func TestGetSharingStatusWithIndicators_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/9999/sharing-status", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "NotFound", resp["error"])
}

// ── RemoveSelfFromShare ───────────────────────────────────────────────────────

// TestRemoveSelfFromShare_NoUserCtx_S13 → 401.
func TestRemoveSelfFromShare_NoUserCtx_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/1/self-share", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRemoveSelfFromShare_BadID_S13 → 400.
func TestRemoveSelfFromShare_BadID_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/bad/self-share", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "InvalidParameter", resp["error"])
}

// TestRemoveSelfFromShare_NotFound_S13 — no share for the caller on secret 9999 → 404.
func TestRemoveSelfFromShare_NotFound_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/9999/self-share", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, "NotFound", resp["error"])
}

// ── sendSuccess / sendError (shares_handler.go) ───────────────────────────────

// TestShareHandler_SendSuccess_SetsContentType_S13 verifies sendSuccess sets
// Content-Type and X-Content-Type-Options headers.
func TestShareHandler_SendSuccess_SetsContentType_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	w := httptest.NewRecorder()
	h.sendSuccess(w, map[string]string{"key": "val"}, "all good")

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, http.StatusOK, w.Code) // WriteHeader not called → 200 default
}

// TestShareHandler_SendSuccess_EncodesBothFields_S13 verifies the JSON body
// has success=true, the correct data, and the message string.
func TestShareHandler_SendSuccess_EncodesBothFields_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	w := httptest.NewRecorder()
	h.sendSuccess(w, "payload", "done")

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["success"])
	assert.Equal(t, "payload", resp["data"])
	assert.Equal(t, "done", resp["message"])
}

// TestShareHandler_SendError_SetsStatusCode_S13 verifies sendError sets the
// correct HTTP status and encodes the error type.
func TestShareHandler_SendError_SetsStatusCode_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	w := httptest.NewRecorder()
	h.sendError(w, "TestErr", "something went wrong", http.StatusTeapot, nil)

	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "TestErr", resp["error"])
	assert.Equal(t, "something went wrong", resp["message"])
	assert.Equal(t, float64(http.StatusTeapot), resp["code"])
}

// TestShareHandler_SendError_WithDetails_S13 verifies details are included.
func TestShareHandler_SendError_WithDetails_S13(t *testing.T) {
	h := newShareHandlerS13(t)

	details := map[string]string{"field": "permission", "reason": "required"}
	w := httptest.NewRecorder()
	h.sendError(w, "ValidationError", "bad input", http.StatusBadRequest, details)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	detailsOut, ok := resp["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "permission", detailsOut["field"])
}

// ── RevokeShare success path ──────────────────────────────────────────────────

// TestRevokeShare_Success_S13 seeds a share owned by user 1 and revokes it → 204.
func TestRevokeShare_Success_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// Wave 6: RevokeShare now also gates the owner on live project membership
	// (RBAC-001, requireLiveOwnerAuthority) — needs a real project.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 200, Name: "revoke-me", IsSecret: true, OwnerID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{ID: 60, SecretID: 200, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/shares/60", nil),
		"id", "60",
	))
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── ShareSecret success path ──────────────────────────────────────────────────

// TestShareSecret_Success_S13 seeds a secret owned by user 1 and shares it → 201.
// freshCoreS12WithAdmin already creates user ID=1 as system_admin, so we just
// need to add a recipient user (ID=2), a project, and a secret.
func TestShareSecret_Success_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// r137 Sprint 1: ShareSecret checks IsProjectMember(recipient, secret.ProjectID).
	// Seed a project and make the recipient a member.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	// User ID=1 is already seeded by freshCoreS12WithAdmin. Add recipient.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recip-share-s13", Email: "recip-share-s13@x.com", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	// Wave 6: ShareSecret now also gates the owner on live project membership
	// (RBAC-001, requireLiveOwnerAuthority) — user 1 (owner) must be a member too.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 300, Name: "my-secret-s13", IsSecret: true, OwnerID: 1, ProjectID: 1}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	body := bytes.NewBufferString(`{"recipient_id": 2, "permission": "read"}`)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/300/share", body),
		"id", "300",
	))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	resp := decodeShareResponse(t, w)
	assert.Equal(t, true, resp["success"])
}
