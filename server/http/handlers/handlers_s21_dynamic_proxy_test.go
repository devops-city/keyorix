// handlers_s21_dynamic_proxy_test.go — coverage sweep for
// dynamic_secrets.go RevokeAllLeases (bad {id} param, config not found, valid).
// Its legal_hold_proxy.go and project_memberships_proxy.go coverage was removed
// with the ADR-108 Phase 6 /system proxy tier deletion.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── dynamic_secrets.go: RevokeAllLeases ──────────────────────────────────────

// TestRevokeAllLeases_BadID_S21 verifies that a non-numeric {id} param returns
// 400 (loadAuthorizedConfig parse guard).
func TestRevokeAllLeases_BadID_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/bad/revoke-all", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestRevokeAllLeases_ConfigNotFound_S21 verifies that a valid numeric {id}
// for a non-existent config returns 404.
func TestRevokeAllLeases_ConfigNotFound_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/9999/revoke-all", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NotFound")
}

// TestRevokeAllLeases_NoUserCtx_S21 verifies that a request with no user
// context against a real config is denied (401 or 403, never 500).
func TestRevokeAllLeases_NoUserCtx_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s21-project-noctx"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s21-env-noctx", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name:          "s21-cfg-noctx",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgres",
		CreatedBy:     "testuser",
	}
	require.NoError(t, db.Create(cfg).Error)

	// No user context injected — authorize() returns false, false.
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", fmt.Sprintf("%d", cfg.ID),
	)
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestRevokeAllLeases_Valid_S21 verifies the happy path: an admin-authed
// request against a real config with no active leases returns 200 with
// revoked=0, failed=0.
func TestRevokeAllLeases_Valid_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s21-project-valid"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s21-env-valid", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name:          "s21-cfg-valid",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgres",
		CreatedBy:     "testuser",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", fmt.Sprintf("%d", cfg.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	// With no active leases the call should succeed (0 revoked, 0 failed).
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}
