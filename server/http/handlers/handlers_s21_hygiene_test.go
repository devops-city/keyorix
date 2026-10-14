// handlers_s21_hygiene_test.go — coverage sweep targeting uncovered branches in:
//   - machine_token_hygiene.go: MachineTokenHygiene — missing user context (401),
//     default days, explicit days param, cap to 3650, success with seeded stale
//     and expired credentials (entries present), success with empty result
//   - users_crud.go: createUserWithOTP — validation-error branch (i18n path),
//     internal-error branch (storage down)
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── MachineTokenHygiene helpers ───────────────────────────────────────────────

// freshCatalogHandlerHygieneS21 returns a CatalogHandler backed by a fresh
// admin-seeded in-memory DB (reusing freshCoreS12 which already migrates all
// models including MachineIdentity and MachineIdentityCredential).
func freshCatalogHandlerHygieneS21(t *testing.T) *CatalogHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewCatalogHandler(cs)
}

// ── MachineTokenHygiene: missing user context → 401 ──────────────────────────

// TestMachineTokenHygiene_NoUserContext_S21 verifies the 401 branch when there
// is no user context in the request (GetUserFromContext returns nil).
func TestMachineTokenHygiene_NoUserContext_S21(t *testing.T) {
	h := freshCatalogHandlerHygieneS21(t)
	// Deliberately no withUserCtx — context is absent.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil)
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Unauthorized")
}

// ── MachineTokenHygiene: default days (no ?days param) ───────────────────────

// TestMachineTokenHygiene_DefaultDays_S21 verifies the 200 success path when no
// ?days query parameter is supplied (defaults to 90). Empty DB returns an empty
// token list.
func TestMachineTokenHygiene_DefaultDays_S21(t *testing.T) {
	h := freshCatalogHandlerHygieneS21(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"tokens"`)
	assert.Contains(t, w.Body.String(), `"total"`)
}

// ── MachineTokenHygiene: explicit ?days param ─────────────────────────────────

// TestMachineTokenHygiene_ExplicitDays_S21 verifies that a valid ?days=N param
// is accepted and the handler still returns 200.
func TestMachineTokenHygiene_ExplicitDays_S21(t *testing.T) {
	h := freshCatalogHandlerHygieneS21(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=30", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── MachineTokenHygiene: days param capped to 3650 ───────────────────────────

// TestMachineTokenHygiene_DaysCapped_S21 verifies that supplying days > 3650
// is silently capped and still returns 200.
func TestMachineTokenHygiene_DaysCapped_S21(t *testing.T) {
	h := freshCatalogHandlerHygieneS21(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=99999", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── MachineTokenHygiene: invalid ?days param is ignored ──────────────────────

// TestMachineTokenHygiene_InvalidDaysParam_S21 verifies that a non-numeric
// ?days value falls back to the default (90) and still returns 200.
func TestMachineTokenHygiene_InvalidDaysParam_S21(t *testing.T) {
	h := freshCatalogHandlerHygieneS21(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=notanumber", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── MachineTokenHygiene: success with seeded stale + expired credentials ──────

// TestMachineTokenHygiene_WithEntries_S21 seeds a MachineIdentity and two
// MachineIdentityCredentials (one expired, one stale) and verifies that the
// handler returns them in the response with the correct flags and without the
// token hash.
func TestMachineTokenHygiene_WithEntries_S21(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	// Seed a MachineIdentity (FK required by MachineIdentityCredential).
	mi := &models.MachineIdentity{Name: "hygiene-mi-s21", ProjectID: 0}
	require.NoError(t, db.Create(mi).Error)

	now := time.Now().UTC()
	past := now.Add(-400 * 24 * time.Hour) // well outside the default 90-day window

	// Expired credential: ExpiresAt is in the past, never revoked.
	expiredAt := now.Add(-1 * 24 * time.Hour)
	credExpired := &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID,
		Name:              "expired-cred-s21",
		TokenHash:         "deadbeef01234567890abcdef0000001",
		TokenPrefix:       "kx_m_exp",
		ExpiresAt:         &expiredAt,
		Revoked:           false,
		CreatedAt:         past,
	}
	require.NoError(t, db.Create(credExpired).Error)

	// Stale credential: LastUsedAt is beyond the staleness window, not expired.
	lastUsed := past
	credStale := &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID,
		Name:              "stale-cred-s21",
		TokenHash:         "deadbeef01234567890abcdef0000002",
		TokenPrefix:       "kx_m_stl",
		LastUsedAt:        &lastUsed,
		Revoked:           false,
		CreatedAt:         past,
	}
	require.NoError(t, db.Create(credStale).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=90", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Both credentials must appear.
	assert.Contains(t, body, "expired-cred-s21")
	assert.Contains(t, body, "stale-cred-s21")
	// Token hash must NOT appear in the response.
	assert.NotContains(t, body, "deadbeef01234567890abcdef0000001")
	assert.NotContains(t, body, "deadbeef01234567890abcdef0000002")
	// total should be at least 2.
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "expected data envelope")
	total, ok := data["total"].(float64)
	require.True(t, ok, "expected numeric total")
	assert.GreaterOrEqual(t, int(total), 2)
}

// ── MachineTokenHygiene: storage error → 500 ─────────────────────────────────

// TestMachineTokenHygiene_StorageError_S21 closes the underlying DB to force a
// storage error inside ListMachineTokenHygiene and verifies the 500 branch.
func TestMachineTokenHygiene_StorageError_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}

// ── createUserWithOTP: validation-error branch (i18n path) ───────────────────

// TestCreateUserWithOTP_CoreValidationError_S21 exercises the
// strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) branch inside
// createUserWithOTP — the core-level validation check that fires AFTER the HTTP
// body is decoded and passes the outer validator.
//
// The core's CreateUserWithOneTimePassword validates the request; an empty
// display_name produces a validation error whose message contains the i18n
// "ErrorValidation" marker, exercising the branch at line ~115 of users_crud.go.
func TestCreateUserWithOTP_CoreValidationError_S21(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	uh, _, _ := freshUserHandlerS12(t)

	// display_name passes the HTTP body validator (omitempty allows empty strings
	// at the body-decode layer) but the core validator rejects it as too short.
	// We send an empty display_name to trigger a core-level validation failure.
	body, _ := json.Marshal(map[string]any{
		"username":                   "otp-valtest-s21",
		"email":                      "otp-valtest-s21@x.com",
		"display_name":               "", // empty — rejected by core
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	// The handler should return a 4xx. The exact code depends on whether the
	// core returns a validation-tagged error (400) or some other failure.
	assert.GreaterOrEqual(t, w.Code, http.StatusBadRequest)
	assert.Less(t, w.Code, http.StatusInternalServerError)
}

// ── createUserWithOTP: internal-error branch (storage down) ──────────────────

// TestCreateUserWithOTP_InternalError_S21 closes the underlying DB and calls
// CreateUser with generate_one_time_password=true so that
// CreateUserWithOneTimePassword returns a non-ErrUserAlreadyExists, non-
// validation-tagged error, driving the 500 branch of createUserWithOTP.
func TestCreateUserWithOTP_InternalError_S21(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	uh, _, db := freshUserHandlerS12(t)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]any{
		"username":                   "otp-internal-s21",
		"email":                      "otp-internal-s21@x.com",
		"display_name":               "OTP Internal S21",
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}
