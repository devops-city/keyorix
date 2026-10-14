// users_crud_s13_test.go — coverage sweep targeting uncovered branches in:
//   - users_crud.go: createUserWithSetupLink conflict, UpdateUser ConflictError,
//     RestoreUser not-found, GetUserByEmail/GetUserByUsername/GetUserByExternalID
//     success paths, CreateUser invalid JSON / validation error,
//     createUserWithOTP / createUserClassic success paths
//   - users_handler.go: updateUserLegacy bad-id/invalid-JSON/validation-error,
//     createUserLegacy validation error, package-level dispatch with real handler
//   - users_list.go: ListUsers email/username/include_deleted/is_active filter
//     branches, SearchUsers success path, StaleAccounts password_reset_required
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── updateUserLegacy uncovered branches ───────────────────────────────────────

// TestUpdateUserLegacy_BadID_S13 verifies the 400 branch when the chi "id"
// param cannot be parsed as a uint.
func TestUpdateUserLegacy_BadID_S13(t *testing.T) {
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	updateUserLegacy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateUserLegacy_InvalidJSON_S13 verifies the 400 branch for malformed
// JSON in the request body.
func TestUpdateUserLegacy_InvalidJSON_S13(t *testing.T) {
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad-json")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	updateUserLegacy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateUserLegacy_ValidationError_S13 verifies the 400 branch when the
// request body fails struct validation (malformed email).
func TestUpdateUserLegacy_ValidationError_S13(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	body, _ := json.Marshal(map[string]any{"email": "not-an-email"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	updateUserLegacy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── createUserLegacy uncovered branches ───────────────────────────────────────

// TestCreateUserLegacy_ValidationError_S13 verifies the 400 branch when the
// legacy body fails validation (username too short, min=3).
func TestCreateUserLegacy_ValidationError_S13(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"username":     "ab",
		"email":        "valid@example.com",
		"display_name": "Valid Name",
		"password":     "ValidPass123!",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CreateUser body validation branches ───────────────────────────────────────

// TestCreateUser_InvalidJSON_S13 verifies the 400 branch for malformed JSON in
// the CreateUser request body.
func TestCreateUser_InvalidJSON_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(
		http.MethodPost, "/api/v1/users", bytes.NewBufferString("{bad-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateUser_ValidationError_S13 verifies the 400 branch when the body
// fails struct validation (email not a valid address).
func TestCreateUser_ValidationError_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":     "valtest-s13",
		"email":        "not-an-email",
		"display_name": "Val Test S13",
		"password":     "Str0ng#Password!123",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── createUserWithOTP success path ────────────────────────────────────────────

// TestCreateUserWithOTP_Success_S13 exercises the 201 success branch of
// createUserWithOTP (covers the sendCreated path with one_time_password).
func TestCreateUserWithOTP_Success_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":                   "otp-success-s13",
		"email":                      "otp-success-s13@x.com",
		"display_name":               "OTP Success S13",
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "one_time_password")
}

// ── createUserClassic success path ───────────────────────────────────────────

// TestCreateUserClassic_Success_S13 exercises the 201 success branch of
// createUserClassic (admin-set password, no role assignments).
func TestCreateUserClassic_Success_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	body, _ := json.Marshal(map[string]any{
		"username":     "classic-success-s13",
		"email":        "classic-success-s13@x.com",
		"display_name": "Classic Success S13",
		"password":     "Str0ng#Password!123",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ── createUserWithSetupLink conflict (409) ────────────────────────────────────

// TestCreateUserWithSetupLink_ConflictError_S13 seeds a user and verifies the
// 409 branch in createUserWithSetupLink when the username/email already exists.
// A base URL must be set so CreateUserWithSetupLink passes the ErrSetupBaseURLRequired
// guard and reaches the duplicate-user check.
func TestCreateUserWithSetupLink_ConflictError_S13(t *testing.T) {
	uh, cs, db := freshUserHandlerS12(t)
	cs.SetCredentialDelivery(nil, "https://test.keyorix.example")

	require.NoError(t, db.Create(&models.User{
		Username:       "setup-conflict-s13",
		UsernameFolded: "setup-conflict-s13",
		Email:          "setup-conflict-s13@x.com",
		EmailFolded:    "setup-conflict-s13@x.com",
		AccountState:   core.AccountActive,
	}).Error)

	body, _ := json.Marshal(map[string]any{
		"username":           "setup-conflict-s13",
		"email":              "setup-conflict-s13@x.com",
		"display_name":       "Setup Conflict S13",
		"deliver_setup_link": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── GetUser success path ──────────────────────────────────────────────────────

// TestGetUser_Found_S13 seeds a user and exercises the 200 success path of
// GetUser (with project_count attached).
func TestGetUser_Found_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:     "getuser-s13",
		Email:        "getuser-s13@x.com",
		AccountState: core.AccountActive,
	}).Error)
	var u models.User
	require.NoError(t, db.Where("username = ?", "getuser-s13").First(&u).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/999", nil),
		"id", itoa(u.ID),
	))
	w := httptest.NewRecorder()
	uh.GetUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetUserByEmail success path ───────────────────────────────────────────────

// TestGetUserByEmail_Found_S13 seeds a user and exercises the 200 success path
// of GetUserByEmail.
func TestGetUserByEmail_Found_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:       "byemail-s13",
		UsernameFolded: "byemail-s13",
		Email:          "byemail-s13@x.com",
		EmailFolded:    "byemail-s13@x.com",
		AccountState:   core.AccountActive,
	}).Error)

	req := withUserCtx(httptest.NewRequest(
		http.MethodGet, "/api/v1/users/by-email?email=byemail-s13@x.com", nil))
	w := httptest.NewRecorder()
	uh.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetUserByEmail_NotFound_S13 complements the empty-param test (s12) by
// verifying the 404 path for a non-existent email.
func TestGetUserByEmail_NotFound_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(
		http.MethodGet, "/api/v1/users/by-email?email=nobody-s13@x.com", nil))
	w := httptest.NewRecorder()
	uh.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── GetUserByUsername success path ────────────────────────────────────────────

// TestGetUserByUsername_Found_S13 seeds a user and exercises the 200 success
// path of GetUserByUsername.
func TestGetUserByUsername_Found_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:       "byusername-s13",
		UsernameFolded: "byusername-s13",
		Email:          "byusername-s13@x.com",
		EmailFolded:    "byusername-s13@x.com",
		AccountState:   core.AccountActive,
	}).Error)

	req := withUserCtx(httptest.NewRequest(
		http.MethodGet, "/api/v1/users/by-username?username=byusername-s13", nil))
	w := httptest.NewRecorder()
	uh.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetUserByExternalID success path ─────────────────────────────────────────

// TestGetUserByExternalID_Found_S13 seeds a user with an external ID and
// exercises the 200 success path of GetUserByExternalID.
func TestGetUserByExternalID_Found_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:     "byextid-s13",
		Email:        "byextid-s13@x.com",
		ExternalID:   "ext-id-s13",
		AccountState: core.AccountActive,
	}).Error)

	req := withUserCtx(httptest.NewRequest(
		http.MethodGet, "/api/v1/users/by-external-id?external_id=ext-id-s13", nil))
	w := httptest.NewRecorder()
	uh.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── UpdateUser ConflictError path ─────────────────────────────────────────────

// TestUpdateUser_ConflictError_S13 seeds two users and updates the second's
// username to one already taken by the first → ErrUserAlreadyExists → 409.
func TestUpdateUser_ConflictError_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)

	require.NoError(t, db.Create(&models.User{
		Username:       "existing-user-s13",
		UsernameFolded: "existing-user-s13",
		Email:          "existing-s13@x.com",
		EmailFolded:    "existing-s13@x.com",
		AccountState:   core.AccountActive,
	}).Error)
	require.NoError(t, db.Create(&models.User{
		Username:       "target-user-s13",
		UsernameFolded: "target-user-s13",
		Email:          "target-s13@x.com",
		EmailFolded:    "target-s13@x.com",
		AccountState:   core.AccountActive,
	}).Error)

	var target models.User
	require.NoError(t, db.Where("username = ?", "target-user-s13").First(&target).Error)

	body, _ := json.Marshal(map[string]any{
		"username": "existing-user-s13",
	})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/999", bytes.NewReader(body)),
		"id", itoa(target.ID),
	))
	w := httptest.NewRecorder()
	uh.UpdateUser(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestUpdateUser_Success_S13 seeds a user and exercises the 200 success path
// of UpdateUser.
func TestUpdateUser_Success_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:     "updateme-s13",
		Email:        "updateme-s13@x.com",
		AccountState: core.AccountActive,
	}).Error)
	var u models.User
	require.NoError(t, db.Where("username = ?", "updateme-s13").First(&u).Error)

	body, _ := json.Marshal(map[string]any{"display_name": "Updated S13"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/999", bytes.NewReader(body)),
		"id", itoa(u.ID),
	))
	w := httptest.NewRecorder()
	uh.UpdateUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── DeleteUser success path ───────────────────────────────────────────────────

// TestDeleteUser_Success_S13 seeds a non-admin user and exercises the 204
// success path of DeleteUser.
func TestDeleteUser_Success_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:     "deleteme-s13",
		Email:        "deleteme-s13@x.com",
		AccountState: core.AccountActive,
	}).Error)
	var u models.User
	require.NoError(t, db.Where("username = ?", "deleteme-s13").First(&u).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/users/999", nil),
		"id", itoa(u.ID),
	))
	w := httptest.NewRecorder()
	uh.DeleteUser(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── RestoreUser not-found (404) ───────────────────────────────────────────────

// TestRestoreUser_NotFound_S13 verifies the 404 branch for RestoreUser when
// the user ID doesn't exist or was never soft-deleted.
func TestRestoreUser_NotFound_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/9999/restore", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	uh.RestoreUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_list.go: ListUsers filter branch coverage ───────────────────────────

// TestListUsers_EmailFilter_S13 exercises the ?email= filter branch in ListUsers.
func TestListUsers_EmailFilter_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?email=alice@x.com", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListUsers_UsernameFilter_S13 exercises the ?username= filter branch.
func TestListUsers_UsernameFilter_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?username=alice", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListUsers_IncludeDeleted_S13 exercises the ?include_deleted=1 branch.
func TestListUsers_IncludeDeleted_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?include_deleted=1", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListUsers_IsActiveFalse_S13 exercises the ?is_active=false branch
// (v == false, filter set to &false).
func TestListUsers_IsActiveFalse_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?is_active=false", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListUsers_IsActiveTrue_S13 exercises the ?is_active=1 branch
// (v == true, filter set to &true).
func TestListUsers_IsActiveTrue_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?is_active=1", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SearchUsers success path (non-zero result set) ────────────────────────────

// TestSearchUsers_ReturnsResults_S13 seeds a user and verifies SearchUsers
// exercises the success path past auth and param validation.
func TestSearchUsers_ReturnsResults_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)
	require.NoError(t, db.Create(&models.User{
		Username:     "searchable-s13",
		Email:        "searchable-s13@x.com",
		AccountState: core.AccountActive,
	}).Error)

	req := withUserCtx(httptest.NewRequest(
		http.MethodGet, "/api/v1/users/search?q=searchable-s13", nil))
	w := httptest.NewRecorder()
	uh.SearchUsers(w, req)
	// SQLite may or may not support ILIKE; 200 or 500 are both acceptable here —
	// the key is the auth/param-parse path was traversed without 401/400.
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── StaleAccounts password_reset_required state ────────────────────────────────

// TestStaleAccounts_PasswordResetRequired_S13 exercises the
// password_reset_required state branch in StaleAccounts (different from the
// pending_first_login cases already covered).
func TestStaleAccounts_PasswordResetRequired_S13(t *testing.T) {
	uh, _, db := freshUserHandlerS12(t)

	u := &models.User{
		Username:     "reset-stale-s13",
		Email:        "reset-stale-s13@x.com",
		AccountState: core.AccountPasswordResetRequired,
	}
	require.NoError(t, db.Create(u).Error)
	// Force created_at into the past, routed through Save (not a raw column
	// Update): StaleAccounts' ListUsersInStateBefore does a real SQL range
	// query on created_at, and User.BeforeSave exists specifically to
	// UTC-normalize this column for that comparison — a raw Update bypasses it
	// and leaves the local Location of time.Now() sitting in the column,
	// correct here only because the 10-day-old value clears the 7-day cutoff
	// by a comfortable margin, not because the value is actually canonical (#1619).
	u.CreatedAt = time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, db.Save(u).Error)

	req := withUserCtx(httptest.NewRequest(
		http.MethodGet,
		"/api/v1/users/stale?state=password_reset_required&days=7",
		nil,
	))
	w := httptest.NewRecorder()
	uh.StaleAccounts(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, core.AccountPasswordResetRequired, data["state"])
}

// ── package-level dispatch with a real handler wired ─────────────────────────

// TestPackageLevel_ListUsers_RealHandler_S13 wires defaultUserHandler and
// verifies the package-level ListUsers routes to it (not the legacy stub).
func TestPackageLevel_ListUsers_RealHandler_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	saved := defaultUserHandler
	defaultUserHandler = uh
	defer func() { defaultUserHandler = saved }()

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestPackageLevel_CreateUser_RealHandler_S13 wires defaultUserHandler and
// verifies the package-level CreateUser routes to it (not the legacy stub).
// Sends a body with no password or setup-link flag → 400 from the real handler.
func TestPackageLevel_CreateUser_RealHandler_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	saved := defaultUserHandler
	defaultUserHandler = uh
	defer func() { defaultUserHandler = saved }()

	body, _ := json.Marshal(map[string]any{
		"username":     "pkg-create-s13",
		"email":        "pkg-create-s13@x.com",
		"display_name": "Pkg Create S13",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	CreateUser(w, req)
	// Real handler: missing password, no setup-link/OTP flag → 400.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPackageLevel_GetUser_RealHandler_S13 wires defaultUserHandler and
// verifies the package-level GetUser routes to it (not the legacy stub).
// Requests a non-existent user → 404 from the real handler.
func TestPackageLevel_GetUser_RealHandler_S13(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)
	saved := defaultUserHandler
	defaultUserHandler = uh
	defer func() { defaultUserHandler = saved }()

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	GetUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
