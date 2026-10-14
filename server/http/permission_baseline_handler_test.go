package http

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPermBaselineRouter is a convenience helper that boots a fresh core + router
// for each permission-baseline test.
func newPermBaselineRouter(t *testing.T) (router http.Handler, token string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{}
	c := newTestCore(t)
	token = createTestToken(t, c)

	r, err := NewRouter(cfg, c)
	require.NoError(t, err)
	return r, token
}

// TestPermissionBaseline_JSON verifies GET /compliance/permission-baseline returns
// 200 with a JSON body that contains the admin user's rows.
func TestPermissionBaseline_JSON(t *testing.T) {
	router, token := newPermBaselineRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-baseline", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["success"])

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "expected data object in response")

	rows, ok := data["rows"].([]any)
	require.True(t, ok, "expected rows array in data")
	assert.NotEmpty(t, rows, "admin user should have at least one permission row")

	// Confirm at least one row belongs to "testadmin".
	found := false
	for _, r := range rows {
		row := r.(map[string]any)
		if row["username"] == "testadmin" {
			found = true
			break
		}
	}
	assert.True(t, found, "testadmin should appear in the baseline rows")
}

// TestPermissionBaseline_CSV verifies GET /compliance/permission-baseline.csv returns
// 200 with Content-Type text/csv and a valid CSV body.
func TestPermissionBaseline_CSV(t *testing.T) {
	router, token := newPermBaselineRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-baseline.csv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv"),
		"expected text/csv Content-Type, got %s", w.Header().Get("Content-Type"))

	// Parse CSV and assert it is well-formed.
	records, err := csv.NewReader(w.Body).ReadAll()
	require.NoError(t, err, "CSV body must be parseable")
	assert.NotEmpty(t, records, "CSV must have at least a header row")
}

// TestPermissionBaseline_CSV_Headers verifies the CSV header row has exactly the
// required columns in the correct order.
func TestPermissionBaseline_CSV_Headers(t *testing.T) {
	router, token := newPermBaselineRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-baseline.csv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	records, err := csv.NewReader(w.Body).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, records, "expected at least a header row")

	// Full column set as actually emitted (handlers/permission_baseline.go:57),
	// asserted explicitly rather than by count: G25 added grant_expired and
	// holder_deleted after this test was written, and a bare length check
	// would have passed even if a column were silently reordered or a
	// DIFFERENT new column added instead of these two specific ones.
	wantHeaders := []string{"user_id", "username", "email", "role_name", "scope", "permission", "grant_expired", "holder_deleted"}
	assert.Equal(t, wantHeaders, records[0], "CSV header must match the spec exactly")
}

// TestPermissionBaseline_SecondUser verifies that after assigning a role to a second
// user, both users appear in the baseline.
func TestPermissionBaseline_SecondUser(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{}
	c := newTestCore(t)
	adminToken := createTestToken(t, c)

	// Create a second user and give them a role.
	ctx := context.Background()
	second, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "seconduser",
		Email:    "second@example.com",
		Password: "Xk7#Qp2$Rn5@Wv9!",
	})
	require.NoError(t, err, "create second user")
	_ = second // suppress unused variable

	// Assign the "viewer" or "system_admin" role to the second user.
	// BootstrapSystem seeds roles including "system_admin"; use AssignRoleToUser.
	_ = c.AssignRoleToUser(ctx, "second@example.com", "system_admin")

	r, err := NewRouter(cfg, c)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-baseline", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	rows := data["rows"].([]any)

	foundAdmin := false
	foundSecond := false
	for _, row := range rows {
		r := row.(map[string]any)
		switch r["username"] {
		case "testadmin":
			foundAdmin = true
		case "seconduser":
			foundSecond = true
		}
	}
	assert.True(t, foundAdmin, "testadmin should be in baseline")
	assert.True(t, foundSecond, "seconduser should be in baseline after role assignment")
}

// TestPermissionBaseline_Unauthenticated verifies that an unauthenticated request
// receives 401 for both the JSON and CSV endpoints.
func TestPermissionBaseline_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{}
	c := newTestCore(t)
	r, err := NewRouter(cfg, c)
	require.NoError(t, err)

	for _, path := range []string{
		"/api/v1/compliance/permission-baseline",
		"/api/v1/compliance/permission-baseline.csv",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			// No Authorization header.
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "unauthenticated request must be rejected")
		})
	}
}
