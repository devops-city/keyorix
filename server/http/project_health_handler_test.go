// project_health_handler_test.go — handler-level integration tests for
// GET /api/v1/projects/{id}/health.
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createSecret is a test helper that POSTs a secret to project 1 / environment 1 and
// returns the newly-created secret's ID.
func createSecret(t *testing.T, srv *httptest.Server, token, name string) uint {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name":           name,
		"value":          "test-value",
		"project_id":     1,
		"environment_id": 1,
		"type":           "password",
	})
	require.NoError(t, err)

	req, err := http.NewRequest("POST", srv.URL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusCreated, resp.StatusCode, "createSecret: expected 201")

	var response map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	data, ok := response["data"].(map[string]any)
	require.True(t, ok, "createSecret: missing data field")
	id, ok := data["id"].(float64)
	require.True(t, ok, "createSecret: missing id field")
	return uint(id)
}

// TestGetProjectHealth_EmptyProject checks that an authenticated admin gets 200
// with zero secrets when the project has no secrets.
func TestGetProjectHealth_EmptyProject(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/projects/1/health", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body missing 'data' object")

	assert.EqualValues(t, 0, data["total_secrets"])
	assert.EqualValues(t, 0, data["high_risk_count"])
}

// TestGetProjectHealth_WithSecrets checks that after creating 2 secrets the
// health endpoint reports total_secrets == 2 and returns a 'secrets' array.
func TestGetProjectHealth_WithSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	createSecret(t, srv, token, "health-secret-a")
	createSecret(t, srv, token, "health-secret-b")

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/projects/1/health", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body missing 'data' object")

	assert.EqualValues(t, 2, data["total_secrets"])
	secrets, ok := data["secrets"].([]any)
	require.True(t, ok, "'secrets' field must be an array")
	assert.Len(t, secrets, 2)
}

// TestGetProjectHealth_LimitParam checks that ?limit=2 caps the returned
// secrets slice to at most 2 entries even when more exist.
func TestGetProjectHealth_LimitParam(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	for i := range 5 {
		createSecret(t, srv, token, fmt.Sprintf("limit-secret-%d", i))
	}

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/projects/1/health?limit=2", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body missing 'data' object")

	assert.EqualValues(t, 5, data["total_secrets"])
	secrets, ok := data["secrets"].([]any)
	require.True(t, ok, "'secrets' field must be an array")
	assert.LessOrEqual(t, len(secrets), 2)
}

// TestGetProjectHealth_Unauthenticated checks that a request with no token
// receives 401.
func TestGetProjectHealth_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.DefaultClient.Get(srv.URL + "/api/v1/projects/1/health")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestGetProjectHealth_NotFound checks the behaviour for a project ID that does
// not exist. GetProjectHealthSummary never queries the projects table; it simply
// lists secrets filtered by project_id and returns an empty summary, so the
// handler returns 200 with total_secrets == 0 rather than 404.
func TestGetProjectHealth_NotFound(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/projects/999999/health", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	// The handler returns 200 with an empty summary for non-existent projects
	// rather than 404, because it delegates to GetProjectHealthSummary which
	// lists secrets filtered by project_id and returns an empty summary when
	// none exist.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body missing 'data' object")
	assert.EqualValues(t, 0, data["total_secrets"])
}
