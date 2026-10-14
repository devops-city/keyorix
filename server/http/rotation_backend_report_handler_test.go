// rotation_backend_report_handler_test.go — integration tests for
// GET /api/v1/compliance/rotation-by-backend.
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRotationBackendTestEnv bootstraps a core, token, and server for
// rotation-by-backend tests.
func newRotationBackendTestEnv(t *testing.T) (c *core.KeyorixCore, token string, srv *httptest.Server) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c = newTestCore(t)
	token = createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv = httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return
}

// doRotationByBackend sends a GET to /api/v1/compliance/rotation-by-backend and
// returns the HTTP status code + the decoded JSON body.
func doRotationByBackend(t *testing.T, srv *httptest.Server, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("GET", srv.URL+"/api/v1/compliance/rotation-by-backend", nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// TestRotationByBackend_Unauthenticated — no token → 401.
func TestRotationByBackend_Unauthenticated(t *testing.T) {
	_, _, srv := newRotationBackendTestEnv(t)
	code, _ := doRotationByBackend(t, srv, "")
	assert.Equal(t, http.StatusUnauthorized, code)
}

// TestRotationByBackend_AuthenticatedEmpty — no rotation policies → 200 with an
// empty backends array and total_overdue == 0.
func TestRotationByBackend_AuthenticatedEmpty(t *testing.T) {
	_, token, srv := newRotationBackendTestEnv(t)
	code, body := doRotationByBackend(t, srv, token)
	assert.Equal(t, http.StatusOK, code)

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "expected data object: %v", body)

	// backends must be present (empty slice or null is fine here).
	_, hasBackends := data["backends"]
	assert.True(t, hasBackends, "response must contain backends field: %v", data)

	totalOverdue, ok := data["total_overdue"].(float64)
	require.True(t, ok, "total_overdue must be numeric: %v", data)
	assert.Equal(t, float64(0), totalOverdue)

	_, hasGeneratedAt := data["generated_at"]
	assert.True(t, hasGeneratedAt, "response must contain generated_at: %v", data)
}

// TestRotationByBackend_WithPolicy — seed a rotation policy and secret; the
// secret appears in the report's backends array.
func TestRotationByBackend_WithPolicy(t *testing.T) {
	c, token, srv := newRotationBackendTestEnv(t)
	ctx := context.Background()

	// Discover bootstrapped project / environment.
	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID

	envs, err := c.ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	// Create a secret (RotationBackend defaults to "" — regenerate in Keyorix only).
	_, err = c.CreateSecret(ctx, &core.CreateSecretRequest{
		ProjectID:     projectID,
		EnvironmentID: envID,
		Name:          "test-backend-secret",
		Value:         []byte("supersecret"),
		Type:          "password",
		CreatedBy:     "testadmin",
	})
	require.NoError(t, err)

	// Create an active rotation policy covering the project (30-day interval).
	// The secret's creation date is "now", so with a 30-day interval the secret
	// is not yet overdue — but it is covered by the policy and will appear.
	pid := projectID
	_, err = c.CreateRotationPolicy(ctx, 0, &core.CreateRotationPolicyRequest{
		Name:            "test-policy",
		Scope:           "project",
		ProjectID:       &pid,
		IntervalDays:    30,
		AlertDaysBefore: 5,
		NotifyOnBreach:  false,
		CreatedBy:       "testadmin",
	})
	require.NoError(t, err)

	code, body := doRotationByBackend(t, srv, token)
	require.Equal(t, http.StatusOK, code)

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "expected data object: %v", body)

	backends, ok := data["backends"].([]any)
	require.True(t, ok, "backends must be an array: %v", data)
	require.NotEmpty(t, backends, "at least one backend must appear when a policy is set")

	// The secret has no RotationBackend (empty string = keyorix-internal). Confirm
	// at least one backend entry exists with total >= 1.
	found := false
	for _, raw := range backends {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		total, _ := entry["total"].(float64)
		if total >= 1 {
			found = true
		}
	}
	assert.True(t, found, "at least one backend entry with total >= 1 must appear")
}

// TestRotationByBackend_ResponseEnvelopeShape — validate the exact response shape:
// success=true, data.generated_at, data.backends (array), data.total_overdue.
func TestRotationByBackend_ResponseEnvelopeShape(t *testing.T) {
	_, token, srv := newRotationBackendTestEnv(t)
	code, body := doRotationByBackend(t, srv, token)
	assert.Equal(t, http.StatusOK, code)

	success, _ := body["success"].(bool)
	assert.True(t, success, "success must be true: %v", body)

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "data must be an object: %v", body)
	assert.Contains(t, data, "generated_at", "data must contain generated_at")
	assert.Contains(t, data, "backends", "data must contain backends")
	assert.Contains(t, data, "total_overdue", "data must contain total_overdue")
}

// Ensure models package is used (RotationPolicy).
var _ = models.RotationPolicy{}
