package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createBulkTestSecret creates a secret via the API and returns its ID from the response.
func createBulkTestSecret(t *testing.T, client *http.Client, baseURL, token, name string, projectID, envID uint) uint {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name":           name,
		"value":          "bulk-rotate-test-value",
		"project_id":     projectID,
		"environment_id": envID,
		"type":           "password",
	})
	req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "expected data object in create-secret response: %v", out)
	id, ok := data["id"].(float64)
	require.True(t, ok, "expected numeric id in create-secret response data: %v", data)
	return uint(id)
}

// newBulkRotateTestEnv bootstraps a core + token + server and returns the bootstrapped
// project and environment IDs (both are created by BootstrapSystem).
func newBulkRotateTestEnv(t *testing.T) (c *core.KeyorixCore, token string, srv *httptest.Server, projectID, envID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c = newTestCore(t)
	token = createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv = httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Discover the project and environment IDs created by BootstrapSystem.
	ctx := context.Background()
	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID = projects[0].ID

	envs, err := c.ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID = envs[0].ID

	return
}

// doBulkRotate posts a bulk-rotate request and returns the HTTP status + decoded body.
func doBulkRotate(t *testing.T, client *http.Client, baseURL, token string, projectID uint, body string) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/projects/%d/secrets/bulk-rotate", baseURL, projectID)
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestBulkRotate_Unauthenticated verifies that the endpoint rejects requests without a token.
func TestBulkRotate_Unauthenticated(t *testing.T) {
	_, _, srv, projectID, _ := newBulkRotateTestEnv(t)
	client := &http.Client{Timeout: 5 * time.Second}

	code, _ := doBulkRotate(t, client, srv.URL, "" /* no token */, projectID, `{}`)
	assert.Equal(t, http.StatusUnauthorized, code)
}

// TestBulkRotate_EmptyIDs posts an explicit empty secret_ids list. The handler forwards
// to core.BulkRotateSecrets with an empty list, which then falls through to the
// project-wide path — returning 200 with total == 0 (no secrets seeded yet).
func TestBulkRotate_EmptyIDs(t *testing.T) {
	_, token, srv, projectID, _ := newBulkRotateTestEnv(t)
	client := &http.Client{Timeout: 5 * time.Second}

	code, out := doBulkRotate(t, client, srv.URL, token, projectID, `{"secret_ids":[]}`)
	assert.Equal(t, http.StatusOK, code)

	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "expected data object: %v", out)
	// When secret_ids is empty the core falls through to the project-wide path.
	// No secrets have been created, so total should be 0.
	total, ok := data["total"].(float64)
	require.True(t, ok, "expected numeric total in response: %v", data)
	assert.Equal(t, float64(0), total)
}

// TestBulkRotate_BySecretIDs posts an explicit list of secret IDs and confirms the
// response envelope contains the expected fields. Secrets without auto-rotation
// configured are reported in failed (not triggered), which is the documented
// "partial-results, never fatal" contract.
func TestBulkRotate_BySecretIDs(t *testing.T) {
	_, token, srv, projectID, envID := newBulkRotateTestEnv(t)
	client := &http.Client{Timeout: 5 * time.Second}

	id1 := createBulkTestSecret(t, client, srv.URL, token, "bulk-id-secret-1", projectID, envID)
	id2 := createBulkTestSecret(t, client, srv.URL, token, "bulk-id-secret-2", projectID, envID)

	bodyJSON := fmt.Sprintf(`{"secret_ids":[%d,%d]}`, id1, id2)
	code, out := doBulkRotate(t, client, srv.URL, token, projectID, bodyJSON)
	assert.Equal(t, http.StatusOK, code)

	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "expected data object: %v", out)
	assert.Contains(t, data, "triggered", "response must contain triggered field")
	assert.Contains(t, data, "total", "response must contain total field")

	// total must equal the number of IDs we submitted.
	total, ok := data["total"].(float64)
	require.True(t, ok, "expected numeric total: %v", data)
	assert.Equal(t, float64(2), total, "total must match the number of submitted IDs")
}

// TestBulkRotate_ByProject posts with no secret_ids, relying on the project-wide path.
// The response must contain both triggered and failed arrays.
func TestBulkRotate_ByProject(t *testing.T) {
	_, token, srv, projectID, envID := newBulkRotateTestEnv(t)
	client := &http.Client{Timeout: 5 * time.Second}

	createBulkTestSecret(t, client, srv.URL, token, "proj-rotate-secret-1", projectID, envID)
	createBulkTestSecret(t, client, srv.URL, token, "proj-rotate-secret-2", projectID, envID)

	code, out := doBulkRotate(t, client, srv.URL, token, projectID, `{}`)
	assert.Equal(t, http.StatusOK, code)

	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "expected data object: %v", out)
	assert.Contains(t, data, "triggered", "response must contain triggered field")
	assert.Contains(t, data, "total", "response must contain total field")
	// failed is omitempty but the key should be present when there are failures;
	// secrets without auto_rotate will land there — just confirm the envelope.
	total, ok := data["total"].(float64)
	require.True(t, ok, "expected numeric total: %v", data)
	assert.GreaterOrEqual(t, total, float64(2), "total must reflect both seeded secrets")
}

// TestBulkRotate_WrongProject submits secret IDs that belong to a different project.
// The cross-project guard must report them in failed, not triggered.
func TestBulkRotate_WrongProject(t *testing.T) {
	c, token, srv, projectID, envID := newBulkRotateTestEnv(t)
	client := &http.Client{Timeout: 5 * time.Second}

	// Seed two secrets in the real project.
	id1 := createBulkTestSecret(t, client, srv.URL, token, "cross-proj-secret-1", projectID, envID)
	id2 := createBulkTestSecret(t, client, srv.URL, token, "cross-proj-secret-2", projectID, envID)

	// Create a second project via the core API and submit the first project's secret
	// IDs scoped to the second project — the cross-project guard must reject them.
	ctx := context.Background()
	otherProject, err := c.CreateProject(ctx, "other-project", "")
	require.NoError(t, err)

	bodyJSON := fmt.Sprintf(`{"secret_ids":[%d,%d]}`, id1, id2)
	code, out := doBulkRotate(t, client, srv.URL, token, otherProject.ID, bodyJSON)
	assert.Equal(t, http.StatusOK, code)

	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "expected data object: %v", out)

	// All submitted IDs belong to the first project; rotated under a different
	// project they must all land in failed.
	failed, hasFailed := data["failed"]
	require.True(t, hasFailed, "response must contain failed field when cross-project IDs are submitted: %v", data)
	failedSlice, ok := failed.([]any)
	require.True(t, ok, "failed must be an array: %v", failed)
	assert.Len(t, failedSlice, 2, "both cross-project secrets must appear in failed")
}
