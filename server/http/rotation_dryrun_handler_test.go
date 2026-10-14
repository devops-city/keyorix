package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dryRunTestEnv holds the common test fixtures for rotation dry-run handler tests.
type dryRunTestEnv struct {
	c         *core.KeyorixCore
	token     string
	srv       *httptest.Server
	projectID uint
	envID     uint
}

// newDryRunTestEnv bootstraps the full server stack for dry-run handler tests.
func newDryRunTestEnv(t *testing.T) *dryRunTestEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID

	envs, err := c.ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	return &dryRunTestEnv{c: c, token: token, srv: srv, projectID: projectID, envID: envID}
}

// createDryRunSecret creates a secret via the API and returns its ID.
func createDryRunSecret(t *testing.T, env *dryRunTestEnv, name string) uint {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name":           name,
		"value":          "test-value",
		"project_id":     env.projectID,
		"environment_id": env.envID,
		"type":           "password",
	})
	req, err := http.NewRequest("POST", env.srv.URL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+env.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data := out["data"].(map[string]any)
	return uint(data["id"].(float64))
}

// postSimulate calls POST /api/v1/secrets/{id}/rotation/simulate and returns the status + body.
func postSimulate(t *testing.T, env *dryRunTestEnv, secretID uint, token string) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/secrets/%d/rotation/simulate", env.srv.URL, secretID)
	req, err := http.NewRequest("POST", url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestRotationDryRun_Unauthenticated verifies that the endpoint rejects unauthenticated calls.
func TestRotationDryRun_Unauthenticated(t *testing.T) {
	env := newDryRunTestEnv(t)
	id := createDryRunSecret(t, env, "sim-no-auth")

	status, _ := postSimulate(t, env, id, "")
	assert.Equal(t, http.StatusUnauthorized, status)
}

// TestRotationDryRun_SecretNotFound verifies that a non-existent secret returns 404.
func TestRotationDryRun_SecretNotFound(t *testing.T) {
	env := newDryRunTestEnv(t)

	status, body := postSimulate(t, env, 99999, env.token)
	assert.Equal(t, http.StatusNotFound, status)
	// The middleware returns a 404 without a "success" field; just check the status code
	// and that the body has an error field.
	assert.NotEmpty(t, body["error"])
}

// TestRotationDryRun_NoPolicy verifies that a secret with no rotation policy returns
// valid=false with the policy_exists check failing.
func TestRotationDryRun_NoPolicy(t *testing.T) {
	env := newDryRunTestEnv(t)
	id := createDryRunSecret(t, env, "sim-no-policy")

	status, body := postSimulate(t, env, id, env.token)
	require.Equal(t, http.StatusOK, status)
	assert.True(t, body["success"].(bool))

	data := body["data"].(map[string]any)
	assert.False(t, data["valid"].(bool))

	checks := data["checks"].([]any)
	require.NotEmpty(t, checks)
	policyCheck := findCheckInSlice(checks, "policy_exists")
	require.NotNil(t, policyCheck)
	assert.False(t, policyCheck["passed"].(bool))
}

// TestRotationDryRun_ValidPolicy verifies that a secret with a covering active policy,
// a known backend and a non-empty ref returns valid=true.
func TestRotationDryRun_ValidPolicy(t *testing.T) {
	env := newDryRunTestEnv(t)

	// Wire a fake backend so the backend_known check passes.
	env.c.SetRotationManager(rotation.NewManager([]rotation.Executor{&fakeRotationExecutor{name: "pg"}}))

	id := createDryRunSecret(t, env, "sim-valid")

	ctx := context.Background()

	// Directly set RotationBackend/Ref on the secret via storage, bypassing the HTTP
	// auto-rotate endpoint's admin-authority gate (which is a correct guard for
	// production use but would require a full role-setup fixture just for this test).
	secret, err := env.c.GetSecret(ctx, id)
	require.NoError(t, err)
	secret.RotationBackend = "pg"
	secret.RotationRef = "myrole"
	_, err = env.c.Storage().UpdateSecret(ctx, secret)
	require.NoError(t, err)

	// Create an active rotation policy for the project.
	_, err = env.c.CreateRotationPolicy(ctx, 0, &core.CreateRotationPolicyRequest{
		Name:         "30-day",
		Scope:        "project",
		ProjectID:    &env.projectID,
		IntervalDays: 30,
		CreatedBy:    "admin",
	})
	require.NoError(t, err)

	status, body := postSimulate(t, env, id, env.token)
	require.Equal(t, http.StatusOK, status)
	assert.True(t, body["success"].(bool))

	data := body["data"].(map[string]any)
	assert.True(t, data["valid"].(bool))
	assert.Equal(t, float64(id), data["secret_id"].(float64))
	assert.NotEmpty(t, data["secret_name"])
	assert.Equal(t, "pg", data["backend"])
	assert.Equal(t, "myrole", data["ref"])
	assert.NotEmpty(t, data["simulated_at"])
}

// TestRotationDryRun_InvalidID verifies that a non-numeric ID returns 400.
func TestRotationDryRun_InvalidID(t *testing.T) {
	env := newDryRunTestEnv(t)

	url := fmt.Sprintf("%s/api/v1/secrets/notanumber/rotation/simulate", env.srv.URL)
	req, err := http.NewRequest("POST", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+env.token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestRotationDryRun_LimitedToken verifies that a user without the secrets.read
// permission is denied (403).
func TestRotationDryRun_LimitedToken(t *testing.T) {
	env := newDryRunTestEnv(t)
	id := createDryRunSecret(t, env, "sim-limited")

	limitedToken := createLimitedToken(t, env.c)
	status, _ := postSimulate(t, env, id, limitedToken)
	// A user with no role at the secret's scope is denied.
	assert.Equal(t, http.StatusForbidden, status)
}

// findCheckInSlice searches a []interface{} of JSON-decoded check maps for the named check.
func findCheckInSlice(checks []any, name string) map[string]any {
	for _, raw := range checks {
		ch, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if ch["name"] == name {
			return ch
		}
	}
	return nil
}

// fakeRotationExecutor is a minimal rotation.Executor for HTTP handler tests.
// (distinct from the core package's fakeExecutor which is unexported there)
type fakeRotationExecutor struct {
	name string
}

func (f *fakeRotationExecutor) Name() string { return f.name }
func (f *fakeRotationExecutor) Type() string { return "fake" }
func (f *fakeRotationExecutor) Rotate(_ context.Context, _, _ string) error {
	return nil
}

// TestRotationDryRun_ChecksReturned verifies that the response always contains exactly
// 4 named checks even when the secret has no rotation configuration at all.
func TestRotationDryRun_ChecksReturned(t *testing.T) {
	env := newDryRunTestEnv(t)
	id := createDryRunSecret(t, env, "sim-checks")

	status, body := postSimulate(t, env, id, env.token)
	require.Equal(t, http.StatusOK, status)

	data := body["data"].(map[string]any)
	checks := data["checks"].([]any)
	assert.Len(t, checks, 4)

	names := make([]string, 0, 4)
	for _, raw := range checks {
		ch := raw.(map[string]any)
		names = append(names, ch["name"].(string))
	}
	assert.Contains(t, names, "policy_exists")
	assert.Contains(t, names, "backend_known")
	assert.Contains(t, names, "ref_non_empty")
	assert.Contains(t, names, "ref_valid")
}

// Ensure the models package import is used (for direct DB manipulation in tests).
var _ = (*models.RotationPolicy)(nil)
