package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestEnvironment POSTs to POST /api/v1/projects/{projectID}/environments and
// returns the newly created environment's ID. It fails the test immediately on any
// non-201 response or decode error.
func createTestEnvironment(t *testing.T, client *http.Client, baseURL, token string, projectID uint, name string) uint {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q}`, name)
	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/v1/projects/%d/environments", baseURL, projectID),
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "createTestEnvironment: unexpected status for %q", name)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "createTestEnvironment: response missing data object")
	id, ok := data["id"].(float64)
	require.True(t, ok, "createTestEnvironment: data.id missing or not a number")
	return uint(id)
}

// createTestSecret POSTs to POST /api/v1/secrets and returns the new secret ID.
func createTestSecret(t *testing.T, client *http.Client, baseURL, token string, projectID, envID uint, name string) uint {
	t.Helper()
	payload := map[string]any{
		"name":           name,
		"value":          "test-value",
		"project_id":     projectID,
		"environment_id": envID,
		"type":           "generic",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "createTestSecret: unexpected status for %q", name)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "createTestSecret: response missing data object")
	id, ok := data["id"].(float64)
	require.True(t, ok, "createTestSecret: data.id missing or not a number")
	return uint(id)
}

// doClone calls POST /api/v1/projects/{projectID}/environments/{srcEnvID}/clone and
// returns the raw *http.Response. The caller owns closing the body.
func doClone(t *testing.T, client *http.Client, baseURL, token string, projectID, srcEnvID, dstEnvID uint) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"destination_environment_id":%d}`, dstEnvID)
	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/v1/projects/%d/environments/%d/clone", baseURL, projectID, srcEnvID),
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// TestCloneEnvironment_EmptySource clones environment 1 (no secrets) to a fresh
// environment and expects 200 with secrets_cloned == 0.
func TestCloneEnvironment_EmptySource(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// BootstrapSystem creates project 1 with environments 1 (development), 2 (staging),
	// 3 (production). Create an additional destination so we do not clone onto a shared
	// built-in environment and risk cross-test state.
	dstEnvID := createTestEnvironment(t, client, srv.URL, token, 1, "clone-dst-empty")

	resp := doClone(t, client, srv.URL, token, 1, 1, dstEnvID)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "response must contain a data object")
	assert.EqualValues(t, 0, data["secrets_cloned"])
}

// TestCloneEnvironment_WithSecrets creates 2 secrets in env 1, clones to a new env,
// and expects 200 with secrets_cloned == 2.
func TestCloneEnvironment_WithSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	createTestSecret(t, client, srv.URL, token, 1, 1, "clone-with-alpha")
	createTestSecret(t, client, srv.URL, token, 1, 1, "clone-with-beta")

	dstEnvID := createTestEnvironment(t, client, srv.URL, token, 1, "clone-dst-with")

	resp := doClone(t, client, srv.URL, token, 1, 1, dstEnvID)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "response must contain a data object")
	assert.EqualValues(t, 2, data["secrets_cloned"])
}

// TestCloneEnvironment_SkipsExisting creates "foo" in env 1, creates env 2 with
// "foo" already in it, clones, and expects 200 with secrets_skipped >= 1.
func TestCloneEnvironment_SkipsExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// Seed "foo" in the source (env 1).
	createTestSecret(t, client, srv.URL, token, 1, 1, "clone-skip-foo")

	// Create destination and pre-seed the same name so it gets skipped.
	dstEnvID := createTestEnvironment(t, client, srv.URL, token, 1, "clone-dst-skip")
	createTestSecret(t, client, srv.URL, token, 1, dstEnvID, "clone-skip-foo")

	resp := doClone(t, client, srv.URL, token, 1, 1, dstEnvID)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "response must contain a data object")
	skipped, _ := data["secrets_skipped"].(float64)
	assert.GreaterOrEqual(t, int(skipped), 1, "at least one secret must be skipped")
}

// TestCloneEnvironment_Unauthenticated verifies that an unauthenticated request
// receives 401.
func TestCloneEnvironment_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	_ = createTestToken(t, c) // seed system so the DB is initialised
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	body := `{"destination_environment_id":2}`
	req, err := http.NewRequest("POST",
		srv.URL+"/api/v1/projects/1/environments/1/clone",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestCloneEnvironment_DestNotFound clones to a non-existent destination environment
// and expects 404 or 400.
func TestCloneEnvironment_DestNotFound(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	resp := doClone(t, client, srv.URL, token, 1, 1, 999999)
	defer func() { _ = resp.Body.Close() }()
	assert.True(t,
		resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest,
		"expected 404 or 400, got %d", resp.StatusCode)
}
