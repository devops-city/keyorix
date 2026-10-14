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

// createIntegrationTestSecret POSTs to /api/v1/secrets and returns the created
// secret's ID. It fails the test immediately if the create request does not
// return 201 or the response cannot be decoded.
func createIntegrationTestSecret(t *testing.T, client *http.Client, baseURL, token, name string) uint {
	t.Helper()
	secretData := map[string]any{
		"name":           name,
		"value":          "secret-value-for-" + name,
		"project_id":     1,
		"environment_id": 1,
		"type":           "password",
		"metadata": map[string]string{
			"test": "diff-integration",
		},
		"tags": []string{"diff", "test"},
	}
	body, err := json.Marshal(secretData)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "expected 201 from POST /api/v1/secrets")

	var response map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))

	data, ok := response["data"].(map[string]any)
	require.True(t, ok, "response.data must be an object")

	id, ok := data["id"].(float64)
	require.True(t, ok, "response.data.id must be a number")
	return uint(id)
}

// updateIntegrationTestSecret PUTs to /api/v1/secrets/{id} to create a new
// version. It fails the test immediately if the update does not return 200.
func updateIntegrationTestSecret(t *testing.T, client *http.Client, baseURL, token string, secretID uint, newValue string) {
	t.Helper()
	updateData := map[string]any{
		"value": newValue,
	}
	body, err := json.Marshal(updateData)
	require.NoError(t, err)

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 from PUT /api/v1/secrets/%d", secretID)
}

// TestDiffSecretVersions_SameVersion verifies that diffing a version against
// itself is rejected with 400 (the implementation treats from==to as a
// validation error: "from and to versions must differ").
func TestDiffSecretVersions_SameVersion(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "diff-same-version-secret")

	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/1/diff/1", srv.URL, secretID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// from == to is a validation error; the handler returns 400.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestDiffSecretVersions_AfterUpdate creates a secret (version 1), updates it
// to produce version 2, then diffs v1→v2 and verifies the response fields.
func TestDiffSecretVersions_AfterUpdate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "diff-after-update-secret")
	updateIntegrationTestSecret(t, client, srv.URL, token, secretID, "updated-secret-value-v2")

	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/1/diff/2", srv.URL, secretID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response.data must be an object")

	assert.Equal(t, float64(1), data["from_version"])
	assert.Equal(t, float64(2), data["to_version"])
}

// TestDiffSecretVersions_InvalidVersion verifies that requesting a diff with a
// version number that does not exist returns 404.
func TestDiffSecretVersions_InvalidVersion(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "diff-invalid-version-secret")

	// Version 99 does not exist; the core returns "Secret version not found" which
	// the handler maps to 404.
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/1/diff/99", srv.URL, secretID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestDiffSecretVersions_Unauthenticated verifies that the endpoint returns 401
// when no token is provided.
func TestDiffSecretVersions_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// Create the secret with a valid token so we have a real secret ID.
	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "diff-unauth-secret")
	updateIntegrationTestSecret(t, client, srv.URL, token, secretID, "v2-value")

	// Attempt the diff request without an Authorization header.
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/1/diff/2", srv.URL, secretID), nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDiffSecretVersions_ResponseShape verifies that a successful diff response
// contains the expected top-level fields: secret_id, secret_name, and changes.
func TestDiffSecretVersions_ResponseShape(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "diff-response-shape-secret")
	updateIntegrationTestSecret(t, client, srv.URL, token, secretID, "v2-shape-value")

	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/1/diff/2", srv.URL, secretID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response.data must be an object")

	assert.Contains(t, data, "secret_id", "response.data must contain secret_id")
	assert.Contains(t, data, "secret_name", "response.data must contain secret_name")
	assert.Contains(t, data, "changes", "response.data must contain changes")

	// changes must be an array or null (null when the Go nil slice is serialised by
	// encoding/json with no omitempty tag). Both nil and []interface{} are valid.
	changesRaw := data["changes"]
	if changesRaw != nil {
		_, ok = changesRaw.([]any)
		assert.True(t, ok, "response.data.changes must be an array when non-null")
	}

	assert.Equal(t, "diff-response-shape-secret", data["secret_name"])
	assert.Equal(t, float64(secretID), data["secret_id"])
}
