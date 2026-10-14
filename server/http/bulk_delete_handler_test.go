package http

import (
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

// createBulkDelTestSecret POSTs to /api/v1/secrets and returns the created secret's ID.
func createBulkDelTestSecret(t *testing.T, client *http.Client, baseURL, token, name string) uint {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"value":"test-value","project_id":1,"environment_id":1,"type":"password"}`, name)
	req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "createBulkDelTestSecret: unexpected status")
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data := out["data"].(map[string]any)
	return uint(data["id"].(float64))
}

func TestBulkDeleteSecrets_Success(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	id1 := createBulkDelTestSecret(t, client, srv.URL, token, "bulk-del-1")
	id2 := createBulkDelTestSecret(t, client, srv.URL, token, "bulk-del-2")

	body := fmt.Sprintf(`{"secret_ids":[%d,%d]}`, id1, id2)
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/1/secrets/bulk-delete", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data := out["data"].(map[string]any)

	deleted := data["deleted"].([]any)
	assert.Len(t, deleted, 2)

	failed, ok := data["failed"].([]any)
	if ok {
		assert.Empty(t, failed)
	}
}

func TestBulkDeleteSecrets_VerifyDeleted(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	id1 := createBulkDelTestSecret(t, client, srv.URL, token, "verify-del-1")
	id2 := createBulkDelTestSecret(t, client, srv.URL, token, "verify-del-2")

	// Bulk-delete both secrets.
	body := fmt.Sprintf(`{"secret_ids":[%d,%d]}`, id1, id2)
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/1/secrets/bulk-delete", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// GET each secret — both must now return 404.
	for _, id := range []uint{id1, id2} {
		getReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d", srv.URL, id), nil)
		require.NoError(t, err)
		getReq.Header.Set("Authorization", "Bearer "+token)
		getResp, err := client.Do(getReq)
		require.NoError(t, err)
		_ = getResp.Body.Close()
		assert.Equal(t, http.StatusNotFound, getResp.StatusCode, "expected 404 for secret %d after bulk delete", id)
	}
}

func TestBulkDeleteSecrets_NonExistentID(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	body := `{"secret_ids":[999999]}`
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/1/secrets/bulk-delete", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data := out["data"].(map[string]any)

	failed := data["failed"].([]any)
	require.NotEmpty(t, failed, "expected 999999 to appear in failed list")

	found := false
	for _, f := range failed {
		entry := f.(map[string]any)
		if uint(entry["secret_id"].(float64)) == 999999 {
			found = true
			break
		}
	}
	assert.True(t, found, "secret ID 999999 must appear in the failed list")
}

func TestBulkDeleteSecrets_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	body := `{"secret_ids":[1]}`
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/1/secrets/bulk-delete", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBulkDeleteSecrets_EmptyRequest(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	body := `{"secret_ids":[]}`
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/1/secrets/bulk-delete", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkDeleteSecrets_BadJSON(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/1/secrets/bulk-delete", strings.NewReader("not-json"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkDeleteSecrets_InvalidProjectID(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// Use an ID that overflows uint32 to trigger the ParseUint error path.
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/projects/9999999999999999999/secrets/bulk-delete",
		strings.NewReader(`{"secret_ids":[1]}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
