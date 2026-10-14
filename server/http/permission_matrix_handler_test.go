package http

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPermissionMatrix_JSON(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/rbac/permission-matrix", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body must contain a 'data' object")
	assert.Contains(t, data, "rows")
	assert.Contains(t, data, "total")
}

func TestGetPermissionMatrix_CSV(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/rbac/permission-matrix?format=csv", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv"),
		"Content-Type must be text/csv, got %s", resp.Header.Get("Content-Type"))

	records, err := csv.NewReader(resp.Body).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, records, "CSV response must contain at least the header row")

	header := records[0]
	assert.Contains(t, header, "username")
	assert.Contains(t, header, "email")
	assert.Contains(t, header, "role")
	assert.Contains(t, header, "permission")
}

func TestGetPermissionMatrix_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	c := newTestCore(t)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/rbac/permission-matrix", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestGetPermissionMatrix_ProjectFilter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/v1/rbac/permission-matrix?project_id=1", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response body must contain a 'data' object")
	assert.Contains(t, data, "rows")
	assert.Contains(t, data, "total")
}
