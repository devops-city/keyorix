package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetSecretValueByRef exercises GET /api/v1/secrets/value?ref=project/environment/name
// end-to-end: a successful by-reference value read, plus the 400/404/401 paths.
func TestGetSecretValueByRef(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	core := newTestCore(t)
	token := createTestToken(t, core)

	// Discover the bootstrapped project + environment names to build a real reference.
	ctx := context.Background()
	projects, err := core.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	project := projects[0]
	envs, err := core.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	router, err := NewRouter(&config.Config{}, core)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	// Seed a secret with a known value via the API (so it has a real encrypted version).
	body, _ := json.Marshal(map[string]any{
		"name":           "ref-test",
		"value":          "v-by-ref",
		"project_id":     project.ID,
		"environment_id": env.ID,
		"type":           "password",
	})
	req, _ := http.NewRequest("POST", server.URL+"/api/v1/secrets", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()

	get := func(t *testing.T, ref, tok string) (int, map[string]any) {
		t.Helper()
		u := server.URL + "/api/v1/secrets/value"
		if ref != "" {
			u += "?ref=" + ref
		}
		req, _ := http.NewRequest("GET", u, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	ref := project.Name + "/" + env.Name + "/ref-test"

	t.Run("resolves value by reference", func(t *testing.T) {
		code, out := get(t, ref, token)
		require.Equal(t, http.StatusOK, code)
		data, ok := out["data"].(map[string]any)
		require.True(t, ok, "response: %v", out)
		assert.Equal(t, "v-by-ref", data["value"], "jsonPath $.data.value carries the secret value")
	})

	t.Run("malformed ref is 400", func(t *testing.T) {
		code, _ := get(t, "not-a-three-part-ref", token)
		assert.Equal(t, http.StatusBadRequest, code)
	})

	t.Run("unknown secret is 404 for a globally-permitted caller", func(t *testing.T) {
		code, _ := get(t, project.Name+"/"+env.Name+"/ghost", token)
		assert.Equal(t, http.StatusNotFound, code)
	})

	t.Run("no token is 401", func(t *testing.T) {
		code, _ := get(t, ref, "")
		assert.Equal(t, http.StatusUnauthorized, code)
	})
}
