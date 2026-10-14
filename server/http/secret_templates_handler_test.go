// secret_templates_handler_test.go — handler-level integration tests for
// the secret template CRUD endpoints under /api/v1/secret-templates.
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// secretTemplateTestSetup initialises i18n, builds a full core (via newTestCore)
// and returns a running httptest.Server and a valid admin bearer token.
func secretTemplateTestSetup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, token
}

// stBody marshals v to a JSON reader; panics on error (test helper).
func stBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// stReq builds an authenticated HTTP request.
func stReq(t *testing.T, method, url, token string, body *bytes.Reader) *http.Request {
	t.Helper()
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// createTestTemplate creates a template via POST and returns its float64 ID.
func createTestTemplate(t *testing.T, srv *httptest.Server, token string, name string) float64 {
	t.Helper()
	payload := map[string]any{
		"name":                   name,
		"description":            "test template",
		"default_classification": "internal",
		"default_tags":           "db,prod",
		"rotation_hint_days":     30,
	}
	resp, err := http.DefaultClient.Do(
		stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates", token, stBody(t, payload)),
	)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	id, ok := data["id"].(float64)
	require.True(t, ok)
	return id
}

// ── Create ──────────────────────────────────────────────────────────────────

func TestSecretTemplateCreate_Success(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates", token,
		stBody(t, map[string]any{
			"name":                   "db-prod",
			"description":            "Production DB secrets",
			"default_classification": "confidential",
			"default_tags":           "db,prod",
			"rotation_hint_days":     90,
		}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "db-prod", data["name"])
	assert.Equal(t, "confidential", data["default_classification"])
	assert.NotNil(t, data["id"])
}

func TestSecretTemplateCreate_EmptyName_Returns400(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates", token,
		stBody(t, map[string]any{"name": "  "}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSecretTemplateCreate_InvalidClassification_Returns400(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates", token,
		stBody(t, map[string]any{
			"name":                   "tpl",
			"default_classification": "TOPSECRET",
		}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSecretTemplateCreate_BadJSON_Returns400(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/secret-templates",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── List ─────────────────────────────────────────────────────────────────────

func TestSecretTemplateList_Empty(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet, srv.URL+"/api/v1/secret-templates", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	templates, ok := data["templates"].([]any)
	require.True(t, ok)
	assert.Empty(t, templates)
}

func TestSecretTemplateList_WithTemplates(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	createTestTemplate(t, srv, token, "tpl-a")
	createTestTemplate(t, srv, token, "tpl-b")

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet, srv.URL+"/api/v1/secret-templates", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	templates := data["templates"].([]any)
	assert.Len(t, templates, 2)
}

// ── Get ──────────────────────────────────────────────────────────────────────

func TestSecretTemplateGet_Found(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	id := createTestTemplate(t, srv, token, "get-me")

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet,
		fmt.Sprintf("%s/api/v1/secret-templates/%d", srv.URL, int(id)), token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	assert.Equal(t, "get-me", data["name"])
}

func TestSecretTemplateGet_NotFound(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet,
		srv.URL+"/api/v1/secret-templates/9999", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSecretTemplateGet_InvalidID(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet,
		srv.URL+"/api/v1/secret-templates/not-a-number", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Update ───────────────────────────────────────────────────────────────────

func TestSecretTemplateUpdate_Success(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	id := createTestTemplate(t, srv, token, "upd-me")

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPut,
		fmt.Sprintf("%s/api/v1/secret-templates/%d", srv.URL, int(id)), token,
		stBody(t, map[string]any{
			"name":                   "updated-name",
			"default_classification": "restricted",
			"rotation_hint_days":     60,
		}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	assert.Equal(t, "updated-name", data["name"])
	assert.Equal(t, "restricted", data["default_classification"])
}

func TestSecretTemplateUpdate_NotFound(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPut,
		srv.URL+"/api/v1/secret-templates/9999", token,
		stBody(t, map[string]any{"name": "x"}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSecretTemplateUpdate_BadJSON(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/secret-templates/1",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSecretTemplateUpdate_InvalidID(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPut,
		srv.URL+"/api/v1/secret-templates/bad", token,
		stBody(t, map[string]any{"name": "x"}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSecretTemplateUpdate_InvalidClassification(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	id := createTestTemplate(t, srv, token, "cls-test")

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPut,
		fmt.Sprintf("%s/api/v1/secret-templates/%d", srv.URL, int(id)), token,
		stBody(t, map[string]any{
			"name":                   "cls-test",
			"default_classification": "ultra-secret",
		}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Delete ───────────────────────────────────────────────────────────────────

func TestSecretTemplateDelete_Success(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	id := createTestTemplate(t, srv, token, "del-me")

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodDelete,
		fmt.Sprintf("%s/api/v1/secret-templates/%d", srv.URL, int(id)), token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Subsequent GET must return 404.
	getResp, err := http.DefaultClient.Do(stReq(t, http.MethodGet,
		fmt.Sprintf("%s/api/v1/secret-templates/%d", srv.URL, int(id)), token, nil))
	require.NoError(t, err)
	defer func() { _ = getResp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

func TestSecretTemplateDelete_NotFound(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodDelete,
		srv.URL+"/api/v1/secret-templates/9999", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSecretTemplateDelete_InvalidID(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodDelete,
		srv.URL+"/api/v1/secret-templates/bad", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Apply ────────────────────────────────────────────────────────────────────

func TestSecretTemplateApply_EmptyRequest_GetsDefaults(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	// Create template with defaults.
	resp0, err := http.DefaultClient.Do(stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates", token,
		stBody(t, map[string]any{
			"name":                   "apply-tpl",
			"default_classification": "internal",
			"default_tags":           "db,prod",
			"description_pattern":    "hint text",
		}),
	))
	require.NoError(t, err)
	var createBody map[string]any
	require.NoError(t, json.NewDecoder(resp0.Body).Decode(&createBody))
	_ = resp0.Body.Close()
	id := int(createBody["data"].(map[string]any)["id"].(float64))

	// Apply with empty overrides → should receive template defaults.
	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost,
		fmt.Sprintf("%s/api/v1/secret-templates/%d/apply", srv.URL, id), token,
		stBody(t, map[string]any{}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	assert.Equal(t, "internal", data["classification"])
	assert.Equal(t, "hint text", data["description"])
}

func TestSecretTemplateApply_CallerOverridesPreserved(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	id := createTestTemplate(t, srv, token, "override-tpl")

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost,
		fmt.Sprintf("%s/api/v1/secret-templates/%d/apply", srv.URL, int(id)), token,
		stBody(t, map[string]any{
			"classification": "confidential",
			"description":    "my description",
			"tags":           []string{"custom"},
		}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	assert.Equal(t, "confidential", data["classification"])
	assert.Equal(t, "my description", data["description"])
}

func TestSecretTemplateApply_NotFound(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost,
		srv.URL+"/api/v1/secret-templates/9999/apply", token,
		stBody(t, map[string]any{}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSecretTemplateApply_BadJSON(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/secret-templates/1/apply",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSecretTemplateApply_InvalidID(t *testing.T) {
	srv, token := secretTemplateTestSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost,
		srv.URL+"/api/v1/secret-templates/bad/apply", token,
		stBody(t, map[string]any{}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Auth ─────────────────────────────────────────────────────────────────────

func TestSecretTemplate_Unauthenticated(t *testing.T) {
	srv, _ := secretTemplateTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/secret-templates", nil)
	require.NoError(t, err)
	// No Authorization header.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ── Storage-error (500) paths ─────────────────────────────────────────────────
//
// secretTemplateBrokenDBSetup creates a server backed by a core that has all
// normal tables migrated but then drops the secret_templates table. Every
// template storage call thereafter returns a "no such table" DB error so we
// can exercise the 500 branch in each handler.
func secretTemplateBrokenDBSetup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	// Build a normal core (full schema) to bootstrap and mint a session.
	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
	// Drop the secret_templates table to provoke DB errors on template calls.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_templates").Error)

	brokenCore := core.NewKeyorixCore(store.NewLocalStorage(db))
	brokenCore.SetBootstrapToken("broken-bootstrap-token")
	_, err := brokenCore.BootstrapSystem(t.Context(), &core.BootstrapRequest{
		Username: "brokenadmin",
		Email:    "brokenadmin@example.com",
		Password: "BrokenPassw0rd!X#",
		Token:    "broken-bootstrap-token",
	})
	require.NoError(t, err)
	session, _, err := brokenCore.Login(t.Context(), &core.LoginRequest{
		Username: "brokenadmin",
		Password: "BrokenPassw0rd!X#",
	})
	require.NoError(t, err)
	brokenToken := session.SessionToken

	router, err := NewRouter(&config.Config{}, brokenCore)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, brokenToken
}

func TestSecretTemplateList_StorageError(t *testing.T) {
	srv, token := secretTemplateBrokenDBSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet, srv.URL+"/api/v1/secret-templates", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestSecretTemplateCreate_StorageError(t *testing.T) {
	srv, token := secretTemplateBrokenDBSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates", token,
		stBody(t, map[string]any{"name": "tpl"}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestSecretTemplateGet_StorageError(t *testing.T) {
	srv, token := secretTemplateBrokenDBSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodGet, srv.URL+"/api/v1/secret-templates/1", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestSecretTemplateUpdate_StorageError(t *testing.T) {
	srv, token := secretTemplateBrokenDBSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPut, srv.URL+"/api/v1/secret-templates/1", token,
		stBody(t, map[string]any{"name": "x"}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestSecretTemplateDelete_StorageError(t *testing.T) {
	srv, token := secretTemplateBrokenDBSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodDelete, srv.URL+"/api/v1/secret-templates/1", token, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestSecretTemplateApply_StorageError(t *testing.T) {
	srv, token := secretTemplateBrokenDBSetup(t)

	resp, err := http.DefaultClient.Do(stReq(t, http.MethodPost, srv.URL+"/api/v1/secret-templates/1/apply", token,
		stBody(t, map[string]any{}),
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
