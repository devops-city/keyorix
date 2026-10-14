// alert_escalation_handler_test.go — integration tests for the alert escalation
// policy CRUD endpoints and the run-alert-escalation admin job trigger.
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// escalationTestEnv bundles the test HTTP server, admin token, and core for each sub-test.
type escalationTestEnv struct {
	server *httptest.Server
	token  string
	c      *core.KeyorixCore
}

func newEscalationTestEnv(t *testing.T) *escalationTestEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &escalationTestEnv{server: srv, token: token, c: c}
}

// --- helpers ---

func escalationURL(env *escalationTestEnv, path string) string {
	return env.server.URL + "/api/v1" + path
}

func escalationDo(t *testing.T, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reqBody)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, respBody
}

func parseEscalationData(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var env struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	return env.Data
}

// --- POST /alert-escalation-policies (create) ---

func TestAlertEscalation_Create_201(t *testing.T) {
	env := newEscalationTestEnv(t)

	resp, body := escalationDo(t, http.MethodPost,
		escalationURL(env, "/alert-escalation-policies"),
		env.token,
		map[string]any{
			"name":                   "on-call-escalation",
			"min_severity":           "medium",
			"escalate_after_minutes": 30,
			"channel_ids":            "",
			"enabled":                true,
		},
	)
	assert.Equal(t, http.StatusCreated, resp.StatusCode, string(body))
	data := parseEscalationData(t, body)
	assert.Equal(t, "on-call-escalation", data["name"])
	assert.Equal(t, "medium", data["min_severity"])
	assert.EqualValues(t, 30, data["escalate_after_minutes"])
}

func TestAlertEscalation_Create_EmptyName_400(t *testing.T) {
	env := newEscalationTestEnv(t)

	resp, _ := escalationDo(t, http.MethodPost,
		escalationURL(env, "/alert-escalation-policies"),
		env.token,
		map[string]any{
			"name":                   "",
			"min_severity":           "medium",
			"escalate_after_minutes": 30,
		},
	)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAlertEscalation_Create_Unauthenticated_401(t *testing.T) {
	env := newEscalationTestEnv(t)

	resp, _ := escalationDo(t, http.MethodPost,
		escalationURL(env, "/alert-escalation-policies"),
		"", // no token
		map[string]any{
			"name":                   "x",
			"min_severity":           "medium",
			"escalate_after_minutes": 30,
		},
	)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- GET /alert-escalation-policies (list) ---

func TestAlertEscalation_List_200(t *testing.T) {
	env := newEscalationTestEnv(t)

	// Seed two policies
	for _, name := range []string{"policy-a", "policy-b"} {
		resp, _ := escalationDo(t, http.MethodPost,
			escalationURL(env, "/alert-escalation-policies"),
			env.token,
			map[string]any{
				"name":                   name,
				"min_severity":           "low",
				"escalate_after_minutes": 15,
			},
		)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	}

	resp, body := escalationDo(t, http.MethodGet,
		escalationURL(env, "/alert-escalation-policies"),
		env.token,
		nil,
	)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := parseEscalationData(t, body)
	policies, ok := data["policies"].([]any)
	require.True(t, ok, "expected 'policies' array in response")
	assert.Len(t, policies, 2)
}

// --- GET /alert-escalation-policies/{id} ---

func TestAlertEscalation_GetByID_200(t *testing.T) {
	env := newEscalationTestEnv(t)

	// Create one
	_, createBody := escalationDo(t, http.MethodPost,
		escalationURL(env, "/alert-escalation-policies"),
		env.token,
		map[string]any{
			"name":                   "get-test",
			"min_severity":           "high",
			"escalate_after_minutes": 60,
		},
	)
	created := parseEscalationData(t, createBody)
	id := created["id"].(float64)

	resp, body := escalationDo(t, http.MethodGet,
		escalationURL(env, fmt.Sprintf("/alert-escalation-policies/%.0f", id)),
		env.token,
		nil,
	)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	data := parseEscalationData(t, body)
	assert.Equal(t, "get-test", data["name"])
}

func TestAlertEscalation_GetByID_NotFound_404(t *testing.T) {
	env := newEscalationTestEnv(t)

	resp, _ := escalationDo(t, http.MethodGet,
		escalationURL(env, "/alert-escalation-policies/9999"),
		env.token,
		nil,
	)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- PUT /alert-escalation-policies/{id} ---

func TestAlertEscalation_Update_200(t *testing.T) {
	env := newEscalationTestEnv(t)

	_, createBody := escalationDo(t, http.MethodPost,
		escalationURL(env, "/alert-escalation-policies"),
		env.token,
		map[string]any{
			"name":                   "update-me",
			"min_severity":           "low",
			"escalate_after_minutes": 10,
		},
	)
	created := parseEscalationData(t, createBody)
	id := created["id"].(float64)

	resp, body := escalationDo(t, http.MethodPut,
		escalationURL(env, fmt.Sprintf("/alert-escalation-policies/%.0f", id)),
		env.token,
		map[string]any{
			"name":         "updated-name",
			"min_severity": "critical",
		},
	)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	data := parseEscalationData(t, body)
	assert.Equal(t, "updated-name", data["name"])
	assert.Equal(t, "critical", data["min_severity"])
}

// --- DELETE /alert-escalation-policies/{id} ---

func TestAlertEscalation_Delete_204(t *testing.T) {
	env := newEscalationTestEnv(t)

	_, createBody := escalationDo(t, http.MethodPost,
		escalationURL(env, "/alert-escalation-policies"),
		env.token,
		map[string]any{
			"name":                   "delete-me",
			"min_severity":           "medium",
			"escalate_after_minutes": 30,
		},
	)
	created := parseEscalationData(t, createBody)
	id := created["id"].(float64)

	resp, _ := escalationDo(t, http.MethodDelete,
		escalationURL(env, fmt.Sprintf("/alert-escalation-policies/%.0f", id)),
		env.token,
		nil,
	)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify it's gone
	getResp, _ := escalationDo(t, http.MethodGet,
		escalationURL(env, fmt.Sprintf("/alert-escalation-policies/%.0f", id)),
		env.token,
		nil,
	)
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// --- POST /system/admin/jobs/run-alert-escalation ---

func TestAlertEscalation_RunJob_200(t *testing.T) {
	env := newEscalationTestEnv(t)

	resp, body := escalationDo(t, http.MethodPost,
		escalationURL(env, "/admin/jobs/run-alert-escalation"),
		env.token,
		nil,
	)
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	data := parseEscalationData(t, body)
	assert.Contains(t, data, "evaluated")
	assert.Contains(t, data, "escalated")
	assert.Contains(t, data, "skipped")
	// With no policies and no alerts, counts should be 0.
	assert.EqualValues(t, 0, data["evaluated"])
	assert.EqualValues(t, 0, data["escalated"])
	assert.EqualValues(t, 0, data["skipped"])
}

func TestAlertEscalation_RunJob_Unauthenticated_401(t *testing.T) {
	env := newEscalationTestEnv(t)

	resp, _ := escalationDo(t, http.MethodPost,
		escalationURL(env, "/admin/jobs/run-alert-escalation"),
		"", // no token
		nil,
	)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Unauthenticated access on CRUD routes ---

func TestAlertEscalation_ListUnauthenticated_401(t *testing.T) {
	env := newEscalationTestEnv(t)
	resp, _ := escalationDo(t, http.MethodGet,
		escalationURL(env, "/alert-escalation-policies"),
		"", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAlertEscalation_GetUnauthenticated_401(t *testing.T) {
	env := newEscalationTestEnv(t)
	resp, _ := escalationDo(t, http.MethodGet,
		escalationURL(env, "/alert-escalation-policies/1"),
		"", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAlertEscalation_UpdateUnauthenticated_401(t *testing.T) {
	env := newEscalationTestEnv(t)
	resp, _ := escalationDo(t, http.MethodPut,
		escalationURL(env, "/alert-escalation-policies/1"),
		"",
		map[string]any{"name": "x"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAlertEscalation_DeleteUnauthenticated_401(t *testing.T) {
	env := newEscalationTestEnv(t)
	resp, _ := escalationDo(t, http.MethodDelete,
		escalationURL(env, "/alert-escalation-policies/1"),
		"", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
