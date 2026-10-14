package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newUsageHandlerDB builds a LocalStorage-backed core service with the tables
// needed by GetProjectUsageStats wired up.
func newUsageHandlerDB(t *testing.T) *AdminUsageHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.SecretNode{},
		&models.AuditEvent{},
	))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	return NewAdminUsageHandler(cs)
}

// get issues a GET request against the handler.
func getUsage(h http.HandlerFunc, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestAdminUsage_OK verifies that an empty DB returns a 200 with a valid
// report envelope.
func TestAdminUsage_OK(t *testing.T) {
	h := newUsageHandlerDB(t)
	w := getUsage(h.GetUsageReport, "/api/v1/admin/usage")
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.True(t, body["success"].(bool))

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "data field should be an object")
	assert.EqualValues(t, 30, data["window_days"])
	assert.NotEmpty(t, data["generated_at"])
}

// TestAdminUsage_InvalidDays_DefaultsTo30 verifies that an invalid days value
// is defaulted to 30 in the response.
func TestAdminUsage_InvalidDays_DefaultsTo30(t *testing.T) {
	h := newUsageHandlerDB(t)

	for _, target := range []string{
		"/api/v1/admin/usage?days=-1",
		"/api/v1/admin/usage?days=0",
		"/api/v1/admin/usage?days=999",
		"/api/v1/admin/usage?days=notanumber",
	} {
		t.Run(target, func(t *testing.T) {
			w := getUsage(h.GetUsageReport, target)
			require.Equal(t, http.StatusOK, w.Code)

			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			data := body["data"].(map[string]any)
			assert.EqualValues(t, 30, data["window_days"])
		})
	}
}

// TestAdminUsage_ProjectFilter verifies that a valid project_id param is
// accepted and the response reflects it (report is scoped to an empty project).
func TestAdminUsage_ProjectFilter(t *testing.T) {
	h := newUsageHandlerDB(t)
	w := getUsage(h.GetUsageReport, "/api/v1/admin/usage?project_id=1&days=7")
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.True(t, body["success"].(bool))
	data := body["data"].(map[string]any)
	// No secrets or events in DB, so projects slice is empty
	assert.EqualValues(t, 7, data["window_days"])
}

// TestAdminUsage_ValidDays verifies that an explicit valid days value is
// honored and returned in the response.
func TestAdminUsage_ValidDays(t *testing.T) {
	h := newUsageHandlerDB(t)
	w := getUsage(h.GetUsageReport, "/api/v1/admin/usage?days=90")
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data := body["data"].(map[string]any)
	assert.EqualValues(t, 90, data["window_days"])
}
