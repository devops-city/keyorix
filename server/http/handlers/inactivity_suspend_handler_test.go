package handlers

import (
	"bytes"
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

// newInactivityHandler builds an AdminJobsHandler backed by a fresh in-memory
// SQLite DB with the full schema.
func newInactivityHandler(t *testing.T) *AdminJobsHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

// postInactivitySuspend helper sends a request directly to the handler (bypasses
// the router — used for unit-level handler tests).
func postInactivitySuspend(h http.HandlerFunc, body any, auth bool) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/suspend-inactive-users", &buf)
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req = withUserCtx(req)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func TestSuspendInactiveUsersHandler_HappyPath(t *testing.T) {
	h := newInactivityHandler(t)
	w := postInactivitySuspend(h.SuspendInactiveUsers,
		map[string]any{"inactive_days": 90}, true)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	assert.Equal(t, float64(0), data["total"])
	assert.Equal(t, float64(0), data["skipped"])
}

func TestSuspendInactiveUsersHandler_RequiresUserContext(t *testing.T) {
	h := newInactivityHandler(t)
	w := postInactivitySuspend(h.SuspendInactiveUsers,
		map[string]any{"inactive_days": 90}, false)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSuspendInactiveUsersHandler_InvalidJSON(t *testing.T) {
	h := newInactivityHandler(t)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/jobs/suspend-inactive-users",
		bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.SuspendInactiveUsers(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSuspendInactiveUsersHandler_ZeroDays(t *testing.T) {
	h := newInactivityHandler(t)
	w := postInactivitySuspend(h.SuspendInactiveUsers,
		map[string]any{"inactive_days": 0}, true)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSuspendInactiveUsersHandler_NegativeDays(t *testing.T) {
	h := newInactivityHandler(t)
	w := postInactivitySuspend(h.SuspendInactiveUsers,
		map[string]any{"inactive_days": -1}, true)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSuspendInactiveUsersHandler_CoreError(t *testing.T) {
	// Trigger the 500 path by closing the underlying DB before calling the handler.
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	h := NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	// Close the underlying SQL DB to force a storage error.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	w := postInactivitySuspend(h.SuspendInactiveUsers,
		map[string]any{"inactive_days": 1}, true)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
