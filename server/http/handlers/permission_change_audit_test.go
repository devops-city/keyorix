package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// openPermChangeAuditDB opens a uniquely-named in-memory DB for permission-
// change-audit handler tests. i18n is initialized (required by GetRole's not-
// found error path). The DB includes every table that GetPermissionChangeAudit
// touches via GetAuditLogs, GetUser, and GetRole.
func openPermChangeAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_perm_audit_")
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SoDPolicy{},
	))
	return db
}

// newDashHandler constructs a DashboardHandler backed by an in-memory DB.
func newDashHandler(t *testing.T) (*DashboardHandler, *gorm.DB) {
	t.Helper()
	db := openPermChangeAuditDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	return h, db
}

// seedPermChangeEvent inserts a raw audit_event row for testing.
func seedPermChangeEvent(t *testing.T, db *gorm.DB, eventType string, diff string, at time.Time) {
	t.Helper()
	tr := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: eventType,
		Diff:      diff,
		Success:   &tr,
		EventTime: at,
	}).Error)
}

// TestGetPermissionChangeAudit_Unauthorized — no user context → 401.
func TestGetPermissionChangeAudit_Unauthorized(t *testing.T) {
	h, _ := newDashHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes", nil)
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetPermissionChangeAudit_OK_Empty — authenticated request with no events → 200, empty changes.
func TestGetPermissionChangeAudit_OK_Empty(t *testing.T) {
	h, _ := newDashHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes", nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			Changes []any `json:"changes"`
			Total   int   `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, 0, resp.Data.Total)
	assert.Empty(t, resp.Data.Changes)
}

// TestGetPermissionChangeAudit_OK_WithEvents — seeded events appear in the response.
func TestGetPermissionChangeAudit_OK_WithEvents(t *testing.T) {
	h, db := newDashHandler(t)
	now := time.Now()
	seedPermChangeEvent(t, db, "role.assigned", `{"role_id":1}`, now)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes", nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			Changes []map[string]any `json:"changes"`
			Total   int              `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Data.Total)
	require.Len(t, resp.Data.Changes, 1)
	assert.Equal(t, "role.assigned", resp.Data.Changes[0]["action"])
}

// TestGetPermissionChangeAudit_WithSinceAndUntil — filtered by since/until.
func TestGetPermissionChangeAudit_WithSinceAndUntil(t *testing.T) {
	h, db := newDashHandler(t)

	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	// Event inside window.
	seedPermChangeEvent(t, db, "role.assigned", `{"role_id":1}`, base)
	// Event outside window (3 days before).
	seedPermChangeEvent(t, db, "role.removed", `{"role_id":2}`, base.Add(-72*time.Hour))

	since := base.Add(-time.Hour).Format(time.RFC3339)
	until := base.Add(time.Hour).Format(time.RFC3339)
	url := "/api/v1/compliance/permission-changes?since=" + since + "&until=" + until
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Data.Total)
}

// TestGetPermissionChangeAudit_InvalidSince — bad RFC3339 since → 400.
func TestGetPermissionChangeAudit_InvalidSince(t *testing.T) {
	h, _ := newDashHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes?since=not-a-time", nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetPermissionChangeAudit_InvalidUntil — bad RFC3339 until → 400.
func TestGetPermissionChangeAudit_InvalidUntil(t *testing.T) {
	h, _ := newDashHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes?until=bad", nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetPermissionChangeAudit_LimitParam — limit query param is forwarded.
func TestGetPermissionChangeAudit_LimitParam(t *testing.T) {
	h, db := newDashHandler(t)
	now := time.Now()
	for i := range 5 {
		seedPermChangeEvent(t, db, "role.assigned", `{"role_id":1}`, now.Add(-time.Duration(i)*time.Second))
	}

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes?limit=2", nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			Total     int              `json:"total"`
			Changes   []map[string]any `json:"changes"`
			Truncated bool             `json:"truncated"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	// #G24: total now reports the TRUE matching count (5), not the returned page
	// size — changes is what's capped at the requested limit.
	assert.LessOrEqual(t, len(resp.Data.Changes), 2)
	assert.Equal(t, 5, resp.Data.Total)
	assert.True(t, resp.Data.Truncated)
}

// TestGetPermissionChangeAudit_StorageError_500 — storage failure → 500.
// Uses a DB with no audit_events table so GetAuditLogs returns an error.
func TestGetPermissionChangeAudit_StorageError_500(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_perm_audit_err_")
	// Deliberately do NOT migrate AuditEvent — queries will fail.

	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/permission-changes", nil))
	w := httptest.NewRecorder()
	h.GetPermissionChangeAudit(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
