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

func newSnapshotHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Full schema: a posture sub-rollup that cannot be read degrades the posture,
	// and a degraded posture is never snapshotted (#2834).
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return db
}

// #2834: a degraded posture (here: the legal-hold table is gone) must NOT yield
// a success response or a persisted row; the response carries a reason.
func TestTakeComplianceSnapshot_HandlerDegradedFailsClosed_2834(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	require.NoError(t, db.Exec("DROP TABLE legal_holds").Error)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	w := httptest.NewRecorder()
	h.TakeComplianceSnapshot(w, httptest.NewRequest(http.MethodPost, "/api/v1/compliance/snapshots", nil))

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "legal_hold", "the response must say which area was unreadable")
	assert.NotContains(t, w.Body.String(), "no such table", "raw storage error text must not reach the client")
	var n int64
	require.NoError(t, db.Model(&models.CompliancePostureSnapshot{}).Count(&n).Error)
	assert.Zero(t, n, "no snapshot row may be persisted")
	var audits int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", core.EventComplianceSnapshotTaken).Count(&audits).Error)
	assert.Zero(t, audits, "no compliance.snapshot_taken event on a failed snapshot")
}

func TestTakeComplianceSnapshot_HandlerSuccess(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.TakeComplianceSnapshot(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			SnapshotDate string `json:"snapshot_date"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

func TestTakeComplianceSnapshot_HandlerError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	// Drop projects so GetCompliancePosture (first call inside TakeComplianceSnapshot) errors.
	require.NoError(t, db.Exec("DROP TABLE projects").Error)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.TakeComplianceSnapshot(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}

func TestListComplianceSnapshots_HandlerNoLimit(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    any  `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

func TestListComplianceSnapshots_HandlerWithLimit(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots?limit=2", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"success":true`)
}

func TestListComplianceSnapshots_HandlerInvalidLimitNegative(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots?limit=-1", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestListComplianceSnapshots_HandlerInvalidLimitNonNumeric(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots?limit=abc", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestListComplianceSnapshots_HandlerStorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	// Drop the snapshots table so the storage query errors.
	require.NoError(t, db.Exec("DROP TABLE compliance_posture_snapshots").Error)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}
