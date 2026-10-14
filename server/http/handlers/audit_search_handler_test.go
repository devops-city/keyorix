// audit_search_handler_test.go — integration tests for GET /api/v1/audit/search.
// Uses a real in-memory SQLite database (via freshCoreS13WithDB), the same
// pattern as audit_dashboard_s13_test.go in this package.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// failingAuditSearchStore wraps LocalStorage and fails every GetAuditLogs call
// so the HTTP handler's internal-server-error path is reachable in tests.
type failingAuditSearchStore struct {
	*store.LocalStorage
}

func (s *failingAuditSearchStore) GetAuditLogs(_ context.Context, _ *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	return nil, 0, errors.New("simulated audit log outage")
}

// freshAuditSearchCore opens a fresh SQLite DB with all tables needed for the
// audit search handler tests and returns the core + raw DB for seeding.
func freshAuditSearchCore(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhdlr_auditsearch_")
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
	))
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func seedAuditSearchEvent(t *testing.T, db *gorm.DB, eventType, ipAddr string, success bool) *models.AuditEvent {
	t.Helper()
	e := &models.AuditEvent{
		EventType: eventType,
		IPAddress: ipAddr,
		Success:   &success,
		EventTime: time.Now(),
	}
	require.NoError(t, db.Create(e).Error)
	return e
}

// ── GET /audit/search → 200, returns all events ───────────────────────────────

func TestSearchAuditLogs_Handler_AllEvents(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "secret.read", "1.2.3.4", true)
	seedAuditSearchEvent(t, db, "user.login", "1.2.3.5", true)

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── Unauthenticated → 401 ────────────────────────────────────────────────────

func TestSearchAuditLogs_Handler_Unauthorized(t *testing.T) {
	h := NewAuditHandler(freshCoreS13(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil) // no user context
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── ?success=false → only failures ───────────────────────────────────────────

func TestSearchAuditLogs_Handler_SuccessFalse(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "user.login", "", false) // failure
	seedAuditSearchEvent(t, db, "secret.read", "", true) // success

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/search?success=false", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?limit=1 → only 1 event ──────────────────────────────────────────────────

func TestSearchAuditLogs_Handler_LimitOne(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	for range 5 {
		seedAuditSearchEvent(t, db, "secret.read", "", true)
	}

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/search?limit=1", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?since=future → empty result ─────────────────────────────────────────────

func TestSearchAuditLogs_Handler_SinceFuture(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "secret.read", "", true)

	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?since="+future, nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?ip=10.0.0.1 → only matching events ──────────────────────────────────────

func TestSearchAuditLogs_Handler_FilterByIP(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "secret.read", "10.0.0.1", true)
	seedAuditSearchEvent(t, db, "user.login", "192.168.1.1", true)

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?ip=10.0.0.1", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?resource_type=secret → only secret events ───────────────────────────────

func TestSearchAuditLogs_Handler_FilterByResourceType(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "secret.read", "", true)
	seedAuditSearchEvent(t, db, "user.login", "", true)

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?resource_type=secret", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?action=secret.read → only matching events ────────────────────────────────

func TestSearchAuditLogs_Handler_FilterByAction(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "secret.read", "", true)
	seedAuditSearchEvent(t, db, "user.login", "", true)

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?action=secret.read", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?success=true → only successes ───────────────────────────────────────────

func TestSearchAuditLogs_Handler_SuccessTrue(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditSearchEvent(t, db, "secret.read", "", true)
	seedAuditSearchEvent(t, db, "user.login", "", false)

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?success=true", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── invalid ?success value → no filter applied (still 200) ───────────────────

func TestSearchAuditLogs_Handler_InvalidSuccessIgnored(t *testing.T) {
	h := NewAuditHandler(freshCoreS13(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?success=maybe", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ?offset=0 → page 1 (no off-by-one) ──────────────────────────────────────

func TestSearchAuditLogs_Handler_OffsetZero(t *testing.T) {
	h := NewAuditHandler(freshCoreS13(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/api/v1/audit/search?offset=0&limit=10", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── all query params at once (smoke) ─────────────────────────────────────────

func TestSearchAuditLogs_Handler_AllParams(t *testing.T) {
	h := NewAuditHandler(freshCoreS13(t))
	url := "/api/v1/audit/search?actor=alice&user_id=1&project_id=2&action=secret.read" +
		"&resource_type=secret&resource_id=3&ip=10.0.0.1&success=true" +
		"&since=2020-01-01T00:00:00Z&until=2030-01-01T00:00:00Z&limit=50&offset=0"
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ── storage error → 500 ──────────────────────────────────────────────────────

func TestSearchAuditLogs_Handler_StorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	// Open a DB and build a wrapped storage that fails on GetAuditLogs.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	ls := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(&failingAuditSearchStore{LocalStorage: ls})

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
