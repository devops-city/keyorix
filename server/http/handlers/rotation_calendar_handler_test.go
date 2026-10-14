// rotation_calendar_handler_test.go — HTTP handler tests for
// GET /api/v1/rotation-calendar.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func freshCalendarDB(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_cal_handler_")
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.RotationPolicy{},
	))
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func doCalendarGet(t *testing.T, svc *core.KeyorixCore, from, to string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	url := "/rotation-calendar"
	if from != "" || to != "" {
		url += "?from=" + from + "&to=" + to
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestRotationCalendarHandler_MissingParams(t *testing.T) {
	svc, _ := freshCalendarDB(t)
	// Both missing
	rr := doCalendarGet(t, svc, "", "")
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_MissingTo(t *testing.T) {
	svc, _ := freshCalendarDB(t)
	// to is empty: use raw request to avoid including to param
	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_InvalidFrom(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=not-a-date&to=2026-08-31", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_InvalidTo(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01&to=not-a-date", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_FromAfterTo(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-09-01&to=2026-07-01", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_StorageError(t *testing.T) {
	svc, db := freshCalendarDB(t)

	// Drop the rotation_policies table to force a storage error from GetRotationCalendar.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS rotation_policies").Error)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01&to=2026-08-31", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRotationCalendarHandler_EmptyResult(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	rr := doCalendarGet(t, svc, "2026-07-01", "2026-08-31")
	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.True(t, body["success"].(bool))
}

// Happy path with YYYY-MM-DD format and seeded data verifies JSON structure.
func TestRotationCalendarHandler_WithEntries(t *testing.T) {
	svc, db := freshCalendarDB(t)

	// Seed: project, environment, policy, secret
	proj := &models.Project{Name: "test-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	pol := &models.RotationPolicy{
		Name:          "30-day",
		Scope:         "environment",
		EnvironmentID: &env.ID,
		IntervalDays:  30,
		IsActive:      true,
	}
	require.NoError(t, db.Create(pol).Error)

	// LastRotatedAt = 2026-07-10 → next = 2026-08-09 (within window)
	lastRotated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	secret := &models.SecretNode{
		Name:          "api-key",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		LastRotatedAt: &lastRotated,
	}
	require.NoError(t, db.Create(secret).Error)

	rr := doCalendarGet(t, svc, "2026-07-01", "2026-08-31")
	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	data := body["data"].([]any)
	require.Len(t, data, 1)

	entry := data[0].(map[string]any)
	assert.Equal(t, "api-key", entry["secret_name"])
	assert.Equal(t, float64(30), entry["interval_days"])
	assert.NotEmpty(t, entry["next_rotation_at"])
}

// core-rotation-2026-08-08-003: an optional project_id query param confines the
// calendar to that project — a caller scoped to project A's secrets.read (see
// router.go's RequireScopedPermission(permSecretsRead, ScopeFromQuery) gate on
// this route) gets project A's rotation detail without needing the broader
// global grant, and never sees project B's secret in the response.
func TestRotationCalendarHandler_ScopedToProject(t *testing.T) {
	svc, db := freshCalendarDB(t)

	projA := &models.Project{Name: "project-a"}
	require.NoError(t, db.Create(projA).Error)
	envA := &models.Environment{Name: "prod", ProjectID: projA.ID}
	require.NoError(t, db.Create(envA).Error)
	polA := &models.RotationPolicy{Name: "30-day-a", Scope: "project", ProjectID: &projA.ID, IntervalDays: 30, IsActive: true}
	require.NoError(t, db.Create(polA).Error)

	projB := &models.Project{Name: "project-b"}
	require.NoError(t, db.Create(projB).Error)
	envB := &models.Environment{Name: "prod", ProjectID: projB.ID}
	require.NoError(t, db.Create(envB).Error)
	polB := &models.RotationPolicy{Name: "30-day-b", Scope: "project", ProjectID: &projB.ID, IntervalDays: 30, IsActive: true}
	require.NoError(t, db.Create(polB).Error)

	lastRotated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	secretA := &models.SecretNode{Name: "a-key", ProjectID: projA.ID, EnvironmentID: envA.ID, LastRotatedAt: &lastRotated}
	require.NoError(t, db.Create(secretA).Error)
	secretB := &models.SecretNode{Name: "b-key", ProjectID: projB.ID, EnvironmentID: envB.ID, LastRotatedAt: &lastRotated}
	require.NoError(t, db.Create(secretB).Error)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	url := fmt.Sprintf("/rotation-calendar?from=2026-07-01&to=2026-08-31&project_id=%d", projA.ID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	data := body["data"].([]any)
	require.Len(t, data, 1, "only project A's secret, never project B's")
	entry := data[0].(map[string]any)
	assert.Equal(t, "a-key", entry["secret_name"])
	assert.Equal(t, float64(projA.ID), entry["project_id"])
}

// An invalid project_id query param is rejected as a 400, not silently ignored.
func TestRotationCalendarHandler_InvalidProjectID(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01&to=2026-08-31&project_id=not-a-number", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// RFC 3339 timestamps are also accepted as from/to values.
func TestRotationCalendarHandler_RFC3339Format(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	from := "2026-07-01T00:00:00Z"
	to := "2026-08-31T23:59:59Z"
	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from="+from+"&to="+to, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}
