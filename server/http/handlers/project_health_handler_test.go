// project_health_handler_test.go — unit tests for GetProjectHealth handler.
//
// Tests all branches in server/http/handlers/project_health.go:
//   - 401 when user context is absent
//   - 400 when the project ID is not a valid integer
//   - 400 when ?limit is present but not a positive integer
//   - 500 when the core service returns an error
//   - 200 on success (empty project)
package handlers

import (
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

func newProjectHealthHandler(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.SecretAccessLog{},
		&models.MachineIdentity{},
		&models.AuditEvent{},
		&models.RotationPolicy{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.UserGroup{},
	))
	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	return h, db
}

func TestGetProjectHealth_Unauthorized(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/health", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetProjectHealth_InvalidProjectID(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/abc/health", nil), "id", "abc")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestGetProjectHealth_InvalidLimit_NonInteger(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/health?limit=abc", nil),
		"id", "1",
	)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestGetProjectHealth_InvalidLimit_Zero(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/health?limit=0", nil),
		"id", "1",
	)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestGetProjectHealth_InvalidLimit_Negative(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/health?limit=-5", nil),
		"id", "1",
	)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectHealth_CoreError_InternalServerError(t *testing.T) {
	h, db := newProjectHealthHandler(t)

	// Close the underlying DB connection to force a core-layer error.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/health", nil),
		"id", "1",
	)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}

func TestGetProjectHealth_Success_EmptyProject(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/99/health", nil),
		"id", "99",
	)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "total_secrets")
}

func TestGetProjectHealth_Success_WithLimit(t *testing.T) {
	h, _ := newProjectHealthHandler(t)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/99/health?limit=5", nil),
		"id", "99",
	)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectHealth(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
