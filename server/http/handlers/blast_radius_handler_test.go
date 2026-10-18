package handlers

import (
	"fmt"
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

// newBlastRadiusHandlerCore creates a minimal isolated core with a seeded
// project, environment, and one secret node so the blast-radius handler can
// return a successful 200 response.
func newBlastRadiusHandlerCore(t *testing.T) (*core.KeyorixCore, uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretDependency{},
		&models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "my-secret", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), s.ID
}

// TestGetBlastRadius_Unauthenticated verifies that the handler rejects requests
// without an authenticated user context with 401.
func TestGetBlastRadius_Unauthenticated(t *testing.T) {
	h := newSecretHandlerS4(t)
	// No withUserCtx — simulates an unauthenticated request.
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetBlastRadius_BadID verifies that a non-numeric ID returns 400.
func TestGetBlastRadius_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "not-a-number"))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetBlastRadius_NotFound verifies that looking up a non-existent secret
// returns a non-200 status and not 401 (the handler's core is hit).
func TestGetBlastRadius_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "99999"))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	// Secret does not exist → core returns "not found" → HTTP 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetBlastRadius_StorageError_G50 proves that a raw storage/DB error from
// ListSecretDependenciesForProject (e.g. a broken secret_dependencies table)
// never reaches the client — only clientSafe()'s generic message, matching
// the file's/package's sanitization convention.
func TestGetBlastRadius_StorageError_G50(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretDependency{},
		&models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "my-secret-2", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)

	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_dependencies").Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id",
		fmt.Sprintf("%d", s.ID),
	))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "secret_dependencies")
	assert.NotContains(t, w.Body.String(), "no such table")
	assert.Contains(t, w.Body.String(), "an internal error occurred")
}

// TestGetBlastRadius_HappyPath verifies that a real secret with zero dependents
// returns 200 and the expected JSON envelope.
func TestGetBlastRadius_HappyPath(t *testing.T) {
	c, secretID := newBlastRadiusHandlerCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id",
		fmt.Sprintf("%d", secretID),
	))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "total_impact")
	assert.Contains(t, body, "my-secret")
}
