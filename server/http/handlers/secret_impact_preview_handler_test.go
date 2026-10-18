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
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newImpactPreviewHandlerCore sets up a minimal in-memory core with one secret
// and one dependent (so the happy-path response is non-trivial).
func newImpactPreviewHandlerCore(t *testing.T) (*core.KeyorixCore, uint) {
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

	root := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "root-secret", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(root).Error)
	dep := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "dep-secret", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(dep).Error)
	// dep depends on root — so root's impact preview shows 1 direct dependent.
	require.NoError(t, db.Create(&models.SecretDependency{
		ProjectID:         1,
		DependentSecretID: dep.ID,
		DependsOnSecretID: root.ID,
	}).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db)), root.ID
}

// TestGetSecretImpactPreview_Unauthenticated: requests without a user context
// receive 401.
func TestGetSecretImpactPreview_Unauthenticated(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretImpactPreview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetSecretImpactPreview_BadID: a non-numeric path param returns 400.
func TestGetSecretImpactPreview_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "not-a-number"))
	w := httptest.NewRecorder()
	h.GetSecretImpactPreview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetSecretImpactPreview_NotFound: a non-existent secret ID returns 404.
func TestGetSecretImpactPreview_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "99999"))
	w := httptest.NewRecorder()
	h.GetSecretImpactPreview(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetSecretImpactPreview_HappyPath: a real secret with one direct dependent
// returns 200 and the expected JSON fields.
func TestGetSecretImpactPreview_HappyPath(t *testing.T) {
	c, secretID := newImpactPreviewHandlerCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id",
		fmt.Sprintf("%d", secretID),
	))
	w := httptest.NewRecorder()
	h.GetSecretImpactPreview(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"direct_dependents":1`)
	assert.Contains(t, body, `"transitive_dependents":1`)
	assert.Contains(t, body, `"max_depth":1`)
	assert.Contains(t, body, `"affected_secret_ids"`)
}
