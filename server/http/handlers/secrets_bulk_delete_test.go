// secrets_bulk_delete_test.go — unit tests for the BulkDeleteSecrets handler.
// These tests run at the handlers package level (no full router) so they cover
// every branch in the handler directly without integration overhead.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// setupBulkDeleteHandler returns a SecretHandler backed by an in-memory SQLite
// DB that already contains project 1, environment 1, and optionally one secret
// (ID 10, name "alpha", project 1).
func setupBulkDeleteHandler(t *testing.T) (*SecretHandler, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Project{},
		&models.Environment{},
		&models.AuditEvent{},
		&models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "env", ProjectID: 1}).Error)

	secretID := uint(10)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: secretID, Name: "alpha", ProjectID: 1, EnvironmentID: 1,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(c)
	require.NoError(t, err)
	return h, secretID
}

// bulkDeleteRequest constructs an httptest.Request for BulkDeleteSecrets, wiring
// the chi route parameter {id} to projectIDStr and setting a valid user context.
func bulkDeleteRequest(method, projectIDStr, body string) *http.Request {
	req := httptest.NewRequest(method, "/api/v1/projects/"+projectIDStr+"/secrets/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withChiParam(withUserCtx(req), "id", projectIDStr)
	return req
}

func TestBulkDeleteSecretsHandler_Success(t *testing.T) {
	h, secretID := setupBulkDeleteHandler(t)

	body := `{"secret_ids":[10]}`
	req := bulkDeleteRequest(http.MethodPost, "1", body)
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := w.Body.String()
	assert.Contains(t, resp, `"deleted"`)
	_ = secretID
}

func TestBulkDeleteSecretsHandler_Unauthorized(t *testing.T) {
	h, _ := setupBulkDeleteHandler(t)

	// No user context — withUserCtx is NOT applied.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-delete",
		strings.NewReader(`{"secret_ids":[10]}`))
	req = withChiParam(req, "id", "1")
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBulkDeleteSecretsHandler_InvalidProjectID(t *testing.T) {
	h, _ := setupBulkDeleteHandler(t)

	// Project ID that overflows uint32 triggers the ParseUint error path.
	req := bulkDeleteRequest(http.MethodPost, "99999999999999999999", `{"secret_ids":[1]}`)
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkDeleteSecretsHandler_BadJSON(t *testing.T) {
	h, _ := setupBulkDeleteHandler(t)

	req := bulkDeleteRequest(http.MethodPost, "1", "not-valid-json")
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBulkDeleteSecretsHandler_RequiredError tests the "required" → 400 branch:
// when BulkDeleteSecrets returns an error containing "required" (empty IDs list),
// the handler must respond with 400 rather than 500.
func TestBulkDeleteSecretsHandler_RequiredError(t *testing.T) {
	h, _ := setupBulkDeleteHandler(t)

	// An empty secret_ids slice triggers "at least one secret ID is required".
	req := bulkDeleteRequest(http.MethodPost, "1", `{"secret_ids":[]}`)
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "required")
}

func TestBulkDeleteSecretsHandler_PartialSuccess(t *testing.T) {
	h, secretID := setupBulkDeleteHandler(t)

	// Include one valid ID and one that does not exist.
	body := `{"secret_ids":[10,99999]}`
	req := bulkDeleteRequest(http.MethodPost, "1", body)
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := w.Body.String()
	assert.Contains(t, resp, `"deleted"`)
	assert.Contains(t, resp, `"failed"`)
	_ = secretID
}

func TestBulkDeleteSecretsHandler_NonExistentOnly(t *testing.T) {
	h, _ := setupBulkDeleteHandler(t)

	req := bulkDeleteRequest(http.MethodPost, "1", `{"secret_ids":[888888]}`)
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	// A missing secret is a partial-success (200 with failed list), not a 4xx.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"failed"`)
}
