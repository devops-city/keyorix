package handlers

import (
	"database/sql"
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

func newReadQuotaHandlers(t *testing.T) (*AdminJobsHandler, *SecretHandler) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.Notification{},
	))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	sh, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return NewAdminJobsHandler(cs), sh
}

func TestRunReadQuotaCheck_HappyPath(t *testing.T) {
	ajh, _ := newReadQuotaHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/admin/jobs/check-read-quotas", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	ajh.RunReadQuotaCheck(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.EqualValues(t, 0, d["warnings"])
	assert.EqualValues(t, 0, d["criticals"])
	assert.EqualValues(t, 0, d["exhausted"])
	assert.EqualValues(t, 0, d["checked"])
}

func TestRunReadQuotaCheck_Unauthorized(t *testing.T) {
	ajh, _ := newReadQuotaHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/admin/jobs/check-read-quotas", nil)
	w := httptest.NewRecorder()
	ajh.RunReadQuotaCheck(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetQuotaReport_EmptyState(t *testing.T) {
	_, sh := newReadQuotaHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/quota-report", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	sh.GetQuotaReport(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	secrets, ok := d["secrets"]
	require.True(t, ok)
	// May be nil or empty slice — both acceptable for empty state.
	switch v := secrets.(type) {
	case nil:
		// ok
	case []any:
		assert.Empty(t, v)
	}
}

func TestGetQuotaReport_Unauthorized(t *testing.T) {
	_, sh := newReadQuotaHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/quota-report", nil)
	w := httptest.NewRecorder()
	sh.GetQuotaReport(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetQuotaReport_WithQuotaSecrets(t *testing.T) {
	_, sh := newReadQuotaHandlers(t)

	// Seed a secret directly via the DB through the handler's core service.
	// We do this by calling the underlying handler's coreService indirectly —
	// use a fresh DB+core with a seeded secret.
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.Notification{},
	))

	maxR := 10
	secret := models.SecretNode{
		Name:      "test-quota",
		IsSecret:  true,
		MaxReads:  &maxR,
		ReadCount: 8,
		OwnerID:   1,
	}
	require.NoError(t, db.Create(&secret).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	seededHandler, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/quota-report", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	seededHandler.GetQuotaReport(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	secrets, ok := d["secrets"].([]any)
	require.True(t, ok)
	require.Len(t, secrets, 1)

	row := secrets[0].(map[string]any)
	assert.Equal(t, "test-quota", row["secret_name"])
	assert.EqualValues(t, 80, row["usage_pct"])
	assert.Equal(t, "warning", row["status"])
	_ = sh // unused but avoids test-only import
}

// newBrokenQuotaHandlers creates handlers backed by a DB whose connection is
// immediately closed so that every storage call returns an error — used to
// exercise the internal error paths in RunReadQuotaCheck and GetQuotaReport.
func newBrokenQuotaHandlers(t *testing.T) (*AdminJobsHandler, *SecretHandler) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.Notification{},
	))
	// Close the underlying connection so every subsequent DB call fails.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	sh, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return NewAdminJobsHandler(cs), sh
}

func TestRunReadQuotaCheck_StorageError(t *testing.T) {
	ajh, _ := newBrokenQuotaHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/admin/jobs/check-read-quotas", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	ajh.RunReadQuotaCheck(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetQuotaReport_StorageError(t *testing.T) {
	_, sh := newBrokenQuotaHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/quota-report", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	sh.GetQuotaReport(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Ensure the import of database/sql is used.
var _ = (*sql.DB)(nil)

func TestQuotaStatus_Labels(t *testing.T) {
	assert.Equal(t, "ok", quotaStatus(0))
	assert.Equal(t, "ok", quotaStatus(79))
	assert.Equal(t, "warning", quotaStatus(80))
	assert.Equal(t, "warning", quotaStatus(94))
	assert.Equal(t, "critical", quotaStatus(95))
	assert.Equal(t, "critical", quotaStatus(99))
	assert.Equal(t, "exhausted", quotaStatus(100))
}
