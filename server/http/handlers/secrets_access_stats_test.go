package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestGetSecretAccessStatsHandler(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.SecretAccessLog{}, &models.Role{}, &models.UserRole{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: 1, VersionNumber: 1, ReadCount: 4}).Error)
	require.NoError(t, db.Create(&models.SecretAccessLog{
		SecretNodeID: 1, AccessedBy: "owner", Action: "read", AccessTime: time.Now().Add(-1 * time.Hour),
	}).Error)

	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	t.Run("returns the secret's read statistics", func(t *testing.T) {
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/stats", nil)), "id", "1")
		w := httptest.NewRecorder()
		h.GetSecretAccessStats(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `"total_reads":1`, "access-log reads, not the version max_reads counter (4)")
		assert.Contains(t, body, `"reads_in_window":1`)
		assert.Contains(t, body, `"unique_readers":1`)
		assert.Contains(t, body, `"window_days":30`)
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/stats", nil), "id", "1")
		w := httptest.NewRecorder()
		h.GetSecretAccessStats(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
