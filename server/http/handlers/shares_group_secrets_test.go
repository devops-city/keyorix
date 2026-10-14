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
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestListGroupSharedSecretsHandler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.ShareRecord{}, &models.Group{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))

	// #G10: ListGroupSharedSecrets now self-authorizes (secrets.read, global scope);
	// withUserCtx's UserID 1 needs a real grant.
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)

	// Two secrets, both shared with group 7 — one live, one via an expired share.
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "alpha", IsSecret: true, OwnerID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, Name: "beta", IsSecret: true, OwnerID: 1}).Error)
	past := time.Now().Add(-1 * time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 7, IsGroup: true, Permission: "read"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{ID: 2, SecretID: 2, OwnerID: 1, RecipientID: 7, IsGroup: true, Permission: "read", ExpiresAt: &past}).Error)

	h, err := NewShareHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	t.Run("returns the live shared secret and excludes the expired share", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/7/shared-secrets", nil), "id", "7"))
		w := httptest.NewRecorder()
		h.ListGroupSharedSecrets(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		data := decodeData(t, w)
		secrets := data["secrets"].([]any)
		require.Len(t, secrets, 1, "only the live (non-expired) share surfaces")
		assert.Equal(t, "alpha", secrets[0].(map[string]any)["name"])
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/7/shared-secrets", nil), "id", "7")
		w := httptest.NewRecorder()
		h.ListGroupSharedSecrets(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("a group with no shares returns an empty list", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/99/shared-secrets", nil), "id", "99"))
		w := httptest.NewRecorder()
		h.ListGroupSharedSecrets(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, decodeData(t, w)["secrets"].([]any))
	})
}
