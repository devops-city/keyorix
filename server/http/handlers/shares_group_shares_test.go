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

// TestListGroupSharesHandler is the regression test for #G66: previously the
// only way to read a group's incoming share grants was the embedded/local CLI
// path, which silently ignored a connected server. This is now a real HTTP
// endpoint, self-authorizing via #G10's AuthorizePrincipal.
func TestListGroupSharesHandler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))

	// #G10: ListGroupShares self-authorizes (secrets.read, global scope);
	// withUserCtx's UserID 1 needs a real grant.
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "alpha", IsSecret: true, OwnerID: 1}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 7, IsGroup: true, Permission: "read"}).Error)

	h, err := NewShareHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	t.Run("returns the group's share grants", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/7/shares", nil), "id", "7"))
		w := httptest.NewRecorder()
		h.ListGroupShares(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		data := decodeData(t, w)
		shares := data["shares"].([]any)
		require.Len(t, shares, 1)
		share := shares[0].(map[string]any)
		assert.Equal(t, float64(1), share["secret_id"])
		assert.Equal(t, float64(7), share["recipient_id"])
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/7/shares", nil), "id", "7")
		w := httptest.NewRecorder()
		h.ListGroupShares(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects an invalid group id", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/not-a-number/shares", nil), "id", "not-a-number"))
		w := httptest.NewRecorder()
		h.ListGroupShares(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("a group with no shares returns an empty list", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/99/shares", nil), "id", "99"))
		w := httptest.NewRecorder()
		h.ListGroupShares(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, decodeData(t, w)["shares"].([]any))
	})
}

// TestListGroupSharesHandler_Unauthorized proves the endpoint refuses a caller
// with no secrets.read grant at all, not just an unauthenticated one.
func TestListGroupSharesHandler_Unauthorized(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))

	h, err := NewShareHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/groups/7/shares", nil), "id", "7"))
	w := httptest.NewRecorder()
	h.ListGroupShares(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
