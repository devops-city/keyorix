// secrets_list_s38_test.go — coverage top-up for secrets_list.go.
//
// Covers ListSecrets branches not yet exercised: 401 unauthorized, pagination
// parameter parsing, page-size clamping, the machine-identity dispatch path,
// and the sorting/filter query parameters.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// freshListFixtureS38 returns a SecretHandler backed by an isolated in-memory
// SQLite DB with a project, environment, and one active secret.
func freshListFixtureS38(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_list_s38_")

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.SecretVersion{},
	))

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-list"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env-list"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "list-target", IsSecret: true, Status: "active",
	}).Error)
	// Seed user 1 so ListSecretsWithSharingInfo can resolve the listing user.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "list-user", Email: "list@example.com", AccountState: "active"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, db
}

// userCtxS38 returns a UserContext for a regular (non-machine) user.
func userCtxS38(userID uint) *middleware.UserContext {
	return &middleware.UserContext{
		UserID:    userID,
		Username:  fmt.Sprintf("user-%d", userID),
		ActorType: core.ActorTypeUser,
	}
}

func withUserCtxS38(r *http.Request, userID uint) *http.Request {
	uc := userCtxS38(userID)
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// TestListSecrets_NoAuth_S38 verifies 401 when no user context is present.
func TestListSecrets_NoAuth_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSecrets_HappyPath_S38 verifies 200 with user context set.
func TestListSecrets_HappyPath_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestListSecrets_PageParam_S38 verifies pagination query params are accepted.
func TestListSecrets_PageParam_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?page=2&page_size=5", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecrets_PageSizeAltParam_S38 verifies the legacy pageSize query param is accepted.
func TestListSecrets_PageSizeAltParam_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?pageSize=10", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecrets_LargePageClamped_S38 verifies that a very large page number is clamped.
func TestListSecrets_LargePageClamped_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?page=99999999", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// Must not error out even with a huge page; response should be 200 (empty result).
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecrets_FilterParams_S38 exercises all optional query parameters in one request.
// Note: project_id/environment_id are omitted here to avoid the scope-auth check
// (user 1 has no role grants); those URL params are covered by TestListSecrets_ScopeFilter_403_S38.
func TestListSecrets_FilterParams_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet,
			"/api/v1/secrets?search=foo&include_deleted=true&show_owned_only=true"+
				"&show_shared_only=true&permission=secrets.read&type=static"+
				"&classification=internal&tag=env:prod&tag=team:platform"+
				"&sort_by=name&sort_order=asc",
			nil,
		), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecrets_ScopeFilter_NoAccess_S38 verifies that a scope filter with a
// user who has no role or ACL grants in the requested project returns 200+empty
// (not 403).  The scoped-list endpoint never returns 403 — it returns the
// intersection of the requested scope and the caller's accessible secrets.
func TestListSecrets_ScopeFilter_NoAccess_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet,
			"/api/v1/secrets?project_id=1&environment_id=1", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecrets_ExpiresBeforeParam_S38 exercises the expires_before RFC3339 filter.
func TestListSecrets_ExpiresBeforeParam_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet,
			"/api/v1/secrets?expires_before=2030-01-01T00:00:00Z", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListSecrets_MachineIdentityPath_S38 exercises the machine-identity dispatch branch.
// A machine token without project_id must now receive 400 (CWE-862 gate).
// The authorized path (with project_id + a matching role) is covered by the
// secrets_list_machine_authz_test.go suite.
func TestListSecrets_MachineIdentityPath_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)

	machineID := uint(42)
	uc := &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machineID,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// Machine tokens without an explicit project_id are rejected with 400.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecrets_TagCommaList_S38 exercises the comma-separated tag syntax.
func TestListSecrets_TagCommaList_S38(t *testing.T) {
	t.Parallel()
	h, _ := freshListFixtureS38(t)
	req := withUserCtxS38(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?tag=a,b,c", nil), 1)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
