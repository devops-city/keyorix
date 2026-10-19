// secrets_list_cov_test.go — coverage top-up for secrets_list.go error and
// edge-case paths not reached by secrets_list_scoped_test.go or secrets_list_s38_test.go.
//
// Covers:
//   - Machine identity missing project_id → 400 (CWE-862 param gate)
//   - Scoped request ListSecretsWithSharingInfo error → 500
//   - GetReadableScopes error → 500
//   - Env-scoped role (EnvironmentID != 0) in the union loop
//   - Page beyond total results → start > totalInt clamp
//   - Zero secrets in union → totalPages == 0 → set to 1
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

func freshCovListFixture(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_cov_list_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.SecretACL{},
		&models.AuditEvent{},
		&models.SecretVersion{},
		&models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, db
}

func withMachineCtx(r *http.Request) *http.Request {
	machineID := uint(42)
	uc := &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machineID,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

func withCovUserCtx(r *http.Request, userID uint) *http.Request {
	uc := &middleware.UserContext{
		UserID:    userID,
		Username:  fmt.Sprintf("cov-user-%d", userID),
		ActorType: core.ActorTypeUser,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// TestListSecrets_MachineIdentity_NoProjectID verifies that a machine principal
// without an explicit ?project_id= query parameter receives 400 (CWE-862 gate).
// The DB does not need to be reachable for this check — it is a param-validation
// guard that runs before any storage call.
func TestListSecrets_MachineIdentity_NoProjectID(t *testing.T) {
	h, db := freshCovListFixture(t)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withMachineCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecrets_EnvironmentNameParamRejected is the #2012 inventory (finding
// S2) regression: `environment=<name>` was never a recognized filter on this
// endpoint (only the numeric environment_id is honored) but was silently
// ignored instead of rejected, letting a caller believe a listing was scoped
// by environment name when it was actually unscoped. It must now fail fast
// with 400, before any storage call (closed DB proves that — a fall-through
// to the storage layer here would error differently, not 400).
func TestListSecrets_EnvironmentNameParamRejected(t *testing.T) {
	h, db := freshCovListFixture(t)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withCovUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?environment=production", nil), 70)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "environment")
}

// TestListSecrets_ScopedRequest_ListError closes the DB so ListSecretsWithSharingInfo
// fails on the scoped path and the handler returns 500 (line 178–182).
func TestListSecrets_ScopedRequest_ListError(t *testing.T) {
	h, db := freshCovListFixture(t)

	// Seed a project so the project_id query param resolves (not strictly needed;
	// the scope check path is entered regardless of project existence).
	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "scoped-err-proj"}).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withCovUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?project_id=10", nil), 20)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListSecrets_GetReadableScopesError closes the DB so GetReadableScopes
// fails for a non-global user (AuthorizePrincipal also fails, making globalOK
// false and falling through to GetReadableScopes), returning 500 (line 207–211).
func TestListSecrets_GetReadableScopesError(t *testing.T) {
	h, db := freshCovListFixture(t)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	// No scope filter; non-machine user with no global role (both conditions
	// fall through to GetReadableScopes which fails with the closed DB).
	req := withCovUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 30)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListSecrets_EnvScopedRole_Union verifies that a user whose secrets.read
// grant is scoped to a specific environment (EnvironmentID != 0) triggers the
// env-scoped branch of the union loop (line 236–239) and returns their secrets.
func TestListSecrets_EnvScopedRole_Union(t *testing.T) {
	h, db := freshCovListFixture(t)

	proj := &models.Project{Name: "proj-env-scoped"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-env-scoped", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name: "env-scoped-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 50, Type: "static", IsSecret: true,
	}
	require.NoError(t, db.Create(secret).Error)

	// User 50: secrets.read scoped to (proj, env) — EnvironmentID != 0.
	require.NoError(t, db.Create(&models.User{ID: 50, Username: "env-scoped-user", AccountState: "active"}).Error)
	role := &models.Role{Name: "env_viewer"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 50, RoleID: role.ID, ProjectID: proj.ID, EnvironmentID: env.ID,
	}).Error)

	req := withCovUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 50)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.GreaterOrEqual(t, resp.Total, int64(1), "env-scoped user should see at least their scoped secret")
}

// TestListSecrets_PageBeyondTotal_Clamp verifies that requesting a page beyond
// the available results clamps start to totalInt (line 260–262) and sets
// totalPages to 1 when the union is empty (line 267–269).
func TestListSecrets_PageBeyondTotal_Clamp(t *testing.T) {
	h, db := freshCovListFixture(t)

	proj := &models.Project{Name: "proj-page-clamp"}
	require.NoError(t, db.Create(proj).Error)

	// User 60: project-scoped role but the project has no secrets → union is empty.
	require.NoError(t, db.Create(&models.User{ID: 60, Username: "page-clamp-user", AccountState: "active"}).Error)
	role := &models.Role{Name: "viewer_page_clamp"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	if err := db.Where("name = ?", "secrets.read").First(perm).Error; err != nil {
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 60, RoleID: role.ID, ProjectID: proj.ID, EnvironmentID: 0,
	}).Error)

	// page=2, page_size=1 → start = (2-1)*1 = 1. With 0 secrets, start > totalInt=0 → clamped.
	req := withCovUserCtx(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets?page=2&page_size=1", nil), 60)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(0), resp.Total)
	assert.Equal(t, 1, resp.TotalPages, "totalPages should be at least 1 even with 0 results")
}
