// secrets_list_scoped_test.go — tests for the scoped-union ListSecrets behaviour.
//
// Covers:
//   - Non-global user with project-scope returns that project's secrets (not 403)
//   - Non-global user with multiple project scopes returns the union
//   - Non-global user with no secrets.read permission returns empty list (not 403)
//   - Specific-scope request returns 403 for unauthorized scopes
//   - Global reader still works normally
package handlers

import (
	"context"
	"encoding/json"
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

// ── DB counter ────────────────────────────────────────────────────────────────

// ── DB / fixture helpers ──────────────────────────────────────────────────────

// freshScopedListFixture opens an isolated named in-memory SQLite DB with all
// models needed by the ListSecrets handler and the RBAC layer.  It returns the
// handler and the raw *gorm.DB so each test can seed its own users, roles, and
// secrets independently.
func freshScopedListFixture(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_scoped_list_")
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

// seedReadRole creates a Role named roleName with the secrets.read permission
// and returns the role ID.  If the permission row already exists it reuses it.
func seedReadRole(t *testing.T, db *gorm.DB, roleName string) uint {
	t.Helper()
	role := &models.Role{Name: roleName}
	require.NoError(t, db.Create(role).Error)

	perm := &models.Permission{}
	err := db.Where("name = ?", "secrets.read").First(perm).Error
	if err != nil { // create if not yet seeded
		perm = &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	return role.ID
}

// withUserCtxID2 builds a request UserContext for the given userID/username —
// helper so each test can inject non-admin principals.
func withUserCtxID2(r *http.Request, userID uint, username string) *http.Request {
	uc := &middleware.UserContext{
		UserID:    userID,
		Username:  username,
		ActorType: core.ActorTypeUser,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// decodeListResponse decodes a SuccessResponse whose Data is a SecretListResponse.
func decodeListResponse(t *testing.T, body []byte) *models.SecretListResponse {
	t.Helper()
	var wrapper struct {
		Success bool                       `json:"success"`
		Data    *models.SecretListResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &wrapper))
	require.NotNil(t, wrapper.Data, "response.Data must not be nil")
	return wrapper.Data
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestListSecrets_ScopedUser_SingleProject verifies that a user with a
// project-scoped secrets.read role gets that project's secrets (not 403).
func TestListSecrets_ScopedUser_SingleProject(t *testing.T) {
	h, db := freshScopedListFixture(t)

	// Seed project + environment + one secret.
	proj := &models.Project{Name: "proj-a"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-a", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name: "my-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 2, Type: "static",
	}
	require.NoError(t, db.Create(secret).Error)

	// Seed user 2 with secrets.read scoped to proj.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "scoped-user", AccountState: "active"}).Error)
	roleID := seedReadRole(t, db, "project_viewer_scoped")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 2, RoleID: roleID, ProjectID: proj.ID, EnvironmentID: 0,
	}).Error)

	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 2, "scoped-user")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(1), resp.Total, "expected 1 secret for the project-scoped user")
	assert.Equal(t, "my-secret", resp.Secrets[0].Name)
}

// TestListSecrets_ScopedUser_MultiProject verifies that a user with secrets.read
// in two projects receives the union of both projects' secrets.
func TestListSecrets_ScopedUser_MultiProject(t *testing.T) {
	h, db := freshScopedListFixture(t)

	// Seed two projects, each with one secret.
	proj1 := &models.Project{Name: "proj-m1"}
	require.NoError(t, db.Create(proj1).Error)
	env1 := &models.Environment{Name: "env-m1", ProjectID: proj1.ID}
	require.NoError(t, db.Create(env1).Error)
	secret1 := &models.SecretNode{
		Name: "secret-in-proj1", ProjectID: proj1.ID, EnvironmentID: env1.ID,
		OwnerID: 3, Type: "static",
	}
	require.NoError(t, db.Create(secret1).Error)

	proj2 := &models.Project{Name: "proj-m2"}
	require.NoError(t, db.Create(proj2).Error)
	env2 := &models.Environment{Name: "env-m2", ProjectID: proj2.ID}
	require.NoError(t, db.Create(env2).Error)
	secret2 := &models.SecretNode{
		Name: "secret-in-proj2", ProjectID: proj2.ID, EnvironmentID: env2.ID,
		OwnerID: 3, Type: "static",
	}
	require.NoError(t, db.Create(secret2).Error)

	// User 3: secrets.read in proj1 and proj2.
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "two-proj-user", AccountState: "active"}).Error)
	roleID := seedReadRole(t, db, "viewer_multi")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 3, RoleID: roleID, ProjectID: proj1.ID, EnvironmentID: 0,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 3, RoleID: roleID, ProjectID: proj2.ID, EnvironmentID: 0,
	}).Error)

	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 3, "two-proj-user")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(2), resp.Total, "expected 2 secrets across both projects")
	names := make(map[string]bool)
	for _, s := range resp.Secrets {
		names[s.Name] = true
	}
	assert.True(t, names["secret-in-proj1"], "expected secret from proj1")
	assert.True(t, names["secret-in-proj2"], "expected secret from proj2")
}

// TestListSecrets_NoSecretsReadPerm_ReturnsEmpty verifies that a user with
// NO secrets.read permission at all gets an empty list (not 403).
func TestListSecrets_NoSecretsReadPerm_ReturnsEmpty(t *testing.T) {
	h, db := freshScopedListFixture(t)

	// Seed a project + secret, but give user 4 no RBAC grants at all.
	proj := &models.Project{Name: "proj-no-perm"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-no-perm", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "hidden-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 5, Type: "static",
	}).Error)

	require.NoError(t, db.Create(&models.User{ID: 4, Username: "no-perm-user", AccountState: "active"}).Error)

	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 4, "no-perm-user")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code, "expected 200, not 403")
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(0), resp.Total, "expected empty list for user with no permissions")
}

// TestListSecrets_ScopedUser_NoAccessProject_ReturnsEmpty verifies that a
// project-scoped user gets an empty list (not 403) when they explicitly
// request a project they have no role or ACL grants in.  The scoped-list
// endpoint never returns 403 — it returns what the caller can access.
func TestListSecrets_ScopedUser_NoAccessProject_ReturnsEmpty(t *testing.T) {
	h, db := freshScopedListFixture(t)

	// Seed two projects; user 5 has read on proj1 only.
	proj1 := &models.Project{Name: "proj-allowed"}
	require.NoError(t, db.Create(proj1).Error)
	proj2 := &models.Project{Name: "proj-no-access"}
	require.NoError(t, db.Create(proj2).Error)

	require.NoError(t, db.Create(&models.User{ID: 5, Username: "partial-user", AccountState: "active"}).Error)
	roleID := seedReadRole(t, db, "viewer_partial")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 5, RoleID: roleID, ProjectID: proj1.ID, EnvironmentID: 0,
	}).Error)

	// Request secrets from the project where the user has no access.
	url := fmt.Sprintf("/api/v1/secrets?project_id=%d", proj2.ID)
	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, url, nil), 5, "partial-user")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code, "scoped listing should return 200+empty, not 403")
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(0), resp.Total, "expected empty list for project with no access")
}

// TestListSecrets_ACLOnly_ScopedRequest verifies that a user with no project
// role but a per-secret ACL grant in a project gets their granted secrets
// when filtering by that project_id (not a 403 or empty list).
func TestListSecrets_ACLOnly_ScopedRequest(t *testing.T) {
	h, db := freshScopedListFixture(t)

	proj := &models.Project{Name: "proj-acl-scoped"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-acl-scoped", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	// Two secrets in the project; user 8 gets an ACL grant only on secret1.
	secret1 := &models.SecretNode{
		Name: "acl-secret-1", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 99, Type: "static", IsSecret: true,
	}
	require.NoError(t, db.Create(secret1).Error)
	secret2 := &models.SecretNode{
		Name: "acl-secret-2", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 99, Type: "static", IsSecret: true,
	}
	require.NoError(t, db.Create(secret2).Error)

	require.NoError(t, db.Create(&models.User{ID: 8, Username: "acl-only-user", AccountState: "active"}).Error)
	// No UserRole — ACL grant only.
	require.NoError(t, db.Create(&models.SecretACL{
		SecretID:    secret1.ID,
		UserID:      8,
		Permissions: `["secrets.read"]`,
		GrantedBy:   99,
	}).Error)

	url := fmt.Sprintf("/api/v1/secrets?project_id=%d", proj.ID)
	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, url, nil), 8, "acl-only-user")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code, "ACL-only user should get 200, not 403")
	resp := decodeListResponse(t, w.Body.Bytes())
	require.Equal(t, int64(1), resp.Total, "expected exactly the ACL-granted secret")
	assert.Equal(t, "acl-secret-1", resp.Secrets[0].Name)
}

// TestListSecrets_ACLOnly_UnfilteredRequest verifies that a user with no
// project role but per-secret ACL grants gets those secrets on an unfiltered
// GET /secrets (not an empty list).
func TestListSecrets_ACLOnly_UnfilteredRequest(t *testing.T) {
	h, db := freshScopedListFixture(t)

	proj := &models.Project{Name: "proj-acl-unfiltered"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-acl-unfiltered", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	secret := &models.SecretNode{
		Name: "acl-unfiltered-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 99, Type: "static", IsSecret: true,
	}
	require.NoError(t, db.Create(secret).Error)

	require.NoError(t, db.Create(&models.User{ID: 9, Username: "acl-only-user-2", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.SecretACL{
		SecretID:    secret.ID,
		UserID:      9,
		Permissions: `["secrets.read"]`,
		GrantedBy:   99,
	}).Error)

	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 9, "acl-only-user-2")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	require.Equal(t, int64(1), resp.Total, "expected the ACL-granted secret to appear on unfiltered list")
	assert.Equal(t, "acl-unfiltered-secret", resp.Secrets[0].Name)
}

// TestListSecrets_GlobalReader_StillWorks verifies that a user with a global
// secrets.read role continues to see all secrets as before.
func TestListSecrets_GlobalReader_StillWorks(t *testing.T) {
	h, db := freshScopedListFixture(t)

	proj := &models.Project{Name: "proj-global"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-global", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "global-visible-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 6, Type: "static",
	}).Error)

	// User 6: secrets.read globally (ProjectID=0, EnvironmentID=0).
	require.NoError(t, db.Create(&models.User{ID: 6, Username: "global-reader", AccountState: "active"}).Error)
	roleID := seedReadRole(t, db, "global_reader_role")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 6, RoleID: roleID, ProjectID: 0, EnvironmentID: 0,
	}).Error)

	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), 6, "global-reader")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.GreaterOrEqual(t, resp.Total, int64(1), "global reader should see at least the seeded secret")
}

// TestListSecrets_NoUserContext_Unauthorized verifies 401 when there is no
// user context in the request.
func TestListSecrets_NoUserContext_Unauthorized(t *testing.T) {
	h, _ := freshScopedListFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSecrets_ScopedUser_AllowedSpecificScope verifies that a project-scoped
// user may explicitly filter to the project they are authorized for.
func TestListSecrets_ScopedUser_AllowedSpecificScope(t *testing.T) {
	h, db := freshScopedListFixture(t)

	proj := &models.Project{Name: "proj-allowed-specific"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-allowed-specific", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name: "allowed-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 7, Type: "static",
	}
	require.NoError(t, db.Create(secret).Error)

	require.NoError(t, db.Create(&models.User{ID: 7, Username: "scoped-user-2", AccountState: "active"}).Error)
	roleID := seedReadRole(t, db, "viewer_specific")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 7, RoleID: roleID, ProjectID: proj.ID, EnvironmentID: 0,
	}).Error)

	url := fmt.Sprintf("/api/v1/secrets?project_id=%d", proj.ID)
	req := withUserCtxID2(httptest.NewRequest(http.MethodGet, url, nil), 7, "scoped-user-2")
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.Equal(t, int64(1), resp.Total)
	assert.Equal(t, "allowed-secret", resp.Secrets[0].Name)
}
