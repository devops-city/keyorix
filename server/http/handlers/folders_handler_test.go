// folders_handler_test.go — HTTP handler tests for FolderHandler.
//
// Covers:
//   - CreateFolder: happy path (201)
//   - CreateFolder: missing name → 400
//   - CreateFolder: missing project_id → 400
//   - ListFolders: happy path (200)
//   - ListFolders: invalid parent_id → 400
//   - DeleteFolder: happy path (204)
//   - DeleteFolder: invalid id → 400
//   - DeleteFolder: deleting a real secret returns 400 (not a folder)
package handlers

import (
	"bytes"
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

// freshFolderFixture creates an isolated in-memory SQLite DB with all required
// schema and seeds: user 1 as system_admin, project 1, environment 10.
// Returns the FolderHandler, core service, and raw DB.
func freshFolderFixture(t *testing.T) (*FolderHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxfolder_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.SecretVersion{}, &models.SecretAccessLog{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice-folder", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "system_admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-folder"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod-folder"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewFolderHandler(cs)
	return h, cs, db
}

// withFolderAdminCtx injects a UserContext for user 1 into the request.
func withFolderAdminCtx(r *http.Request) *http.Request {
	uc := &middleware.UserContext{
		UserID: 1, Username: "alice-folder",
		ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// ── CreateFolder ─────────────────────────────────────────────────────────────

func TestCreateFolder_HappyPath(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]any{
		"name":           "configs",
		"project_id":     1,
		"environment_id": 10,
	})
	r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestCreateFolder_MissingName(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]any{
		"project_id":     1,
		"environment_id": 10,
	})
	r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

func TestCreateFolder_MissingProjectID(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]any{
		"name":           "configs",
		"environment_id": 10,
	})
	r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id is required")
}

func TestCreateFolder_NoUserContext_401(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]any{
		"name": "configs", "project_id": 1, "environment_id": 10,
	})
	// No user context injected.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// withScopedWriterCtx injects a UserContext for a non-admin user with only
// secrets.write on a single project (no admin bypass) — the "caller
// authorized only on project A" persona used by the #G86 regression tests.
func withScopedWriterCtx(r *http.Request, userID uint, username string) *http.Request {
	uc := &middleware.UserContext{
		UserID: userID, Username: username,
		ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// seedScopedWriter creates user userID with a non-admin role granting
// secrets.write scoped ONLY to projectID (EnvironmentID: 0 = any environment
// within that project, per the established RBAC scoping convention — see
// TestListSecrets_ScopedUser_SingleProject in secrets_list_scoped_test.go).
func seedScopedWriter(t *testing.T, db *gorm.DB, userID uint, username string, projectID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: userID, Username: username, AccountState: "active"}).Error)
	role := mustCreateRole(t, db, username+"-writer")
	perm := mustCreatePermission(t, db, "secrets.write", "secrets", "write")
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: userID, RoleID: role.ID, ProjectID: projectID, EnvironmentID: 0,
	}).Error)
}

// TestCreateFolder_RefusesCrossProjectParent_HTTP is the #G86 regression: a
// caller authorized ONLY on project 1 (secrets.write, not admin) declares
// project_id=1 (their own, authorized scope) but points parent_id at a
// folder that actually lives in project 2 — a project they have no access
// to. Before the fix, CreateFolder happily nested the new project-1 folder
// under the foreign project-2 parent; folder-inheriting ACL/sharing
// resolution would then apply project 2's grants to it. Must be refused.
func TestCreateFolder_RefusesCrossProjectParent_HTTP(t *testing.T) {
	h, _, db := freshFolderFixture(t)

	// A second project the scoped writer has no access to, with a folder in it.
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "proj-foreign"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "env-foreign"}).Error)
	foreignFolder := &models.SecretNode{
		Name: "foreign-parent", ProjectID: 2, EnvironmentID: 20,
		IsSecret: false, Type: "folder", Status: "active",
		CreatedBy: "attacker", OwnerID: 99,
	}
	require.NoError(t, db.Create(foreignFolder).Error)

	seedScopedWriter(t, db, 2, "attacker", 1) // write access to project 1 ONLY

	body, _ := json.Marshal(map[string]any{
		"name":           "smuggled",
		"project_id":     1,
		"environment_id": 10,
		"parent_id":      foreignFolder.ID,
	})
	r := withScopedWriterCtx(
		httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)),
		2, "attacker",
	)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "same project")
}

// TestCreateFolder_ScopedWriter_SameProjectParent_Succeeds_HTTP is the
// legitimate-case companion to the above: the SAME scoped-to-project-1
// writer nests a new folder under a parent that also lives in project 1 —
// this must keep working after the #G86 fix.
func TestCreateFolder_ScopedWriter_SameProjectParent_Succeeds_HTTP(t *testing.T) {
	h, cs, db := freshFolderFixture(t)

	parent, err := cs.CreateFolder(context.Background(), 1, "legit-parent", 1, 10, nil)
	require.NoError(t, err)

	seedScopedWriter(t, db, 2, "legit-user", 1)

	body, _ := json.Marshal(map[string]any{
		"name":           "legit-child",
		"project_id":     1,
		"environment_id": 10,
		"parent_id":      parent.ID,
	})
	r := withScopedWriterCtx(
		httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)),
		2, "legit-user",
	)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

// ── ListFolders ──────────────────────────────────────────────────────────────

func TestListFolders_HappyPath(t *testing.T) {
	h, cs, _ := freshFolderFixture(t)

	// Create a couple of folders first.
	_, err := cs.CreateFolder(context.Background(), 1, "alpha", 1, 10, nil)
	require.NoError(t, err)
	_, err = cs.CreateFolder(context.Background(), 1, "beta", 1, 10, nil)
	require.NoError(t, err)

	r := withFolderAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/folders?project_id=1", nil))
	w := httptest.NewRecorder()
	h.ListFolders(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestListFolders_InvalidParentID(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	r := withFolderAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/folders?parent_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.ListFolders(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListFolders_NoUserContext_401(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/folders", nil)
	w := httptest.NewRecorder()
	h.ListFolders(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── DeleteFolder ─────────────────────────────────────────────────────────────

func TestDeleteFolder_HappyPath(t *testing.T) {
	h, cs, _ := freshFolderFixture(t)

	folder, err := cs.CreateFolder(context.Background(), 1, "to-delete", 1, 10, nil)
	require.NoError(t, err)

	r := withFolderAdminCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/folders/%d", folder.ID), nil),
		"id", fmt.Sprintf("%d", folder.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteFolder(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteFolder_InvalidID(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	r := withFolderAdminCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/folders/notanumber", nil),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.DeleteFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteFolder_IsSecret_Returns400(t *testing.T) {
	h, cs, _ := freshFolderFixture(t)

	// Create a real secret (IsSecret=true) and try to delete it as a folder.
	secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "real-secret", Value: []byte("val"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)

	r := withFolderAdminCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/folders/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "not a folder")
}
