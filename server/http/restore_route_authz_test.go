package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Regression (#147 HIGH): POST /api/v1/groups/{id}/restore reinstates every role
// grant the group carried at deletion — the same blast radius as a role grant —
// so it must require roles.assign, not the group-wide users.write. Previously a
// users.write holder (without roles.assign) could restore a soft-deleted,
// admin-conferring group and get their own admin access back.
func TestRestoreGroupRouteRequiresRolesAssign(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	ctx := context.Background()

	db := sqlitetest.OpenWithDialector(t, "restoregroupauthz_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "usermgr", Email: "u@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "usermgr"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.write", Resource: "users", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "admin-tok")
	seedSession(t, db, 2, "usermgr-tok")

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	g, err := c.CreateGroup(ctx, 1, &core.CreateGroupRequest{Name: "ops"})
	require.NoError(t, err)
	require.NoError(t, c.DeleteGroup(ctx, 1, g.ID))

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	restore := func(token string) int {
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/groups/%d/restore", server.URL, g.ID), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// The fix: users.write alone (no roles.assign) is rejected.
	assert.Equal(t, http.StatusForbidden, restore("usermgr-tok"),
		"users.write holder without roles.assign must NOT restore a group")
	// An admin (privilege-bypass, holds roles.assign) passes the gate.
	assert.NotEqual(t, http.StatusForbidden, restore("admin-tok"),
		"admin should be allowed past the roles.assign gate")
}

// Regression (#161 HIGH): POST /api/v1/projects/{id}/restore and
// POST /api/v1/projects/{projectId}/environments/{id}/restore reinstate every role
// grant bound to the project/environment — so they must require roles.assign, not
// secrets.write. Previously a secrets.write-only principal could restore a
// soft-deleted project/environment and get back every role grant it carried.
func TestRestoreProjectAndEnvironmentRoutesRequireRolesAssign(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	ctx := context.Background()

	db := sqlitetest.OpenWithDialector(t, "restoreauthz_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "writer", Email: "w@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "secretwriter"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	p, err := c.CreateProject(ctx, "proj", "")
	require.NoError(t, err)
	// The writer's secrets.write is scoped to the project created above.
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: p.ID}).Error)
	seedSession(t, db, 1, "admin-tok")
	seedSession(t, db, 2, "writer-tok")

	// CreateProject seeds default environments; reuse one rather than creating a
	// colliding duplicate.
	envs, err := c.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]
	require.NoError(t, c.Storage().DeleteEnvironment(ctx, env.ID))
	require.NoError(t, c.DeleteProject(ctx, p.ID, true))

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	post := func(token, path string) int {
		req, err := http.NewRequest("POST", server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	projectRestorePath := fmt.Sprintf("/api/v1/projects/%d/restore", p.ID)
	assert.Equal(t, http.StatusForbidden, post("writer-tok", projectRestorePath),
		"secrets.write holder without roles.assign must NOT restore a project")
	assert.NotEqual(t, http.StatusForbidden, post("admin-tok", projectRestorePath),
		"admin should be allowed past the roles.assign gate on project restore")

	envRestorePath := fmt.Sprintf("/api/v1/projects/%d/environments/%d/restore", p.ID, env.ID)
	assert.Equal(t, http.StatusForbidden, post("writer-tok", envRestorePath),
		"secrets.write holder without roles.assign must NOT restore an environment")
	assert.NotEqual(t, http.StatusForbidden, post("admin-tok", envRestorePath),
		"admin should be allowed past the roles.assign gate on environment restore")
}
