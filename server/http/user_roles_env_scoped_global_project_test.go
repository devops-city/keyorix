package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestAssignRoleHTTP_EnvironmentScopedGlobalProjectGrantIsCreatable pins the
// reachability fact #2857's fix rests on: POST /api/v1/user-roles accepts
// {"project_id": 0, "environment_id": X} and persists exactly that grant
// shape, with no check that the environment's project is named. So the
// {ProjectID: 0, EnvironmentID: X} grant is constructible through a live route
// (a global admin may grant any role at any scope), and the global-admin holder
// queries must not count it as global
// (store TestListProjectRoleAssignments_GlobalExcludesEnvironmentScopedGrant,
// core TestSuspendUser_EnvironmentScopedAdminGrantIsNotAGlobalAdminBackup).
//
// If this test starts failing because the route now REJECTS the shape, that is
// the stronger fix (the shape becomes unconstructible): keep the query filter,
// and turn this into the rejection test.
func TestAssignRoleHTTP_EnvironmentScopedGlobalProjectGrantIsCreatable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.SoDPolicy{}, &models.SystemMetadata{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 5, ProjectID: 2, Name: "e5"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "admin", Email: "admin@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "target", Email: "target@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1}).Error) // global admin
	seedSession(t, db, 2, "env-scoped-global-2857-tok")

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/user-roles",
		strings.NewReader(`{"user_id":3,"role_id":1,"project_id":0,"environment_id":5}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer env-scoped-global-2857-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var grants []models.UserRole
	require.NoError(t, db.Where("user_id = 3").Find(&grants).Error)
	require.Len(t, grants, 1)
	require.EqualValues(t, 0, grants[0].ProjectID)
	require.EqualValues(t, 5, grants[0].EnvironmentID, "the route persists a {ProjectID: 0, EnvironmentID: 5} grant")
}
