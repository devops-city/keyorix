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

// roleScopeHTTPWorld is a real router over SQLite with a global admin (user 2,
// session token roleScopeToken), a target user 3, group 7, project 2 with
// environment 5, and the roles admin (1), project_developer (10),
// system_admin (11).
type roleScopeHTTPWorld struct {
	db     *gorm.DB
	server *httptest.Server
}

const roleScopeToken = "role-scope-3546-tok"

func newRoleScopeHTTPWorld(t *testing.T) *roleScopeHTTPWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
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
	require.NoError(t, db.Create(&models.Group{ID: 7, Name: "devs"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "project_developer", NameFolded: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "system_admin", NameFolded: "system_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1}).Error) // global admin
	seedSession(t, db, 2, roleScopeToken)

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return &roleScopeHTTPWorld{db: db, server: server}
}

func (w *roleScopeHTTPWorld) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, w.server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+roleScopeToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

func (w *roleScopeHTTPWorld) userGrants(t *testing.T, userID uint) []models.UserRole {
	t.Helper()
	var out []models.UserRole
	require.NoError(t, w.db.Where("user_id = ?", userID).Order("role_id, project_id, environment_id").Find(&out).Error)
	return out
}

func (w *roleScopeHTTPWorld) groupGrants(t *testing.T, groupID uint) []models.GroupRole {
	t.Helper()
	var out []models.GroupRole
	require.NoError(t, w.db.Where("group_id = ?", groupID).Order("role_id, project_id, environment_id").Find(&out).Error)
	return out
}

// TestAssignRoleHTTP_EnvironmentScopedGlobalProjectGrantIsRefused was
// TestAssignRoleHTTP_EnvironmentScopedGlobalProjectGrantIsCreatable, the
// reachability premise of #2857: POST /api/v1/user-roles used to persist a
// {"project_id": 0, "environment_id": X} grant. #3546 makes the shape
// unconstructible (the "stronger fix" that test's doc anticipated); the
// global-admin holder queries keep their filter
// (store TestListProjectRoleAssignments_GlobalExcludesEnvironmentScopedGrant,
// core TestSuspendUser_EnvironmentScopedAdminGrantIsNotAGlobalAdminBackup)
// because grants written before #3546 may still have it.
func TestAssignRoleHTTP_EnvironmentScopedGlobalProjectGrantIsRefused(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	status, body := w.post(t, "/api/v1/user-roles", `{"user_id":3,"role_id":1,"project_id":0,"environment_id":5}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "environment_id requires project_id")
	require.Empty(t, w.userGrants(t, 3), "the refused {0, 5} grant must not be written")
}

// TestAssignRoleToGroupHTTP_ProjectRoleWithoutProjectIsRefused is the
// DEMO-WALK-4 regression (#3546): the web UI's Manage Roles posted
// {role_id: project_developer} with no project_id, and the group (alice
// included) became project_developer in EVERY project.
func TestAssignRoleToGroupHTTP_ProjectRoleWithoutProjectIsRefused(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)

	status, body := w.post(t, "/api/v1/groups/7/roles", `{"role_id":10}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "role project_developer is project-scoped; specify a project_id")
	require.Empty(t, w.groupGrants(t, 7), "no grant row may be written for the refused request")

	// The time-bound variant goes through the same core write.
	status, body = w.post(t, "/api/v1/groups/7/roles",
		`{"role_id":10,"expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Empty(t, w.groupGrants(t, 7))

	// Positive control: the same request WITH a project is granted at that project.
	status, body = w.post(t, "/api/v1/groups/7/roles", `{"role_id":10,"project_id":2,"environment_id":5}`)
	require.Equal(t, http.StatusCreated, status, body)
	require.Equal(t, []models.GroupRole{{GroupID: 7, RoleID: 10, ProjectID: 2, EnvironmentID: 5}}, w.groupGrants(t, 7))

	// A global grant of a system-tier / legacy admin role still works.
	status, body = w.post(t, "/api/v1/groups/7/roles", `{"role_id":11}`)
	require.Equal(t, http.StatusCreated, status, body)
	status, body = w.post(t, "/api/v1/groups/7/roles", `{"role_id":1}`)
	require.Equal(t, http.StatusCreated, status, body)
	require.Len(t, w.groupGrants(t, 7), 3)
}

// TestAssignUserRoleHTTP_ProjectRoleWithoutProjectIsRefused: the user-grant
// path had the same gap (#3546).
func TestAssignUserRoleHTTP_ProjectRoleWithoutProjectIsRefused(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)

	status, body := w.post(t, "/api/v1/user-roles", `{"user_id":3,"role_id":10}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "role project_developer is project-scoped")
	require.Empty(t, w.userGrants(t, 3))

	status, body = w.post(t, "/api/v1/user-roles", `{"user_id":3,"role_id":10,"project_id":2}`)
	require.Equal(t, http.StatusCreated, status, body)
	status, body = w.post(t, "/api/v1/user-roles", `{"user_id":3,"role_id":11}`)
	require.Equal(t, http.StatusCreated, status, body)
	require.Equal(t, []models.UserRole{
		{UserID: 3, RoleID: 10, ProjectID: 2},
		{UserID: 3, RoleID: 11},
	}, w.userGrants(t, 3))
}
