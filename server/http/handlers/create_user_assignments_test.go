package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

func setupCreateUserAssignmentsTest(t *testing.T) (*UserHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.UserRole{}, &models.Role{}, &models.Project{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Environment{}, &models.SoDPolicy{},
		&models.Permission{}, &models.RolePermission{},
		// AuditEvent: the user commits with its user.created row (AUDIT-TX-2).
		&models.AuditEvent{}))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.Project{Name: "default"}).Error)
	// withUserCtx authenticates as user 1; create that user as a real row (so it
	// takes id 1 and provisioned users get id 2+, no collision) and make them a
	// global admin so they pass the ADR-028 provisioning authz (a system-role
	// override + project assignments require roles.assign, here via admin-bypass).
	require.NoError(t, db.Create(&models.User{Username: "admin1", Email: "admin1@x.io", IsActive: true}).Error)
	var adminRole models.Role
	require.NoError(t, db.Create(&models.Role{Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Where("name = ?", "admin").First(&adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID, ProjectID: 0}).Error)
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	uh, err := NewUserHandler(coreService)
	require.NoError(t, err)
	return uh, db
}

// postCreateUserAsUser posts a create-user request authenticated as an arbitrary
// (non-admin) user id, for exercising the provisioning authorization checks.
func postCreateUserAsUser(t *testing.T, h *UserHandler, jsonBody string, userID uint) *httptest.ResponseRecorder {
	t.Helper()
	uc := &customMiddleware.UserContext{UserID: userID, Username: "caller", Email: "c@x.io"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader([]byte(jsonBody)))
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.CreateUser(w, req)
	return w
}

func postCreateUser(t *testing.T, h *UserHandler, jsonBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader([]byte(jsonBody))))
	w := httptest.NewRecorder()
	h.CreateUser(w, req)
	return w
}

func TestCreateUser_AtomicAssignments(t *testing.T) {
	h, db := setupCreateUserAssignmentsTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)

	t.Run("creates the user with system + project role grants", func(t *testing.T) {
		body := `{"username":"provisioned","email":"prov@x.io","display_name":"Prov","password":"Str0ng#Pass!word","role":"system_viewer","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"project_developer"}]}`
		w := postCreateUser(t, h, body)
		require.Equal(t, http.StatusCreated, w.Code)

		var u models.User
		require.NoError(t, db.Where("username = ?", "provisioned").First(&u).Error)
		var roles []models.UserRole
		require.NoError(t, db.Where("user_id = ?", u.ID).Find(&roles).Error)
		require.Len(t, roles, 2)
		// One global (system_viewer) + one at the project scope.
		var globals, scoped int
		for _, r := range roles {
			if r.ProjectID == 0 {
				globals++
			} else if r.ProjectID == proj.ID {
				scoped++
			}
		}
		assert.Equal(t, 1, globals)
		assert.Equal(t, 1, scoped)
	})

	t.Run("an unknown project rejects with 400 and creates no user", func(t *testing.T) {
		body := `{"username":"badproj","email":"badproj@x.io","display_name":"Bad","password":"Str0ng#Pass!word","project_assignments":[{"project_id":9999,"role":"project_developer"}]}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		var n int64
		require.NoError(t, db.Model(&models.User{}).Where("username = ?", "badproj").Count(&n).Error)
		assert.Equal(t, int64(0), n)
	})

	t.Run("an unknown project role rejects with 400", func(t *testing.T) {
		body := `{"username":"badrole","email":"badrole@x.io","display_name":"Bad","password":"Str0ng#Pass!word","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"nope"}]}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("an unknown system role rejects with 400", func(t *testing.T) {
		body := `{"username":"badsys","email":"badsys@x.io","display_name":"Bad","password":"Str0ng#Pass!word","role":"nonexistent_role"}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("assignments combined with a setup link are rejected", func(t *testing.T) {
		body := `{"username":"mix","email":"mix@x.io","display_name":"Mix","role":"system_viewer","deliver_setup_link":true}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// A caller who lacks roles.assign at the grant's scope cannot use atomic
// provisioning to hand out a system role or a project role they couldn't assign
// directly (ADR-028 privilege-escalation guard). User 9 has no roles.
func TestCreateUser_AssignmentAuthorization(t *testing.T) {
	h, db := setupCreateUserAssignmentsTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)

	t.Run("non-privileged caller cannot grant a system role", func(t *testing.T) {
		body := `{"username":"esc1","email":"esc1@x.io","display_name":"E","password":"Str0ng#Pass!word","role":"system_viewer"}`
		w := postCreateUserAsUser(t, h, body, 9)
		assert.Equal(t, http.StatusForbidden, w.Code)
		var n int64
		require.NoError(t, db.Model(&models.User{}).Where("username = ?", "esc1").Count(&n).Error)
		assert.Equal(t, int64(0), n, "no account is created when the grant is refused")
	})

	t.Run("non-privileged caller cannot grant a project role", func(t *testing.T) {
		body := `{"username":"esc2","email":"esc2@x.io","display_name":"E","password":"Str0ng#Pass!word","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"project_developer"}]}`
		w := postCreateUserAsUser(t, h, body, 9)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("global admin (user 1) may grant both", func(t *testing.T) {
		body := `{"username":"okuser","email":"ok@x.io","display_name":"OK","password":"Str0ng#Pass!word","role":"system_viewer","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"project_developer"}]}`
		w := postCreateUser(t, h, body) // user 1 = admin
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}
