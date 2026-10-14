package handlers

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/keyorixhq/keyorix/server/middleware"
)

// TestCreateSecret_PerProjectMFAGate is a regression guard for ADR-037: the
// in-handler-authorized POST /secrets must enforce the per-project MFA policy,
// exactly like the scoped-permission middleware. (A security review found this
// call site originally missed the gate.)
func TestCreateSecret_PerProjectMFAGate(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{}, &models.Group{}, &models.GroupRole{},
		&models.UserGroup{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}))

	// A global admin user (bypasses the RBAC check, so we reach the MFA gate).
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "needs-mfa", RequireMFA: true}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "open"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "prod"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler, err := NewSecretHandler(coreService)
	require.NoError(t, err)

	// Interactive session, no second factor.
	userCtx := &middleware.UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	post := func(projectID, environmentID uint) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"name": "API_KEY", "value": "v", "project_id": projectID,
			"environment_id": environmentID, "type": "static",
		})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
		rr := httptest.NewRecorder()
		handler.CreateSecret(rr, r)
		return rr
	}

	t.Run("MFA-required project blocks an interactive no-MFA user", func(t *testing.T) {
		rr := post(1, 10)
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "ProjectMFARequired")
	})

	t.Run("open project does not trip the MFA gate", func(t *testing.T) {
		rr := post(2, 20)
		assert.NotContains(t, rr.Body.String(), "ProjectMFARequired",
			"a project without require_mfa must not be blocked by the policy")
	})
}
