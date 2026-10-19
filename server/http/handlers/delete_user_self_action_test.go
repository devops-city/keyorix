package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
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
)

// setupDeleteUserTest builds a fully bootstrapped core (real BootstrapSystem over
// the full RBAC schema) with TWO global admins: user 1, the bootstrap admin
// (matching withUserCtx's hardcoded UserID: 1), and a second, independently
// admin-role-assigned user.
//
// Unlike setupUserHandlerTest (revoke_sessions_self_action_test.go), DeleteUser
// routes through core's guardLastAdminDeactivation, which calls IsGlobalAdmin and
// needs the full RBAC schema to resolve rather than erroring on missing tables.
// Seeding a SECOND admin is the point of this setup: it means core's "last install
// administrator" guard would NOT block user 1 from deleting themselves (another
// admin survives them), so if the self-action delete is still rejected, it can
// only be the handler-level guard doing it — exactly the gap this test pins.
func setupDeleteUserTest(t *testing.T) (handler *UserHandler, secondAdminID uint) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.PersonalAccessToken{}, &models.Session{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.AuditEvent{},
		&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.ProjectMembership{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.DynamicSecretConfig{}, &models.SoDPolicy{},
		&models.StatsSnapshot{}, &models.DeploymentStatsSnapshot{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.SecretACL{}, &models.PasswordHistory{},
		&models.SecretAccessSchedule{},
	))

	ctx := context.Background()
	st := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	result, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	require.Equal(t, uint(1), result.User.ID, "withUserCtx hardcodes UserID 1 as the acting admin")

	secondAdmin, err := st.CreateUser(ctx, &models.User{
		Username: "second-admin", Email: "second-admin@example.com", IsActive: true,
	})
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, secondAdmin.ID, adminRole.ID, core.Scope{}))

	handler, err = NewUserHandler(c)
	require.NoError(t, err)
	return handler, secondAdmin.ID
}

// DeleteUser previously had no guard against an admin targeting their own ID —
// unlike accountStateAction (Suspend/Reactivate/RequirePasswordReset) and
// RevokeSessions, which explicitly block self-action. Core's own backstop
// (guardLastAdminDeactivation, "refusing to deactivate the last install
// administrator") only fires when the target is the SOLE admin, so it does
// nothing to stop a self-delete while other admins still exist — exactly the
// setup here (a second admin is seeded). Only the handler-level guard added
// below can catch this case.
func TestDeleteUser_BlocksSelfAction(t *testing.T) {
	handler, _ := setupDeleteUserTest(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/1", nil)
	req = withUserCtx(req) // admin, UserID: 1
	req = withChiParam(req, "id", "1")

	w := httptest.NewRecorder()
	handler.DeleteUser(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "an admin must not be able to delete their own account")
}

func TestDeleteUser_AllowsTargetingOtherUsers(t *testing.T) {
	handler, secondAdminID := setupDeleteUserTest(t)
	idStr := strconv.FormatUint(uint64(secondAdminID), 10)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+idStr, nil)
	req = withUserCtx(req) // admin, UserID: 1
	req = withChiParam(req, "id", idStr)

	w := httptest.NewRecorder()
	handler.DeleteUser(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code, "deleting another user must still work")
}
