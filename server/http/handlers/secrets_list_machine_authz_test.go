// secrets_list_machine_authz_test.go — machine-principal authorization tests for ListSecrets.
//
// Covers CWE-862: machine tokens must supply an explicit project_id and must hold
// secrets.read in that project's scope before the handler calls ListSecretsInScope.
//
// Test matrix:
//   - Machine token with no project_id → 400 (missing required param)
//   - Machine token with project_id for a project it has NO role in → 403
//   - Machine token scoped to project 1 accessing project 2 → 403
//   - Machine token scoped to project 1 accessing project 1 → 200 (authorised)
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

// freshMachineAuthzFixture opens an isolated named in-memory SQLite DB with all
// models required by the ListSecrets handler and the RBAC / machine-role layer.
func freshMachineAuthzFixture(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_machine_authz_")
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
		&models.MachineIdentity{},
		&models.MachineIdentityRole{},
	))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, db
}

// withMachineCtxID builds a request UserContext for the given machine identity ID.
func withMachineCtxID(r *http.Request, machineID uint) *http.Request {
	uc := &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machineID,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// seedMachineReadRole creates a Role with secrets.read and grants it to machineID at
// projectID scope via MachineIdentityRole. Returns the role ID.
func seedMachineReadRole(t *testing.T, db *gorm.DB, roleName string, machineID, projectID uint) uint {
	t.Helper()

	role := &models.Role{Name: roleName}
	require.NoError(t, db.Create(role).Error)

	perm := &models.Permission{}
	if err := db.Where("name = ?", permSecretsRead).First(perm).Error; err != nil {
		perm = &models.Permission{Name: permSecretsRead, Resource: "secrets", Action: "read"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: machineID,
		RoleID:            role.ID,
		ProjectID:         projectID,
		EnvironmentID:     0,
	}).Error)
	return role.ID
}

// TestListSecrets_MachineToken_NoProjectID verifies that a machine principal
// calling GET /api/v1/secrets without ?project_id= receives 400.
func TestListSecrets_MachineToken_NoProjectID(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)

	// Seed a machine identity so it is a valid principal.
	const machineID = uint(10)
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: 1, Name: "ci-runner", State: "active",
	}).Error)

	req := withMachineCtxID(httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil), machineID)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "machine token without project_id must get 400")
}

// TestListSecrets_MachineToken_WrongProject verifies that a machine principal
// scoped to project 1 cannot list secrets from project 2 (→ 403).
func TestListSecrets_MachineToken_WrongProject(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)

	// Seed two projects.
	proj1 := &models.Project{Name: "proj-machine-1"}
	require.NoError(t, db.Create(proj1).Error)
	proj2 := &models.Project{Name: "proj-machine-2"}
	require.NoError(t, db.Create(proj2).Error)

	// Machine 20 has secrets.read only in project 1.
	const machineID = uint(20)
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: proj1.ID, Name: "ci-runner-20", State: "active",
	}).Error)
	seedMachineReadRole(t, db, "machine_reader_p1", machineID, proj1.ID)

	// Request secrets from project 2 — the machine has no role there.
	url := fmt.Sprintf("/api/v1/secrets?project_id=%d", proj2.ID)
	req := withMachineCtxID(httptest.NewRequest(http.MethodGet, url, nil), machineID)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "machine token accessing wrong project must get 403")
}

// TestListSecrets_MachineToken_AuthorizedProject verifies that a machine principal
// with secrets.read in project 1 can list secrets from project 1 (→ 200).
func TestListSecrets_MachineToken_AuthorizedProject(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)

	proj := &models.Project{Name: "proj-machine-auth"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-machine-auth", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "machine-visible-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 0, Type: "static", IsSecret: true,
	}).Error)

	const machineID = uint(30)
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: proj.ID, Name: "ci-runner-30", State: "active",
	}).Error)
	seedMachineReadRole(t, db, "machine_reader_auth", machineID, proj.ID)

	url := fmt.Sprintf("/api/v1/secrets?project_id=%d", proj.ID)
	req := withMachineCtxID(httptest.NewRequest(http.MethodGet, url, nil), machineID)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)

	require.Equal(t, http.StatusOK, w.Code, "authorized machine token should get 200")
	resp := decodeListResponse(t, w.Body.Bytes())
	assert.GreaterOrEqual(t, resp.Total, int64(1), "authorized machine token should see its project's secrets")
}

// TestListSecrets_MachineToken_OwnershipFiltersFailClosedToEmpty: a machine owns
// nothing and has nothing shared with it, so ?show_owned_only=true /
// ?show_shared_only=true must yield an empty list, not silently ignore the filter
// and return everything in scope (#2874 review, minor 1). The unfiltered call is
// the calibration: the same fixture must still list the secret.
func TestListSecrets_MachineToken_OwnershipFiltersFailClosedToEmpty(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)

	proj := &models.Project{Name: "proj-machine-own"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-machine-own", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "machine-scope-secret", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: 0, Type: "static", IsSecret: true,
	}).Error)
	const machineID = uint(40)
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: proj.ID, Name: "ci-runner-40", State: "active",
	}).Error)
	seedMachineReadRole(t, db, "machine_reader_own", machineID, proj.ID)

	list := func(query string) *models.SecretListResponse {
		url := fmt.Sprintf("/api/v1/secrets?project_id=%d%s", proj.ID, query)
		w := httptest.NewRecorder()
		h.ListSecrets(w, withMachineCtxID(httptest.NewRequest(http.MethodGet, url, nil), machineID))
		require.Equal(t, http.StatusOK, w.Code)
		return decodeListResponse(t, w.Body.Bytes())
	}

	assert.GreaterOrEqual(t, list("").Total, int64(1), "calibration: unfiltered machine listing still returns the secret")
	assert.Equal(t, int64(0), list("&show_shared_only=true").Total, "a machine has nothing shared with it")
	assert.Equal(t, int64(0), list("&show_owned_only=true").Total, "a machine owns nothing")
}
