package core

// role_scope_guard_test.go — GROUP-ROLE-SCOPE-1 (#3546). DEMO-WALK-4: alice,
// viewer on one project, got project_developer on EVERY project because the
// web UI posted a group grant with no project_id and core wrote it at {0, 0}.
//
// TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope drives every
// grant entry point in this package with a project-tier role at the global
// scope (and the environment-only shapes) and asserts the EFFECT: no grant row
// was written, read back from storage, not only the returned error.
// TestEveryRoleGrantWriteChecksRoleScope (role_scope_guard_registry_test.go)
// proves that list of entry points is complete.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestValidateRoleScope(t *testing.T) {
	cases := []struct {
		role    string
		scope   Scope
		refused bool
	}{
		{"project_admin", Scope{}, true},
		{"project_developer", Scope{}, true},
		{"project_viewer", Scope{}, true},
		{"project_auditor", Scope{}, true},
		{"project_developer", Scope{ProjectID: 3}, false},
		{"project_developer", Scope{ProjectID: 3, EnvironmentID: 4}, false},
		{"system_viewer", Scope{}, false},
		{"system_admin", Scope{}, false},
		{"admin", Scope{}, false},
		{"viewer", Scope{}, false},
		{"system_viewer", Scope{EnvironmentID: 4}, true},
		{"admin", Scope{EnvironmentID: 4}, true},
		// Exact names, not a prefix: a custom role named project_* keeps its
		// behaviour in a patch release (Phase 2 gives custom roles an explicit
		// assignable scope).
		{"project_custom", Scope{}, false},
		{"Project_Developer", Scope{}, false},
	}
	for _, tc := range cases {
		err := validateRoleScope(tc.role, tc.scope)
		require.Equal(t, tc.refused, err != nil, "%s at %+v: %v", tc.role, tc.scope, err)
		if tc.refused {
			require.ErrorIs(t, err, ErrRoleScopeInvalid)
			msg, ok := RoleScopeClientMessage(err)
			require.True(t, ok)
			require.NotEmpty(t, msg)
		}
	}
	msg, _ := RoleScopeClientMessage(validateRoleScope("project_developer", Scope{}))
	require.Equal(t, "role project_developer is project-scoped; specify a project_id (and optionally environment_id)", msg)
}

// roleScopeWorld is a bootstrapped install with two projects (each with one
// environment), a target user, a group, and the built-in roles.
type roleScopeWorld struct {
	c                *KeyorixCore
	adminID, userID  uint
	groupID          uint
	p1, e1, p2, e2   uint
	projectDeveloper *models.Role
	systemViewer     *models.Role
}

func newRoleScopeWorld(t *testing.T, c *KeyorixCore) *roleScopeWorld {
	t.Helper()
	ctx := context.Background()
	admin, err := c.storage.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	w := &roleScopeWorld{c: c, adminID: admin.ID}
	p1, err := c.CreateProject(ctx, "rs-one", "")
	require.NoError(t, err)
	p2, err := c.CreateProject(ctx, "rs-two", "")
	require.NoError(t, err)
	e1, err := c.CreateEnvironment(ctx, p1.ID, "rs-e1")
	require.NoError(t, err)
	e2, err := c.CreateEnvironment(ctx, p2.ID, "rs-e2")
	require.NoError(t, err)
	w.p1, w.p2, w.e1, w.e2 = p1.ID, p2.ID, e1.ID, e2.ID
	u, err := c.CreateUser(ctx, &CreateUserRequest{Username: "alice", Email: "alice@example.com", DisplayName: "Alice", Password: "Correct-Horse-Battery-9"})
	require.NoError(t, err)
	w.userID = u.ID
	g, err := c.CreateGroup(ctx, w.adminID, &CreateGroupRequest{Name: "devs"})
	require.NoError(t, err)
	w.groupID = g.ID
	w.projectDeveloper, err = c.storage.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	w.systemViewer, err = c.storage.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	return w
}

// grantRows returns every user and group grant row, as comparable strings.
func (w *roleScopeWorld) grantRows(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	users, err := w.c.storage.ListAllUserRoleGrants(ctx)
	require.NoError(t, err)
	groups, err := w.c.storage.ListAllGroupRoleGrants(ctx)
	require.NoError(t, err)
	var out []string
	for _, g := range users {
		out = append(out, fmtGrant("user", g.UserID, g.RoleID, g.ProjectID, g.EnvironmentID))
	}
	for _, g := range groups {
		out = append(out, fmtGrant("group", g.GroupID, g.RoleID, g.ProjectID, g.EnvironmentID))
	}
	return out
}

func fmtGrant(kind string, principal, role, project, env uint) string {
	return fmt.Sprintf("%s:%d role:%d at {%d,%d}", kind, principal, role, project, env)
}

// roleScopeEntryPoints is every grant entry point of this package, each driven
// with an invalid scope. TestEveryRoleGrantWriteChecksRoleScope pins that each
// storage grant write is reached through one of these (or is exempt).
func roleScopeEntryPoints(w *roleScopeWorld) map[string]func(ctx context.Context) error {
	c, pd := w.c, w.projectDeveloper
	exp := time.Now().Add(time.Hour)
	return map[string]func(ctx context.Context) error{
		"AssignUserRole": func(ctx context.Context) error {
			return c.AssignUserRole(ctx, w.adminID, w.userID, pd.ID, Scope{}, false)
		},
		"AssignUserRoleWithExpiry": func(ctx context.Context) error {
			return c.AssignUserRoleWithExpiry(ctx, w.adminID, w.userID, pd.ID, Scope{}, exp, false)
		},
		"AssignRoleToGroup (the DEMO-WALK-4 path)": func(ctx context.Context) error {
			return c.AssignRoleToGroup(ctx, w.adminID, w.groupID, pd.ID, Scope{}, false)
		},
		"AssignGroupRoleWithExpiry": func(ctx context.Context) error {
			return c.AssignGroupRoleWithExpiry(ctx, w.adminID, w.groupID, pd.ID, Scope{}, exp, false)
		},
		"SetUserRoles": func(ctx context.Context) error {
			return c.SetUserRoles(ctx, w.adminID, w.userID, []uint{w.systemViewer.ID, pd.ID}, Scope{}, false)
		},
		"AddProjectMember with project 0": func(ctx context.Context) error {
			return c.AddProjectMember(ctx, w.adminID, 0, w.userID, "project_developer", false)
		},
		"AssignUserRoleScoped (local CLI)": func(ctx context.Context) error {
			return c.AssignUserRoleScoped(ctx, "alice@example.com", "project_developer", Scope{})
		},
		"CreateUserWithAssignments system role": func(ctx context.Context) error {
			_, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{Username: "bob", Email: "bob@example.com", DisplayName: "Bob", Password: "Correct-Horse-Battery-9"},
				"project_developer", nil, w.adminID, false)
			return err
		},
		"InviteGlobal system role": func(ctx context.Context) error {
			_, err := c.InviteGlobal(ctx, "carol@example.com", "project_developer", nil, w.adminID, 0)
			return err
		},
		"assignUserRoleSystemGrant (SSO group mapping primitive)": func(ctx context.Context) error {
			return c.assignUserRoleSystemGrant(ctx, w.userID, w.userID, pd.ID, Scope{})
		},
		"assignUserRoleWithExpirySkipSoD (break-glass primitive)": func(ctx context.Context) error {
			return c.assignUserRoleWithExpirySkipSoD(ctx, w.adminID, w.userID, pd.ID, Scope{}, exp)
		},
		"grantBreakGlassTx": func(ctx context.Context) error {
			return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
				_, err := c.grantBreakGlassTx(ctx, tx, w.userID, 0, pd, "incident", time.Now(), exp, Scope{}, false)
				return err
			})
		},
		"finalizeAccessRequestApproval": func(ctx context.Context) error {
			_, err := c.finalizeAccessRequestApproval(ctx, &models.AccessRequest{ID: 99, UserID: w.userID, ProjectID: 0},
				w.adminID, 0, pd, 0, 1, 1)
			return err
		},
		"provisionSSOUser default_role": func(ctx context.Context) error {
			_, err := c.provisionSSOUser(ctx, &SSOProvider{Name: "okta", AutoProvision: true, DefaultRole: "project_developer"},
				"okta|dave", "dave@example.com", true, "Dave")
			return err
		},
		// Environment-only scopes, which apply nowhere sensible.
		"AssignUserRole environment without project": func(ctx context.Context) error {
			return c.AssignUserRole(ctx, w.adminID, w.userID, w.systemViewer.ID, Scope{EnvironmentID: w.e1}, false)
		},
		"AssignRoleToGroup environment of another project": func(ctx context.Context) error {
			return c.AssignRoleToGroup(ctx, w.adminID, w.groupID, pd.ID, Scope{ProjectID: w.p1, EnvironmentID: w.e2}, false)
		},
		"AssignUserRole unknown environment": func(ctx context.Context) error {
			return c.AssignUserRole(ctx, w.adminID, w.userID, pd.ID, Scope{ProjectID: w.p1, EnvironmentID: 9999}, false)
		},
	}
}

func runRoleScopeEntryPoints(t *testing.T, c *KeyorixCore) {
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)
	for name, call := range roleScopeEntryPoints(w) {
		t.Run(name, func(t *testing.T) {
			before := w.grantRows(t)
			err := call(ctx)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrRoleScopeInvalid), "want a role-scope refusal, got: %v", err)
			require.ElementsMatch(t, before, w.grantRows(t), "a refused grant must write no grant row")
		})
	}
	// The SSO default-role refusal is fail-closed for the whole provision.
	_, err := c.storage.GetUserByEmail(ctx, "dave@example.com")
	require.Error(t, err, "no JIT user may be created behind a refused default_role")
	_, err = c.storage.GetUserByEmail(ctx, "bob@example.com")
	require.Error(t, err, "no user may be created behind a refused system role")
	grants, err := c.ListGlobalProjectTierRoleGrants(ctx)
	require.NoError(t, err)
	require.Empty(t, grants)

	// SSO group_role_map: a project-tier mapping is not granted, and the login
	// is not refused for it (like an escalation block).
	p := &SSOProvider{Name: "okta", GroupRoleMap: map[string]string{"idp-devs": "project_developer", "idp-viewers": "system_auditor"}}
	before := w.grantRows(t)
	require.NoError(t, c.reconcileSSORoles(ctx, p, w.userID, []string{"idp-devs", "idp-viewers"}))
	auditor, err := c.storage.GetRoleByName(ctx, "system_auditor")
	require.NoError(t, err)
	require.ElementsMatch(t, append(before, fmtGrant("user", w.userID, auditor.ID, 0, 0)), w.grantRows(t),
		"only the system-tier mapping is granted")

	// Positive controls: the same roles at a valid scope still work.
	require.NoError(t, c.AssignRoleToGroup(ctx, w.adminID, w.groupID, w.projectDeveloper.ID, Scope{ProjectID: w.p1}, false))
	require.NoError(t, c.AssignUserRole(ctx, w.adminID, w.userID, w.projectDeveloper.ID, Scope{ProjectID: w.p1, EnvironmentID: w.e1}, false))
	sysAdmin, err := c.storage.GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)
	require.NoError(t, c.AssignUserRole(ctx, w.adminID, w.userID, sysAdmin.ID, Scope{}, false))
	legacyAdmin, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, w.adminID, w.groupID, legacyAdmin.ID, Scope{}, false))
	require.Contains(t, w.grantRows(t), fmtGrant("group", w.groupID, w.projectDeveloper.ID, w.p1, 0))
	require.Contains(t, w.grantRows(t), fmtGrant("user", w.userID, w.projectDeveloper.ID, w.p1, w.e1))
}

// TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope is the SQLite
// leg. Red without the guard: every refused case writes its grant.
func TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	runRoleScopeEntryPoints(t, c)
}

// TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope_Postgres is the
// same on a production-migrated Postgres database. Skips without
// KEYORIX_TEST_PG_DSN.
func TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope_Postgres(t *testing.T) {
	db := pgOpen(t, pgMigratedDatabaseDSN(t, pgTestDSN(t)))
	runRoleScopeEntryPoints(t, bootstrapCoreOn(t, db))
}

// TestListGlobalProjectTierRoleGrants_ReportsLegacyGrants: grants written
// before the guard (here straight into storage) are listed, users and groups,
// and nothing else is.
func TestListGlobalProjectTierRoleGrants_ReportsLegacyGrants(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)
	require.NoError(t, c.storage.AssignRoleToGroup(ctx, w.groupID, w.projectDeveloper.ID, Scope{}))
	require.NoError(t, c.storage.AssignRole(ctx, w.userID, w.projectDeveloper.ID, Scope{EnvironmentID: w.e1}))
	require.NoError(t, c.storage.AssignRole(ctx, w.userID, w.projectDeveloper.ID, Scope{ProjectID: w.p1})) // valid: not listed
	got, err := c.ListGlobalProjectTierRoleGrants(ctx)
	require.NoError(t, err)
	require.Equal(t, []GlobalProjectRoleGrant{
		{PrincipalType: "group", PrincipalID: w.groupID, RoleName: "project_developer"},
		{PrincipalType: "user", PrincipalID: w.userID, RoleName: "project_developer", EnvironmentID: w.e1},
	}, got)
}

func bootstrapCoreOn(t *testing.T, db *gorm.DB) *KeyorixCore {
	t.Helper()
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	return c
}
