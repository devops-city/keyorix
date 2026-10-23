package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestGlobalProjectRoleGrantNotice(t *testing.T) {
	require.Nil(t, globalProjectRoleGrantNotice(nil), "no grants, no notice")

	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	lines := globalProjectRoleGrantNotice([]core.GlobalProjectRoleGrant{
		{PrincipalType: "group", PrincipalID: 7, RoleName: "project_developer"},
		{PrincipalType: "user", PrincipalID: 3, RoleName: "project_viewer", EnvironmentID: 5, ExpiresAt: &exp},
	})
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], "2 existing grant(s) of a project role at the global scope")
	require.Contains(t, lines[0], "#3546")
	require.Equal(t, "WARNING:   group 7 holds project_developer globally", lines[1])
	require.Equal(t, "WARNING:   user 3 holds project_viewer globally, environment_id=5, expires 2026-11-01T00:00:00Z", lines[2])

	many := make([]core.GlobalProjectRoleGrant, maxGlobalProjectRoleGrantLines+3)
	for i := range many {
		many[i] = core.GlobalProjectRoleGrant{PrincipalType: "user", PrincipalID: uint(i + 1), RoleName: "project_viewer"}
	}
	lines = globalProjectRoleGrantNotice(many)
	require.Len(t, lines, maxGlobalProjectRoleGrantLines+2)
	require.Equal(t, "WARNING:   ... and 3 more", lines[len(lines)-1])
}

func TestSSOProjectTierRoleWarnings(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSO.Providers = []config.SSOProviderConfig{
		{Name: "okta", DefaultRole: " project_viewer ", GroupRoleMap: map[string]string{
			"idp-devs": "project_developer", "idp-auditors": "system_auditor", "idp-admins": "project_admin",
		}},
		{Name: "clean", DefaultRole: "system_viewer", GroupRoleMap: map[string]string{"x": "system_admin"}},
	}
	got := ssoProjectTierRoleWarnings(cfg)
	require.Len(t, got, 3)
	require.Contains(t, got[0], `sso provider "okta": default_role project_viewer is a project role`)
	require.True(t, strings.Contains(got[1], `"idp-admins" -> project_admin`), got[1])
	require.True(t, strings.Contains(got[2], `"idp-devs" -> project_developer`), got[2])
}

// TestWireGlobalProjectRoleGrantsNotice_LogsLegacyGrants drives the wiring step
// itself against a real store holding grants written before #3546 (straight
// into the tables, as an older release left them): it names each one, writes
// nothing, and never blocks startup.
func TestWireGlobalProjectRoleGrantsNotice_LogsLegacyGrants(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, kxstorage.MigrateExisting(db))
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "project_developer", NameFolded: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "system_viewer", NameFolded: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 7, RoleID: 10}).Error)                 // legacy: DEMO-WALK-4
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 10, EnvironmentID: 5}).Error) // legacy {0, 5}
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 10, ProjectID: 2}).Error)     // valid
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 11}).Error)                   // valid
	var before int64
	require.NoError(t, db.Model(&models.UserRole{}).Count(&before).Error)

	cfg := &config.Config{}
	cfg.SSO.Providers = []config.SSOProviderConfig{{Name: "okta", DefaultRole: "project_viewer"}}
	cw := &coreWiring{cfg: cfg, core: core.NewKeyorixCore(store.NewLocalStorage(db))}
	var stepErr error
	out := captureLogs(func() { stepErr = wireGlobalProjectRoleGrantsNotice(cw) })
	require.NoError(t, stepErr)
	t.Logf("startup notice:\n%s", out)
	require.Contains(t, out, `WARNING: sso provider "okta": default_role project_viewer is a project role`)
	require.Contains(t, out, "WARNING: 2 existing grant(s) of a project role at the global scope")
	require.Contains(t, out, "WARNING:   group 7 holds project_developer globally\n")
	require.Contains(t, out, "WARNING:   user 3 holds project_developer globally, environment_id=5\n")
	var after int64
	require.NoError(t, db.Model(&models.UserRole{}).Count(&after).Error)
	require.Equal(t, before, after, "the check is read-only")
}

// TestWireGlobalProjectRoleGrantsNotice_LogsEnvironmentWithoutProjectGrants
// (ROLE-SHAPE-1): a legacy grant at {0, X} of ANY role (here a system role the
// project-tier notice does not cover) is named at startup with its project and
// the fix; a grant whose environment is gone is named with "remove"; nothing
// is written. Red before ROLE-SHAPE-1: no line named either grant.
func TestWireGlobalProjectRoleGrantsNotice_LogsEnvironmentWithoutProjectGrants(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, kxstorage.MigrateExisting(db))
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 5, ProjectID: 2, Name: "e5"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "system_auditor", NameFolded: "system_auditor"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 11, EnvironmentID: 5}).Error)    // legacy {0, 5}
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 7, RoleID: 11, EnvironmentID: 99}).Error) // legacy, environment gone
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 11, ProjectID: 2, EnvironmentID: 5}).Error)
	var before int64
	require.NoError(t, db.Model(&models.UserRole{}).Count(&before).Error)

	cw := &coreWiring{cfg: &config.Config{}, core: core.NewKeyorixCore(store.NewLocalStorage(db))}
	var stepErr error
	out := captureLogs(func() { stepErr = wireGlobalProjectRoleGrantsNotice(cw) })
	require.NoError(t, stepErr)
	t.Logf("startup notice:\n%s", out)
	require.NotContains(t, out, "of a project role at the global scope", "no project-tier grant here")
	require.Contains(t, out, "WARNING: 2 existing role grant(s) at project_id=0 with an environment_id")
	require.Contains(t, out, "WARNING:   group 7 holds role system_auditor (id 11) at project_id=0, environment_id=99; "+
		"environment 99 no longer exists: remove the grant (DELETE /api/v1/groups/7/roles/11?project_id=0&environment_id=99)\n")
	require.Contains(t, out, "WARNING:   user 3 holds role system_auditor (id 11) at project_id=0, environment_id=5; "+
		"it applies in environment 5 of project 2 but that project's access review does not list it: re-create it with project_id=2")
	var after int64
	require.NoError(t, db.Model(&models.UserRole{}).Count(&after).Error)
	require.Equal(t, before, after, "the check is read-only")
}

func TestEnvironmentWithoutProjectGrantNotice_Truncates(t *testing.T) {
	require.Nil(t, environmentWithoutProjectGrantNotice(nil), "no grants, no notice")
	many := make([]core.EnvironmentWithoutProjectGrant, maxGlobalProjectRoleGrantLines+2)
	for i := range many {
		many[i] = core.EnvironmentWithoutProjectGrant{PrincipalType: "user", PrincipalID: uint(i + 1), RoleName: "system_viewer", EnvironmentID: 5, ProjectID: 2}
	}
	lines := environmentWithoutProjectGrantNotice(many)
	require.Len(t, lines, maxGlobalProjectRoleGrantLines+2)
	require.Contains(t, lines[0], fmt.Sprintf("%d existing role grant(s)", len(many)))
	require.Equal(t, "WARNING:   ... and 2 more (each project's access review names its own)", lines[len(lines)-1])
}
