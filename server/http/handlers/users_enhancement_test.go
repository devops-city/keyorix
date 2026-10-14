package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func setupUserEnhancementTest(t *testing.T) (*UserHandler, *UsersRolesHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// The RBAC tables are migrated because project membership is defined by a
	// project-scoped ROLE GRANT, not by a project_memberships row (#2781,
	// internal/core/project_membership_definition.go) — the membership and
	// project-count views both read user_roles/group_roles/roles now, and a DB
	// without them answers 500 rather than "no memberships".
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.ProjectMembership{}, &models.Project{},
		&models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		// SecretNode: the membership/count path resolves projects through
		// ListProjectsWithCounts (so soft-deleted ones are identifiable rather than
		// nameless), and that query LEFT JOINs secret_nodes AND environments. Neither
		// is seeded; the tables just have to exist.
		&models.SecretNode{}, &models.Environment{},
	))
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	uh, err := NewUserHandler(coreService)
	require.NoError(t, err)
	return uh, NewUsersRolesHandler(coreService), db
}

func decodeData(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "response has a data object")
	return data
}

func TestStaleAccountsHandler(t *testing.T) {
	uh, _, db := setupUserEnhancementTest(t)

	// One stale pending account (>7d), one recent pending, one active old.
	// Force created_at into the past, routed through Save (not a raw column
	// Update): StaleAccounts' ListUsersInStateBefore does a real SQL range
	// query on created_at, and User.BeforeSave exists specifically to
	// UTC-normalize this column for that comparison — a raw Update bypasses it
	// and leaves the local Location of time.Now() sitting in the column,
	// correct today only by the margin between each case's age and the 7-day
	// cutoff, not because the value is actually canonical (#1619).
	mk := func(name, state string, age time.Duration) {
		u := &models.User{Username: name, Email: name + "@x.com", AccountState: state}
		require.NoError(t, db.Create(u).Error)
		u.CreatedAt = time.Now().Add(-age)
		require.NoError(t, db.Save(u).Error)
	}
	mk("stale-bot", core.AccountPendingFirstLogin, 10*24*time.Hour)
	mk("fresh-bot", core.AccountPendingFirstLogin, 1*24*time.Hour)
	mk("old-active", core.AccountActive, 30*24*time.Hour)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?days=7", nil))
	w := httptest.NewRecorder()
	uh.StaleAccounts(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	users := data["users"].([]any)
	require.Len(t, users, 1, "only the >7d pending account")
	assert.Equal(t, "stale-bot", users[0].(map[string]any)["username"])
	assert.Equal(t, core.AccountPendingFirstLogin, data["state"])

	// Unsupported state is a 400.
	bad := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?state=active", nil))
	bw := httptest.NewRecorder()
	uh.StaleAccounts(bw, bad)
	assert.Equal(t, http.StatusBadRequest, bw.Code)
}

// TestListUsers_MergesProjectCounts checks that ListUsers merges per-user project
// tallies into its rows. The tallies' MEANING changed with #2781: they count the
// projects a user holds a live project-scoped grant in, not project_memberships
// rows — which were empty for every user on an install whose members were added
// through POST /projects/{id}/members, so this column read 0 across the board.
// `project_count` additionally counts onboarding still in flight (a non-revoked
// journal row with no grant behind it yet), which is the field's original
// "including pending" meaning, preserved.
//
// This test previously seeded three project_memberships rows and no grant at all,
// and asserted 2/2. That premise is the bug; the fixture now seeds what a real
// install has.
func TestListUsers_MergesProjectCounts(t *testing.T) {
	uh, _, db := setupUserEnhancementTest(t)

	require.NoError(t, db.Create(&models.User{Username: "alice", Email: "alice@x.com", AccountState: core.AccountActive}).Error)
	var alice models.User
	require.NoError(t, db.Where("username = ?", "alice").First(&alice).Error)

	viewer := &models.Role{Name: "project_viewer"}
	require.NoError(t, db.Create(viewer).Error)
	// The projects have to EXIST: the counts exclude soft-deleted projects, and a
	// grant pointing at a project that is not in the index at all counts as not-live
	// for the same reason (a dangling grant must not inflate the number either). This
	// fixture previously created grants on project ids 1/2 with no project rows and
	// still reported 2 — nothing checked. See
	// internal/core/project_membership_soft_delete_test.go.
	for id, name := range map[uint]string{1: "alpha", 2: "beta", 3: "gamma"} {
		require.NoError(t, db.Create(&models.Project{ID: id, Name: name}).Error)
	}
	// Member of two projects (grants), plus an invite to a third still in flight,
	// plus a revoked journal row that must not count at all.
	for _, pid := range []uint{1, 2} {
		require.NoError(t, db.Create(&models.UserRole{UserID: alice.ID, RoleID: viewer.ID, ProjectID: pid}).Error)
	}
	require.NoError(t, db.Create(&models.ProjectMembership{ProjectID: 3, UserID: alice.ID, State: "invited"}).Error)
	// Project 4 deliberately does not exist: a revoked journal row counts for
	// nothing regardless, so this also pins that a dangling one is harmless.
	require.NoError(t, db.Create(&models.ProjectMembership{ProjectID: 4, UserID: alice.ID, State: "revoked"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	users := data["users"].([]any)
	require.Len(t, users, 1)
	u := users[0].(map[string]any)
	assert.Equal(t, float64(2), u["active_project_count"],
		"two live project-scoped grants = member of two projects")
	assert.Equal(t, float64(3), u["project_count"],
		"the two memberships plus the in-flight invite; the revoked journal row counts for neither")
}

// TestGetUserMembershipsHandler covers the per-user assignments view the detail
// page renders. Its fixture now seeds a project-scoped role grant — the thing that
// makes someone a project member (#2781) — rather than a project_memberships row
// with no grant behind it, which is the shape that used to make this route report
// "Not a member of any project" for everyone.
func TestGetUserMembershipsHandler(t *testing.T) {
	_, rh, db := setupUserEnhancementTest(t)

	require.NoError(t, db.Create(&models.Project{Name: "payments"}).Error)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "payments").First(&proj).Error)
	devRole := &models.Role{Name: "project_developer"}
	require.NoError(t, db.Create(devRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 42, RoleID: devRole.ID, ProjectID: proj.ID}).Error)
	// A journal row too, so the lifecycle state this view reports has a source and
	// the "state comes from the journal when there is one" half is exercised.
	require.NoError(t, db.Create(&models.ProjectMembership{
		ProjectID: proj.ID, UserID: 42, Role: "project_developer", State: "active",
	}).Error)

	// G84: reading a DIFFERENT user's memberships requires self, admin, or
	// roles.read. Exercise the self-read path — the caller IS user 42 — which is the
	// case this test's data models (a user's own memberships, with project names).
	req := withChiParam(withUserCtxID(httptest.NewRequest(http.MethodGet, "/api/v1/users/42/memberships", nil), 42, "g84-self-42"), "id", "42")
	w := httptest.NewRecorder()
	rh.GetUserMembershipsForUser(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	data := decodeData(t, w)
	memberships := data["memberships"].([]any)
	require.Len(t, memberships, 1)
	m := memberships[0].(map[string]any)
	assert.Equal(t, "payments", m["project_name"])
	assert.Equal(t, "project_developer", m["role"])
	assert.Equal(t, "active", m["state"])
	assert.Equal(t, float64(proj.ID), m["project_id"])
	assert.Equal(t, false, m["via_group"], "a direct grant is not group-inherited")
}
