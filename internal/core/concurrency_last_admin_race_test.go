// concurrency_last_admin_race_test.go — #G03 regressions: the last-admin guards
// (guardLastAdminDeactivation, guardLastProjectAdmin) are correct read-then-decide
// checks, but were not serialized against the write that follows — two concurrent
// calls removing/demoting two DIFFERENT admins could each read "another admin
// survives" before either commits, and both proceed, jointly stranding the
// install/project with zero admins.
//
// installAdminRoleIDSet (rbac_management.go) only recognizes a FIXED set of role
// names ("admin", "super_admin", "system_admin", "project_admin") as admin-tier —
// role names are also unique — so, unlike the per-user-independent #344 SCIM races
// (concurrency_account_suspension_scim_test.go), a "2 global admins" fixture can't
// be trivially replicated hundreds of times in ONE shared DB under distinct role
// names. Each trial below therefore gets its own fresh, file-backed SQLite DB (WAL +
// busy_timeout, same rigor as #344) and runs its own isolated 2-admin race; running
// many trials (not many pairs in one DB) gets the same statistical confidence.
package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const lastAdminRaceTrials = 50

// newTwoGlobalAdminFixture creates a fresh file-backed DB (WAL + busy_timeout) with
// exactly two global admins (users 1 and 2, both holding the "admin" role).
func newTwoGlobalAdminFixture(t *testing.T, dbFile string) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	dsn := "file:" + dbFile + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// userIsGone reports whether userID is no longer usable as a fallback admin
// (soft-deleted, or IsActive=false).
func userIsGone(db *gorm.DB, userID uint) bool {
	var user models.User
	err := db.First(&user, userID).Error
	return err != nil || !user.IsActive
}

// runTwoAdminRace fires removeA against user 1 and removeB against user 2, both
// released from a single start barrier, and counts how many of lastAdminRaceTrials
// independent trials end with both admins gone / both admins surviving — either
// outcome is the #G03 bug (jointly stranding the install, or a spurious double
// refusal); exactly one gone is the only correct outcome.
func runTwoAdminRace(t *testing.T, name string, removeA, removeB func(ctx context.Context, c *core.KeyorixCore)) (bothGone, neitherGone int) {
	t.Helper()
	for range lastAdminRaceTrials {
		c, db := newTwoGlobalAdminFixture(t, filepath.Join(t.TempDir(), name+".db"))
		ctx := context.Background()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; removeA(ctx, c) }()
		go func() { defer wg.Done(); <-start; removeB(ctx, c) }()
		close(start)
		wg.Wait()

		aGone, bGone := userIsGone(db, 1), userIsGone(db, 2)
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
	}
	return bothGone, neitherGone
}

// TestConcurrency_DeleteUser_ExactlyOneOfTwoAdminsRemoved is the #G03 regression for
// internal/core/users.go's DeleteUser.
func TestConcurrency_DeleteUser_ExactlyOneOfTwoAdminsRemoved(t *testing.T) {
	t.Parallel()
	// S1 (CLI-split inventory #2012): DeleteUser now enforces the admin-rank
	// ceiling (requireAdminRankCeilingForTarget) -- actor 99 (unseeded, holds
	// nothing) would be correctly refused against both admin targets, which
	// isn't the race this test exercises. The two admins (1, 2) race to
	// remove EACH OTHER instead: both are real, ceiling-satisfying actors,
	// and this fixture deliberately stays at exactly two admins so the
	// last-admin guard's own counting is unaffected by this fix.
	bothGone, neitherGone := runTwoAdminRace(t, "delete_user",
		func(ctx context.Context, c *core.KeyorixCore) { _ = c.DeleteUser(ctx, 2, 1) },
		func(ctx context.Context, c *core.KeyorixCore) { _ = c.DeleteUser(ctx, 1, 2) },
	)
	assert.Zero(t, bothGone, "%d/%d trials removed BOTH admins, stranding the install with zero admins", bothGone, lastAdminRaceTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH removals (should allow exactly one)", neitherGone, lastAdminRaceTrials)
}

// TestConcurrency_UpdateSCIMUser_ExactlyOneOfTwoAdminsDeactivated is the #G03
// regression for scim.go's UpdateSCIMUser.
func TestConcurrency_UpdateSCIMUser_ExactlyOneOfTwoAdminsDeactivated(t *testing.T) {
	t.Parallel()
	no := false
	bothGone, neitherGone := runTwoAdminRace(t, "scim_update",
		func(ctx context.Context, c *core.KeyorixCore) { _, _ = c.UpdateSCIMUser(ctx, 99, 1, nil, nil, &no) },
		func(ctx context.Context, c *core.KeyorixCore) { _, _ = c.UpdateSCIMUser(ctx, 99, 2, nil, nil, &no) },
	)
	assert.Zero(t, bothGone, "%d/%d trials deactivated BOTH admins, stranding the install with zero admins", bothGone, lastAdminRaceTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH deactivations (should allow exactly one)", neitherGone, lastAdminRaceTrials)
}

// TestConcurrency_DeprovisionSCIMUser_ExactlyOneOfTwoAdminsRemoved is the #G03
// regression for scim.go's DeprovisionSCIMUser (SCIM DELETE): it held NO lock at
// all before this fix, so it raced not only with itself but with every sibling
// accountStateMu-guarded path too.
func TestConcurrency_DeprovisionSCIMUser_ExactlyOneOfTwoAdminsRemoved(t *testing.T) {
	t.Parallel()
	bothGone, neitherGone := runTwoAdminRace(t, "scim_deprovision",
		func(ctx context.Context, c *core.KeyorixCore) { _ = c.DeprovisionSCIMUser(ctx, 99, 1) },
		func(ctx context.Context, c *core.KeyorixCore) { _ = c.DeprovisionSCIMUser(ctx, 99, 2) },
	)
	assert.Zero(t, bothGone, "%d/%d trials deprovisioned BOTH admins, stranding the install with zero admins", bothGone, lastAdminRaceTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH deprovisions (should allow exactly one)", neitherGone, lastAdminRaceTrials)
}

// TestConcurrency_RemoveProjectMember_ExactlyOneOfTwoProjectAdminsRemoved is the
// #G03 regression for project_members.go's guardLastProjectAdmin: two concurrent
// RemoveProjectMember calls, each targeting a different one of a project's two
// roles.assign-holding members.
func TestConcurrency_RemoveProjectMember_ExactlyOneOfTwoProjectAdminsRemoved(t *testing.T) {
	t.Parallel()
	const trials = 50
	var bothRemoved, neitherRemoved int
	for range trials {
		dsn := "file:" + filepath.Join(t.TempDir(), "project_member.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(
			&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
			&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
			&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SecretNode{},
			&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		))
		require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "roles.assign"}).Error)
		require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
		require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
		require.NoError(t, db.Create(&models.User{ID: 1, Username: "a"}).Error)
		require.NoError(t, db.Create(&models.User{ID: 2, Username: "b"}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 1}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10, ProjectID: 1}).Error)

		c := core.NewKeyorixCore(store.NewLocalStorage(db))
		ctx := context.Background()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = c.RemoveProjectMember(ctx, 99, 1, 1) }()
		go func() { defer wg.Done(); <-start; _ = c.RemoveProjectMember(ctx, 99, 1, 2) }()
		close(start)
		wg.Wait()

		var count int64
		require.NoError(t, db.Model(&models.UserRole{}).Where("project_id = ?", 1).Count(&count).Error)
		switch count {
		case 0:
			bothRemoved++
		case 2:
			neitherRemoved++
		}
	}
	assert.Zero(t, bothRemoved, "%d/%d trials removed BOTH project admins, stranding the project with zero roles.assign holders", bothRemoved, trials)
	assert.Zero(t, neitherRemoved, "%d/%d trials refused BOTH removals (should allow exactly one)", neitherRemoved, trials)
}

// The TOCTOU-1 regression for rbac_management.go's RemoveUserRole
// (project-scope branch: the named lock covered only the guard's read, not the
// write that followed) is NOT covered by a plain goroutine race here, unlike
// the trials above. A 2-way (and even an 8-way) timing race against it,
// empirically, could not land the bug reliably: the winning goroutine's
// unguarded write is a single round trip after its own unlock, while a losing
// goroutine needs two (lock-acquire, then read) before it could even observe
// stale data -- a structural head start that consistently let the write land
// first. See TestConcurrency_RemoveUserRole_ProjectScope_TOCTOU_Deterministic
// (concurrency_remove_user_role_toctou_test.go) for the deterministic
// reproduction (a storage decorator that pauses the real write call so the
// exact vulnerable interleaving lands every time), and
// TestConcurrency_RemoveUserRole_ProjectScope_CrossReplicaPostgres
// (concurrency_remove_user_role_project_postgres_test.go) for the same
// technique across two genuinely independent Postgres connections.
