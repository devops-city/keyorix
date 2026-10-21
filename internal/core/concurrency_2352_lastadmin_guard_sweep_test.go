// concurrency_2352_lastadmin_guard_sweep_test.go — SESSION-AT #2352: every
// path that can remove the install's (or a project's) last admin must
// serialize its guard check AND its write under the SAME named lock,
// across every replica. The sweep found and fixed five real gaps:
//
//  1. RemoveUserFromGroup (groups.go) — guard ran with no lock at all.
//  2. RemoveRoleFromGroup (rbac_management.go), global scope — guard ran
//     with no lock at all.
//  3. RemoveRoleFromGroup, project scope — DID take projectAdminGuardLockKey,
//     but released it before the write (the identical TOCTOU-1 shape
//     concurrency_remove_user_role_toctou_test.go already fixed for
//     RemoveUserRole).
//  4. PatchSCIMGroup/applyGroupMembershipChanges (scim_groups.go) — guard
//     ran with no lock at all.
//  5. DeprovisionSCIMGroup (scim_groups.go) — called storage.DeleteGroup
//     DIRECTLY, bypassing every guard AND DeleteGroup's own lock entirely.
//
// Plus a SIXTH, previously undiscovered gap this sweep's own analysis
// surfaced: DeleteGroup's existing lock (PR #2348) used ONLY
// lastAdminGuardLockKey (the global key) for its project-admin check,
// while every other project-admin-affecting operation
// (RemoveProjectMember/SetProjectMemberRole/RemoveUserRole/RemoveRoleFromGroup)
// uses projectAdminGuardLockKey(projectID) instead — two DIFFERENT lock
// domains for the SAME invariant, so DeleteGroup was never actually
// serialized against any of the other four. Fixed via
// withGroupProjectAdminGuardLocks (project_members.go), which every
// group-wide operation above now shares.
package core_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const lastAdminSweepTrials = 50

// isGuardRefusal reports whether err is one of the last-admin guards' own
// refusal messages, not a generic/storage error — guardLastProjectAdmin
// (direct user removal) and the group-path guards
// (guardLastGlobalAdminGroupDelete/GroupRole/Membership,
// guardLastProjectAdminGroupDelete/Role/Membership) use two different fixed
// phrasings, both asserted here, so a trial can't "pass" by coincidentally
// returning some other, unrelated error.
func isGuardRefusal(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "refusing to") || strings.Contains(msg, "last administrator")
}

// raceTwoOps runs opA and opB concurrently from one start barrier, returning
// each one's error.
func raceTwoOps(opA, opB func() error) (errA, errB error) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; errA = opA() }()
	go func() { defer wg.Done(); <-start; errB = opB() }()
	close(start)
	wg.Wait()
	return errA, errB
}

func sqliteDB(t *testing.T, name string) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), name) + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PendingAuditEvent{}, &models.PersonalAccessToken{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Project{}, &models.Environment{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.SecretNode{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
	))
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "roles.assign"}).Error)
	return db
}

func groupGone(db *gorm.DB, groupID uint) bool {
	var g models.Group
	return db.First(&g, groupID).Error != nil
}

func membershipGone(db *gorm.DB, userID, groupID uint) bool {
	var n int64
	require1 := db.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", userID, groupID).Count(&n)
	return require1.Error == nil && n == 0
}

func groupRoleGone(db *gorm.DB, groupID, roleID uint, projectID uint) bool {
	var n int64
	_ = db.Model(&models.GroupRole{}).Where("group_id = ? AND role_id = ? AND project_id = ?", groupID, roleID, projectID).Count(&n)
	return n == 0
}

// --- 1. RemoveUserFromGroup, global scope -----------------------------------

// newTwoGlobalAdminGroupMembershipFixture: two groups (10, 20) each hold the
// install's only global "admin" role; each has exactly one distinct member
// (user 1 in group 10, user 2 in group 20). Removing BOTH memberships leaves
// zero admins.
func newTwoGlobalAdminGroupMembershipFixture(t *testing.T, name string) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	db := sqliteDB(t, name)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "admin-group-a"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 20, Name: "admin-group-b"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 20, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 20}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestConcurrency_RemoveUserFromGroup_GlobalScope_ExactlyOneOfTwoAdminRoutesRemoved(t *testing.T) {
	t.Parallel()
	var bothGone, neitherGone, badErr int
	for range lastAdminSweepTrials {
		c, db := newTwoGlobalAdminGroupMembershipFixture(t, "remove_user_from_group.db")
		ctx := context.Background()
		errA, errB := raceTwoOps(
			func() error { return c.RemoveUserFromGroup(ctx, 99, 1, 10, 0) },
			func() error { return c.RemoveUserFromGroup(ctx, 99, 2, 20, 0) },
		)
		aGone, bGone := membershipGone(db, 1, 10), membershipGone(db, 2, 20)
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
		if aGone && !isGuardRefusalOrNil(errB) || bGone && !isGuardRefusalOrNil(errA) {
			badErr++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials removed BOTH admin-route memberships, stranding the install with zero admins", bothGone, lastAdminSweepTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH removals (should allow exactly one)", neitherGone, lastAdminSweepTrials)
	assert.Zero(t, badErr, "%d/%d trials: the losing call's error was not the guard's own refusal message", badErr, lastAdminSweepTrials)
}

// isGuardRefusalOrNil: the WINNING call's error should be nil (its removal
// succeeded); only the LOSER should see a guard refusal. This helper lets
// the same post-trial check apply regardless of which of the two calls won.
func isGuardRefusalOrNil(err error) bool {
	return err == nil || isGuardRefusal(err)
}

// --- 2. RemoveRoleFromGroup, global scope ------------------------------------

func newTwoGlobalAdminGroupRoleFixture(t *testing.T, name string) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	db := sqliteDB(t, name)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "admin-group-a"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 20, Name: "admin-group-b"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 20, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 20}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestConcurrency_RemoveRoleFromGroup_GlobalScope_ExactlyOneOfTwoAdminRoutesRemoved(t *testing.T) {
	t.Parallel()
	var bothGone, neitherGone, badErr int
	for range lastAdminSweepTrials {
		c, db := newTwoGlobalAdminGroupRoleFixture(t, "remove_role_from_group_global.db")
		ctx := context.Background()
		errA, errB := raceTwoOps(
			func() error { return c.RemoveRoleFromGroup(ctx, 99, 10, 10, core.Scope{}) },
			func() error { return c.RemoveRoleFromGroup(ctx, 99, 20, 10, core.Scope{}) },
		)
		aGone, bGone := groupRoleGone(db, 10, 10, 0), groupRoleGone(db, 20, 10, 0)
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
		if (aGone && !isGuardRefusalOrNil(errB)) || (bGone && !isGuardRefusalOrNil(errA)) {
			badErr++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials removed BOTH groups' admin role grant, stranding the install with zero admins", bothGone, lastAdminSweepTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH removals (should allow exactly one)", neitherGone, lastAdminSweepTrials)
	assert.Zero(t, badErr, "%d/%d trials: the losing call's error was not the guard's own refusal message", badErr, lastAdminSweepTrials)
}

// --- 3. RemoveRoleFromGroup, project scope: deterministic TOCTOU ------------

// delayedRemoveRoleFromGroupStorage pauses exactly one targeted
// RemoveRoleFromGroup(groupID, roleID, scope) call right before it runs,
// signaling blocked once it starts waiting — same technique as
// concurrency_remove_user_role_toctou_test.go's delayedRemoveRoleStorage,
// applied to the group-role storage call instead of the direct-user one.
type delayedRemoveRoleFromGroupStorage struct {
	storage.Storage
	targetGroupID, targetRoleID uint
	blocked, release            chan struct{}
}

// WithTransaction re-wraps the transaction handle so the pause still fires now that
// the targeted call runs INSIDE the mutation's audited transaction (AUDIT-TX-3):
// without it the call would hit the undecorated store the transaction builds.
func (d *delayedRemoveRoleFromGroupStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return d.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		wrapped := *d
		wrapped.Storage = tx
		return fn(&wrapped)
	})
}

func (d *delayedRemoveRoleFromGroupStorage) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	if groupID == d.targetGroupID && roleID == d.targetRoleID {
		close(d.blocked)
		<-d.release
	}
	return d.Storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope)
}

// TestConcurrency_RemoveRoleFromGroup_ProjectScope_TOCTOU_Deterministic forces
// the exact interleaving a plain timing race can't reliably reproduce (see
// concurrency_remove_user_role_toctou_test.go's doc comment for why): group
// A's RemoveRoleFromGroup passes its guard and is paused right before its
// storage write; group B's RemoveRoleFromGroup is given a generous window to
// run to completion while A is still paused. Pre-fix (lock released before
// the write), B's call completes fully within that window because the lock
// was already free — both groups' project-admin role grant ends up removed.
// Post-fix (write moved inside the same WithNamedLock acquisition as the
// guard), B blocks on the lock A still holds and never completes in the
// window.
func TestConcurrency_RemoveRoleFromGroup_ProjectScope_TOCTOU_Deterministic(t *testing.T) {
	db := sqliteDB(t, "remove_role_from_group_project_toctou.db")
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "group-a"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 20, Name: "group-b"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 10, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 20, RoleID: 10, ProjectID: 1}).Error)
	// resolveProjectAdminHolders expands a group's grant to its LIVE members --
	// an admin-holding group with zero members resolves to zero holders (same
	// rule resolveGlobalAdminHolders applies at the global scope), so each
	// group needs at least one member or guardLastProjectAdminGroupRole would
	// refuse BOTH removals outright and the race would never reach either
	// write.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 20}).Error)

	realStorage := store.NewLocalStorage(db)
	wrapped := &delayedRemoveRoleFromGroupStorage{
		Storage:       realStorage,
		targetGroupID: 10, targetRoleID: 10,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	c := core.NewKeyorixCore(wrapped)
	ctx := context.Background()
	scope := core.Scope{ProjectID: 1}

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = c.RemoveRoleFromGroup(ctx, 99, 10, 10, scope)
	}()

	<-wrapped.blocked // group A's removal passed the guard, paused right before its write

	go func() {
		defer close(doneB)
		errB = c.RemoveRoleFromGroup(ctx, 99, 20, 10, scope)
	}()

	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("remove group-a's role result: %v", errA)
	t.Logf("remove group-b's role result: %v", errB)

	aGone, bGone := groupRoleGone(db, 10, 10, 1), groupRoleGone(db, 20, 10, 1)
	if aGone && bGone {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED (project-scope TOCTOU): group A's guard read the "+
			"pre-write grant set, group B's removal raced in and committed before group A's own (delayed) "+
			"write landed, and both writes committed -- the project is left with ZERO roles.assign holders "+
			"(errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, aGone && bGone, "both groups' project-admin grant must not be removable concurrently")
}

// --- 4. SCIM PatchSCIMGroup membership removal -------------------------------

func TestConcurrency_PatchSCIMGroup_ExactlyOneOfTwoAdminRoutesRemoved(t *testing.T) {
	t.Parallel()
	var bothGone, neitherGone int
	for range lastAdminSweepTrials {
		c, db := newTwoGlobalAdminGroupMembershipFixture(t, "patch_scim_group.db")
		ctx := context.Background()
		_, _ = raceTwoOps(
			func() error { _, err := c.PatchSCIMGroup(ctx, 99, 10, nil, nil, []uint{1}); return err },
			func() error { _, err := c.PatchSCIMGroup(ctx, 99, 20, nil, nil, []uint{2}); return err },
		)
		aGone, bGone := membershipGone(db, 1, 10), membershipGone(db, 2, 20)
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials SCIM-removed BOTH admin-route memberships, stranding the install with zero admins", bothGone, lastAdminSweepTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH SCIM removals (should allow exactly one)", neitherGone, lastAdminSweepTrials)
}

// --- 5. DeprovisionSCIMGroup --------------------------------------------------

func TestConcurrency_DeprovisionSCIMGroup_ExactlyOneOfTwoAdminGroupsRemoved(t *testing.T) {
	t.Parallel()
	var bothGone, neitherGone int
	for range lastAdminSweepTrials {
		c, db := newTwoGlobalAdminGroupMembershipFixture(t, "deprovision_scim_group.db")
		ctx := context.Background()
		_, _ = raceTwoOps(
			func() error { return c.DeprovisionSCIMGroup(ctx, 99, 10) },
			func() error { return c.DeprovisionSCIMGroup(ctx, 99, 20) },
		)
		aGone, bGone := groupGone(db, 10), groupGone(db, 20)
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials SCIM-deleted BOTH admin groups, stranding the install with zero admins", bothGone, lastAdminSweepTrials)
	assert.Zero(t, neitherGone, "%d/%d trials refused BOTH SCIM deletes (should allow exactly one)", neitherGone, lastAdminSweepTrials)
}

// --- 6. Cross-path: DeleteGroup vs RemoveProjectMember -----------------------

// newGroupVsDirectProjectAdminFixture: project 1 has exactly TWO routes to
// roles.assign authority -- group 10's project-scoped role grant (member:
// user 1), and user 2's own direct project-scoped role grant. This is
// EXACTLY the scenario the lock-domain mismatch this sweep found could not
// protect: DeleteGroup(10) used only the GLOBAL lock, RemoveProjectMember(2)
// only the PER-PROJECT lock -- two different lock domains for the same
// invariant, so neither call was ever actually serialized against the
// other.
func newGroupVsDirectProjectAdminFixture(t *testing.T, name string) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	db := sqliteDB(t, name)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "group-a"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 10, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10, ProjectID: 1}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// projectHasNoAdmin reports whether BOTH of project 1's two roles.assign
// routes are gone: group 10 soft-deleted (DeleteGroup soft-deletes the GROUP
// row -- it does NOT cascade-delete the GroupRole join row itself; a live
// authorization check excludes a soft-deleted group's grants by filtering on
// the group's own deleted_at, not by the join row's mere absence, so
// checking groupGone is the correct liveness test here, not GroupRole
// row-count) AND user 2's direct grant gone.
func projectHasNoAdmin(db *gorm.DB, groupID uint) bool {
	var userGrants int64
	_ = db.Model(&models.UserRole{}).Where("user_id = ? AND project_id = ?", 2, 1).Count(&userGrants)
	return groupGone(db, groupID) && userGrants == 0
}

func TestConcurrency_DeleteGroup_RemoveProjectMember_CrossPath_NeverStripsBothAdminRoutes(t *testing.T) {
	t.Parallel()
	var bothGone int
	for range lastAdminSweepTrials {
		c, db := newGroupVsDirectProjectAdminFixture(t, "deletegroup_vs_removeprojectmember.db")
		ctx := context.Background()
		_, _ = raceTwoOps(
			func() error { return c.DeleteGroup(ctx, 99, 10) },
			func() error { return c.RemoveProjectMember(ctx, 99, 1, 2) },
		)
		if projectHasNoAdmin(db, 10) {
			bothGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials: DeleteGroup and RemoveProjectMember together stripped project 1's ONLY two roles.assign routes, leaving it with zero administrators (the lock-domain-mismatch bug this sweep found: DeleteGroup used the global key, RemoveProjectMember the per-project key)", bothGone, lastAdminSweepTrials)
}

// delayedDeleteGroupStorage pauses exactly one targeted storage.DeleteGroup(id)
// call right before it runs, signaling blocked once it starts waiting -- same
// technique as delayedRemoveRoleFromGroupStorage above, applied to DeleteGroup's
// own write instead of RemoveRoleFromGroup's.
type delayedDeleteGroupStorage struct {
	storage.Storage
	targetGroupID    uint
	blocked, release chan struct{}
}

// WithTransaction re-wraps the transaction handle so the pause still fires now that
// the targeted call runs INSIDE the mutation's audited transaction (AUDIT-TX-3):
// without it the call would hit the undecorated store the transaction builds.
func (d *delayedDeleteGroupStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return d.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		wrapped := *d
		wrapped.Storage = tx
		return fn(&wrapped)
	})
}

func (d *delayedDeleteGroupStorage) DeleteGroup(ctx context.Context, id uint) error {
	if id == d.targetGroupID {
		close(d.blocked)
		<-d.release
	}
	return d.Storage.DeleteGroup(ctx, id)
}

// TestConcurrency_DeleteGroup_RemoveProjectMember_CrossPath_TOCTOU_Deterministic
// forces the exact interleaving the plain timing race above could not reliably
// reproduce (confirmed empirically: 0/50 trials on the UNFIXED code -- DeleteGroup's
// guard chain runs several more queries than RemoveProjectMember's, a structural
// head start that consistently let one side's write land before the other's read
// could observe the pre-write state, the same timing-asymmetry phenomenon
// concurrency_remove_user_role_toctou_test.go's own doc comment documents for its
// bug). DeleteGroup's actual storage write is paused right after its OWN guards
// pass (having seen RemoveProjectMember's direct grant still present);
// RemoveProjectMember is given a generous window to run to completion while
// DeleteGroup is still paused.
//
// Pre-fix: DeleteGroup held only lastAdminGuardLockKey (global); RemoveProjectMember
// holds only projectAdminGuardLockKey(1) -- two different lock domains, so
// RemoveProjectMember is never blocked at all and completes well within the
// window, its own guard seeing the group's grant still present (DeleteGroup's
// write hasn't landed yet) and passing. Releasing DeleteGroup's write then commits
// the group deletion too -- both of project 1's only two roles.assign routes gone.
//
// Post-fix: DeleteGroup holds BOTH the global key AND projectAdminGuardLockKey(1)
// (withGroupProjectAdminGuardLocks) for its ENTIRE guard+write. RemoveProjectMember
// needs the SAME per-project key, so it blocks on DeleteGroup's lock and cannot
// complete within the window.
func TestConcurrency_DeleteGroup_RemoveProjectMember_CrossPath_TOCTOU_Deterministic(t *testing.T) {
	_, db := newGroupVsDirectProjectAdminFixture(t, "deletegroup_vs_removeprojectmember_toctou.db")
	realStorage := store.NewLocalStorage(db)
	wrapped := &delayedDeleteGroupStorage{
		Storage: realStorage, targetGroupID: 10,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	cWrapped := core.NewKeyorixCore(wrapped)
	ctx := context.Background()

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = cWrapped.DeleteGroup(ctx, 99, 10)
	}()

	<-wrapped.blocked // DeleteGroup passed both its guards, paused right before its write

	go func() {
		defer close(doneB)
		errB = cWrapped.RemoveProjectMember(ctx, 99, 1, 2)
	}()

	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("DeleteGroup result: %v", errA)
	t.Logf("RemoveProjectMember result: %v", errB)

	if projectHasNoAdmin(db, 10) {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED ACROSS LOCK DOMAINS: DeleteGroup's guard read the "+
			"pre-write grant set, RemoveProjectMember raced in on a DIFFERENT lock and committed before "+
			"DeleteGroup's own (delayed) write landed, and both writes committed -- project 1 is left with "+
			"ZERO roles.assign holders (errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, projectHasNoAdmin(db, 10), "DeleteGroup and RemoveProjectMember must not both succeed concurrently")
}

// --- 7. Cross-path: RemoveUserFromGroup vs DeleteUser ------------------------

// newGroupVsDirectGlobalAdminFixture: the install has exactly TWO routes to
// global admin authority -- user 1's membership in group 10 (which holds the
// admin role), and user 2's own direct global-scope admin role grant.
func newGroupVsDirectGlobalAdminFixture(t *testing.T, name string) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	db := sqliteDB(t, name)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|b"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "admin-group"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 10, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestConcurrency_RemoveUserFromGroup_DeleteUser_CrossPath_NeverStripsBothAdminRoutes(t *testing.T) {
	t.Parallel()
	var bothGone int
	for range lastAdminSweepTrials {
		c, db := newGroupVsDirectGlobalAdminFixture(t, "removeuserfromgroup_vs_deleteuser.db")
		ctx := context.Background()
		_, _ = raceTwoOps(
			func() error { return c.RemoveUserFromGroup(ctx, 99, 1, 10, 0) },
			func() error { return c.DeleteUser(ctx, 99, 2) },
		)
		membershipDone := membershipGone(db, 1, 10)
		var u2 models.User
		userDeleted := db.First(&u2, 2).Error != nil
		if membershipDone && userDeleted {
			bothGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d trials: RemoveUserFromGroup and DeleteUser together stripped the install's ONLY two global-admin routes, leaving zero administrators", bothGone, lastAdminSweepTrials)
}
