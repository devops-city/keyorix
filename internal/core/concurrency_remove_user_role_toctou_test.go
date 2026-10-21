// concurrency_remove_user_role_toctou_test.go — TOCTOU-1: rbac_management.go's
// RemoveUserRole (project-scope branch) originally acquired projectAdminGuardLockKey
// only around the guard's READ and DECIDE, releasing it BEFORE calling
// removeUserRoleUnguarded -- so the lock never actually serialized the
// read-then-write sequence, only the read.
//
// A plain goroutine race against this (see the two-admin trials in
// concurrency_last_admin_race_test.go's style, and the cross-replica Postgres
// version in concurrency_remove_user_role_project_postgres_test.go) could NOT
// reproduce the bug reliably: the winning goroutine's unguarded write is a single
// round trip after its own unlock, while a waiting goroutine needs two round
// trips (lock-acquire, then read) before it could possibly observe stale data --
// a structural head start that, empirically (30+ trials across 2-way and 8-way
// races, local SQLite and real Postgres), let the winner's write consistently
// land before any loser's read could ever see the pre-write state. That timing
// asymmetry says nothing about correctness -- moving the write inside the lock
// closure is still required, and this file proves it -- it only means a pure
// timing race is the wrong tool to prove it deterministically in CI.
//
// This test instead forces the exact vulnerable interleaving directly, using a
// thin storage.Storage decorator that pauses ONLY the specific RemoveRole call
// RemoveUserRole's write step issues for one target -- no production code is
// touched, and every other call (the guard's read, the guard's decision, the
// second removal) goes through the real, unmodified RemoveUserRole /
// guardLastProjectAdmin / removeUserRoleUnguarded path. This reliably lands the
// interleaving the doc comment on the old code claimed couldn't happen:
//  1. Goroutine A calls RemoveUserRole for admin 1: acquires the lock, reads
//     [admin1, admin2], decides "admin2 survives", then (pre-fix: releases the
//     lock, then; post-fix: still holding the lock) blocks via the decorator
//     right before its own write lands.
//  2. A second goroutine, started once A is confirmed blocked there, calls
//     RemoveUserRole for admin 2 -- it must run in its own goroutine, since
//     post-fix it blocks trying to acquire the same lock admin1 still holds,
//     and calling it synchronously would deadlock this test against the fixed
//     code. The test waits for THIS call to either finish naturally or hit a
//     generous timeout before releasing admin1's write: pre-fix the lock is
//     already free, so admin2's whole guard-and-write sequence (several
//     sequential queries: GetUserRoleIDsExact, ListProjectRoleAssignments,
//     one GetUser per surviving holder) completes well within the window;
//     post-fix admin2's call is genuinely blocked on the lock and never
//     completes, so the timeout always elapses. An earlier version of this
//     test released admin1 as soon as admin2's FIRST guard query started
//     (not finished) -- that left a real window, between admin2's first read
//     and its later ListProjectRoleAssignments/GetUser calls, where admin1's
//     released write could land first and admin2's guard would then correctly
//     (if accidentally, from the test's point of view) refuse it, masking the
//     bug. Waiting for admin2 to actually FINISH (or definitively hang)
//     removes that ambiguity.
//  3. The test releases A's decorator; A's write commits (and, post-fix, A's
//     lock acquisition finally releases, letting step 2's call proceed).
//
// Before the fix: both writes commit -- the project ends with ZERO
// roles.assign holders. After the fix (the write moved inside the SAME
// WithNamedLock acquisition as the read+decide), step 2's RemoveUserRole call
// blocks on the lock until A's ENTIRE closure -- write included -- completes,
// then correctly observes admin1 already removed and refuses to remove the
// last remaining admin.
package core_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// delayedRemoveRoleStorage wraps a real storage.Storage, pausing exactly one
// targeted RemoveRole(userID, roleID, ...) call until released -- signaling
// blocked once it starts waiting, so the test can deterministically sequence a
// second, concurrent call around the pause.
type delayedRemoveRoleStorage struct {
	storage.Storage
	targetUserID, targetRoleID uint
	blocked, release           chan struct{}
}

// WithTransaction wraps the transaction-scoped storage.Storage fn receives
// with an identical decorator sharing this one's channels, so a caller that
// performs its targeted RemoveRole call INSIDE a transaction
// (RevokeBreakGlassActivationAtomic's tx.RemoveRole, break_glass.go) still
// gets paused -- without this override, that RemoveRole call would run on
// the fresh, un-decorated *LocalStorage WithTransaction constructs
// internally (local_transaction.go) and the pause would never fire.
func (d *delayedRemoveRoleStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return d.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&delayedRemoveRoleStorage{
			Storage:      tx,
			targetUserID: d.targetUserID, targetRoleID: d.targetRoleID,
			blocked: d.blocked, release: d.release,
		})
	})
}

func (d *delayedRemoveRoleStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	if userID == d.targetUserID && roleID == d.targetRoleID {
		close(d.blocked)
		<-d.release
	}
	return d.Storage.RemoveRole(ctx, userID, roleID, scope)
}

func TestConcurrency_RemoveUserRole_ProjectScope_TOCTOU_Deterministic(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "remove_user_role_toctou.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.PendingAuditEvent{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Session{},
	))
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "roles.assign"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin1"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "admin2"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10, ProjectID: 1}).Error)

	realStorage := store.NewLocalStorage(db)
	wrapped := &delayedRemoveRoleStorage{
		Storage:      realStorage,
		targetUserID: 1, targetRoleID: 10,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	c := core.NewKeyorixCore(wrapped)
	ctx := context.Background()
	scope := core.Scope{ProjectID: 1}

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = c.RemoveUserRole(ctx, 99, 1, 10, scope)
	}()

	<-wrapped.blocked // admin1's removal has passed the guard and is paused right before its write lands

	// admin2's removal must run in its own goroutine too: pre-fix it completes
	// immediately (the lock was already released before admin1's delayed write),
	// but post-fix it blocks on the SAME lock admin1 still holds through its
	// delayed write -- calling it synchronously here would deadlock this test
	// against the fixed code (this call would never return, so release below
	// would never be reached).
	go func() {
		defer close(doneB)
		errB = c.RemoveUserRole(ctx, 99, 2, 10, scope)
	}()

	// Give admin2's call a generous bounded window to run to COMPLETION before
	// releasing admin1's delayed write -- see the file doc comment for why
	// waiting for completion (not merely "started reading") is required.
	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("remove admin1 result: %v", errA)
	t.Logf("remove admin2 result: %v", errB)

	remainingA, err := realStorage.GetUserRoleIDsExact(ctx, 1, storage.Scope{ProjectID: 1})
	require.NoError(t, err)
	remainingB, err := realStorage.GetUserRoleIDsExact(ctx, 2, storage.Scope{ProjectID: 1})
	require.NoError(t, err)
	aSurvives, bSurvives := len(remainingA) > 0, len(remainingB) > 0

	if !aSurvives && !bSurvives {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED (TOCTOU-1): admin1's guard read the pre-write role "+
			"set, admin2's removal raced in and committed before admin1's own (delayed) write landed, and "+
			"both writes committed -- the project is left with ZERO roles.assign holders (errA=%v errB=%v)",
			errA, errB)
	}
	assert.False(t, !aSurvives && !bSurvives, "at least one of the two racing removals must be refused")
	assert.True(t, aSurvives || bSurvives, "exactly one admin's grant should survive")
}
