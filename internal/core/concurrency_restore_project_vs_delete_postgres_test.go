// concurrency_restore_project_vs_delete_postgres_test.go — #2723, #2724.
//
// deleteProjectCascade's #2656 project lock was written with GORM's default
// scope, which appends `deleted_at IS NULL`. On an ALREADY-deleted project that
// matched zero rows and locked NOTHING — and that is exactly the case where a
// concurrent RestoreProject has to be excluded. RestoreProject took no lock on
// the project row either; it was locked only by its own final UPDATE, after both
// child UPDATEs had already run.
//
// Every other statement in the cascade is `deleted_at IS NULL`-scoped too, so
// under READ COMMITTED:
//
//	B's cascade locks nothing (project already deleted), its secret and
//	environment sweeps skip (their snapshots see deleted children)
//	A's restore commits — project, environments and secrets all live
//	B's final `UPDATE projects ... WHERE deleted_at IS NULL` takes a FRESH
//	statement snapshot, sees the project live, deletes it, commits
//
// End state: the project is deleted while every restored environment and secret
// is LIVE under it. No serial order produces that (restore-then-delete sweeps the
// children; delete-then-restore is a no-op on the delete side). The consequences
// are #2702/#2710/#2712's: a live secret under a deleted project is reachable
// through global-scope roles, ACLs and the owner short-circuit, is never purged
// (the purge only collects deleted rows), and outlives the project purge.
//
// WHY NOT THE beforeA HOOK, same reason as the break-glass pair: the fix makes
// the two contend on a Postgres ROW lock, and beforeA runs replica B
// synchronously inside replica A's own callback, on A's goroutine, while A's
// transaction holds that lock. B would wait for a transaction that cannot commit
// until B returns, and the test would hang instead of failing. So:
//
//   - TestCTAReview_DeleteProject_WaitsForARestoreHoldingTheProjectRow_Postgres
//     is the deterministic one: replica A holds the project row with the same
//     unscoped FOR UPDATE the fix added, and B's DeleteProject must not complete
//     until it is released. That is the mutual exclusion the fix provides,
//     asserted directly — and it is red before the fix because the old
//     default-scoped lock never contended on a deleted project's row at all.
//
// There is deliberately NO end-state test here, and the reason is worth writing
// down because it looks like an omission. One was written: 14 iterations racing
// RestoreProject against DeleteProject, asserting "never (project deleted AND
// live children)". It was DELETED, because the red proof showed it never
// reproduced the orphan state even with the fix reverted — it failed only on its
// own non-vacuity floor, i.e. it reported that the scenario had not occurred.
// Unsynchronized goroutines do not hit a window this narrow.
//
// Making it deterministic is impossible by construction, not merely hard. The
// interleaving needs A's restore to COMMIT between B's child sweeps and B's final
// project UPDATE, which a one-shot hook on B can arrange — but only before the
// fix. After it, B holds the project row from its first statement, so A's restore
// blocks inside B's callback and the test hangs instead of passing. A hook-driven
// interleaving test can only exist for the broken version of this code.
//
// So the mechanism is asserted instead of the forbidden end state: mutual
// exclusion on the project row (the pg-gated test above) plus the unscoped-lock
// shape on both sides (TestProjectRowLocks_AreUnscoped, default-ci). Shipping an
// end-state test that passes for the wrong reason would have been worse than
// having none — it would read as coverage of exactly the thing it never exercised.
package core

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// deleteFixtureProject soft-deletes the fixture project through the real cascade
// and asserts it worked, so each test starts from the state #2723 is about: an
// already-deleted project whose children the cascade has swept.
func (f *ctaReview) deleteFixtureProject() {
	f.t.Helper()
	require.NoError(f.t, f.setup.DeleteProject(f.ctx, 0, f.projectID, true))
	var live int64
	require.NoError(f.t, f.setupDB.Model(&models.Project{}).
		Where("id = ? AND deleted_at IS NULL", f.projectID).Count(&live).Error)
	require.Zero(f.t, live, "fixture precondition: the project must be soft-deleted before the race")
}

func TestCTAReview_DeleteProject_WaitsForARestoreHoldingTheProjectRow_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	f.secret("s2723wait", f.adminID)
	f.deleteFixtureProject()

	held := make(chan struct{})
	release := make(chan struct{})
	txDone := make(chan struct{})

	// Release via cleanup, never only on the happy path: a t.Fatalf below would
	// otherwise abort with this transaction still open, holding a row lock that
	// every later statement against this project blocks on. Same lesson as the
	// break-glass lock-wait test, where the equivalent leak hung a parallel test
	// for a full timeout rather than failing.
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		<-txDone
	})

	go func() {
		defer close(txDone)
		// Exactly the lock RestoreProject now takes: by id, UNSCOPED, so it
		// actually lands on a soft-deleted project's row.
		_ = f.dbA.Transaction(func(tx *gorm.DB) error {
			var ids []uint
			if err := tx.Unscoped().Model(&models.Project{}).
				Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("id = ?", f.projectID).Pluck("id", &ids).Error; err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	deleted := make(chan error, 1)
	go func() { deleted <- f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) }()

	select {
	case err := <-deleted:
		t.Fatalf("DeleteProject's cascade completed while another replica held the project row — its lock does "+
			"not contend on an already-deleted project, so a concurrent RestoreProject is not serialized "+
			"against it (#2723/#2724); err=%v", err)
	case <-time.After(750 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	<-txDone
	// The cascade now proceeds and legitimately reports the project already gone.
	require.Error(t, <-deleted, "a re-issued delete of an already-deleted project must still report not-found")
}
