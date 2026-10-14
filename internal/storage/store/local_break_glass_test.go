// local_break_glass_test.go — pins that the partial unique index on
// break_glass_activations (project_id, user_id) WHERE state='active' actually closes
// the concurrent-activation race: at most one row for a given (project, user) can be
// 'active' at a time, even when two callers race the insert.
package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newBreakGlassStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}))
	// Mirrors ensureBreakGlassActiveIndex (internal/storage/factory.go) — this is the
	// actual race gate under test, so create it exactly as the real migration does.
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
	).Error)
	return NewLocalStorage(db)
}

// A second active activation for the same (project_id, user_id) is rejected with
// storage.ErrBreakGlassAlreadyActive, not a raw driver error — proving the sentinel
// wiring works end to end (index → OnConflict DoNothing → RowsAffected check).
func TestCreateBreakGlassActivation_RejectsSecondActiveForSameProjectUser(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	first, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)
	assert.NotZero(t, first.ID)

	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrBreakGlassAlreadyActive), "got %v", err)
}

// The index is scoped to state='active' (a PARTIAL unique index), not a plain unique
// index: a second row for the same (project_id, user_id) is fine once the first is no
// longer active (revoked/expired) — that's how re-activation after revoke works.
func TestCreateBreakGlassActivation_AllowsReactivationAfterPriorIsInactive(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	first, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	first.State = "revoked"
	require.NoError(t, ls.UpdateBreakGlassActivation(ctx, first))

	second, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err, "a fresh activation must be allowed once the prior one is no longer active")
	assert.NotEqual(t, first.ID, second.ID)
}

// A DIFFERENT user or project is unaffected by another (project, user)'s active
// activation — the index is scoped to the exact pair, not global.
func TestCreateBreakGlassActivation_DifferentProjectOrUserUnaffected(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	_, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 11, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err, "a different user on the same project is unaffected")

	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 3, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err, "the same user on a different project is unaffected")
}

// The actual concurrency claim: N goroutines racing to activate break-glass for the
// SAME (project, user) must yield exactly one winner — the DB constraint, not
// application-level sequencing, is what closes the race. Uses a real file-backed
// SQLite DB with WAL + a busy timeout (concurrentDB) so connections genuinely
// contend; a single shared in-memory connection would serialize every statement and
// mask the race this test exists to catch.
func TestCreateBreakGlassActivation_ConcurrentRaceYieldsExactlyOneWinner(t *testing.T) {
	ls := newBreakGlassStore(t)

	const racers = 16
	var successes, conflicts, otherErrs atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			_, err := ls.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{
				ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
			})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, storage.ErrBreakGlassAlreadyActive):
				conflicts.Add(1)
			default:
				otherErrs.Add(1)
			}
		})
	}
	close(start) // release all racers at once
	wg.Wait()

	assert.Zero(t, otherErrs.Load(), "every losing racer must fail with the sentinel, not some other error")
	assert.EqualValues(t, 1, successes.Load(), "exactly one concurrent activation must win, regardless of goroutine scheduling")
	assert.EqualValues(t, racers-1, conflicts.Load())

	// And the database agrees: exactly one 'active' row exists for this (project, user).
	var count int64
	require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).
		Where("project_id = ? AND user_id = ? AND state = ?", 2, 10, "active").
		Count(&count).Error)
	assert.EqualValues(t, 1, count)
}

// TestBreakGlassReads_NeverPersistState is #1653's durable guard, rewritten
// for the new target state (2026-09-02): the original guard question was "no
// authorization decision reads BreakGlassActivation.State" -- correct
// question, and the answer turned out to be no (core.RevokeBreakGlass's own
// guard, and its remote-storage-proxy mirror, both did). The actual defect
// was upstream of that: ListBreakGlassActivations, a read path, computed a
// wall-clock transition and PERSISTED it -- a list/get endpoint writing
// access-control-adjacent state is a defect on its own terms, independent of
// clocks, because it means a benign read by anyone who can list/get
// activations is what triggers the write. Once State is a genuine read-time
// projection (projectEffectiveBreakGlassState), the durable invariant this
// fix establishes -- the one a future change would break -- is: neither
// GetBreakGlassActivation nor ListBreakGlassActivations EVER writes. This
// test proves it directly: seed a TTL-lapsed 'active' row, call both read
// functions, then re-query the row's raw persisted state and assert it is
// UNCHANGED. See ReconcileExpiredBreakGlassActivation for the one place
// (a mutating operation, ActivateBreakGlass) a TTL-lapse transition is ever
// actually written.
func TestBreakGlassReads_NeverPersistState(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)

	seeded, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active", ExpiresAt: &past,
	})
	require.NoError(t, err)

	got, err := ls.GetBreakGlassActivation(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, "expired", got.State, "GetBreakGlassActivation must project the TTL-lapse for the caller")

	list, err := ls.ListBreakGlassActivations(ctx, 2)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "expired", list[0].State, "ListBreakGlassActivations must project the TTL-lapse for the caller")

	var stored models.BreakGlassActivation
	require.NoError(t, ls.db.First(&stored, seeded.ID).Error)
	assert.Equal(t, "active", stored.State,
		"neither read above may have persisted the projection -- the row's real, stored state must be unchanged")
}

// TestReconcileExpiredBreakGlassActivation_TransitionsOnlyTheMatchingRow is
// the ONE place a TTL-lapse transition is actually persisted (see
// ActivateBreakGlass, its sole caller) -- it must flip exactly the row named
// by (projectID, userID) that is still 'active' and past its expiry, and
// leave every other row (different project/user, already revoked, not yet
// expired, permanent/no-expiry) untouched.
func TestReconcileExpiredBreakGlassActivation_TransitionsOnlyTheMatchingRow(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	target, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "active", ExpiresAt: &past,
	})
	require.NoError(t, err)

	// Different user, same project, also expired -- must stay untouched.
	otherUser, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 11, RoleID: 3, RoleName: "editor", State: "active", ExpiresAt: &past,
	})
	require.NoError(t, err)

	// Same (project, user) but not yet expired -- must stay 'active'.
	notExpired, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active", ExpiresAt: &future,
	})
	require.NoError(t, err)

	// Permanent grant (no expiry) for the same (project, user) -- must never
	// be reconciled regardless of how much time has passed.
	permanent, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 3, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	require.NoError(t, ls.ReconcileExpiredBreakGlassActivation(ctx, 1, 10))

	var got1 models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got1, target.ID).Error)
	assert.Equal(t, "expired", got1.State, "the matching, expired, still-active row must transition")

	var got2 models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got2, otherUser.ID).Error)
	assert.Equal(t, "active", got2.State, "a different user's expired row must not be touched")

	var got3 models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got3, notExpired.ID).Error)
	assert.Equal(t, "active", got3.State, "a not-yet-expired row for the same user must stay active")

	var got4 models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got4, permanent.ID).Error)
	assert.Equal(t, "active", got4.State, "a permanent (no ExpiresAt) grant must never be reconciled to expired")
}

// A row already revoked must not be reverted to 'expired' by a later
// reconcile -- Reconcile only ever transitions FROM active, never from
// revoked (#1653's "revoked always wins" invariant).
func TestReconcileExpiredBreakGlassActivation_LeavesRevokedRowAlone(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)

	activation, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "active", ExpiresAt: &past,
	})
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).Where("id = ?", activation.ID).
		Update("state", "revoked").Error)

	require.NoError(t, ls.ReconcileExpiredBreakGlassActivation(ctx, 1, 10))

	var got models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got, activation.ID).Error)
	assert.Equal(t, "revoked", got.State, "a revoked row must never be reverted to expired by a later reconcile")
}

// No matching row at all is a harmless no-op, not an error.
func TestReconcileExpiredBreakGlassActivation_NoMatchIsNoop(t *testing.T) {
	ls := newBreakGlassStore(t)
	require.NoError(t, ls.ReconcileExpiredBreakGlassActivation(context.Background(), 404, 404))
}

// ReviewBreakGlassActivation records the reviewer, timestamp, and note.
func TestReviewBreakGlassActivation_RecordsReviewerAndNote(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	activation, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ls.ReviewBreakGlassActivation(ctx, activation.ID, 99, "checked the justification, looks legitimate", now))

	var got models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got, activation.ID).Error)
	assert.Equal(t, uint(99), got.ReviewedBy)
	assert.Equal(t, "checked the justification, looks legitimate", got.ReviewNote)
	require.NotNil(t, got.ReviewedAt)
	assert.Equal(t, now, got.ReviewedAt.UTC())
}

// A second review attempt on an already-reviewed activation is refused with
// ErrBreakGlassAlreadyReviewed, not a silent overwrite of the first review.
func TestReviewBreakGlassActivation_SecondAttemptIsRefused(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	activation, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	require.NoError(t, ls.ReviewBreakGlassActivation(ctx, activation.ID, 99, "first review", now))

	err = ls.ReviewBreakGlassActivation(ctx, activation.ID, 100, "second review attempt", now)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrBreakGlassAlreadyReviewed)

	// The first review must be untouched.
	var got models.BreakGlassActivation
	require.NoError(t, ls.db.First(&got, activation.ID).Error)
	assert.Equal(t, uint(99), got.ReviewedBy)
	assert.Equal(t, "first review", got.ReviewNote)
}

// A review is allowed regardless of the activation's state -- a revoked
// activation can still (and should) be reviewed.
func TestReviewBreakGlassActivation_AllowedOnRevokedActivation(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	activation, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "revoked",
	})
	require.NoError(t, err)

	require.NoError(t, ls.ReviewBreakGlassActivation(ctx, activation.ID, 99, "reviewed after revoke", time.Now().UTC()))
}

// Reviewing a nonexistent activation ID is a no-op error (RowsAffected==0),
// same shape as RevokeBreakGlassActivation's own not-found handling.
func TestReviewBreakGlassActivation_NonexistentID(t *testing.T) {
	ls := newBreakGlassStore(t)
	err := ls.ReviewBreakGlassActivation(context.Background(), 404, 99, "no such activation", time.Now().UTC())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrBreakGlassAlreadyReviewed)
}

// ListUnreviewedBreakGlassActivationsBefore returns only unreviewed rows at
// or before cutoff, across every project, oldest first.
func TestListUnreviewedBreakGlassActivationsBefore_FiltersCorrectly(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	old, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).Where("id = ?", old.ID).
		Update("created_at", time.Now().UTC().Add(-48*time.Hour)).Error)

	recent, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 11, RoleID: 4, RoleName: "viewer", State: "active",
	})
	require.NoError(t, err)

	reviewed, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 3, UserID: 12, RoleID: 5, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).Where("id = ?", reviewed.ID).
		Update("created_at", time.Now().UTC().Add(-48*time.Hour)).Error)
	require.NoError(t, ls.ReviewBreakGlassActivation(ctx, reviewed.ID, 99, "already handled", time.Now().UTC()))

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	rows, err := ls.ListUnreviewedBreakGlassActivationsBefore(ctx, cutoff)
	require.NoError(t, err)

	var gotIDs []uint
	for _, r := range rows {
		gotIDs = append(gotIDs, r.ID)
	}
	assert.Contains(t, gotIDs, old.ID, "old + unreviewed must appear")
	assert.NotContains(t, gotIDs, recent.ID, "recent (not yet past the cutoff) must not appear")
	assert.NotContains(t, gotIDs, reviewed.ID, "already-reviewed must not appear even though it's old")
}
