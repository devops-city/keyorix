package core

// update_user_deactivate_owed_audit_test.go — AUDIT-TX-3 item 2.
//
// UpdateUser's deactivating branch is a revocation: it is never blocked by the
// audit log (Andrei 2026-10-14), and its user.updated row must be written without
// ever being a second writer behind the write gate its own transaction holds (the
// SQLite self-deadlock shape DEADLOCK-SHAPE-1 fixed for the cleanup-failure row).
// The row is recorded as an owed-audit record inside the deactivation's
// transaction and appended after the commit (withOwedAuditMutation); a refused
// append leaves the record for BackfillPendingAuditEvents.
//
// The SQLite leg opens the store the way production does (the storage factory, so
// the real in-process write gate is in place: a bare gorm.Open has no gate and
// would not reproduce a self-deadlock). Assertions are on persisted rows.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (w *txClosureWorld) pendingCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&models.PendingAuditEvent{}).Count(&n).Error)
	return n
}

// TestUpdateUser_DeactivateAuditInOwnTransaction_NoSQLiteDeadlock: a deactivation
// writes its user.updated row, with the PAT/session cleanup failing too (so both
// the owed row and the cleanup-failure row are in play), and returns instead of
// waiting on the write gate it holds.
func TestUpdateUser_DeactivateAuditInOwnTransaction_NoSQLiteDeadlock(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		id := w.seedDeactivationTarget(t, "owed")
		w.fs.Arm(&faultstorage.FaultSpec{
			Method: "RevokeAllPersonalAccessTokensForUser", NthCall: 1, Kind: faultstorage.KindError,
			Err: errors.New("simulated cleanup failure"),
		})
		off := false
		runWithDeadline(t, 30*time.Second, func() {
			_, err := w.c.UpdateUser(context.Background(), &UpdateUserRequest{ID: id, IsActive: &off})
			require.NoError(t, err, "a deactivation is never failed by its audit row or its cleanup")
		})
		require.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")
		w.fs.Arm(nil)

		var after models.User
		require.NoError(t, w.db.First(&after, id).Error)
		assert.False(t, after.IsActive, "the user must be inactive")
		assert.Equal(t, int64(1), w.auditCount(t, EventUserUpdated), "exactly one user.updated row, appended after the commit")
		assert.Equal(t, int64(1), w.auditCount(t, EventUserDeactivationCleanupFailed))
		assert.Zero(t, w.pendingCount(t), "an appended row leaves nothing queued")
	})
}

// TestUpdateUser_DeactivateAuditRefused_RowIsOwedAndBackfilled: the audit log
// refuses the append; the deactivation stands and its row is queued, then written
// exactly once by the backfill.
func TestUpdateUser_DeactivateAuditRefused_RowIsOwedAndBackfilled(t *testing.T) {
	for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError, faultstorage.KindPanic} {
		t.Run(fk.String(), func(t *testing.T) {
			txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
				id := w.seedDeactivationTarget(t, "refused")
				w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: fk, Err: errors.New("audit log refused")})
				off := false
				runWithDeadline(t, 30*time.Second, func() {
					_, err := w.c.UpdateUser(context.Background(), &UpdateUserRequest{ID: id, IsActive: &off})
					require.NoError(t, err, "a deactivation is never blocked by the audit log")
				})
				require.True(t, w.fs.Fired())
				w.fs.Arm(nil)

				var after models.User
				require.NoError(t, w.db.First(&after, id).Error)
				assert.False(t, after.IsActive, "the user must be inactive")
				assert.Zero(t, w.auditCount(t, EventUserUpdated), "the append was refused")
				assert.Equal(t, int64(1), w.pendingCount(t), "the row is owed: queued with the deactivation")

				written, err := w.c.BackfillPendingAuditEvents(context.Background())
				require.NoError(t, err)
				assert.Equal(t, 1, written)
				assert.Equal(t, int64(1), w.auditCount(t, EventUserUpdated), "the backfill writes the row once")
				assert.Zero(t, w.pendingCount(t))
			})
		})
	}
}
