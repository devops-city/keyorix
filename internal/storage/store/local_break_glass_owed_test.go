package store

// BREAKGLASS-OWED-1 storage halves: retention never removes a degraded activation
// whose owed audit rows are not in the chain yet, and SettleBreakGlassOwedAudit
// settles only when no owed row links to the activation any more.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestDeleteExpiredBreakGlassBefore_KeepsUnsettledDegraded(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.BreakGlassActivation{}, &models.PendingAuditEvent{})
	ctx := context.Background()
	old := time.Now().Add(-90 * 24 * time.Hour)
	expired := old.Add(15 * time.Minute)
	reviewed := old.Add(time.Hour)
	mk := func(degraded bool) *models.BreakGlassActivation {
		a := &models.BreakGlassActivation{ProjectID: 1, UserID: 1, State: "expired", ExpiresAt: &expired, CreatedAt: old,
			ReviewedBy: 2, ReviewedAt: &reviewed, Degraded: degraded}
		require.NoError(t, ls.db.Create(a).Error)
		return a
	}
	normal, degraded := mk(false), mk(true)
	owed := &models.PendingAuditEvent{EventType: "break_glass.activated", Event: "{}", BreakGlassActivationID: degraded.ID}
	require.NoError(t, ls.db.Create(owed).Error)

	n, err := ls.DeleteExpiredBreakGlassBefore(ctx, time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "only the normal, reviewed, old activation is purged")
	var left []models.BreakGlassActivation
	require.NoError(t, ls.db.Find(&left).Error)
	require.Len(t, left, 1)
	require.Equal(t, degraded.ID, left[0].ID, "an unsettled degraded activation is the record that its rows are owed")
	require.NotEqual(t, normal.ID, left[0].ID)

	// Not settled while an owed row still links to it.
	settled, err := ls.SettleBreakGlassOwedAudit(ctx, degraded.ID, time.Now())
	require.NoError(t, err)
	require.False(t, settled)
	unsettled, err := ls.ListUnsettledBreakGlassActivations(ctx)
	require.NoError(t, err)
	require.Len(t, unsettled, 1)

	// The backfill claims the row; then it settles (once), and retention may purge it.
	claimed, err := ls.ClaimPendingAuditEvent(ctx, owed.ID)
	require.NoError(t, err)
	require.True(t, claimed)
	settled, err = ls.SettleBreakGlassOwedAudit(ctx, degraded.ID, time.Now())
	require.NoError(t, err)
	require.True(t, settled)
	settled, err = ls.SettleBreakGlassOwedAudit(ctx, degraded.ID, time.Now())
	require.NoError(t, err)
	require.False(t, settled, "settling twice is a no-op")
	unsettled, err = ls.ListUnsettledBreakGlassActivations(ctx)
	require.NoError(t, err)
	require.Empty(t, unsettled)

	n, err = ls.DeleteExpiredBreakGlassBefore(ctx, time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	// A normal activation, or one already gone, is never "settled".
	settled, err = ls.SettleBreakGlassOwedAudit(ctx, normal.ID, time.Now())
	require.NoError(t, err)
	require.False(t, settled)
}
