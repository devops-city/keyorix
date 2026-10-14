package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestDeleteAuditLogsBefore_PurgedEventsCountsChainedRowsOnly (#3257): the
// candidate's PurgedEvents feeds the signed cumulative purged count that the
// checkpoint/high-water checks add to the live chained count. Checkpoints never
// counted legacy unchained rows (empty entry_hash), so counting them here would
// over-credit a purge and could hide an equal-sized unsanctioned deletion.
func TestDeleteAuditLogsBefore_PurgedEventsCountsChainedRowsOnly(t *testing.T) {
	t.Parallel()
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	old := now.AddDate(0, 0, -40)

	// 3 legacy rows, then 2 chained rows, all older than the cutoff...
	for range 3 {
		require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: old}).Error)
	}
	for _, h := range []string{"a", "b"} {
		require.NoError(t, ls.db.Create(&models.AuditEvent{
			EventType: "secret.read", EventTime: old, PrevHash: "prev-" + h, EntryHash: "entry-" + h,
		}).Error)
	}
	// ...and one chained row that survives.
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", EventTime: now, PrevHash: "entry-b", EntryHash: "entry-c",
	}).Error)

	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	require.Equal(t, int64(5), n)
	require.NotNil(t, anchor)
	require.Equal(t, "entry-c", anchor.EntryHash)
	require.Equal(t, int64(2), anchor.PurgedEvents, "only the chained rows the delete removed count")
}
