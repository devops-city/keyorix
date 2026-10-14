package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetAuditLogs in cursor mode (Ascending + AfterID) returns events in ascending
// id order with id > cursor — the stable forward cursor used by /audit/export.
func TestGetAuditLogs_CursorExport(t *testing.T) {
	ctx := context.Background()
	ls := newAuditTestStore(t)
	base := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)

	// Insert 5 events; event_time DESCENDING vs id so we can prove the cursor
	// orders by id, not by time.
	for i := range 5 {
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read",
			EventTime: base.Add(time.Duration(-i) * time.Minute),
		}))
	}

	// First page from the start.
	page1, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{Ascending: true, PageSize: 2})
	require.NoError(t, err)
	require.Len(t, page1, 2)
	assert.Equal(t, uint(1), page1[0].ID)
	assert.Equal(t, uint(2), page1[1].ID)

	// Advance the cursor past id=2.
	after := page1[1].ID
	page2, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{Ascending: true, PageSize: 2, AfterID: &after})
	require.NoError(t, err)
	require.Len(t, page2, 2)
	assert.Equal(t, uint(3), page2[0].ID)
	assert.Equal(t, uint(4), page2[1].ID)

	// Final partial page.
	after = page2[1].ID
	page3, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{Ascending: true, PageSize: 2, AfterID: &after})
	require.NoError(t, err)
	require.Len(t, page3, 1)
	assert.Equal(t, uint(5), page3[0].ID)
}
