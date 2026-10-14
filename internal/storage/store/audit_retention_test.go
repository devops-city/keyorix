package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newAuditRetentionTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewLocalStorage(db)
}

func TestAuditRetentionStats_Empty(t *testing.T) {
	ls := newAuditRetentionTestStore(t)

	stats, err := ls.AuditRetentionStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.TotalEvents)
	assert.Nil(t, stats.Oldest, "no oldest on an empty table")
	assert.Nil(t, stats.Newest, "no newest on an empty table")
}

func TestAuditRetentionStats_OldestNewestAndCount(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	oldest := now.AddDate(0, 0, -400) // > 12 months back
	mid := now.AddDate(0, 0, -30)
	newest := now.AddDate(0, 0, -1)

	for _, at := range []time.Time{mid, oldest, newest} {
		require.NoError(t, ls.db.WithContext(ctx).Create(&models.AuditEvent{
			EventType: "secret.read", EventTime: at,
		}).Error)
	}

	stats, err := ls.AuditRetentionStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalEvents)
	require.NotNil(t, stats.Oldest)
	require.NotNil(t, stats.Newest)
	assert.WithinDuration(t, oldest, *stats.Oldest, time.Second)
	assert.WithinDuration(t, newest, *stats.Newest, time.Second)
}

// TestDeleteAuditLogsBefore_DeletesOldRows verifies the hard-delete removes
// events strictly before the cutoff and leaves newer ones intact.
func TestDeleteAuditLogsBefore_DeletesOldRows(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.AddDate(0, 0, -30)

	// Three events older than the cutoff.
	for i := range 3 {
		require.NoError(t, ls.db.WithContext(ctx).Create(&models.AuditEvent{
			EventType: "secret.read", EventTime: now.AddDate(0, 0, -(31 + i)),
		}).Error)
	}
	// Two events newer than the cutoff.
	for i := range 2 {
		require.NoError(t, ls.db.WithContext(ctx).Create(&models.AuditEvent{
			EventType: "secret.read", EventTime: now.AddDate(0, 0, -(i + 1)),
		}).Error)
	}

	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n, "three old events deleted")
	assert.Nil(t, anchor, "raw-inserted events have empty hashes (legacy/unchained) — nothing to re-anchor")

	stats, err := ls.AuditRetentionStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.TotalEvents, "two recent events remain")
}

// TestDeleteAuditLogsBefore_EmptyTable returns 0 rows deleted on an empty table.
func TestDeleteAuditLogsBefore_EmptyTable(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()

	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
	assert.Nil(t, anchor)
}

// TestDeleteAuditLogsBefore_NoneBeforeCutoff returns 0 when all events are newer.
func TestDeleteAuditLogsBefore_NoneBeforeCutoff(t *testing.T) {
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	// All events are 1 day old; cutoff is 30 days ago.
	for range 3 {
		require.NoError(t, ls.db.WithContext(ctx).Create(&models.AuditEvent{
			EventType: "secret.read", EventTime: now.AddDate(0, 0, -1),
		}).Error)
	}

	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "no events old enough to delete")
	assert.Nil(t, anchor)

	stats, err := ls.AuditRetentionStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalEvents, "all 3 events remain")
}
