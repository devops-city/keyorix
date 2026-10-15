package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func segmentChain(t *testing.T, n int) (*LocalStorage, []*models.AuditEvent) {
	t.Helper()
	ls := newAuditChainTestStore(t)
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	var rows []*models.AuditEvent
	for i := range n {
		rows = append(rows, appendEvent(t, ls, "secret.read", "e", at.Add(time.Duration(i)*time.Second)))
	}
	return ls, rows
}

// The zero segment is exactly the full walk.
func TestVerifyAuditChainSegment_ZeroSegmentIsFullWalk(t *testing.T) {
	ls, rows := segmentChain(t, 5)
	full, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	seg, err := ls.VerifyAuditChainSegment(context.Background(), storage.AuditChainSegment{})
	require.NoError(t, err)
	assert.Equal(t, full, seg)
	assert.Equal(t, rows[4].ID, seg.HeadID)
	assert.False(t, seg.Truncated)
}

// A pinned seed walk continues from the seed; bounds and the row cap stop it
// and say so.
func TestVerifyAuditChainSegment_PinnedBoundedAndCapped(t *testing.T) {
	ctx := context.Background()
	ls, rows := segmentChain(t, 6)
	v, err := ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash})
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, int64(4), v.ChainedEvents, "rows after the pinned seed")
	assert.Equal(t, rows[5].ID, v.HeadID)

	v, err = ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, ThroughID: rows[3].ID})
	require.NoError(t, err)
	assert.Equal(t, rows[3].ID, v.HeadID)
	assert.Equal(t, rows[3].EntryHash, v.HeadHash)
	assert.False(t, v.Truncated)

	v, err = ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: rows[1].ID, SeedHash: rows[1].EntryHash, MaxRows: 2})
	require.NoError(t, err)
	assert.True(t, v.Truncated)
	assert.Equal(t, rows[3].ID, v.HeadID)

	v, err = ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: rows[5].ID, SeedHash: rows[5].EntryHash, MaxRows: 3})
	require.NoError(t, err)
	assert.False(t, v.Truncated, "nothing after the seed: not truncated")
	assert.Equal(t, rows[5].ID, v.HeadID)
	assert.Zero(t, v.ChainedEvents)
}

// The pinned seed must exist, carry the certified hash and recompute; the
// first row after it must link to it.
func TestVerifyAuditChainSegment_SeedPinning(t *testing.T) {
	ctx := context.Background()
	ls, rows := segmentChain(t, 4)
	seed := rows[1]

	v, err := ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: seed.ID, SeedHash: "not-the-certified-hash"})
	require.NoError(t, err)
	assert.False(t, v.Valid)
	assert.Contains(t, v.Reason, "differs from the value it was certified")

	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("id = ?", seed.ID).Update("description", "x").Error)
	v, err = ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: seed.ID, SeedHash: seed.EntryHash})
	require.NoError(t, err)
	assert.False(t, v.Valid)
	assert.Contains(t, v.Reason, "event modified")

	require.NoError(t, ls.db.Delete(&models.AuditEvent{}, seed.ID).Error)
	v, err = ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: seed.ID, SeedHash: seed.EntryHash})
	require.NoError(t, err)
	assert.False(t, v.Valid)
	assert.Contains(t, v.Reason, "is missing")
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, seed.ID, *v.FirstBrokenID)

	// Link check: with row 1 gone, the first row after seed row 0 is row 2,
	// whose prev_hash names the deleted row, not row 0.
	v, err = ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: rows[0].ID, SeedHash: rows[0].EntryHash})
	require.NoError(t, err)
	assert.False(t, v.Valid, "row 2 links to the deleted row 1, not to row 0")
	assert.Equal(t, rows[2].ID, *v.FirstBrokenID)
}
