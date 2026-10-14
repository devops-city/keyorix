// audit_purge_after_checkpoint_tamper_test.go — #3257 tamper cases: a
// purge-aware checkpoint must stay red for a DB-level attacker without the
// signing key. See audit_purge_after_checkpoint_test.go for the fixture.
package core

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- tamper cases: must stay red for the attacker ---------------------------

// (a) An unsanctioned DELETE of the earliest surviving row (beyond what the
// signed anchor covers) is still detected after a purge-after-checkpoint.
func TestPurgeAfterCheckpoint_UnsanctionedDeleteBeyondAnchor_Detected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed)

	var earliest models.AuditEvent
	require.NoError(t, db.Order("id ASC").First(&earliest).Error)
	require.NoError(t, db.Delete(&models.AuditEvent{}, earliest.ID).Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "deleting past the anchor outside a sanctioned purge must be detected")
	_, _, err = c.WriteAuditCheckpoint(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
}

// (a') Purge, checkpoint, then tail-truncate AND delete every checkpoint row so
// only the high-water count check is left: the purged count must not be
// double-counted (it was already included in the certified total), so the
// truncation still shows.
func TestPurgeAfterCheckpoint_TailTruncationWithCheckpointsDeleted_Detected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed)
	for range 3 {
		logChainedEvent(t, c, "secret.read", fixed)
	}
	cp, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(12), cp.ChainedEvents) // 6 live + 6 purged

	var tail []models.AuditEvent
	require.NoError(t, db.Order("id DESC").Limit(2).Find(&tail).Error)
	for _, e := range tail {
		require.NoError(t, db.Delete(&models.AuditEvent{}, e.ID).Error)
	}
	require.NoError(t, db.Where("1 = 1").Delete(&models.AuditCheckpoint{}).Error)

	// Fresh process, so only the persisted high-water mark carries the certified length.
	c2 := NewKeyorixCore(store.NewLocalStorage(db))
	c2.now = c.now
	c2.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c2.SeedAuditWatermark(ctx)
	v, err := c2.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "tail truncation below the certified total must be detected")
	assert.Contains(t, v.CheckpointReason, "high-water")
}

// (b) An inflated purged count in an otherwise valid anchor fails the anchor
// signature: the anchor is ignored, so it cannot paper over a truncation.
func TestPurgeAfterCheckpoint_InflatedPurgedCount_SignatureFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed)

	// Attacker truncates the tail (including the certified head) and inflates
	// the purged count by the same amount, keeping the original signature.
	var tail models.AuditEvent
	require.NoError(t, db.Order("id DESC").First(&tail).Error)
	require.NoError(t, db.Delete(&models.AuditEvent{}, tail.ID).Error)

	val, ok, err := c.storage.GetSystemMetadata(ctx, auditRetentionAnchorKey)
	require.NoError(t, err)
	require.True(t, ok)
	parts := strings.Split(val, auditRetentionAnchorSep)
	require.Len(t, parts, 7, "the anchor is written in the v2 layout")
	require.Equal(t, "6", parts[4])
	parts[4] = strconv.Itoa(6 + 100)
	require.NoError(t, c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey, strings.Join(parts, auditRetentionAnchorSep)))

	a, err := c.loadAuditRetentionAnchor(ctx)
	require.NoError(t, err)
	assert.Nil(t, a, "an anchor whose purged count was changed must fail its signature and be ignored")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
	_, _, err = c.WriteAuditCheckpoint(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
}

// (b') Downgrading a v2 anchor to the v1 layout (dropping the count) with the
// v2 signature does not verify either: the two layouts are domain-separated.
func TestPurgeAfterCheckpoint_AnchorLayoutDowngrade_SignatureFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed)

	val, _, err := c.storage.GetSystemMetadata(ctx, auditRetentionAnchorKey)
	require.NoError(t, err)
	p := strings.Split(val, auditRetentionAnchorSep)
	require.Len(t, p, 7)
	v1 := strings.Join([]string{"v1", p[1], p[2], p[3], p[5], p[6]}, auditRetentionAnchorSep)
	require.NoError(t, c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey, v1))

	a, err := c.loadAuditRetentionAnchor(ctx)
	require.NoError(t, err)
	assert.Nil(t, a)
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
}

// (c) Deleting more rows and rewriting the anchor to cover them (new row,
// larger count) without the signing key is detected.
func TestPurgeAfterCheckpoint_DeleteAndRewriteAnchorWithoutKey_Detected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed)

	var earliest models.AuditEvent
	require.NoError(t, db.Order("id ASC").First(&earliest).Error)
	require.NoError(t, db.Delete(&models.AuditEvent{}, earliest.ID).Error)
	var head models.AuditEvent
	require.NoError(t, db.Order("id ASC").First(&head).Error)

	// The attacker computes a well-formed v2 anchor for the new earliest row
	// with the count raised by one, but under a key they hold, not the server's.
	attacker := NewKeyorixCore(store.NewLocalStorage(db))
	attacker.SetAuditCheckpointKey([]byte("attacker-guessed-key-32-bytes!!"), "v1")
	sig := attacker.signRetentionAnchorV2(head.ID, head.PrevHash, head.EntryHash, 7)
	forged := auditRetentionAnchorValueV2(head.ID, head.PrevHash, head.EntryHash, 7, "v1", sig)
	require.NoError(t, c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey, forged))

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a re-written anchor without the signing key must not sanction a deletion")
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, head.ID, *v.FirstBrokenID)
	_, _, err = c.WriteAuditCheckpoint(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
}

// A v1 anchor written before this change (no count) still authenticates, with
// purged = 0: today's behaviour, no new trust.
func TestRetentionAnchor_V1LayoutStillAccepted_PurgedZero(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)
	for i := range 3 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	logChainedEvent(t, c, "secret.read", fixed)
	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	var head models.AuditEvent
	require.NoError(t, db.Order("id ASC").First(&head).Error)
	sig := c.signRetentionAnchorWithVersion(head.ID, head.PrevHash, head.EntryHash, "v1")
	require.NoError(t, c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey,
		auditRetentionAnchorValue(head.ID, head.PrevHash, head.EntryHash, "v1", sig)))

	a, err := c.loadAuditRetentionAnchor(ctx)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, int64(0), a.PurgedEvents)
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
}
