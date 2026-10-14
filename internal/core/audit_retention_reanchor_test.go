// audit_retention_reanchor_test.go — regression coverage for the retention-purge
// chain re-anchor fix (ADR-029 / audit_retention_anchor.go).
//
// Before the fix, DeleteAuditLogsBefore's hard-delete left the new earliest
// surviving row's prev_hash pointing at a now-deleted predecessor, so
// VerifyAuditChain's bare walk (which always started at auditGenesisHash) broke
// permanently on the very next call — indistinguishable from real tampering,
// and forever after for the life of the deployment (any subsequent purge only
// makes it worse, never better). These tests assert the purge → verify sequence
// now succeeds (TestPurgeAuditLogs_ChainVerifiesAfterPurge), that checkpointing
// recovers too (TestWriteAuditCheckpoint_SucceedsAfterPurge), and that the fix
// does not weaken tamper detection: a DB-level actor deleting MORE than the
// purge authorized (TestPurgeAuditLogs_AttackerDeletesAnchoredRow_StillDetected)
// or forging an anchor without the signing key
// (TestVerifyAuditChain_ForgedRetentionAnchorRejected) is still caught.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newReanchorTestCore builds a real-SQLite core with a fixed checkpoint signing
// key and a fixed clock, migrating every table the retention-purge +
// chain-verify + checkpoint path touches.
func newReanchorTestCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.now = func() time.Time { return fixed }
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	return c, db, fixed
}

// logChainedEvent appends one properly hash-chained audit event at the given
// time, via the real LogAuditEvent path (not a raw INSERT), so it links into
// the ADR-029 chain exactly like a real event would.
func logChainedEvent(t *testing.T, c *KeyorixCore, eventType string, at time.Time) *models.AuditEvent {
	t.Helper()
	tr := true
	e := &models.AuditEvent{
		EventType: eventType, Description: "reanchor test event",
		Success: &tr, EventTime: at, ActorType: "user",
	}
	require.NoError(t, c.storage.LogAuditEvent(context.Background(), e))
	return e
}

// TestPurgeAuditLogs_ChainVerifiesAfterPurge is the core regression test: purge
// the earliest chained events, then verify the SURVIVING chain still succeeds.
// Against pre-fix code this fails — VerifyAuditChain reports the trail
// permanently broken at the new earliest row because its prev_hash points at a
// row the purge just deleted, and the walk unconditionally requires genesis.
func TestPurgeAuditLogs_ChainVerifiesAfterPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, fixed := newReanchorTestCore(t)

	// 5 events older than the 30-day retention window (will be purged)...
	var oldIDs []uint
	for i := range 5 {
		e := logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
		oldIDs = append(oldIDs, e.ID)
	}
	// ...and 3 recent events that must survive.
	var survivors []*models.AuditEvent
	for i := range 3 {
		survivors = append(survivors, logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -(1+i))))
	}
	require.Len(t, oldIDs, 5)

	// Sanity: before the purge, the raw store-layer walk from genesis succeeds
	// (nothing has been deleted yet).
	pre, err := c.storage.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, pre.Valid)
	require.Equal(t, int64(8), pre.ChainedEvents)

	result, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.Equal(t, int64(5), result.DeletedCount)

	// The critical assertion: core.VerifyAuditChain (which composes the raw walk
	// with the retention anchor) must STILL SUCCEED on the surviving chain.
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify after a sanctioned retention purge: %s", v.Reason)
	assert.Nil(t, v.FirstBrokenID)
	// 3 surviving user events + 1 system.audit_purge event PurgeAuditLogs itself
	// appends after the delete commits.
	assert.Equal(t, int64(4), v.ChainedEvents)
	assert.Equal(t, int64(0), v.UnchainedEvents)

	_ = survivors
}

// TestWriteAuditCheckpoint_SucceedsAfterPurge covers the other half of the
// finding: writeAuditCheckpointLocked calls the same raw chain walk and
// refuses to sign over a chain it sees as broken. Before the fix, checkpointing
// was ALSO permanently disabled after the first retention purge.
func TestWriteAuditCheckpoint_SucceedsAfterPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, fixed := newReanchorTestCore(t)

	for i := range 4 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(35+i)))
	}
	for range 2 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -1))
	}

	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err, "checkpointing must recover after a sanctioned purge, not stay permanently refused")
	require.True(t, written)
	require.NotNil(t, cp)
	assert.Equal(t, int64(3), cp.ChainedEvents, "2 surviving user events + the system.audit_purge event")
}

// TestPurgeAuditLogs_AttackerDeletesAnchoredRow_StillDetected proves the fix
// does not weaken tamper detection: after a legitimate purge establishes an
// anchor at row N, a DB-level actor deleting row N itself (going further than
// any sanctioned purge did, without a fresh anchor covering the new gap) must
// still be caught, not silently absorbed by the existing anchor.
func TestPurgeAuditLogs_AttackerDeletesAnchoredRow_StillDetected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	for i := range 3 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	survivor1 := logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))

	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	// Confirm the purge legitimately re-anchored (chain verifies).
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, v.Valid, "sanity: purge alone must not break verification")

	// Attack: delete the anchored row directly (bypassing PurgeAuditLogs and its
	// re-anchor step entirely) — simulating a malicious insider or an actor with
	// raw DB access removing more than any sanctioned purge authorized.
	require.NoError(t, db.Delete(&models.AuditEvent{}, survivor1.ID).Error)

	v2, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v2.Valid, "deleting the anchored row outside a sanctioned purge must still be detected")
	assert.Contains(t, v2.Reason, "re-anchor")
}

// TestVerifyAuditChain_ForgedRetentionAnchorRejected proves the anchor is
// authenticated, not a plain trusted marker: a DB-level actor who deletes
// chained rows and forges a plausible-looking (but unsigned/incorrectly signed)
// retention-anchor system_metadata row — attempting to make an unsanctioned gap
// look like a legitimate purge — must NOT have that anchor accepted. Without
// the checkpoint signing key (held only in this process's memory), the forged
// signature cannot verify, so the anchor is ignored and the walk correctly
// reports the chain broken, exactly as if no anchor existed.
func TestVerifyAuditChain_ForgedRetentionAnchorRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	var ids []uint
	for i := range 5 {
		e := logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -i))
		ids = append(ids, e.ID)
	}

	// No PurgeAuditLogs call at all — this is unsanctioned, raw deletion.
	require.NoError(t, db.Where("id IN ?", ids[:3]).Delete(&models.AuditEvent{}).Error)

	var survivingHead models.AuditEvent
	require.NoError(t, db.Order("id ASC").First(&survivingHead).Error)
	require.Equal(t, ids[3], survivingHead.ID)

	// Forge an anchor claiming this gap is a legitimate re-anchor point, but
	// signed with a key the attacker does not actually have (a wrong/garbage
	// signature, as any DB-only actor would be forced to produce).
	forged := auditRetentionAnchorValue(survivingHead.ID, survivingHead.PrevHash, survivingHead.EntryHash, "v1", "0000forged0000signature0000")
	require.NoError(t, c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey, forged))

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a forged retention anchor must not be trusted to paper over an unsanctioned deletion")
	require.NotNil(t, v.FirstBrokenID)
	assert.Equal(t, survivingHead.ID, *v.FirstBrokenID)
}
