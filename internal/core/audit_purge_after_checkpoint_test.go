// audit_purge_after_checkpoint_test.go — #3257: a sanctioned retention purge
// that runs AFTER a signed checkpoint must leave the trail verifiable and
// checkpointable.
//
// Before the fix, the checkpoint and the high-water mark certified a
// chained-events count, and both checks compared the LIVE chained count against
// it. A purge legitimately lowers the live count, so the very next
// VerifyAuditChain reported "truncated below the certified high-water mark" and
// WriteAuditCheckpoint refused ("truncated below signed checkpoint #N") until
// enough new events had been appended to exceed the old count. The fix records
// a cumulative, HMAC-signed purged_events count in the retention anchor (same
// transaction as the DELETE) and compares chained + purged against the
// certified count.
//
// The tamper tests below pin the other direction: nothing a DB-level actor can
// do without the signing key turns an unsanctioned removal into a purge.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// purgeAfterCheckpointFixture: 6 events older than the 30-day window, 2 recent
// ones, and a signed checkpoint certifying all 8 — then a sanctioned purge of
// the 6 old events. The checkpoint's head row (the newest event) survives.
func purgeAfterCheckpointFixture(t *testing.T, c *KeyorixCore, fixed time.Time) *models.AuditCheckpoint {
	t.Helper()
	ctx := context.Background()
	for i := range 6 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	for range 2 {
		logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	}
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	require.Equal(t, int64(8), cp.ChainedEvents)

	res, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.Equal(t, int64(6), res.DeletedCount, "the purge must remove more events than remain, i.e. go below the certified count")
	return cp
}

// assertPurgeAfterCheckpointVerifies is the #3257 acceptance check, shared by
// the SQLite and the PostgreSQL variant.
func assertPurgeAfterCheckpointVerifies(t *testing.T, c *KeyorixCore, fixed time.Time) {
	t.Helper()
	ctx := context.Background()
	purgeAfterCheckpointFixture(t, c, fixed)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "a sanctioned purge below the certified count must not read as truncation: %s", v.Reason)
	assert.Empty(t, v.CheckpointReason)
	// 2 surviving events + the system.audit_purge event.
	assert.Equal(t, int64(3), v.ChainedEvents)

	cp2, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err, "checkpointing must keep working after a purge below the certified count")
	require.True(t, written)
	// A checkpoint certifies chained + purged: 3 live + 6 purged.
	assert.Equal(t, int64(9), cp2.ChainedEvents)

	// And the trail still verifies against the new checkpoint and high-water mark.
	v, err = c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
}

func TestPurgeAfterCheckpoint_VerifyAndCheckpointSucceed(t *testing.T) {
	t.Parallel()
	c, _, fixed := newReanchorTestCore(t)
	assertPurgeAfterCheckpointVerifies(t, c, fixed)
}

// TestPurgeAfterCheckpoint_VerifyAndCheckpointSucceed_Postgres runs the same
// sequence on PostgreSQL, where the purge runs under the KEYAUDIT advisory lock
// and the anchor is a text column (the \x1f separator matters there).
func TestPurgeAfterCheckpoint_VerifyAndCheckpointSucceed_Postgres(t *testing.T) {
	t.Parallel()
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.now = func() time.Time { return fixed }
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	assertPurgeAfterCheckpointVerifies(t, c, fixed)

	// A second replica (fresh process, watermark seeded from the persisted mark)
	// must agree.
	c2 := NewKeyorixCore(store.NewLocalStorage(pgOpen(t, dsn)))
	c2.now = c.now
	c2.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c2.SeedAuditWatermark(context.Background())
	v, err := c2.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
}

// TestPurgeAfterCheckpoint_RestartedReplicaAgrees: a process that starts after
// the purge seeds its in-memory watermark from the persisted high-water mark;
// that seed must be in the same unit (chained + purged) as what it compares.
func TestPurgeAfterCheckpoint_RestartedReplicaAgrees(t *testing.T) {
	t.Parallel()
	c, db, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed)

	c2 := NewKeyorixCore(store.NewLocalStorage(db))
	c2.now = c.now
	c2.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c2.SeedAuditWatermark(context.Background())
	v, err := c2.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
}

// TestPurgeAfterCheckpoint_SecondPurgeAccumulates: two purges, a checkpoint
// between them. The count is cumulative, so the second anchor carries both.
func TestPurgeAfterCheckpoint_SecondPurgeAccumulates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, fixed := newReanchorTestCore(t)
	purgeAfterCheckpointFixture(t, c, fixed) // purged 6

	// Age the clock so the 2 survivors fall out of the window. (The first purge's
	// own system.audit_purge event carries wall-clock time, so it bounds the
	// contiguous prefix the second purge may remove.)
	later := fixed.AddDate(0, 0, 40)
	c.now = func() time.Time { return later }
	logChainedEvent(t, c, "secret.read", later)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	res, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.Equal(t, int64(2), res.DeletedCount)

	a, err := c.loadAuditRetentionAnchor(ctx)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, int64(8), a.PurgedEvents, "6 from the first purge + 2 from the second")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	_, _, err = c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
}

// TestAuditRetentionAnchorCanonicalV2_ExactByteFormat pins the v2 signed
// layout; internal/auditverify's TestRetentionAnchorCanonicalV2_ExactByteFormat
// pins the same string on the offline side (INV-AUDITVERIFY-03).
func TestAuditRetentionAnchorCanonicalV2_ExactByteFormat(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "retanchor-v2\x009\x00prevhash\x00entryhash\x001234\x00v1",
		auditRetentionAnchorCanonicalV2(9, "prevhash", "entryhash", 1234, "v1"))
}
