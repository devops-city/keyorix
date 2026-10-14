package auditverify_test

// #3257, offline side: a sanctioned retention purge AFTER a signed checkpoint
// must verify VALID offline (with the checkpoint key) exactly as it does
// online, and every way a DB-only actor could try to pass an unsanctioned
// removal off as a purge must still read BROKEN. Fixtures are written through
// the real core/store path (see differential_test.go).

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
)

// purgeAfterCheckpoint: 5 old + 5 recent events, a checkpoint certifying all
// 10, then a sanctioned purge of the 5 old ones (below the certified count).
func purgeAfterCheckpoint(t *testing.T, f *diffFixture) {
	t.Helper()
	f.logEvents(5, 40*24*time.Hour)
	f.logEvents(5, time.Hour)
	cp, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)
	require.Equal(t, int64(10), cp.ChainedEvents)
	res, err := f.core.PurgeAuditLogs(f.ctx, core.AuditLogRetentionConfig{RetentionDays: 7})
	require.NoError(t, err)
	require.Equal(t, int64(5), res.DeletedCount)
}

func anchorValue(t *testing.T, f *diffFixture) string {
	t.Helper()
	var val string
	require.NoError(t, f.db.Raw("SELECT value FROM system_metadata WHERE key = 'audit_retention_anchor'").Scan(&val).Error)
	require.NotEmpty(t, val)
	return val
}

func TestDifferential_PurgeAfterCheckpoint_ValidWithKey(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)

	want := f.oracle()
	require.True(t, want.Valid, "online: %s", want.Reason)

	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.True(t, got.Checkpoint.Authenticated)
	require.True(t, got.RetentionGap.Sanctioned)
	require.Equal(t, int64(5), got.PurgedEvents)
	require.Equal(t, int64(6), got.ChainedEvents, "5 survivors + the system.audit_purge event")
}

// A checkpoint written after the purge certifies chained + purged; offline
// agrees with it too.
func TestDifferential_PurgeAfterCheckpoint_NewCheckpointValid(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)
	cp, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.Equal(t, int64(11), cp.ChainedEvents)

	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
}

// Without the key nothing is authenticated: the gap reads INDETERMINATE (as
// before #3257), never VALID, and no purge credit is given.
func TestDifferential_PurgeAfterCheckpoint_NoKeyIndeterminate(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)

	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictIndeterminate, got.Verdict, "reason: %s", got.Reason)
	require.Zero(t, got.PurgedEvents)
}

// An externally-held anchor exported before the purge still verifies after it
// when the purge count authenticates under the key.
func TestDifferential_PurgeAfterCheckpoint_ExternalAnchorStillValid(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(5, 40*24*time.Hour)
	f.logEvents(5, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	bundle, err := auditverify.ParseExternalAnchorBundle(captureAnchorBundle(t, f))
	require.NoError(t, err)
	_, err = f.core.PurgeAuditLogs(f.ctx, core.AuditLogRetentionConfig{RetentionDays: 7})
	require.NoError(t, err)

	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{
		CheckpointKey: fixedCheckpointKey, ExternalAnchor: bundle,
	})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.True(t, got.ExternalAnchor.Authenticated)
}

// --- tamper cases: must stay BROKEN -----------------------------------------

// (a) An unsanctioned DELETE of the earliest surviving row after the purge.
func TestDifferential_PurgeAfterCheckpoint_UnsanctionedDeleteBeyondAnchor_Broken(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)
	f.exec("DELETE FROM audit_events WHERE id = (SELECT MIN(id) FROM audit_events)")

	require.False(t, f.oracle().Valid)
	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
}

// (a') Tail truncation with every checkpoint row deleted: the high-water mark
// (in chained + purged units) still catches it — the purged count is not
// double-credited.
func TestDifferential_PurgeAfterCheckpoint_TailTruncationCheckpointsDeleted_Broken(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx) // certifies 6 + 5 = 11
	require.NoError(t, err)
	f.exec("DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)")
	f.exec("DELETE FROM audit_checkpoints")

	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Contains(t, got.Reason, "high-water")
}

// (b) Inflating the purged count (to cover a tail truncation) breaks the
// anchor signature: no purge credit, BROKEN.
func TestDifferential_PurgeAfterCheckpoint_InflatedPurgedCount_Broken(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)
	f.exec("DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)")

	parts := strings.Split(anchorValue(t, f), "\x1f")
	require.Len(t, parts, 7)
	require.Equal(t, "5", parts[4])
	parts[4] = strconv.Itoa(5 + 1)
	f.exec("UPDATE system_metadata SET value = ? WHERE key = 'audit_retention_anchor'", strings.Join(parts, "\x1f"))

	require.False(t, f.oracle().Valid)
	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Zero(t, got.PurgedEvents, "an anchor that fails its signature must give no purge credit")
	require.False(t, got.RetentionGap.Sanctioned)
}

// (c) Deleting more rows and rewriting the anchor for the new earliest row
// with a raised count, signed under a key other than the server's.
func TestDifferential_PurgeAfterCheckpoint_DeleteAndRewriteAnchor_Broken(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	purgeAfterCheckpoint(t, f)
	f.exec("DELETE FROM audit_events WHERE id = (SELECT MIN(id) FROM audit_events)")

	var head struct {
		ID        uint64
		PrevHash  string
		EntryHash string
	}
	require.NoError(t, f.db.Raw("SELECT id, prev_hash, entry_hash FROM audit_events ORDER BY id ASC LIMIT 1").Scan(&head).Error)
	wrongKey := []byte("attacker-guessed-key-32-bytes!!!")
	sig := auditverify.SignRetentionAnchorV2(head.ID, head.PrevHash, head.EntryHash, 6, "v1", wrongKey)
	forged := strings.Join([]string{"v2", strconv.FormatUint(head.ID, 10), head.PrevHash, head.EntryHash, "6", "v1", sig}, "\x1f")
	f.exec("UPDATE system_metadata SET value = ? WHERE key = 'audit_retention_anchor'", forged)

	require.False(t, f.oracle().Valid)
	got, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Zero(t, got.PurgedEvents)
}
