// audit_verify_state_replay_test.go — the verification state cannot be replayed,
// rolled back or silently replaced, and a recorded failure stays until a full
// verification that covers it (docs/specs/audit-incremental-verification.md §3).
package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const stateRejectedEvent = "system.audit_verification_state_rejected"

func rawAuditVerifyState(t *testing.T, c *KeyorixCore) string {
	t.Helper()
	val, ok, err := c.storage.GetSystemMetadata(context.Background(), auditVerifyStateKey)
	require.NoError(t, err)
	require.True(t, ok)
	return val
}

func putAuditVerifyState(t *testing.T, c *KeyorixCore, val string) {
	t.Helper()
	require.NoError(t, c.storage.SetSystemMetadata(context.Background(), auditVerifyStateKey, val))
}

// restartedIncrementalCore is a new process over the same database: nothing
// in memory (no watermark, no state generation), only what is persisted.
func restartedIncrementalCore(c *KeyorixCore, segments int) *KeyorixCore {
	c2 := NewKeyorixCore(c.storage)
	c2.now = c.now
	c2.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c2.SetAuditIncrementalVerification(24*time.Hour, segments)
	c2.auditVerifyMinWidth = 1
	return c2
}

func restoreDescription(t *testing.T, db *gorm.DB, id uint) {
	t.Helper()
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", id).Update("description", "reanchor test event").Error)
}

// F1: an older signed state, put back after newer checkpoints were written, is
// rejected by its binding to the signed checkpoint trail, even in a process
// that has never seen a newer generation (a restart or another replica).
func TestIncrementalVerify_ReplayedOlderStateRejected(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 4)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c)
	require.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
	old := rawAuditVerifyState(t, c)

	clk.advance()
	logIncrEvents(t, c, clk, 3)
	tickOK(t, c)

	c2 := restartedIncrementalCore(c, 4)
	putAuditVerifyState(t, c2, old)
	r := incrVerify(t, c2)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status, "a replayed state claims nothing")
	assert.Contains(t, r.StateReason, "older than the signed checkpoint")
	p, err := c2.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusNotProven, p.Status)

	// The next tick does not overwrite it silently: it records the rejection.
	clk.advance()
	tickOK(t, c2)
	assert.Equal(t, int64(1), countEvents(t, db, stateRejectedEvent))
	r = incrVerify(t, c2)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.NotProvenReason, "was rejected")
}

// F1: within one checkpoint interval the binding cannot tell two states apart;
// the generation can. Putting back the state saved before a segment recorded a
// failure must not erase that failure.
func TestIncrementalVerify_RolledBackStateWithinProcessRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 4)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c) // full-walk checkpoint; cycle segment 1 (ids 1..~10)
	tamperDescription(t, db, 15)

	clk.advance()
	_, _, err := c.WriteAuditCheckpointIncremental(ctx)
	require.NoError(t, err)
	before := rawAuditVerifyState(t, c)
	require.NoError(t, c.advanceAuditRollingCycle(ctx, &AuditVerifyTickResult{}))
	require.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status, "premise: segment 2 caught row 15")

	putAuditVerifyState(t, c, before)
	r := incrVerify(t, c)
	assert.NotEqual(t, AuditVerifyStatusValid, r.Status, "a rolled-back state must not hide the failure")
	assert.Contains(t, r.StateReason, "older than generation")
}

// A deleted state row is not a fresh start for a process that already read one.
func TestIncrementalVerify_DeletedStateRowReported(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	require.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
	require.NoError(t, db.Where("key = ?", auditVerifyStateKey).Delete(&models.SystemMetadata{}).Error)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.StateReason, "missing although this server already read")
	clk.advance()
	tickOK(t, c)
	assert.Equal(t, int64(1), countEvents(t, db, stateRejectedEvent))
}

// F1, the attack itself: a row below the checkpoint head is edited after the
// cycle passed it, and the attacker puts the pre-edit state back before every
// tick (each tick in a fresh process, so no in-memory floor helps). The edit
// must still be caught within one cycle plus one tick, as without the replays.
// (Before that it can read valid: the edit is behind the last verification of
// row 3, the design's stated window. Without the binding the replayed cursor
// never reaches the end, and nothing restarts the cycle for two cycles.)
func TestIncrementalVerify_TamperBelowCheckpointStaysDetectedAcrossReplay(t *testing.T) {
	t.Parallel()
	const segments = 4
	c, db, clk := newIncrementalTestCore(t, segments)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c) // segment 1
	clk.advance()
	tickOK(t, c) // segment 2: the cycle is past row 3
	replay := rawAuditVerifyState(t, c)
	tamperDescription(t, db, 3)

	caught := false
	for tick := 1; tick <= segments+1 && !caught; tick++ {
		clk.advance()
		logIncrEvents(t, c, clk, 1)
		p := restartedIncrementalCore(c, segments)
		putAuditVerifyState(t, p, replay)
		_, _ = p.RunAuditVerificationTick(context.Background())
		r := incrVerify(t, p)
		if r.Status == AuditVerifyStatusBroken && r.FirstBrokenID != nil && *r.FirstBrokenID == 3 {
			caught = true
		}
	}
	assert.True(t, caught, "the edit of row 3 must be caught within one cycle despite the replays")
}

// F1 backstop: a cycle is never resumed after two cycle durations, whatever
// its persisted progress says.
func TestIncrementalVerify_StaleCycleRestarted(t *testing.T) {
	t.Parallel()
	c, _, clk := newIncrementalTestCore(t, 4)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c)
	clk.advance()
	tickOK(t, c)
	r := incrVerify(t, c)
	require.NotNil(t, r.RollingCycle)
	firstStart := r.RollingCycle.StartedAt

	clk.t = clk.t.Add(9 * 24 * time.Hour)
	tickOK(t, c)
	r = incrVerify(t, c)
	require.NotNil(t, r.RollingCycle)
	assert.True(t, r.RollingCycle.StartedAt.After(firstStart), "the stale cycle restarted")
	assert.Equal(t, clk.t, r.RollingCycle.StartedAt)
}

// F2: a failure recorded while a cycle runs (here a tail row past the cycle's
// target) is not cleared when that cycle completes, even after the row is put
// back; only a full job started after it clears it.
func TestIncrementalVerify_FailureSurvivesUnrelatedCycleCompletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 2)
	logIncrEvents(t, c, clk, 20)
	tickOK(t, c) // full-walk checkpoint at 20; cycle segment 1 of 2
	head := latestHeadID(t, c)
	logIncrEvents(t, c, clk, 5)
	tamperDescription(t, db, head+3)

	clk.advance()
	res, err := c.RunAuditVerificationTick(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	require.True(t, res.CycleCompleted, "premise: the cycle (target %d) completed in the tick that recorded the failure", head)

	restoreDescription(t, db, head+3)
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status, "the failure is sticky: %s", r.NotProvenReason)
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, head+3, *r.FirstBrokenID)
	clk.advance()
	_, err = c.RunAuditVerificationTick(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)

	id, _, err := c.StartAuditFullVerification(ctx)
	require.NoError(t, err)
	require.True(t, waitAuditJob(t, c, id).Result.Valid)
	assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status, "a full job started after the failure clears it")
}

// F2: the full-walk fallback (no checkpoint row and no high-water mark) refuses
// while a failure is recorded, instead of clearing it.
func TestIncrementalVerify_FailureSurvivesFullWalkFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	head := latestHeadID(t, c)
	logIncrEvents(t, c, clk, 3)
	tamperDescription(t, db, head+1)
	clk.advance()
	_, err := c.RunAuditVerificationTick(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)

	restoreDescription(t, db, head+1)
	require.NoError(t, db.Where("1 = 1").Delete(&models.AuditCheckpoint{}).Error)
	require.NoError(t, db.Where("key = ?", auditHighWaterKey).Delete(&models.SystemMetadata{}).Error)
	clk.advance()
	_, err = c.RunAuditVerificationTick(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&n).Error)
	assert.Zero(t, n, "no checkpoint re-baselined over a recorded failure")
	p, err := c.AuditVerificationStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusBroken, p.Status)
}

// F2: a corrupted state row is reported (an in-chain event, not_proven with
// the reason) rather than re-signed as a fresh state, until a full verification
// that started after the rejection completes.
func TestIncrementalVerify_CorruptedStateRowReportedNotResigned(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 2)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	require.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
	parts := strings.Split(rawAuditVerifyState(t, c), auditVerifyStateSep)
	require.Len(t, parts, 3)
	putAuditVerifyState(t, c, strings.Join([]string{parts[0], parts[1] + "A", parts[2]}, auditVerifyStateSep))

	clk.advance()
	tickOK(t, c)
	assert.Equal(t, int64(1), countEvents(t, db, stateRejectedEvent))
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.NotProvenReason, "was rejected")
	p, err := c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusNotProven, p.Status)

	completed := false
	for range 3 {
		clk.advance()
		if tickOK(t, c).CycleCompleted {
			completed = true
			break
		}
	}
	require.True(t, completed)
	assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status, "a cycle started after the rejection clears it")
	assert.Equal(t, int64(1), countEvents(t, db, stateRejectedEvent))
}

// With every checkpoint row deleted, the write path checks the tail from the
// signed high-water mark (pinning its head) instead of the count-only full-walk
// fallback, so a chain rewritten through the head is refused, not re-baselined.
func TestIncrementalVerify_WritePathUsesHighWaterBaseWhenCheckpointsDeleted(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	logIncrEvents(t, c, clk, 3)
	rehashFrom(t, db, 5, 0)
	require.NoError(t, db.Where("1 = 1").Delete(&models.AuditCheckpoint{}).Error)

	clk.advance()
	_, err := c.RunAuditVerificationTick(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&n).Error)
	assert.Zero(t, n, "no checkpoint signed over the rewritten chain")
}
