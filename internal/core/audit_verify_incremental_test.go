// audit_verify_incremental_test.go — acceptance tests for incremental audit-chain
// verification (docs/specs/audit-incremental-verification.md §7).
package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// incrClock is a settable test clock.
type incrClock struct{ t time.Time }

func (k *incrClock) now() time.Time { return k.t }
func (k *incrClock) advance()       { k.t = k.t.Add(24 * time.Hour) }

// newIncrementalTestCore is newReanchorTestCore with incremental verification
// on (24h ticks, the given segments per cycle) and a 1-id minimum segment
// width, so small chains really are walked in several segments.
func newIncrementalTestCore(t *testing.T, segments int) (*KeyorixCore, *gorm.DB, *incrClock) {
	t.Helper()
	c, db, fixed := newReanchorTestCore(t)
	// One connection: ":memory:" is per connection, and the full job's
	// goroutine must see the same database.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	clk := &incrClock{t: fixed}
	c.now = clk.now
	c.SetAuditIncrementalVerification(24*time.Hour, segments)
	c.auditVerifyMinWidth = 1
	return c, db, clk
}

func logIncrEvents(t *testing.T, c *KeyorixCore, clk *incrClock, n int) {
	t.Helper()
	for range n {
		logChainedEvent(t, c, "secret.read", clk.t)
	}
}

func incrVerify(t *testing.T, c *KeyorixCore) *AuditVerifyReport {
	t.Helper()
	r, err := c.VerifyAuditChainIncremental(context.Background())
	require.NoError(t, err)
	require.Equal(t, r.Status == AuditVerifyStatusValid, r.Valid, "valid must be true exactly when status is valid")
	return r
}

// tamperDescription edits a row's content without touching its hashes.
func tamperDescription(t *testing.T, db *gorm.DB, id uint) {
	t.Helper()
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", id).Update("description", "tampered").Error)
}

// rehashFrom models an attacker who edits row from and recomputes entry_hash /
// prev_hash for every row in [from, through] (through = 0: to the end), so the
// rewritten span is self-consistent.
func rehashFrom(t *testing.T, db *gorm.DB, from, through uint) {
	t.Helper()
	var rows []models.AuditEvent
	q := db.Where("id >= ?", from)
	if through > 0 {
		q = q.Where("id <= ?", through)
	}
	require.NoError(t, q.Order("id ASC").Find(&rows).Error)
	require.NotEmpty(t, rows)
	prev := rows[0].PrevHash
	for i := range rows {
		e := &rows[i]
		if i == 0 {
			e.Description = "rewritten by an attacker"
		}
		e.PrevHash = prev
		e.EntryHash = store.ComputeAuditEntryHash(e, prev)
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", e.ID).
			Updates(map[string]any{"description": e.Description, "prev_hash": e.PrevHash, "entry_hash": e.EntryHash}).Error)
		prev = e.EntryHash
	}
}

func tickOK(t *testing.T, c *KeyorixCore) *AuditVerifyTickResult {
	t.Helper()
	res, err := c.RunAuditVerificationTick(context.Background())
	require.NoError(t, err)
	return res
}

func latestHeadID(t *testing.T, c *KeyorixCore) uint {
	t.Helper()
	cp, err := c.storage.LatestAuditCheckpoint(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cp)
	return cp.HeadID
}

func countEvents(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// (3) An upgraded deployment (a checkpoint, no persisted state) reports
// not_proven — never valid — until one rolling cycle completes, then valid.
func TestIncrementalVerify_NotProvenUntilFirstCycleCompletes(t *testing.T) {
	t.Parallel()
	c, _, clk := newIncrementalTestCore(t, 3)
	logIncrEvents(t, c, clk, 30)
	_, _, err := c.WriteAuditCheckpoint(context.Background()) // written by the pre-upgrade server
	require.NoError(t, err)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.NotProvenReason, "no full verification has completed yet")
	assert.Nil(t, r.LastFullVerificationAt)
	require.NotNil(t, r.Coverage)
	assert.True(t, r.Coverage.TailComplete)

	p, err := c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusNotProven, p.Status)
	assert.False(t, p.Valid)

	for tick := 1; tick <= 3; tick++ {
		clk.advance()
		logIncrEvents(t, c, clk, 2)
		res := tickOK(t, c)
		require.True(t, res.Written, "tick %d writes a checkpoint", tick)
		require.True(t, res.SegmentWalked)
		r = incrVerify(t, c)
		if tick < 3 {
			assert.False(t, res.CycleCompleted, "tick %d", tick)
			assert.Equal(t, AuditVerifyStatusNotProven, r.Status, "tick %d: a partial cycle proves nothing about the unwalked rows", tick)
			require.NotNil(t, r.RollingCycle)
		}
	}
	assert.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)
	require.NotNil(t, r.LastFullVerificationAt)
	assert.Equal(t, auditFullSourceRolling, r.LastFullVerificationSource)
	assert.Equal(t, int64(36), r.ChainedEvents)

	p, err = c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusValid, p.Status)
}

// A fresh install's first tick has no checkpoint to extend: it takes the
// unchanged full-walk path, which counts as a full verification.
func TestIncrementalVerify_FirstCheckpointIsAFullVerification(t *testing.T) {
	t.Parallel()
	c, _, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	res := tickOK(t, c)
	require.True(t, res.Written)
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)
	assert.Equal(t, auditFullSourceCheckpoint, r.LastFullVerificationSource)
}

// (1) A tamper in the tail is reported by the next request and refused by the
// next tick, which records a sticky failure and an in-chain event.
func TestIncrementalVerify_TailTamperCaughtAtNextTick(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	head := latestHeadID(t, c)
	logIncrEvents(t, c, clk, 5)
	tamperDescription(t, db, head+2)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, head+2, *r.FirstBrokenID)

	clk.advance()
	_, err := c.RunAuditVerificationTick(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	assert.Equal(t, head, latestHeadID(t, c), "no checkpoint may be signed over the tampered tail")
	assert.Equal(t, int64(1), countEvents(t, db, "system.audit_chain_verification_failed"))

	p, err := c.AuditVerificationStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusBroken, p.Status)
	assert.False(t, p.Valid)

	// Sticky: the next tick refuses again and does not log a second event.
	clk.advance()
	_, err = c.RunAuditVerificationTick(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	assert.Equal(t, int64(1), countEvents(t, db, "system.audit_chain_verification_failed"))
	_, _, err = c.WriteAuditCheckpointIncremental(ctx)
	require.ErrorIs(t, err, ErrAuditCheckpointRefused, "the on-demand checkpoint refuses too")
}

// runTicksUntilBroken ticks (one per simulated day, appending an event each
// time) until the API reports broken, returning how many ticks it took.
func runTicksUntilBroken(t *testing.T, c *KeyorixCore, clk *incrClock, maxTicks int) (int, *AuditVerifyReport) {
	t.Helper()
	for i := 1; i <= maxTicks; i++ {
		clk.advance()
		logIncrEvents(t, c, clk, 1)
		_, _ = c.RunAuditVerificationTick(context.Background())
		if r := incrVerify(t, c); r.Status == AuditVerifyStatusBroken {
			return i, r
		}
	}
	return 0, nil
}

// (2) A content edit in an old segment (before the checkpoint head, so the tail
// check cannot see it) is caught within one rolling cycle.
func TestIncrementalVerify_OldSegmentTamperCaughtWithinOneCycle(t *testing.T) {
	t.Parallel()
	const segments = 4
	c, db, clk := newIncrementalTestCore(t, segments)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c) // full-walk first checkpoint; starts a cycle
	tickOK(t, c) // the cycle is now past segment 1
	tamperDescription(t, db, 3)

	n, r := runTicksUntilBroken(t, c, clk, segments+1)
	require.NotZero(t, n, "the rolling re-walk must catch an old-segment tamper within one cycle")
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, uint(3), *r.FirstBrokenID)
	assert.Equal(t, int64(1), countEvents(t, db, "system.audit_chain_verification_failed"))
	// The tail is intact, but a recorded failure blocks re-notarising the chain.
	_, _, err := c.WriteAuditCheckpointIncremental(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
}

// (5) A content edit of the certified head row itself (hash left alone, so the
// next row still links) is caught by pinning the head: it must recompute.
func TestIncrementalVerify_HeadRowContentEditCaughtImmediately(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	head := latestHeadID(t, c)
	logIncrEvents(t, c, clk, 2)
	tamperDescription(t, db, head)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, head, *r.FirstBrokenID)
	_, err := c.RunAuditVerificationTick(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
}

// (2') An edit plus a rehash up to just before the signed checkpoint head keeps
// the head row intact (the tail check passes), but breaks the head's link: the
// rolling re-walk catches it within one cycle.
func TestIncrementalVerify_RehashBelowCheckpointHeadCaughtWithinOneCycle(t *testing.T) {
	t.Parallel()
	const segments = 4
	c, db, clk := newIncrementalTestCore(t, segments)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c)
	head := latestHeadID(t, c)
	rehashFrom(t, db, 5, head-1)

	r := incrVerify(t, c)
	assert.NotEqual(t, AuditVerifyStatusBroken, r.Status, "premise: the tail check alone cannot see this rewrite")

	n, r := runTicksUntilBroken(t, c, clk, segments+1)
	require.NotZero(t, n, "the rolling re-walk must catch a rehash that stops before a checkpoint head")
	require.NotNil(t, r.FirstBrokenID)
	// Caught either at a later segment's pinned seed (rewritten after it was
	// verified) or at the head row, whose link the rewrite broke.
	assert.True(t, *r.FirstBrokenID >= 5 && *r.FirstBrokenID <= head, "first broken id %d", *r.FirstBrokenID)
}

// (5) An edit plus a rehash through the checkpoint head changes the certified
// head hash: the very next request and tick catch it.
func TestIncrementalVerify_RehashThroughCheckpointHeadCaughtImmediately(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 20)
	tickOK(t, c)
	logIncrEvents(t, c, clk, 3)
	rehashFrom(t, db, 5, 0)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
	assert.Contains(t, r.Reason, "head of signed checkpoint")
	_, err := c.RunAuditVerificationTick(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
}

// (5) Deleting the newer checkpoints and truncating the tail leaves an older
// checkpoint whose tail is self-consistent: the high-water floor still catches it.
func TestIncrementalVerify_TailTruncationWithNewerCheckpointsDeleted(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	first := latestHeadID(t, c)
	logIncrEvents(t, c, clk, 5)
	clk.advance()
	tickOK(t, c)
	require.NoError(t, db.Where("head_id > ?", first).Delete(&models.AuditCheckpoint{}).Error)
	require.NoError(t, db.Where("id > ?", first+2).Delete(&models.AuditEvent{}).Error)

	// A restarted process: only the persisted high-water mark remembers.
	c2 := NewKeyorixCore(c.storage)
	c2.now = c.now
	c2.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c2.SetAuditIncrementalVerification(24*time.Hour, 7)
	c2.SeedAuditWatermark(context.Background())
	r := incrVerify(t, c2)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
	assert.Contains(t, r.CheckpointReason, "high-water")
}

// (4) A state row edited without the key, or replaced with a forged claim, is
// ignored: the API reports not_proven with the reason, never valid.
func TestIncrementalVerify_ForgedStateIgnored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	require.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)

	val, ok, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
	require.NoError(t, err)
	require.True(t, ok)
	parts := strings.Split(val, auditVerifyStateSep)
	require.Len(t, parts, 3)

	// Flip one signature character.
	sig := []byte(parts[2])
	sig[0] ^= 1
	require.NoError(t, c.storage.SetSystemMetadata(ctx, auditVerifyStateKey, strings.Join([]string{parts[0], parts[1], string(sig)}, auditVerifyStateSep)))
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.StateReason, "fails its signature")

	// A forged state claiming a recent valid full verification, signed with the wrong key.
	forger := NewKeyorixCore(c.storage)
	forger.now = c.now
	forger.SetAuditCheckpointKey([]byte("attacker-key-not-the-real-one!!"), "v1")
	require.NoError(t, forger.saveAuditVerifyState(ctx, &auditVerifyState{LastFull: &auditFullResult{
		StartedAt: clk.t, CompletedAt: clk.t, ThroughID: 10, Source: auditFullSourceJob, Valid: true}}))
	r = incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Nil(t, r.LastFullVerificationAt)

	// The next tick replaces the untrusted row with fresh state that records the
	// rejection (not_proven, with an in-chain event), never with a clean slate.
	clk.advance()
	tickOK(t, c)
	r = incrVerify(t, c)
	assert.Empty(t, r.StateReason)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.NotProvenReason, "fails its signature")
	assert.Equal(t, int64(1), countEvents(t, db, "system.audit_verification_state_rejected"))
}

// A stale full verification (older than two cycles) is not_proven again.
func TestIncrementalVerify_StaleFullVerificationNotProven(t *testing.T) {
	t.Parallel()
	c, _, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	require.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
	clk.t = clk.t.Add(15 * 24 * time.Hour)
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
	assert.Contains(t, r.NotProvenReason, "more than two rolling cycles ago")
}

// The request-path tail check is row-bounded: a longer tail is not_proven.
func TestIncrementalVerify_LongTailNotProven(t *testing.T) {
	t.Parallel()
	c, _, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 5)
	tickOK(t, c)
	logIncrEvents(t, c, clk, 5)
	tail, err := c.auditTailCheck(context.Background(), 3, false)
	require.NoError(t, err)
	assert.True(t, tail.truncated)
	assert.True(t, tail.v.Valid)
}

func waitAuditJob(t *testing.T, c *KeyorixCore, id string) *AuditVerifyJobStatus {
	t.Helper()
	var j *AuditVerifyJobStatus
	require.Eventually(t, func() bool {
		var err error
		j, err = c.AuditFullVerificationJob(context.Background(), id)
		require.NoError(t, err)
		return j.State != AuditVerifyJobRunning
	}, 10*time.Second, 10*time.Millisecond)
	return j
}

// ?full=true: the background job proves the chain at once (no wait for a
// cycle), and a failing job records the failure.
func TestIncrementalVerify_FullJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 20)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.Equal(t, AuditVerifyStatusNotProven, incrVerify(t, c).Status)

	id, started, err := c.StartAuditFullVerification(ctx)
	require.NoError(t, err)
	require.True(t, started)
	j := waitAuditJob(t, c, id)
	assert.Equal(t, AuditVerifyJobSucceeded, j.State)
	require.NotNil(t, j.Result)
	assert.True(t, j.Result.Valid)
	assert.Equal(t, AuditVerifyModeFull, j.Result.Mode)
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)
	assert.Equal(t, auditFullSourceJob, r.LastFullVerificationSource)

	_, err = c.AuditFullVerificationJob(ctx, "not-a-job")
	require.ErrorIs(t, err, ErrAuditVerifyJobNotFound)

	tamperDescription(t, db, 4)
	id2, _, err := c.StartAuditFullVerification(ctx)
	require.NoError(t, err)
	j = waitAuditJob(t, c, id2)
	assert.Equal(t, AuditVerifyJobSucceeded, j.State, "the job ran; its result is the verdict")
	assert.False(t, j.Result.Valid)
	assert.Equal(t, AuditVerifyStatusBroken, j.Result.Status)
	_, err = c.AuditFullVerificationJob(ctx, id)
	require.ErrorIs(t, err, ErrAuditVerifyJobNotFound, "a superseded job id is gone")
	assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status)
}

// One job at a time: a start while one runs returns the running job's id.
func TestIncrementalVerify_FullJobSingleFlight(t *testing.T) {
	t.Parallel()
	c, _, _ := newIncrementalTestCore(t, 7)
	c.auditVerifyJobMu.Lock()
	c.auditVerifyJobID.Store("running-job")
	id, started, err := c.StartAuditFullVerification(context.Background())
	c.auditVerifyJobMu.Unlock()
	require.NoError(t, err)
	assert.False(t, started)
	assert.Equal(t, "running-job", id)
}

// A job whose process died (state says running, no one runs it) reads interrupted.
func TestIncrementalVerify_InterruptedJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, clk := newIncrementalTestCore(t, 7)
	require.NoError(t, c.updateAuditVerifyState(ctx, func(st *auditVerifyState) *auditVerifyFailure {
		st.Job = &auditVerifyJob{ID: "dead", State: AuditVerifyJobRunning, StartedAt: clk.t}
		return nil
	}))
	j, err := c.AuditFullVerificationJob(ctx, "dead")
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyJobInterrupted, j.State)
}

// A sanctioned purge between two segments (past the cycle's seed) restarts the
// segment from the signed anchor; the cycle still completes valid.
func TestIncrementalVerify_PurgeBetweenSegments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, clk := newIncrementalTestCore(t, 3)
	for i := range 20 {
		logChainedEvent(t, c, "secret.read", clk.t.AddDate(0, 0, -(60-i)))
	}
	logIncrEvents(t, c, clk, 10)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	tickOK(t, c) // segment 1 of 3: ids 1..~10, all of them about to be purged
	_, err = c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	var completed bool
	for range 4 {
		clk.advance()
		res := tickOK(t, c)
		if res.CycleCompleted {
			completed = true
			break
		}
	}
	require.True(t, completed)
	assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
}

// walkSpy fails the test on any full walk and records segment walks.
type walkSpy struct {
	inner    storage.Storage
	t        *testing.T
	segments []storage.AuditChainSegment
	rows     int64
}

func (s *walkSpy) VerifyAuditChain(next storage.Storage, ctx context.Context, a *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	s.t.Errorf("a full chain walk ran on a path that must be incremental")
	return next.VerifyAuditChain(ctx, a)
}

func (s *walkSpy) VerifyAuditChainSegment(next storage.Storage, ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	s.segments = append(s.segments, seg)
	v, err := next.VerifyAuditChainSegment(ctx, seg)
	if v != nil {
		s.rows += v.ChainedEvents
	}
	return v, err
}

// wrap returns inner decorated with walkSpy's overrides.
func (s *walkSpy) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		VerifyAuditChain:        s.VerifyAuditChain,
		VerifyAuditChainSegment: s.VerifyAuditChainSegment,
	})
}

// store returns s.inner decorated with walkSpy's overrides.
func (s *walkSpy) store() storage.Storage { return s.wrap(s.inner) }

// (6) Startup/tick cost is O(tail + one segment), never a full walk, once a
// checkpoint exists; posture walks nothing at all.
func TestIncrementalVerify_TickAndPostureNeverWalkTheWholeChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	seed, db, clk := newIncrementalTestCore(t, 10)
	logIncrEvents(t, seed, clk, 1000)
	_, _, err := seed.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	logIncrEvents(t, seed, clk, 7)

	spy := &walkSpy{inner: store.NewLocalStorage(db), t: t}
	c := NewKeyorixCore(spy.store())
	c.now = clk.now
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	c.SetAuditIncrementalVerification(24*time.Hour, 10)
	c.auditVerifyMinWidth = 1

	res := tickOK(t, c)
	require.True(t, res.Written)
	assert.LessOrEqual(t, spy.rows, int64(7+101), "tick walked the tail plus one tenth of the chain, not all of it")
	assert.Len(t, spy.segments, 2)

	spy.segments, spy.rows = nil, 0
	_, err = c.AuditVerificationStatus(ctx)
	require.NoError(t, err)
	assert.Empty(t, spy.segments, "posture reads the persisted state only")

	_ = incrVerify(t, c)
	require.Len(t, spy.segments, 1, "a request walks only the tail")
	assert.Equal(t, auditVerifyRequestTailRows, spy.segments[0].MaxRows)
}

// (6) The first tick after a restart is deferred while the latest checkpoint is
// fresh; the delay is clamped to one interval (created_at is not signed).
func TestAuditCheckpointFirstTickDelay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, clk := newIncrementalTestCore(t, 7)
	day := 24 * time.Hour
	assert.Zero(t, c.AuditCheckpointFirstTickDelay(ctx, day), "no checkpoint: tick at once")

	logIncrEvents(t, c, clk, 3)
	cp, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	setCreated := func(at time.Time) {
		require.NoError(t, db.Model(&models.AuditCheckpoint{}).Where("id = ?", cp.ID).Update("created_at", at).Error)
	}
	setCreated(clk.t.Add(-6 * time.Hour))
	assert.Equal(t, 18*time.Hour, c.AuditCheckpointFirstTickDelay(ctx, day))
	setCreated(clk.t.Add(-30 * time.Hour))
	assert.Zero(t, c.AuditCheckpointFirstTickDelay(ctx, day))
	setCreated(clk.t.Add(400 * day))
	assert.Equal(t, day, c.AuditCheckpointFirstTickDelay(ctx, day), "a forged future created_at defers by at most one interval")

	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Where("id = ?", cp.ID).Update("signature", "00").Error)
	assert.Zero(t, c.AuditCheckpointFirstTickDelay(ctx, day), "an unauthenticated checkpoint never defers")
}

// Without incremental verification configured (no scheduler), every path is
// the unchanged full walk.
func TestIncrementalVerify_NotConfiguredIsFullWalk(t *testing.T) {
	t.Parallel()
	c, db, fixed := newReanchorTestCore(t)
	clk := &incrClock{t: fixed}
	logIncrEvents(t, c, clk, 5)
	r, err := c.VerifyAuditChainIncremental(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyModeFull, r.Mode)
	assert.Equal(t, AuditVerifyStatusValid, r.Status)
	tamperDescription(t, db, 2)
	r, err = c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
}

// Every checkpoint row deleted plus a tail truncation: the request path checks
// the tail from the signed high-water mark instead and reports broken.
func TestIncrementalVerify_AllCheckpointsDeletedUsesHighWaterBase(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	head := latestHeadID(t, c)
	require.NoError(t, db.Where("1 = 1").Delete(&models.AuditCheckpoint{}).Error)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusValid, r.Status, "an intact chain checked from the high-water mark: %s %s", r.Reason, r.NotProvenReason)

	require.NoError(t, db.Where("id >= ?", head).Delete(&models.AuditEvent{}).Error)
	r = incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
	assert.Contains(t, r.Reason, "the signed high-water mark")
}

// Write-path parity with WriteAuditCheckpoint: a deleted high-water mark is
// flagged on the read path but does not block the next checkpoint, which
// re-establishes it (it is not recorded as a sticky failure).
func TestIncrementalVerify_DeletedHighWaterMarkIsReestablishedByTheNextTick(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 7)
	logIncrEvents(t, c, clk, 10)
	tickOK(t, c)
	require.NoError(t, db.Where("key = ?", auditHighWaterKey).Delete(&models.SystemMetadata{}).Error)
	assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status)

	clk.advance()
	res := tickOK(t, c)
	require.True(t, res.Written)
	assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
}
