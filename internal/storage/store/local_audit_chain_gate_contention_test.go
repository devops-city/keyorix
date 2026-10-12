// local_audit_chain_gate_contention_test.go — the blocker the coordinator's
// review of #2637 found: the in-process SQLite write gate's error was invisible
// to this package's busy classifier, and #2420's bisection turned that into
// unbounded amplification.
//
// Two separate defects, one cause:
//
//  1. isSQLiteBusyErr matched only SQLITE_BUSY / "database is locked". Once the
//     gate exists, contention is resolved by WAITING in-process and reported as
//     storage.ErrSQLiteWriteContention — so the DOMINANT contention error on
//     SQLite stopped being covered by the retry budget that exists for exactly
//     this condition. SQLITE_BUSY survives only for what the gate does not cover
//     (autocommit writes, a second *sql.DB handle in one process).
//
//  2. commitAuditBatch bisected on it. Its doc comment anticipated a contention
//     failure and dismissed it — "every leaf gets the same outcome … only adds a
//     few harmless extra attempts" — but that reasoning depends on the CTX
//     HAVING EXPIRED, which is what makes each leaf fail instantly. The gate
//     gives up after its own bound while auditWriteContext's deadline can still
//     be live, so each of a 256-item batch's ~511 leaves can queue for the full
//     bound AGAIN. A bounded single failure becomes an unbounded serial
//     amplification, under precisely the load the gate was built to bound — and
//     recordAuditFlush fires once per recursion level, corrupting
//     keyorix_audit_flusher_batch_size / _flushes_total at exactly the moment an
//     operator is reading them.
//
// Only reachable under load, which is why it needs a guard rather than a
// comment: the error is injected directly here instead of by generating real
// contention, so the classification and the no-bisect decision are tested
// without a timing-dependent fixture.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestIsSQLiteBusyErr_RecognisesTheWriteGateSentinel is defect 1.
//
// RED before the fix on the first two subtests: the gate's error text contains
// neither "SQLITE_BUSY" nor "database is locked", so the classifier returned
// false and commitBatchWithBusyRetry / logAuditEventDirect's retry loops
// returned immediately on the one error they were written to retry.
//
// Matched with errors.Is on the sentinel rather than by substring, so a reworded
// message cannot silently un-cover it again — which is how the original
// substring-only classifier came to miss this in the first place.
func TestIsSQLiteBusyErr_RecognisesTheWriteGateSentinel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the gate sentinel itself", corestorage.ErrSQLiteWriteContention, true},
		{
			"the sentinel wrapped, as a caller sees it",
			fmt.Errorf("begin write transaction: %w", corestorage.ErrSQLiteWriteContention),
			true,
		},
		{"driver SQLITE_BUSY still matches", errors.New("SQLITE_BUSY: ..."), true},
		{"driver lock text still matches", errors.New("database is locked"), true},
		{"an unrelated error does not", errors.New("UNIQUE constraint failed: audit_events.id"), false},
		{"nil does not", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSQLiteBusyErr(tc.err))
		})
	}
}

// TestCommitAuditBatch_GateContentionFailsTheBatchWithoutBisecting is defect 2,
// and it asserts the AMPLIFICATION rather than just the returned errors: a
// bisecting implementation returns the same error to every caller, so the
// returned errors look identical either way and the bug is invisible in them.
//
// Measured as the delta on keyorix_audit_flusher_flushes_total, which
// recordAuditFlush increments once per commitAuditBatch INVOCATION. That is
// exactly the recursion count, and unlike counting commit attempts it is
// independent of the busy-retry loop — which legitimately makes many attempts
// per invocation now that the contention error is (correctly) retryable. It is
// also the metric the review flags as corrupted by the recursion, so asserting
// on it tests the reported symptom rather than a proxy for it.
//
// RED before the fix: 9 flushes for a 5-item batch (the full ~2n-1 recursion;
// ~511 at the 256-item batch size this runs at in production). GREEN: 1.
func TestCommitAuditBatch_GateContentionFailsTheBatchWithoutBisecting(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()

	// Every commit attempt fails with the gate's sentinel, wrapped the way a
	// caller actually receives it. Injected at the gorm layer rather than by
	// generating real contention: the point under test is the classification and
	// the bisect decision, not the gate's own timing.
	var attempts atomic.Int64
	require.NoError(t, ls.db.Callback().Create().Before("gorm:before_create").Register(
		"test:gate_contention_every_attempt",
		func(tx *gorm.DB) {
			if len(auditEventsInCreate(tx)) > 0 {
				attempts.Add(1)
				_ = tx.AddError(fmt.Errorf("begin write transaction: %w", corestorage.ErrSQLiteWriteContention))
			}
		},
	))
	t.Cleanup(func() {
		_ = ls.db.Callback().Create().Remove("test:gate_contention_every_attempt")
	})

	base := time.Now().UTC()
	const n = 5
	batch := make([]*auditBatchItem, n)
	for i := 0; i < n; i++ {
		tr := true
		// A ctx with a LIVE deadline, which is the premise that makes the
		// amplification possible: the old doc comment's "every leaf fails
		// instantly" only holds for an already-expired ctx. Short, because the
		// retry loop inside each invocation runs until the deadline and the
		// recursion count — not the retry count — is what is under test.
		itemCtx, cancel := context.WithDeadline(ctx, time.Now().Add(300*time.Millisecond))
		t.Cleanup(cancel)
		batch[i] = &auditBatchItem{
			event: &models.AuditEvent{
				EventType: "secret.read", Description: "ok", Success: &tr,
				EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
			},
			ctx:  itemCtx,
			done: make(chan error, 1),
		}
	}

	before := testutil.ToFloat64(auditFlushesTotal)
	errs := ls.commitAuditBatch(batch)
	flushes := testutil.ToFloat64(auditFlushesTotal) - before

	require.Len(t, errs, n)
	for i, err := range errs {
		require.Error(t, err, "item %d must still be told the batch failed", i)
		assert.ErrorIs(t, err, corestorage.ErrSQLiteWriteContention,
			"item %d must get the contention error, not a rewritten one", i)
	}

	// The load-bearing assertion.
	assert.Equal(t, float64(1), flushes,
		"commitAuditBatch bisected a BATCH-GLOBAL contention failure: %v flushes recorded for a %d-item batch, "+
			"so it recursed. There is no poisoned item for a bisection to find, each leaf can queue on the write "+
			"gate for its full bound again (~511 leaves at the production batch size), and every extra level "+
			"corrupts keyorix_audit_flusher_batch_size / _flushes_total (#2637 review)", flushes, n)
	// Sanity: the injection really did fire, so the assertion above is not
	// passing because nothing was attempted.
	assert.Positive(t, attempts.Load(), "the injected contention error must actually have been hit")
}

// TestCommitAuditBatch_StillBisectsAPoisonedItemUnderContentionsSibling is the
// calibration, and it is the reason the fix is a narrow predicate rather than
// "stop bisecting". #2420's isolation property must survive: a genuine,
// ITEM-SPECIFIC error still has to be bisected down so the other items in the
// batch commit. Without this, "never bisect" would pass the test above and
// silently undo #2420.
func TestCommitAuditBatch_StillBisectsAPoisonedItemUnderContentionsSibling(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()

	const poisonMarker = "POISON-ME-TOO"
	require.NoError(t, ls.db.Callback().Create().Before("gorm:before_create").Register(
		"test:poison_one_not_contention",
		func(tx *gorm.DB) {
			for _, ev := range auditEventsInCreate(tx) {
				if ev.Description == poisonMarker {
					_ = tx.AddError(errors.New("injected: item-specific constraint violation"))
				}
			}
		},
	))
	t.Cleanup(func() {
		_ = ls.db.Callback().Create().Remove("test:poison_one_not_contention")
	})

	base := time.Now().UTC()
	const n = 4
	const poisoned = 1
	batch := make([]*auditBatchItem, n)
	for i := 0; i < n; i++ {
		tr := true
		desc := "ok"
		if i == poisoned {
			desc = poisonMarker
		}
		batch[i] = &auditBatchItem{
			event: &models.AuditEvent{
				EventType: "secret.read", Description: desc, Success: &tr,
				EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
			},
			ctx:  ctx,
			done: make(chan error, 1),
		}
	}

	errs := ls.commitAuditBatch(batch)
	require.Len(t, errs, n)
	for i, err := range errs {
		if i == poisoned {
			assert.Error(t, err, "the poisoned item must still fail")
			continue
		}
		assert.NoError(t, err,
			"item %d shares the batch with a poisoned item and must still commit — that is #2420's isolation "+
				"property, and the contention carve-out must not weaken it", i)
	}
}

// TestCommitAuditBatch_GateWaitEndedByCtxDeadlineIsAlsoBatchGlobal is the
// coordinator's Finding 1 on #2637 (Opus pass): auditWriteTimeout (10s) ==
// sqliteWriteGateMaxWait == sqliteBusyTimeoutMillis (10s), and the caller's ctx
// deadline starts BEFORE the gate's own timer, so the gate's 3-way select can
// return a wrapped ctx.Err() ("sqlite write gate: context deadline exceeded")
// instead of ErrSQLiteWriteContention. That error matched neither classifier, so
// the bisection the sibling test pins shut was still reachable on the audit path.
//
// RED before the fix: 9 flushes for a 5-item batch. GREEN: 1.
func TestCommitAuditBatch_GateWaitEndedByCtxDeadlineIsAlsoBatchGlobal(t *testing.T) {
	ls := newAuditChainTestStore(t)

	// Exactly the shape sqliteWriteGate.acquire returns when ctx ends first.
	gateCtxErr := fmt.Errorf("begin write transaction: %w",
		fmt.Errorf("sqlite write gate: %w", context.DeadlineExceeded))
	require.NoError(t, ls.db.Callback().Create().Before("gorm:before_create").Register(
		"test:gate_ctx_deadline_every_attempt",
		func(tx *gorm.DB) {
			if len(auditEventsInCreate(tx)) > 0 {
				_ = tx.AddError(gateCtxErr)
			}
		},
	))
	t.Cleanup(func() {
		_ = ls.db.Callback().Create().Remove("test:gate_ctx_deadline_every_attempt")
	})

	base := time.Now().UTC()
	const n = 5
	batch := make([]*auditBatchItem, n)
	for i := 0; i < n; i++ {
		tr := true
		itemCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
		t.Cleanup(cancel)
		batch[i] = &auditBatchItem{
			event: &models.AuditEvent{
				EventType: "secret.read", Description: "ok", Success: &tr,
				EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
			},
			ctx:  itemCtx,
			done: make(chan error, 1),
		}
	}

	before := testutil.ToFloat64(auditFlushesTotal)
	errs := ls.commitAuditBatch(batch)
	flushes := testutil.ToFloat64(auditFlushesTotal) - before

	require.Len(t, errs, n)
	for i, err := range errs {
		require.Error(t, err, "item %d must still be told the batch failed", i)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}
	assert.Equal(t, float64(1), flushes,
		"a gate wait that ended on the ctx deadline was bisected: %v flushes for a %d-item batch (#2637 Finding 1)", flushes, n)
}

// The predicate's own table, so the narrowness is pinned in both directions: ctx
// expiry and the sentinel are batch-global; an item-specific error is not.
func TestIsBatchGlobalContentionErr_Table(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"sentinel":                {corestorage.ErrSQLiteWriteContention, true},
		"wrapped sentinel":        {fmt.Errorf("x: %w", corestorage.ErrSQLiteWriteContention), true},
		"ctx deadline":            {context.DeadlineExceeded, true},
		"gate-wrapped ctx expiry": {fmt.Errorf("sqlite write gate: %w", context.DeadlineExceeded), true},
		"ctx canceled":            {context.Canceled, true},
		"item-specific":           {errors.New("UNIQUE constraint failed: audit_events.id"), false},
		"plain SQLITE_BUSY":       {errors.New("SQLITE_BUSY"), false},
		"nil":                     {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, isBatchGlobalContentionErr(tc.err))
		})
	}
}
