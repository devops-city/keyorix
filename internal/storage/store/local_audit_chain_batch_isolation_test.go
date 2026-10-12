// local_audit_chain_batch_isolation_test.go — proof for coordinator review
// item 3 on #2420: a non-busy, item-specific error on ONE item in a
// multi-item audit-flusher batch must not fail every OTHER item sharing
// that batch window.
package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCommitAuditBatch_PoisonedItemIsolatedFromRest builds a 5-item batch
// directly (bypassing the flusher's own queue/timing, so the batch's
// composition is deterministic rather than scheduler-dependent) with the
// middle item rigged to fail via a GORM before-create callback keyed on a
// sentinel Description — a stand-in for any genuine, item-specific DB
// error (a constraint violation on one access-log row, for example; the
// coordinator review's own example). This is NOT a transient
// SQLite-busy-retry scenario — that path is unchanged and covered
// elsewhere (TestLogAuditEvent_SQLiteBusyRetries and friends).
//
// Before this fix, commitAuditBatch ran the whole batch in one transaction
// and returned ONE error for every item on any failure — a single poisoned
// item would have rolled back and failed the 4 unrelated, perfectly good
// items alongside it. commitAuditBatch now bisects on a genuine (non-busy)
// failure, isolating the bad item down to its own one-item retry while
// every other item still commits, with full chain linkage.
func TestCommitAuditBatch_PoisonedItemIsolatedFromRest(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()

	const poisonMarker = "POISON-ME"
	sentinelErr := errors.New("injected: simulated constraint violation on one item")
	require.NoError(t, ls.db.Callback().Create().Before("gorm:before_create").Register(
		"test:poison_one_audit_event",
		func(tx *gorm.DB) {
			for _, ev := range auditEventsInCreate(tx) {
				if ev.Description == poisonMarker {
					_ = tx.AddError(sentinelErr)
				}
			}
		},
	))
	t.Cleanup(func() {
		_ = ls.db.Callback().Create().Remove("test:poison_one_audit_event")
	})

	base := time.Now().UTC()
	const n = 5
	const poisonedIndex = 2
	batch := make([]*auditBatchItem, n)
	for i := 0; i < n; i++ {
		tr := true
		desc := "ok"
		if i == poisonedIndex {
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
		if i == poisonedIndex {
			assert.ErrorIs(t, err, sentinelErr, "the poisoned item must report the injected error")
			continue
		}
		assert.NoError(t, err, "item %d must succeed even though item %d in the same batch was poisoned", i, poisonedIndex)
	}

	// Every surviving item actually persisted, and the chain those items
	// form (the poisoned one never got a row at all) verifies cleanly.
	var count int64
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Count(&count).Error)
	assert.Equal(t, int64(n-1), count, "exactly the non-poisoned items were persisted")

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "the chain formed by the surviving items must verify: %s", v.Reason)
	assert.Equal(t, int64(n-1), v.ChainedEvents)
}

// TestCommitAuditBatch_AllItemsSucceedWhenNonePoisoned is the companion
// green case: the same 5-item batch shape with NOTHING poisoned must still
// commit as one single transaction (not silently always bisecting), and
// every item must succeed.
func TestCommitAuditBatch_AllItemsSucceedWhenNonePoisoned(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()

	base := time.Now().UTC()
	const n = 5
	batch := make([]*auditBatchItem, n)
	for i := 0; i < n; i++ {
		tr := true
		batch[i] = &auditBatchItem{
			event: &models.AuditEvent{
				EventType: "secret.read", Description: "ok", Success: &tr,
				EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
			},
			ctx:  ctx,
			done: make(chan error, 1),
		}
	}

	errs := ls.commitAuditBatch(batch)
	require.Len(t, errs, n)
	for i, err := range errs {
		assert.NoError(t, err, "item %d must succeed", i)
	}

	var count int64
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Count(&count).Error)
	assert.Equal(t, int64(n), count)

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.Equal(t, int64(n), v.ChainedEvents)
}

// TestCommitBatchAttempt_ResetsStaleIDOnReuse is the proof requested in
// coordinator review item 4 on #2420: a retried attempt must zero
// event/accessLog IDs before inserting, not reuse whatever a PRIOR attempt
// already assigned onto the same Go struct.
//
// Simulates exactly what commitBatchWithBusyRetry's loop does when it
// retries the same batch slice after a rolled-back attempt: call
// commitBatchAttempt twice on the SAME item (same *models.AuditEvent
// pointer), the second time with event.ID already carrying whatever the
// first, successful call assigned. Without zeroing ID at the start of each
// attempt, the second call's tx.Create would issue an explicit
// primary-key INSERT with that stale, already-used ID — a unique-
// constraint violation on SQLite's INTEGER PRIMARY KEY, since that row
// already exists. With the fix, the second attempt gets a fresh,
// auto-assigned ID and succeeds cleanly.
func TestCommitBatchAttempt_ResetsStaleIDOnReuse(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()

	tr := true
	event := &models.AuditEvent{
		EventType: "secret.read", Description: "first", Success: &tr,
		EventTime: time.Now().UTC(), ActorType: "user",
	}
	item := &auditBatchItem{event: event, ctx: ctx, done: make(chan error, 1)}
	batch := []*auditBatchItem{item}

	require.NoError(t, ls.commitBatchAttempt(ctx, batch))
	firstID := event.ID
	require.NotZero(t, firstID)

	// Reuse the SAME item/event for a second attempt, still carrying firstID.
	event.Description = "second"
	require.NoError(t, ls.commitBatchAttempt(ctx, batch),
		"a retried attempt reusing the same struct must not fail with a stale-ID conflict")
	assert.NotEqual(t, firstID, event.ID, "the second attempt must get a FRESH id, not reuse the stale one from the first")

	var count int64
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Count(&count).Error)
	assert.Equal(t, int64(2), count, "both attempts persisted their own row")
}
