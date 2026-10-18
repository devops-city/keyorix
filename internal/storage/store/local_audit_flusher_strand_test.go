// local_audit_flusher_strand_test.go — PERF-LOWCONC-1: the flusher's idle exit
// can no longer strand a submission that is on its way to the queue.
package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A send slower than the flusher's idle timeout still commits promptly: the
// flusher may not stop while a submission is registered. Before, the flusher
// exited after auditFlusherIdleTimeout with an empty queue even when a
// submission had already read af.queue and was about to send; that row then
// sat in a channel nobody read until its 10 s audit deadline, and the read it
// belonged to failed closed.
func TestAuditFlusher_SlowSendIsNotStrandedByIdleExit(t *testing.T) {
	ls := newAuditChainTestStore(t)
	auditBeforeQueueSendHook = func() { time.Sleep(auditFlusherIdleTimeout + 150*time.Millisecond) }
	t.Cleanup(func() { auditBeforeQueueSendHook = nil })

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- ls.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType: "secret.read", Description: "slow-send", EventTime: time.Now().UTC(), ActorType: "user",
		})
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
		assert.Less(t, time.Since(start), 2*time.Second, "the row must commit once sent, not wait out its audit deadline")
	case <-time.After(5 * time.Second):
		t.Fatal("the submission was stranded: the flusher stopped while it was registered")
	}
}

// Concurrent submissions: every one commits exactly once, the chain verifies,
// they were batched (fewer flushes than submissions), and the flusher ends
// with nothing registered.
func TestAuditFlusher_ConcurrentSubmissionsNoneStranded(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()
	const clients, perClient = 32, 25
	before := testutil.ToFloat64(auditFlushesTotal)

	var wg sync.WaitGroup
	errs := make(chan error, clients*perClient)
	for c := range clients {
		wg.Go(func() {
			for i := range perClient {
				errs <- ls.LogAuditEvent(ctx, &models.AuditEvent{
					EventType: "secret.read", Description: fmt.Sprintf("c%d-%d", c, i), EventTime: time.Now().UTC(), ActorType: "user",
				})
			}
		})
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(60 * time.Second):
		t.Fatal("submissions did not all return: one was stranded")
	}
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.Equal(t, int64(clients*perClient), v.ChainedEvents)
	assert.Less(t, testutil.ToFloat64(auditFlushesTotal)-before, float64(clients*perClient), "concurrent submissions must be batched")
	ls.auditFlusher.mu.Lock()
	defer ls.auditFlusher.mu.Unlock()
	assert.Zero(t, ls.auditFlusher.pending, "nothing may stay registered once every submission returned")
}
