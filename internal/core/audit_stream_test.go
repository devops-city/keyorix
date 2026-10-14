package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuditBroker_SignalDelivered(t *testing.T) {
	t.Parallel()
	b := newAuditBroker()
	id, wake := b.subscribe()
	defer b.unsubscribe(id)

	b.signal()
	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("expected a wake tick after signal")
	}
}

func TestAuditBroker_SignalsCoalesce(t *testing.T) {
	t.Parallel()
	b := newAuditBroker()
	id, wake := b.subscribe()
	defer b.unsubscribe(id)

	// Several signals with no drain in between collapse to a single pending tick
	// (1-slot buffer) — the subscriber re-queries the DB once and catches up.
	for range 5 {
		b.signal()
	}
	<-wake // one pending
	select {
	case <-wake:
		t.Fatal("signals must coalesce to a single pending tick")
	default:
	}
}

func TestAuditBroker_SignalNonBlockingAndUnsubscribe(t *testing.T) {
	t.Parallel()
	b := newAuditBroker()
	id, wake := b.subscribe()

	// Fill the buffer, then signal again — must not block even though no one drains.
	b.signal()
	b.signal()
	b.signal() // would deadlock if signal blocked on a full channel

	b.unsubscribe(id)
	// After unsubscribe, a signal reaches no one; the old channel gets nothing new.
	b.signal()
	<-wake // drain the one buffered tick from before unsubscribe
	select {
	case <-wake:
		t.Fatal("no further ticks after unsubscribe")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAuditBroker_MultipleSubscribersAllWoken(t *testing.T) {
	t.Parallel()
	b := newAuditBroker()
	id1, w1 := b.subscribe()
	id2, w2 := b.subscribe()
	defer b.unsubscribe(id1)
	defer b.unsubscribe(id2)

	b.signal()
	for _, w := range []<-chan struct{}{w1, w2} {
		select {
		case <-w:
		case <-time.After(time.Second):
			t.Fatal("every subscriber must be woken")
		}
	}
}

// emitAudit must wake a live subscriber (the write→deliver hook), in addition to
// persisting the row.
func TestEmitAudit_SignalsSubscribers(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := &KeyorixCore{storage: ms, auditStream: newAuditBroker()}

	id, wake := c.SubscribeAuditStream()
	defer c.UnsubscribeAuditStream(id)

	c.emitAudit(context.Background(), &models.AuditEvent{EventType: "test.event"})

	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("emitAudit should wake live audit-stream subscribers")
	}
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// A constructed core always has a non-nil broker (no lazy-init nil panic in emitAudit).
func TestNewKeyorixCore_HasAuditBroker(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	require.NotNil(t, c.auditStream)
	id, _ := c.SubscribeAuditStream()
	c.UnsubscribeAuditStream(id)
	assert.NotPanics(t, func() { c.auditStream.signal() })
}
