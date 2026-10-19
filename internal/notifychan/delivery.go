// delivery.go — the async delivery engine shared by every notification sink.
//
// Each sink (webhook, chat, email) is just a bounded queue drained by a worker that
// POSTs/sends one event at a time, so Deliver never blocks the triggering operation.
// The engine adds the durability all sinks need: retry transient failures with
// exponential backoff, count the terminal outcome to Prometheus, and abandon in-flight
// backoff promptly on shutdown so Close stays bounded. A sink supplies only its own
// send func (which reports whether a failure is transient) and a channel label.
package notifychan

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

const (
	// A transient failure is retried up to deliveryMaxAttempts with exponential
	// backoff (0.5s + 1s + 2s) so a brief destination blip doesn't lose an alert.
	deliveryMaxAttempts = 4
	deliveryBaseBackoff = 500 * time.Millisecond
)

// sendFunc delivers one event. retryable reports whether a non-nil err is transient
// (worth retrying) rather than permanent.
type sendFunc func(ctx context.Context, ev core.NotificationEvent) (retryable bool, err error)

// redactURLHost renders rawURL as just its scheme and host, dropping the
// path/query — and with it any bearer token embedded there. The implementation
// lives in netutil so internal/core (which this package imports, so cannot be
// imported back) applies the identical policy to its own delivery path.
func redactURLHost(rawURL string) string { return netutil.RedactURLHost(rawURL) }

// sanitizeDeliveryError renders err for logging with any embedded destination URL
// cut down to scheme+host, so an ordinary transient delivery failure (the routine
// case this exists to handle — a network hiccup, a DNS blip, a closed connection)
// never writes a live webhook token to the log stream, which is typically shipped
// to a broader-access SIEM/log platform than whoever administers the channel config.
func sanitizeDeliveryError(err error) string { return netutil.SanitizeErrorURLs(err) }

// deliverer is the shared queue+worker+retry engine. Sinks embed one.
type deliverer struct {
	channel     string
	queue       chan core.NotificationEvent
	send        sendFunc
	baseBackoff time.Duration
	closing     chan struct{} // closed by close() to abort in-flight retry backoff
	closeOnce   sync.Once
	wg          sync.WaitGroup
	// mu guards both dropped and closed below — #G63: enqueue()'s non-blocking
	// send on queue and close()'s close(queue) are otherwise unsynchronized, so
	// a concurrent enqueue()/close() can send on an already-closed channel
	// (a genuine Go runtime panic, not just a logical race). close() sets
	// closed=true and enqueue() checks it under the SAME mutex as the send
	// itself, so either enqueue() completes its send/drop entirely before
	// close() can proceed to actually close the channel, or it observes
	// closed=true and never touches the channel at all.
	mu      sync.Mutex
	closed  bool
	dropped int
}

// newDeliverer starts the worker. channel is the Prometheus label; baseBackoff is
// injectable so tests don't sleep for real seconds.
func newDeliverer(channel string, queueSize int, baseBackoff time.Duration, send sendFunc) *deliverer {
	d := &deliverer{
		channel:     channel,
		queue:       make(chan core.NotificationEvent, queueSize),
		send:        send,
		baseBackoff: baseBackoff,
		closing:     make(chan struct{}),
	}
	d.wg.Add(1)
	go d.worker()
	return d
}

// enqueue offers the event to the queue without blocking; a full queue (a wedged
// destination) drops and counts it rather than stalling the caller. A queue
// that's being (or has been) closed also drops silently rather than sending —
// see the deliverer.mu doc comment for why the closed check and the send share
// one critical section.
func (d *deliverer) enqueue(ev core.NotificationEvent) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	select {
	case d.queue <- ev:
		d.mu.Unlock()
	default:
		d.dropped++
		dropped := d.dropped
		d.mu.Unlock()
		notifyDeliveries.WithLabelValues(d.channel, outcomeDropped).Inc()
		log.Printf("notifychan: %s queue full, dropped notification (total dropped: %d)", d.channel, dropped)
	}
}

func (d *deliverer) worker() {
	defer d.wg.Done()
	for ev := range d.queue {
		d.deliver(ev)
	}
}

// deliver sends one event, retrying transient failures with exponential backoff up to
// deliveryMaxAttempts and recording the terminal outcome. Backoff is abandoned promptly
// when closing so shutdown isn't extended by retries.
func (d *deliverer) deliver(ev core.NotificationEvent) {
	backoff := d.baseBackoff
	for attempt := 1; ; attempt++ {
		retryable, err := d.send(context.Background(), ev)
		if err == nil {
			notifyDeliveries.WithLabelValues(d.channel, outcomeDelivered).Inc()
			return
		}
		if !retryable || attempt >= deliveryMaxAttempts {
			notifyDeliveries.WithLabelValues(d.channel, outcomeFailed).Inc()
			log.Printf("notifychan: %s delivery failed after %d attempt(s): %s", d.channel, attempt, sanitizeDeliveryError(err))
			return
		}
		notifyRetries.WithLabelValues(d.channel).Inc()
		select {
		case <-time.After(backoff):
		case <-d.closing:
			notifyDeliveries.WithLabelValues(d.channel, outcomeFailed).Inc()
			log.Printf("notifychan: %s delivery abandoned on shutdown after %d attempt(s): %s", d.channel, attempt, sanitizeDeliveryError(err))
			return
		}
		backoff *= 2
	}
}

// close drains queued events, abandoning in-flight retry backoff so shutdown stays
// bounded. Idempotent.
func (d *deliverer) close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		close(d.closing)
		close(d.queue)
	})
	d.wg.Wait()
}
