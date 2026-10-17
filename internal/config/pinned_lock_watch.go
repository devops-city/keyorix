package config

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"
)

// PinnedLockPingInterval is how often WatchPinnedLockConn checks that the
// connection holding an advisory lock across statements is still alive. A
// variable so tests can shorten it; read when a watch starts.
var PinnedLockPingInterval = 5 * time.Second

// PinnedLockPingTimeout bounds one ping. A pinned connection that does not
// answer in this time is treated as lost: the driver closes a connection whose
// statement was cancelled, which ends the backend (or the pinning transaction)
// and the lock with it. A variable so tests can shorten it; read when a watch
// starts.
var PinnedLockPingTimeout = 5 * time.Second

// ReportAdvisoryLockLost is the one log line every advisory-lock holder writes
// when it finds its lock gone (WatchPinnedLockConnGated, and the single_writer
// poller, which checks the lock itself): who names the holder, err is what
// showed the loss. One wording, so an operator can search for every kind of
// lock loss at once.
func ReportAdvisoryLockLost(who string, err error) {
	log.Printf("%s: the connection holding the advisory lock is gone, so the lock is lost: %v", who, err)
}

// WatchPinnedLockConn pings conn, which holds an advisory lock across
// statements, every PinnedLockPingInterval until stop is called: a
// transaction-scoped lock in its pinning transaction (BeginPinnedLockTx), or a
// session lock on a connection checked out for the lock's whole life. The
// first failed ping means the backend, and the lock with it, is gone (a
// pg_terminate_backend, a PostgreSQL restart or failover, a network partition,
// a PgBouncer timeout or restart): nothing else would tell the holder, since
// the critical section's own queries run on other connections. onLost is then
// called once, from the watcher goroutine, with the ping error, and the watch
// ends.
//
// The ping is the driver's empty statement over the simple query protocol, so
// it holds no snapshot in the open transaction (see advisoryLockSession).
// stop does not return while a ping is in flight, so the caller can use conn
// again (ROLLBACK) right after it; a loss found after stop is not reported.
// who names the holder in the log line.
//
// Use it only when nothing else runs statements on conn while it is watched
// (the serverguard presence lock). A conn that other statements share must be
// watched with WatchPinnedLockConnGated.
func WatchPinnedLockConn(conn *sql.Conn, who string, onLost func(error)) (stop func()) {
	return WatchPinnedLockConnGated(conn, nil, who, onLost)
}

// PinnedConnGate serialises the statements run on one pinned lock connection
// with the liveness ping (REVIEW-2 on #3299). database/sql queues statements on
// one *sql.Conn behind each other without regard to their contexts, so a ping
// sent while a lock statement waits in PostgreSQL (a nested WithNamedLock
// under another key, held elsewhere) queued behind it with its timeout
// running, started only once the wait ended, failed at once on the expired
// context, and pgx closed the connection on that error: the watcher itself
// ended the pinning transaction and released every lock on it. With the gate,
// the ping is only sent while no statement is using the connection, so its
// timeout measures the backend's answer and nothing else.
//
// A statement holds the gate for its whole run (Enter / Leave); the watcher
// skips a tick while it is held (TryEnter). A statement waiting in PostgreSQL
// on a dead connection fails by itself, and the next tick after it pings
// again, so a loss is still found.
type PinnedConnGate chan struct{}

// NewPinnedConnGate returns an open gate.
func NewPinnedConnGate() PinnedConnGate { return make(PinnedConnGate, 1) }

// Enter waits until no ping or other statement is using the connection, or
// ctx is done. A ping holds it for at most PinnedLockPingTimeout.
func (g PinnedConnGate) Enter(ctx context.Context) error {
	select {
	case g <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryEnter takes the gate if it is free.
func (g PinnedConnGate) TryEnter() bool {
	select {
	case g <- struct{}{}:
		return true
	default:
		return false
	}
}

// Leave releases the gate taken by Enter or TryEnter.
func (g PinnedConnGate) Leave() { <-g }

// WatchPinnedLockConnGated is WatchPinnedLockConn for a connection that other
// statements also use: a tick is skipped while gate is held, and the ping
// holds gate while it runs. A nil gate means no other statement uses conn.
func WatchPinnedLockConnGated(conn *sql.Conn, gate PinnedConnGate, who string, onLost func(error)) (stop func()) {
	interval, timeout := PinnedLockPingInterval, PinnedLockPingTimeout
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
			}
			// Not derived from stopCh: cancelling a ping in flight would make the
			// driver close a healthy connection that the caller is about to
			// ROLLBACK and pool again.
			if gate != nil && !gate.TryEnter() {
				continue // a lock statement is using conn; it reports a dead conn itself
			}
			pctx, cancel := context.WithTimeout(context.Background(), timeout)
			err := conn.PingContext(pctx)
			cancel()
			if gate != nil {
				gate.Leave()
			}
			select {
			case <-stopCh:
				return
			default:
			}
			if err == nil {
				continue
			}
			ReportAdvisoryLockLost(who, err)
			onLost(err)
			return
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stopCh) })
		<-done
	}
}
