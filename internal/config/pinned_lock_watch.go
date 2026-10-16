package config

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"
)

// PinnedLockPingInterval is how often WatchPinnedLockConn checks that the
// connection holding a transaction-scoped advisory lock is still alive. A
// variable so tests can shorten it; read when a watch starts.
var PinnedLockPingInterval = 5 * time.Second

// pinnedLockPingTimeout bounds one ping. A pinned connection that does not
// answer in this time is treated as lost: the driver closes a connection whose
// statement was cancelled, which ends the transaction and the lock with it.
const pinnedLockPingTimeout = 5 * time.Second

// WatchPinnedLockConn pings conn, which holds a transaction-scoped advisory
// lock (BeginPinnedLockTx), every PinnedLockPingInterval until stop is called.
// The first failed ping means the lock transaction is gone (a
// pg_terminate_backend, a PostgreSQL restart or failover, a PgBouncer timeout
// or restart): the lock is no longer held, and nothing else would tell the
// holder. onLost is then called once, from the watcher goroutine, with the
// ping error, and the watch ends.
//
// The ping is the driver's empty statement over the simple query protocol, so
// it holds no snapshot in the open transaction (see advisoryLockSession).
// stop does not return while a ping is in flight, so the caller can use conn
// again (ROLLBACK) right after it; a loss found after stop is not reported.
// who names the holder in the log line.
func WatchPinnedLockConn(conn *sql.Conn, who string, onLost func(error)) (stop func()) {
	interval := PinnedLockPingInterval
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
			pctx, cancel := context.WithTimeout(context.Background(), pinnedLockPingTimeout)
			err := conn.PingContext(pctx)
			cancel()
			select {
			case <-stopCh:
				return
			default:
			}
			if err == nil {
				continue
			}
			log.Printf("%s: the connection holding the advisory lock is gone, so the lock is lost: %v", who, err)
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
