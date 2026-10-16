package config

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pingDriver is a database/sql driver whose connections answer Ping from a
// switch the test flips, standing in for a lock connection whose backend is
// killed (the real thing is covered against Postgres in
// internal/storage/store and internal/serverguard).
type pingDriver struct {
	fail  atomic.Bool
	pings atomic.Int64
}

func (d *pingDriver) Open(string) (driver.Conn, error) { return &pingConn{d: d}, nil }

type pingConn struct{ d *pingDriver }

func (c *pingConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (c *pingConn) Close() error                        { return nil }
func (c *pingConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }
func (c *pingConn) Ping(context.Context) error {
	c.d.pings.Add(1)
	if c.d.fail.Load() {
		return errors.New("terminating connection due to administrator command")
	}
	return nil
}

var pingDriverSeq atomic.Int64

func openPingConn(t *testing.T) (*pingDriver, *sql.Conn) {
	t.Helper()
	d := &pingDriver{}
	name := "pingdriver-" + time.Now().Format("150405.000000000") + "-" + string(rune('a'+pingDriverSeq.Add(1)%26))
	sql.Register(name, d)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return d, conn
}

func shortPingInterval(t *testing.T) {
	t.Helper()
	old := PinnedLockPingInterval
	PinnedLockPingInterval = 10 * time.Millisecond
	t.Cleanup(func() { PinnedLockPingInterval = old })
}

// TestWatchPinnedLockConn_ReportsDeadConnectionOnce: a failed ping calls onLost
// exactly once, with the ping error, and the watch ends.
func TestWatchPinnedLockConn_ReportsDeadConnectionOnce(t *testing.T) {
	shortPingInterval(t)
	d, conn := openPingConn(t)
	var mu sync.Mutex
	var got []error
	lost := make(chan struct{})
	stop := WatchPinnedLockConn(conn, "test", func(err error) {
		mu.Lock()
		got = append(got, err)
		mu.Unlock()
		close(lost)
	})
	defer stop()

	time.Sleep(50 * time.Millisecond)
	select {
	case <-lost:
		t.Fatal("onLost fired while the connection answered pings")
	default:
	}
	if d.pings.Load() == 0 {
		t.Fatal("no ping was sent")
	}

	d.fail.Store(true)
	select {
	case <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("a dead connection was not reported")
	}
	time.Sleep(50 * time.Millisecond) // a second report would show up now
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] == nil {
		t.Fatalf("onLost calls = %v, want exactly one with the ping error", got)
	}
}

// TestWatchPinnedLockConn_StopEndsWatchWithoutReport: after stop, a failing
// ping is never reported, and stop is idempotent.
func TestWatchPinnedLockConn_StopEndsWatchWithoutReport(t *testing.T) {
	shortPingInterval(t)
	d, conn := openPingConn(t)
	var fired atomic.Bool
	stop := WatchPinnedLockConn(conn, "test", func(error) { fired.Store(true) })
	time.Sleep(30 * time.Millisecond)
	stop()
	stop()
	d.fail.Store(true)
	before := d.pings.Load()
	time.Sleep(60 * time.Millisecond)
	if fired.Load() {
		t.Fatal("onLost fired after stop")
	}
	if d.pings.Load() != before {
		t.Fatal("the watcher kept pinging after stop")
	}
}
