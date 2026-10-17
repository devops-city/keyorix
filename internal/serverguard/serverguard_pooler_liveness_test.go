package serverguard

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestPgBouncer_ServerGuard_LostPresenceLockIsReported: with
// pgbouncer-transaction the presence lock lives in an open transaction, and a
// pg_terminate_backend (a failover, a PgBouncer restart or timeout look the
// same to the holder) drops it with no other signal. Presence.Lost must close
// promptly so the server can stop; while the backend lives it must stay open;
// Release after a loss must still work.
func TestPgBouncer_ServerGuard_LostPresenceLockIsReported(t *testing.T) {
	cfg, pooler := poolerGuardCfg(t)
	if pooler != "pgbouncer-transaction" {
		t.Skipf("pooler %s keeps a session lock, which has no lock transaction to watch", pooler)
	}
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 100 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = old })

	direct, err := sql.Open("pgx", pgTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()

	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	released := false
	defer func() {
		if !released {
			_ = p.Release()
		}
	}()

	select {
	case <-p.Lost():
		t.Fatal("Lost closed while the presence lock connection was alive")
	case <-time.After(400 * time.Millisecond):
	}

	var killed int
	err = direct.QueryRowContext(context.Background(), `SELECT count(*) FROM (
			SELECT pg_terminate_backend(pid) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid = $1 AND objid = $2
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())) k`,
		serverPresenceLockKey>>32, serverPresenceLockKey&0xFFFFFFFF).Scan(&killed)
	if err != nil || killed != 1 {
		t.Fatalf("terminate the presence lock backend: killed=%d err=%v", killed, err)
	}

	select {
	case <-p.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the presence lock was lost (backend terminated) but Presence.Lost never closed")
	}

	released = true
	if err := p.Release(); err != nil {
		t.Logf("Release after loss: %v (fine: the connection is already gone)", err)
	}
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive after the lost presence lock was released: %v", err)
	}
	_ = x.Release()
}
