package serverguard

import (
	"context"
	"database/sql"
	"testing"
)

// TestPgBouncer_ServerGuard_HeldLockKeepsNoSnapshot: with pgbouncer-transaction
// the presence lock lives in a transaction held open for the server's whole
// life. That transaction must hold no snapshot, or it pins the database's xmin
// for as long: VACUUM keeps every dead row, and every CREATE INDEX CONCURRENTLY
// (the audit list index build, internal/storage/store) waits for the server's
// own presence lock to end. An extended-protocol lock statement left exactly
// that open (its portal's snapshot lives until the transaction ends).
func TestPgBouncer_ServerGuard_HeldLockKeepsNoSnapshot(t *testing.T) {
	cfg, pooler := poolerGuardCfg(t)
	direct, err := sql.Open("pgx", pgTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()
	// Holders of the presence lock (bigint key: classid high, objid low half),
	// and how many of them hold back xmin. In this database only: pg_locks
	// lists every database's locks, and a test in another database may hold
	// the same key.
	holders := func() (n, withXmin int) {
		t.Helper()
		err := direct.QueryRowContext(context.Background(), `SELECT count(*), count(a.backend_xmin)
			FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE l.locktype = 'advisory' AND l.granted AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
			AND l.objsubid = 1 AND l.classid = $1 AND l.objid = $2`,
			serverPresenceLockKey>>32, serverPresenceLockKey&0xFFFFFFFF).Scan(&n, &withXmin)
		if err != nil {
			t.Fatal(err)
		}
		return n, withXmin
	}

	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	n, withXmin := holders()
	_ = p.Release()
	if n != 1 || withXmin != 0 {
		t.Fatalf("pooler %s: presence lock held by %d backends, %d of them holding back xmin; want 1, 0", pooler, n, withXmin)
	}

	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	n, withXmin = holders()
	_ = x.Release()
	if n != 1 || withXmin != 0 {
		t.Fatalf("pooler %s: exclusive lock held by %d backends, %d of them holding back xmin; want 1, 0", pooler, n, withXmin)
	}
}
