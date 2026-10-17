package storage

// pgbouncer_audit_index_build_postgres_test.go — the audit list index build's
// lock (store.BuildAuditListIndexesPostgres) follows storage.database.pooler
// like every other advisory lock held across statements
// (INV-STORE-advisory-lock-pooler-scope): with pgbouncer-transaction it is a
// transaction-scoped lock on a pinned, idle connection, never a session lock
// on the connection running CREATE INDEX CONCURRENTLY; and Close, cancelling
// the build mid-statement, returns promptly with the lock released. Targets
// as in pgbouncer_postgres_test.go: direct Postgres (transaction shape), or
// through PgBouncer in each mode via scripts/pgbouncer-matrix.sh.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestPgBouncer_AuditIndexBuild_LockFollowsThePooler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	tg := pgBouncerTargetFor(t)
	xact := tg.pooler == config.PoolerPgBouncerTransaction

	st := tg.open(t, false) // migrates and builds the indexes
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "%T", st)
	// The startup build of this small table finished before serving: it did not
	// wait for its own lock transaction past auditIndexSyncBuildTimeout and fall
	// back to a background build (which would wait for it forever).
	requireNothingPending(t, pgRawOpen(t, tg.direct))
	require.False(t, ls.WaitAuditListIndexBuild(), "the startup build fell back to the background")
	require.Equal(t, xact, ls.TransactionPooling())
	direct := pgRawOpen(t, tg.direct)
	for _, ix := range store.AuditListIndexes {
		require.NoError(t, direct.Exec("DROP INDEX IF EXISTS "+ix.Name).Error)
	}
	holder := holdAuditWriter(t, direct) // CREATE INDEX CONCURRENTLY waits on it

	openBuild := func() *sql.DB {
		d := config.DatabaseConfig{DSN: tg.dsn}
		setTestPooler(&d, tg.pooler)
		bdb, _, err := openPostgresSQLDB(&d)
		require.NoError(t, err)
		bdb.SetMaxOpenConns(2) // as ensureAuditListIndexesPostgres sets it
		return bdb
	}
	ls.StartAuditListIndexBuild(openBuild(), t.Logf)
	waitForLockWait(t, direct)

	// The one backend holding the build lock, read directly from PostgreSQL.
	// In this test's database only: pg_locks lists every database's locks, and
	// another package's test may hold the same key in its own.
	var holders []struct {
		State string
		Query string
	}
	require.NoError(t, direct.Raw(`SELECT a.state, a.query FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND l.granted AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
		AND l.classid = ? AND l.objid = ? AND l.objsubid = 1`,
		store.AuditIndexBuildLockClassID, store.AuditIndexBuildLockObjID).Scan(&holders).Error)
	require.Len(t, holders, 1, "exactly one backend holds the build lock")
	if xact {
		require.Equal(t, "idle in transaction", holders[0].State,
			"pgbouncer-transaction: a transaction-scoped lock on a pinned connection, not a session lock (holder ran %q)", holders[0].Query)
	} else {
		require.Equal(t, "idle", holders[0].State,
			"the lock connection stays idle; CREATE INDEX CONCURRENTLY runs on another (holder ran %q)", holders[0].Query)
	}

	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- ls.Close() }()
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not return while the background index build waited")
	}
	require.Less(t, time.Since(start), 10*time.Second, "Close stalled releasing the build lock")
	var held int64
	require.NoError(t, direct.Raw(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		AND classid = ? AND objid = ? AND objsubid = 1`,
		store.AuditIndexBuildLockClassID, store.AuditIndexBuildLockObjID).Scan(&held).Error)
	require.Zero(t, held, "Close returned while a backend still held the audit index build lock")

	require.NoError(t, holder.Commit().Error)
	next := openBuild()
	t.Cleanup(func() { _ = next.Close() })
	require.NoError(t, store.BuildAuditListIndexesPostgres(context.Background(), next, xact, t.Logf), "the next start")
	requireNothingPending(t, direct)
}
