// local_audit_chain_pipeline_test.go — PERF-FIX-1: the Postgres group commit
// runs as two pipelined flights, fails closed when either flight fails or the
// backend dies mid-batch, never hands a connection back to the pool inside a
// transaction, and keeps the fast audit mode's effect on the INSERT itself.
// All pg-gated (KEYORIX_TEST_PG_DSN); the chain bytes are pinned by
// local_audit_chain_golden_test.go and equivalence with the per-row path by
// local_audit_chain_multirow_insert_test.go.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// writeCountingConn counts Write calls: one per network flight, since pgx
// buffers a whole pipeline and flushes it in one write.
type writeCountingConn struct {
	net.Conn
	writes *atomic.Int64
}

func (c writeCountingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// pipelinePGStore is a Postgres LocalStorage on a one-connection pgx pool (so
// the connection a test inspects is the one the flusher used) in a schema of
// its own, opened the way storage.openPostgresGorm opens production pools. It
// returns a counter of client-to-server writes.
func pipelinePGStore(t *testing.T) (*LocalStorage, *atomic.Int64) {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "audit_pipeline_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if a, e := admin.DB(); e == nil {
			_ = a.Close()
		}
	})
	return pipelinePGStoreInSchema(t, schema)
}

// pipelinePGStoreInSchema is pipelinePGStore on an existing schema, with a pool
// of its own: a second replica of the store pipelinePGStore returned.
func pipelinePGStoreInSchema(t *testing.T, schema string) (*LocalStorage, *atomic.Int64) {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	cc, err := pgx.ParseConfig(pgdsn.PGSearchPathDSN(dsn, schema))
	require.NoError(t, err)
	writes := &atomic.Int64{}
	dial := cc.DialFunc
	cc.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return writeCountingConn{Conn: c, writes: writes}, nil
	}
	sqlDB := stdlib.OpenDB(*cc)
	sqlDB.SetMaxOpenConns(1)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	return NewLocalStorage(db), writes
}

// requireConnIdle asserts the pool's one connection is not inside a
// transaction: two consecutive statements on it run in two different
// transactions (an aborted one would fail the first probe outright).
func requireConnIdle(t *testing.T, ls *LocalStorage) {
	t.Helper()
	var first, second int64
	require.NoError(t, ls.db.Raw("SELECT txid_current()").Scan(&first).Error)
	require.NoError(t, ls.db.Raw("SELECT txid_current()").Scan(&second).Error)
	require.NotEqual(t, first, second, "the pooled connection was handed back inside a transaction")
}

// A batch commit is two client-to-server flights in both durability modes
// (BEGIN through the id allocation, then the INSERTs and COMMIT) right after
// boot and whenever the chain-head cache is not armed, and one flight once it
// is (AUDIT-1FLIGHT-1). The GORM transaction path takes one per statement (six
// or seven), so this also fails if commitBatchAttempt silently stops using the
// pipeline.
func TestCommitBatchAttempt_PostgresFlightCount(t *testing.T) {
	for _, fast := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "fast"}[fast], func(t *testing.T) {
			ls, writes := pipelinePGStore(t)
			ls.SetAuditSkipDurableSync(fast)
			ctx := context.Background()
			counted := func(n, want int, what string) {
				t.Helper()
				before := writes.Load()
				batch := buildMultiRowBatch(n, "counted")
				require.NoError(t, ls.commitBatchAttempt(ctx, batch))
				assert.Equal(t, int64(want), writes.Load()-before, "a %d-item batch %s", n, what)
				assert.Equal(t, batch[n-1].event.EntryHash, chainHeadHash(t, ls))
			}
			for _, n := range []int{1, 21} {
				// Warm the connection's statement cache for this batch size in both
				// shapes, as a long-running server's is; a first use adds a describe
				// flight. The two-flight batch arms the cache.
				ls.invalidateAuditChainHead()
				require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(n, "warm")))
				require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(n, "warm")))

				counted(n, 1, "after the flusher's own batch must commit in one flight")
				counted(n, 1, "after a one-flight batch must commit in one flight")
				ls.invalidateAuditChainHead()
				counted(n, 2, "after an invalidation must commit in two flights")
				counted(n, 1, "after a two-flight batch that found its own head must commit in one flight")
			}
			assert.Zero(t, ls.auditHead.oneFlightMisses.Load())
			v, err := ls.VerifyAuditChain(ctx, nil)
			require.NoError(t, err)
			assert.True(t, v.Valid, v.Reason)
			requireConnIdle(t, ls)
		})
	}
}

// The fast audit mode still governs the transaction the rows are written in,
// observed by the server inside the INSERT: synchronous_commit is "off" there
// with the mode on and "on" without it, and back to "on" on the same
// connection afterwards.
func TestCommitBatchAttempt_PostgresFastModeAppliesToTheInsert(t *testing.T) {
	for _, fast := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "fast"}[fast], func(t *testing.T) {
			ls, _ := pipelinePGStore(t)
			ls.SetAuditSkipDurableSync(fast)
			require.NoError(t, ls.db.Exec(`CREATE TABLE kx_sync_seen (setting text)`).Error)
			require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_record_sync() RETURNS trigger AS $$
BEGIN
  INSERT INTO kx_sync_seen VALUES (current_setting('synchronous_commit'));
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
			require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_record_sync BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_record_sync()`).Error)

			// The first batch goes in two flights, the second in one.
			require.NoError(t, ls.commitBatchAttempt(context.Background(), buildMultiRowBatch(3, "sync")))
			require.NoError(t, ls.commitBatchAttempt(context.Background(), buildMultiRowBatch(2, "sync-one-flight")))
			require.Equal(t, int64(1), ls.auditHead.oneFlightCommits.Load())
			var seen []string
			require.NoError(t, ls.db.Raw("SELECT setting FROM kx_sync_seen").Scan(&seen).Error)
			want := map[bool]string{false: "on", true: "off"}[fast]
			assert.Equal(t, []string{want, want, want, want, want}, seen)

			var after string
			require.NoError(t, ls.db.Raw("SHOW synchronous_commit").Scan(&after).Error)
			assert.Equal(t, "on", after, "the setting must not outlive the audit transaction")
		})
	}
}

// The backend dies in the middle of the second flight (a trigger terminates
// its own session while inserting the marked row). Nothing of that attempt
// survives, bisection still commits every other item, the dead connection is
// not reused, and the chain verifies and keeps growing.
func TestCommitAuditBatch_PostgresBackendDiesMidBatch(t *testing.T) {
	for _, tc := range []struct{ name, table, column, marker string }{
		{"during events insert", "audit_events", "description", "KILL-EVENT"},
		{"during access-log insert", "secret_access_logs", "accessed_by", "KILL-LOG"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ls, _ := pipelinePGStore(t)
			require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_kill_self() RETURNS trigger AS $$
BEGIN
  IF to_jsonb(NEW)->>TG_ARGV[0] = TG_ARGV[1] THEN PERFORM pg_terminate_backend(pg_backend_pid()); END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
			require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_kill_self BEFORE INSERT ON `+tc.table+
				` FOR EACH ROW EXECUTE FUNCTION kx_kill_self('`+tc.column+`', '`+tc.marker+`')`).Error)

			require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(2, "before")))
			const n, bad = 6, 4
			batch := buildMultiRowBatch(n, "crash")
			if tc.table == "audit_events" {
				batch[bad].event.Description = tc.marker
			} else {
				require.NotNil(t, batch[bad].accessLog)
				batch[bad].accessLog.AccessedBy = tc.marker
			}
			errs := ls.commitAuditBatch(batch)
			assert.Positive(t, ls.auditHead.oneFlightMisses.Load(), "the batch must have been tried in one flight first")
			for i, err := range errs {
				if i == bad {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err, "item %d", i)
				}
			}

			requireConnIdle(t, ls)
			events, _ := loadAuditRows(t, ls)
			assert.Len(t, events, 2+n-1)
			for _, e := range events {
				assert.NotEqual(t, batch[bad].event.EntryHash, e.EntryHash, "the killed item's event must not survive")
			}
			require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(3, "after")))
			v, err := ls.VerifyAuditChain(ctx, nil)
			require.NoError(t, err)
			assert.True(t, v.Valid, v.Reason)
			assert.Equal(t, int64(2+n-1+3), v.ChainedEvents)
		})
	}
}

// A failure in Go between the flights, with the server's transaction still
// open and healthy (here: the id column has no owned sequence, so the
// allocation returns NULL): the attempt fails, writes nothing, and the
// connection goes back to the pool idle, not inside the open transaction.
func TestCommitBatchAttempt_PostgresFailureBetweenFlightsRollsBack(t *testing.T) {
	ctx := context.Background()
	ls, _ := pipelinePGStore(t)
	require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(2, "before")))
	require.NoError(t, ls.db.Exec("ALTER SEQUENCE audit_events_id_seq OWNED BY NONE").Error)

	// Only the two-flight path allocates ids between its flights; the one-flight
	// path takes them from the column default.
	ls.invalidateAuditChainHead()
	err := ls.commitBatchAttempt(ctx, buildMultiRowBatch(3, "orphaned"))
	require.Error(t, err)

	// Checked from another session BEFORE the pool's connection is used again:
	// pgx's stdlib discards a connection that is still in a transaction, but only
	// when it is next checked out. Until then an idle connection left inside the
	// transaction would keep holding KEYAUDIT, and every other replica's audit
	// append would wait on it.
	other, err := pgx.Connect(ctx, os.Getenv("KEYORIX_TEST_PG_DSN"))
	require.NoError(t, err)
	defer func() { _ = other.Close(ctx) }()
	var got bool
	require.NoError(t, other.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(auditAdvisoryLockKey)).Scan(&got))
	require.True(t, got, "the failed attempt's connection still holds the audit advisory lock")
	_, err = other.Exec(ctx, "SELECT pg_advisory_unlock($1)", int64(auditAdvisoryLockKey))
	require.NoError(t, err)

	requireConnIdle(t, ls)
	events, _ := loadAuditRows(t, ls)
	assert.Len(t, events, 2)

	require.NoError(t, ls.db.Exec("ALTER SEQUENCE audit_events_id_seq OWNED BY audit_events.id").Error)
	require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(3, "after")))
	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, int64(5), v.ChainedEvents)
}
