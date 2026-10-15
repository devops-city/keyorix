// local_audit_chain_one_flight_test.go — AUDIT-1FLIGHT-1: the one-flight
// audit commit never chains a batch onto a head that is no longer the head.
// Every path that moves the head outside the flusher either invalidates the
// cache or is caught by the in-transaction checks and retried in two flights,
// and the chain verifies afterwards. pg-gated (KEYORIX_TEST_PG_DSN) except the
// SQLite case.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// pipelinePGSchema is the schema a pipelinePGStore store's tables live in.
func pipelinePGSchema(t *testing.T, ls *LocalStorage) string {
	t.Helper()
	var schema string
	require.NoError(t, ls.db.Raw("SELECT current_schema()").Scan(&schema).Error)
	return schema
}

// armedHead reports whether ls's next batch would go in one flight.
func armedHead(ls *LocalStorage) bool {
	_, _, armed := ls.auditHead.begin()
	return armed
}

// commitAll commits batch through the flusher's entry point and requires every
// item to succeed.
func commitAll(t *testing.T, ls *LocalStorage, batch []*auditBatchItem) {
	t.Helper()
	for i, err := range ls.commitAuditBatch(batch) {
		require.NoError(t, err, "item %d", i)
	}
}

// requireChainValid verifies the whole chain and that no two rows share a
// prev_hash (a fork).
func requireChainValid(t *testing.T, ls *LocalStorage, anchor *storage.AuditChainAnchor, wantEvents int) {
	t.Helper()
	v, err := ls.VerifyAuditChain(context.Background(), anchor)
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	events, _ := loadAuditRows(t, ls)
	require.Len(t, events, wantEvents)
	seen := map[string]uint{}
	for _, e := range events {
		if prev, dup := seen[e.PrevHash]; dup {
			t.Fatalf("chain fork: rows %d and %d both follow %s", prev, e.ID, e.PrevHash)
		}
		seen[e.PrevHash] = e.ID
	}
}

// Two replicas (two LocalStorages, each with its own pool and flusher state)
// append to one audit_events. Whenever one replica wrote since the other's
// last batch, the other's armed one-flight attempt must fail inside its
// transaction and be retried in two flights, and the chain must stay linear.
// While both keep writing in turn, neither re-arms, so the retries stop.
func TestOneFlight_PostgresTwoReplicasAlternate(t *testing.T) {
	a, _ := pipelinePGStore(t)
	b, _ := pipelinePGStoreInSchema(t, pipelinePGSchema(t, a))
	total := 0
	step := func(ls *LocalStorage, tag string, wantOneFlight, wantMiss int64) {
		t.Helper()
		commits, misses := ls.auditHead.oneFlightCommits.Load(), ls.auditHead.oneFlightMisses.Load()
		batch := buildMultiRowBatch(3, tag)
		commitAll(t, ls, batch)
		total += len(batch)
		assert.Equal(t, wantOneFlight, ls.auditHead.oneFlightCommits.Load()-commits, "%s: one-flight commits", tag)
		assert.Equal(t, wantMiss, ls.auditHead.oneFlightMisses.Load()-misses, "%s: one-flight misses (retried in two flights)", tag)
		assert.Equal(t, batch[2].event.EntryHash, chainHeadHash(t, ls), "%s: the batch's last row must be the head", tag)
	}

	step(a, "a-boot", 0, 0) // two flights, arms
	step(a, "a-1", 1, 0)
	step(a, "a-2", 1, 0)
	step(b, "b-boot", 0, 0) // two flights; nothing to compare with yet, so arms
	step(a, "a-after-b", 0, 1)
	step(b, "b-after-a", 0, 1)
	for i := range 4 { // strict alternation: no re-arming, no more misses
		step(a, fmt.Sprintf("a-alt-%d", i), 0, 0)
		step(b, fmt.Sprintf("b-alt-%d", i), 0, 0)
	}
	assert.False(t, armedHead(a))
	// After one miss, two quiet two-flight batches re-arm.
	step(b, "b-quiet", 0, 0)
	assert.False(t, armedHead(b))
	step(b, "b-quiet-1", 0, 0)
	assert.True(t, armedHead(b))
	step(b, "b-quiet-2", 1, 0)
	step(a, "a-after-quiet-b", 0, 0) // a is still disarmed: plain two flights, found b's rows
	step(b, "b-after-a-again", 0, 1)

	requireChainValid(t, a, nil, total)
}

// The same two replicas, appending concurrently through the public entry point
// from many goroutines each: no interleaving of the two flushers may fork the
// chain or lose an acknowledged row.
func TestOneFlight_PostgresTwoReplicasConcurrent(t *testing.T) {
	a, _ := pipelinePGStore(t)
	b, _ := pipelinePGStoreInSchema(t, pipelinePGSchema(t, a))
	const writers, perWriter = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, 2*writers*perWriter)
	for _, ls := range []*LocalStorage{a, b} {
		for w := range writers {
			wg.Go(func() {
				for i := range perWriter {
					// Bursts with pauses, so each flusher sees quiet spells (and
					// re-arms) as well as the other replica's writes.
					if i%5 == 0 {
						time.Sleep(time.Duration(w) * time.Millisecond)
					}
					item := buildMultiRowBatch(1, fmt.Sprintf("conc-%p-%d-%d", ls, w, i))[0]
					errs <- ls.LogAuditEventWithAccessLog(context.Background(), item.event, item.accessLog)
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	t.Logf("one-flight commits a=%d b=%d, misses a=%d b=%d",
		a.auditHead.oneFlightCommits.Load(), b.auditHead.oneFlightCommits.Load(),
		a.auditHead.oneFlightMisses.Load(), b.auditHead.oneFlightMisses.Load())
	attempts := a.auditHead.oneFlightCommits.Load() + b.auditHead.oneFlightCommits.Load() +
		a.auditHead.oneFlightMisses.Load() + b.auditHead.oneFlightMisses.Load()
	assert.Positive(t, attempts, "the one-flight path was never tried")
	requireChainValid(t, a, nil, 2*writers*perWriter)

	// Once b stops, a alone settles back on one flight.
	commits := a.auditHead.oneFlightCommits.Load()
	for range 2*auditOneFlightMaxQuiet + 2 {
		commitAll(t, a, buildMultiRowBatch(1, "a-alone"))
	}
	assert.Positive(t, a.auditHead.oneFlightCommits.Load()-commits, "a never re-armed once it was the only writer")
	requireChainValid(t, a, nil, 2*writers*perWriter+2*auditOneFlightMaxQuiet+2)
}

// Writes that bypass every in-process hook: hand-written SQL on another
// connection, standing in for an offline `admin restore` or an operator. The
// armed cache is not told; the in-transaction head check must catch each one,
// the batch must be retried in two flights, and the chain must verify.
func TestOneFlight_PostgresOutOfBandWritesAreCaught(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, other *LocalStorage, schema string)
		wantLen func(before int) int
	}{
		{
			// The whole table emptied (a purge with a cutoff in the future, or a
			// restore of an empty trail): the next batch restarts at genesis.
			name: "table emptied",
			mutate: func(t *testing.T, other *LocalStorage, _ string) {
				require.NoError(t, other.db.Exec("DELETE FROM audit_events").Error)
			},
			wantLen: func(int) int { return 0 },
		},
		{
			// A restore that replaces the trail with another valid chain, written
			// by another store (so neither its ids nor its hashes match the cache).
			name: "trail replaced",
			mutate: func(t *testing.T, other *LocalStorage, _ string) {
				require.NoError(t, other.db.Exec("DELETE FROM audit_events").Error)
				commitAll(t, other, buildMultiRowBatch(4, "restored"))
			},
			wantLen: func(int) int { return 4 },
		},
		{
			// The head row rewritten in place with a consistent new entry_hash, as
			// a re-hashing migration does, without the migration's own
			// invalidation: same id, different hash.
			name: "head rewritten",
			mutate: func(t *testing.T, other *LocalStorage, _ string) {
				var head models.AuditEvent
				require.NoError(t, other.db.Order("id DESC").Take(&head).Error)
				head.Description += " (rewritten)"
				hash := computeAuditEntryHash(&head, head.PrevHash)
				require.NoError(t, other.db.Exec("UPDATE audit_events SET description = ?, entry_hash = ? WHERE id = ?", head.Description, hash, head.ID).Error)
			},
			wantLen: func(before int) int { return before },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls, _ := pipelinePGStore(t)
			schema := pipelinePGSchema(t, ls)
			other, _ := pipelinePGStoreInSchema(t, schema)
			commitAll(t, ls, buildMultiRowBatch(3, "before"))
			commitAll(t, ls, buildMultiRowBatch(2, "before-one-flight"))
			require.Equal(t, int64(1), ls.auditHead.oneFlightCommits.Load())
			require.True(t, armedHead(ls))

			tc.mutate(t, other, schema)
			require.True(t, armedHead(ls), "nothing told the cache")

			batch := buildMultiRowBatch(3, "after")
			commitAll(t, ls, batch)
			assert.Equal(t, int64(1), ls.auditHead.oneFlightMisses.Load(), "the moved head must fail the one-flight attempt")
			assert.Equal(t, int64(1), ls.auditHead.oneFlightCommits.Load())
			assert.Equal(t, batch[2].event.EntryHash, chainHeadHash(t, ls))
			events, _ := loadAuditRows(t, ls)
			require.Len(t, events, tc.wantLen(5)+3)
			wantPrev := auditGenesisHash
			if len(events) > 3 {
				wantPrev = events[len(events)-4].EntryHash
			}
			assert.Equal(t, wantPrev, batch[0].event.PrevHash, "the batch must chain onto the row that really was the head")

			requireChainValid(t, ls, nil, tc.wantLen(5)+3)
		})
	}
}

// Every in-process path that moves the head outside the flusher invalidates
// the cache (so the next batch re-reads the head rather than spend a flight
// on a check that would fail), and the chain verifies after it. Checkpoint
// rows live in audit_checkpoints and do not move the head, so they leave the
// cache armed.
func TestOneFlight_PostgresInProcessPathsInvalidate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		run        func(t *testing.T, ls *LocalStorage) *storage.AuditChainAnchor
		staysArmed bool
	}{
		{
			name: "retention purge",
			run: func(t *testing.T, ls *LocalStorage) *storage.AuditChainAnchor {
				// Backdate the first two rows so the purge removes exactly them.
				require.NoError(t, ls.db.Exec("UPDATE audit_events SET event_time = event_time - interval '400 days' WHERE id IN (SELECT id FROM audit_events ORDER BY id LIMIT 2)").Error)
				var anchor *storage.AuditChainAnchor
				require.NoError(t, ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
					n, a, err := tx.DeleteAuditLogsBefore(context.Background(), time.Now().AddDate(0, 0, -300))
					require.Equal(t, int64(2), n)
					anchor = a
					return err
				}))
				require.NotNil(t, anchor)
				return anchor
			},
		},
		{
			name: "encoding migration",
			run: func(t *testing.T, ls *LocalStorage) *storage.AuditChainAnchor {
				_, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
				require.NoError(t, err)
				return nil
			},
		},
		{
			name: "transaction-scoped direct append",
			run: func(t *testing.T, ls *LocalStorage) *storage.AuditChainAnchor {
				item := buildMultiRowBatch(1, "direct")[0]
				require.NoError(t, ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
					return tx.LogAuditEventWithAccessLog(context.Background(), item.event, item.accessLog)
				}))
				return nil
			},
		},
		{
			name: "checkpoint row",
			run: func(t *testing.T, ls *LocalStorage) *storage.AuditChainAnchor {
				require.NoError(t, ls.db.AutoMigrate(&models.AuditCheckpoint{}))
				require.NoError(t, ls.CreateAuditCheckpoint(context.Background(), &models.AuditCheckpoint{
					ChainedEvents: 5, HeadID: 5, HeadHash: chainHeadHash(t, ls), Signature: "sig",
				}))
				return nil
			},
			staysArmed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls, _ := pipelinePGStore(t)
			commitAll(t, ls, buildMultiRowBatch(3, "before"))
			commitAll(t, ls, buildMultiRowBatch(2, "before-one-flight"))
			require.True(t, armedHead(ls))

			anchor := tc.run(t, ls)
			assert.Equal(t, tc.staysArmed, armedHead(ls))

			batch := buildMultiRowBatch(3, "after")
			commitAll(t, ls, batch)
			assert.Zero(t, ls.auditHead.oneFlightMisses.Load(), "no flight may be spent on a head this process moved")
			assert.Equal(t, batch[2].event.EntryHash, chainHeadHash(t, ls))
			events, _ := loadAuditRows(t, ls)
			requireChainValid(t, ls, anchor, len(events))
		})
	}
}

// The link check is what guarantees, before COMMIT, that the rows got ids in
// batch order. A trigger hands out ids in reverse VALUES order (each row a
// smaller id than the one before): the one-flight attempt must fail inside
// its transaction and write nothing, and so must the two-flight retry (whose
// INSERT carries ids the trigger overrides).
func TestOneFlight_PostgresOutOfOrderIDsFailClosed(t *testing.T) {
	ctx := context.Background()
	ls, _ := pipelinePGStore(t)
	commitAll(t, ls, buildMultiRowBatch(3, "before"))
	commitAll(t, ls, buildMultiRowBatch(2, "before-one-flight"))
	require.True(t, armedHead(ls))
	require.NoError(t, ls.db.Exec(`CREATE SEQUENCE kx_reverse_ids INCREMENT -1 MINVALUE 1 MAXVALUE 1000000 START 1000000`).Error)
	require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_reverse_id() RETURNS trigger AS $$
BEGIN
  NEW.id := nextval('kx_reverse_ids');
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_reverse_id BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_reverse_id()`).Error)

	err := ls.commitBatchAttempt(ctx, buildMultiRowBatch(3, "reversed"))
	require.Error(t, err)
	assert.Equal(t, int64(1), ls.auditHead.oneFlightMisses.Load())
	requireConnIdle(t, ls)
	requireChainValid(t, ls, nil, 5)
}

// The two in-transaction checks raise only when they should: they pass on
// every flight, including those after Postgres stops planning them per
// execution, and they run from cached generic plans (a check that only raised
// while being planned would fail here on every flight, and one that the
// planner could fold would raise even when it passes).
func TestOneFlight_PostgresChecksRunFromGenericPlans(t *testing.T) {
	ls, _ := pipelinePGStore(t)
	ctx := context.Background()
	commitAll(t, ls, buildMultiRowBatch(2, "boot"))
	const flights = 12
	for range flights {
		require.NoError(t, ls.commitBatchAttempt(ctx, buildMultiRowBatch(2, "plans")))
	}
	require.Equal(t, int64(flights), ls.auditHead.oneFlightCommits.Load())
	var rows []struct {
		Statement    string
		GenericPlans int64
		CustomPlans  int64
	}
	require.NoError(t, ls.db.Raw("SELECT statement, generic_plans, custom_plans FROM pg_prepared_statements").Scan(&rows).Error)
	found := 0
	for _, r := range rows {
		if !strings.Contains(r.Statement, "THEN 0") || strings.Contains(r.Statement, "from genesis") {
			continue // the genesis link check ran once, in the boot batch
		}
		found++
		// Postgres plans a statement with parameters per execution for its first
		// five runs, then keeps the generic plan when it costs no more.
		assert.LessOrEqual(t, r.CustomPlans, int64(5), "re-planned on every flight: %q", r.Statement)
		assert.GreaterOrEqual(t, r.GenericPlans, int64(flights-5), "not run from its cached plan: %q", r.Statement)
	}
	require.Equal(t, 2, found, "the head check and the link check must both be cached: %+v", rows)
}

// Only a failure that provably wrote nothing is retried in two flights: an
// error Postgres answered for a statement before COMMIT (it then runs COMMIT
// as a ROLLBACK, or never reaches it), or one raised before the flight was
// sent. A lost connection or an expired context may have let COMMIT run, and
// so may an error answered for COMMIT itself; those are returned as is.
func TestAuditOneFlightRolledBack(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "22P02", Message: "audit chain head moved"}
	for _, tc := range []struct {
		name         string
		err          error
		beforeCommit bool
		want         bool
	}{
		{"server error before COMMIT", fmt.Errorf("wrapped: %w", pgErr), true, true},
		{"backend terminated before COMMIT", &pgconn.PgError{Severity: "FATAL", Code: "57P01"}, true, true},
		{"nothing sent", fmt.Errorf("%w: %w", errAuditNothingSent, errors.New("dry run")), true, true},
		{"server error answered for COMMIT", pgErr, false, false},
		{"connection lost before COMMIT's answer", io.ErrUnexpectedEOF, true, false},
		{"context expired", context.DeadlineExceeded, true, false},
		{"no error", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, auditOneFlightRolledBack(tc.err, tc.beforeCommit))
		})
	}
}

// The backend running a one-flight attempt dies mid-flight: it is terminated
// from another session while its flight waits on the audit advisory lock.
// Nothing of the attempt ran, so it is retried in two flights on a fresh
// connection once the lock is free, the batch is stored exactly once, and the
// chain verifies.
func TestOneFlight_PostgresBackendDiesMidFlight(t *testing.T) {
	ctx := context.Background()
	ls, _ := pipelinePGStore(t)
	commitAll(t, ls, buildMultiRowBatch(3, "before"))
	require.True(t, armedHead(ls))
	var pid int64
	require.NoError(t, ls.db.Raw("SELECT pg_backend_pid()").Scan(&pid).Error)

	other, err := pgx.Connect(ctx, os.Getenv("KEYORIX_TEST_PG_DSN"))
	require.NoError(t, err)
	defer func() { _ = other.Close(ctx) }()
	_, err = other.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(auditAdvisoryLockKey))
	require.NoError(t, err)

	batch := buildMultiRowBatch(3, "mid-flight")
	done := make(chan []error, 1)
	go func() { done <- ls.commitAuditBatch(batch) }()
	require.Eventually(t, func() bool {
		var waiting bool
		err := other.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND locktype = 'advisory' AND NOT granted)", pid).Scan(&waiting)
		return err == nil && waiting
	}, 10*time.Second, 5*time.Millisecond, "the one-flight attempt never waited on the lock")
	_, err = other.Exec(ctx, "SELECT pg_terminate_backend($1)", pid)
	require.NoError(t, err)
	_, err = other.Exec(ctx, "SELECT pg_advisory_unlock($1)", int64(auditAdvisoryLockKey))
	require.NoError(t, err)

	for i, err := range <-done {
		require.NoError(t, err, "item %d", i)
	}
	assert.Equal(t, int64(1), ls.auditHead.oneFlightMisses.Load())
	assert.Equal(t, batch[2].event.EntryHash, chainHeadHash(t, ls))
	requireConnIdle(t, ls)
	requireChainValid(t, ls, nil, 6)
}

// SQLite never takes the one-flight path: its commit is in-process, so there
// is no flight to save, and its cache is never armed.
func TestOneFlight_SQLiteNeverArms(t *testing.T) {
	ls := multiRowSQLiteStore(t)
	for range 3 {
		commitAll(t, ls, buildMultiRowBatch(2, "sqlite"))
	}
	assert.False(t, armedHead(ls))
	assert.Zero(t, ls.auditHead.oneFlightCommits.Load()+ls.auditHead.oneFlightMisses.Load())
	requireChainValid(t, ls, nil, 6)
}
