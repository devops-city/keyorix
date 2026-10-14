// local_audit_chain_multirow_insert_test.go — PERF-FIX-2: commitBatchAttempt
// writes a flusher batch with one multi-row INSERT for the events and one for
// the access logs instead of one statement per item. These tests pin that the
// rows, ids and hash chain are identical to the per-item path, that returned
// ids map to VALUES order, that the statement is chunked under SQLite's
// bind-variable limit, and that a genuine per-row database error still only
// fails its own caller. Postgres variants skip without KEYORIX_TEST_PG_DSN.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// commitBatchAttemptPerRowForTest is commitBatchAttempt as it was before
// PERF-FIX-2, kept verbatim as the reference the multi-row path is compared
// against: one tx.Create per event and per access log.
func (ls *LocalStorage) commitBatchAttemptPerRowForTest(ctx context.Context, batch []*auditBatchItem) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
			if err := applyAuditCommitDurability(tx, ls.auditSkipDurableSync); err != nil {
				return err
			}
		}
		var head struct{ EntryHash string }
		if err := tx.Model(&models.AuditEvent{}).
			Select("entry_hash").
			Order("id DESC").
			Limit(1).
			Scan(&head).Error; err != nil {
			return err
		}
		prev := head.EntryHash
		if prev == "" {
			prev = auditGenesisHash
		}
		for _, item := range batch {
			item.event.ID = 0
			if item.accessLog != nil {
				item.accessLog.ID = 0
			}
			item.event.PrevHash = prev
			item.event.EntryHash = computeAuditEntryHash(item.event, prev)
			if err := tx.Create(item.event).Error; err != nil {
				return err
			}
			prev = item.event.EntryHash
			if item.accessLog != nil {
				if err := tx.Create(item.accessLog).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// multiRowSQLiteStore is an in-memory SQLite LocalStorage with both tables the
// flusher writes.
func multiRowSQLiteStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	return NewLocalStorage(db)
}

// multiRowPGStore is the same on Postgres, in a schema of its own (dropped at
// cleanup) so two stores in one test, and parallel packages, never share rows.
func multiRowPGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "audit_multirow_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	return NewLocalStorage(db)
}

// buildMultiRowBatch returns a deterministic n-item batch that exercises every
// hashed column: nil and set pointers, Success false/true/unset, impersonation,
// machine actors, an empty ActorType, non-UTC times, multi-byte text and a Diff.
// Every third item has no access log. Calling it twice yields two independent
// but identical batches. Items go through normalizeAuditEventForHash exactly as
// logAuditEvent does before an item reaches the flusher.
func buildMultiRowBatch(n int, tag string) []*auditBatchItem {
	base := time.Date(2026, 10, 12, 13, 14, 15, 123456789, time.UTC)
	zone := time.FixedZone("UTC+5:30", 5*3600+1800)
	u := func(v int) *uint { x := uint(v); return &x }
	batch := make([]*auditBatchItem, n)
	for i := range n {
		e := &models.AuditEvent{
			EventType:   fmt.Sprintf("secret.read.%d", i%5),
			IPAddress:   fmt.Sprintf("203.0.113.%d", i%250),
			Description: fmt.Sprintf("%s item %d — é✓", tag, i),
			EventTime:   base.Add(time.Duration(i) * time.Millisecond),
		}
		if i%2 == 0 {
			e.UserID = u(i + 1)
		}
		if i%3 != 0 {
			e.SecretNodeID = u(1000 + i)
		}
		if i%4 == 1 {
			e.ProjectID = u(7)
		}
		switch i % 7 {
		case 0:
			f := false
			e.Success = &f
		case 1:
			tr := true
			e.Success = &tr
		} // otherwise nil: normalized to true
		if i%2 == 1 {
			e.EventTime = e.EventTime.In(zone)
		}
		if i%6 == 0 {
			e.Impersonation, e.ImpersonatedBy, e.ActingAs = true, u(9), u(i+1)
		}
		switch i % 3 {
		case 0:
			e.ActorType = "user"
		case 1:
			e.ActorType, e.MachineIdentityID = "machine_identity", u(40+i)
		} // otherwise "": normalized to "user"
		if i%5 == 0 {
			e.Diff = fmt.Sprintf(`{"name":{"before":"a%d","after":"b%d"}}`, i, i)
		}
		normalizeAuditEventForHash(e)
		item := &auditBatchItem{event: e, ctx: context.Background(), done: make(chan error, 1)}
		if i%3 != 2 {
			item.accessLog = &models.SecretAccessLog{
				SecretNodeID: uint(1000 + i), SecretVersionID: uint(i + 1),
				AccessedBy: fmt.Sprintf("user-%d", i), AccessTime: base.Add(time.Duration(i) * time.Millisecond).In(zone),
				Action: "read", IPAddress: e.IPAddress, UserAgent: "kx-test/1",
			}
		}
		batch[i] = item
	}
	return batch
}

// createCounter counts create statements per table on ls, so a test can assert
// how many INSERTs a batch took.
type createCounter struct{ events, logs atomic.Int64 }

func countCreates(t *testing.T, ls *LocalStorage) *createCounter {
	t.Helper()
	c := &createCounter{}
	name := "test:count_creates_" + t.Name()
	require.NoError(t, ls.db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Schema == nil {
			return
		}
		switch tx.Statement.Schema.Table {
		case "audit_events":
			c.events.Add(1)
		case "secret_access_logs":
			c.logs.Add(1)
		}
	}))
	t.Cleanup(func() { _ = ls.db.Callback().Create().Remove(name) })
	return c
}

func loadAuditRows(t *testing.T, ls *LocalStorage) ([]models.AuditEvent, []models.SecretAccessLog) {
	t.Helper()
	var events []models.AuditEvent
	require.NoError(t, ls.db.Order("id ASC").Find(&events).Error)
	var logs []models.SecretAccessLog
	require.NoError(t, ls.db.Order("id ASC").Find(&logs).Error)
	return events, logs
}

// assertSameAuditRows compares two stores row by row. Times are compared at
// microsecond precision as instants (what is hashed and what both dialects
// keep), every other column exactly.
func assertSameAuditRows(t *testing.T, want, got *LocalStorage) {
	t.Helper()
	wantEvents, wantLogs := loadAuditRows(t, want)
	gotEvents, gotLogs := loadAuditRows(t, got)
	require.Len(t, gotEvents, len(wantEvents))
	require.Len(t, gotLogs, len(wantLogs))
	for i := range wantEvents {
		w, g := wantEvents[i], gotEvents[i]
		assert.Equal(t, w.EventTime.UnixMicro(), g.EventTime.UnixMicro(), "event row %d event_time", i)
		w.EventTime, g.EventTime = time.Time{}, time.Time{}
		assert.Equal(t, w, g, "event row %d", i)
	}
	for i := range wantLogs {
		w, g := wantLogs[i], gotLogs[i]
		assert.Equal(t, w.AccessTime.UnixMicro(), g.AccessTime.UnixMicro(), "access-log row %d access_time", i)
		w.AccessTime, g.AccessTime = time.Time{}, time.Time{}
		assert.Equal(t, w, g, "access-log row %d", i)
	}
}

func chainHeadHash(t *testing.T, ls *LocalStorage) string {
	t.Helper()
	var head struct{ EntryHash string }
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Select("entry_hash").Order("id DESC").Limit(1).Scan(&head).Error)
	return head.EntryHash
}

// runMultiRowEquivalence commits the same batch through the per-row reference
// on one store and through commitBatchAttempt on another, both after the same
// already-chained prefix, and requires identical results.
func runMultiRowEquivalence(t *testing.T, newStore func(*testing.T) *LocalStorage, n int) {
	ctx := context.Background()
	perRow, multiRow := newStore(t), newStore(t)

	// A non-genesis head, so the batch links to an existing row on both.
	require.NoError(t, perRow.commitBatchAttemptPerRowForTest(ctx, buildMultiRowBatch(3, "prefix")))
	require.NoError(t, multiRow.commitBatchAttemptPerRowForTest(ctx, buildMultiRowBatch(3, "prefix")))

	want, got := buildMultiRowBatch(n, "batch"), buildMultiRowBatch(n, "batch")
	counter := countCreates(t, multiRow)
	require.NoError(t, perRow.commitBatchAttemptPerRowForTest(ctx, want))
	require.NoError(t, multiRow.commitBatchAttempt(ctx, got))

	// One INSERT for the events, one for the access logs.
	assert.Equal(t, int64(1), counter.events.Load(), "events of a %d-item batch must go in one INSERT", n)
	assert.Equal(t, int64(1), counter.logs.Load(), "access logs of a %d-item batch must go in one INSERT", n)

	// What each caller's structs carry afterwards is identical.
	for i := range want {
		assert.Equal(t, want[i].event.ID, got[i].event.ID, "item %d id", i)
		assert.Equal(t, want[i].event.PrevHash, got[i].event.PrevHash, "item %d prev_hash", i)
		assert.Equal(t, want[i].event.EntryHash, got[i].event.EntryHash, "item %d entry_hash", i)
		if want[i].accessLog != nil {
			assert.Equal(t, want[i].accessLog.ID, got[i].accessLog.ID, "item %d access-log id", i)
		}
	}

	// Identical stored rows.
	assertSameAuditRows(t, perRow, multiRow)

	// Every returned id points at the row holding that item's own hash and text:
	// the RETURNING rows were mapped back in VALUES order.
	events, logs := loadAuditRows(t, multiRow)
	eventByID := map[uint]models.AuditEvent{}
	for _, e := range events {
		eventByID[e.ID] = e
	}
	logByID := map[uint]models.SecretAccessLog{}
	for _, l := range logs {
		logByID[l.ID] = l
	}
	for i, item := range got {
		row, ok := eventByID[item.event.ID]
		require.True(t, ok, "item %d: no row with returned id %d", i, item.event.ID)
		assert.Equal(t, item.event.EntryHash, row.EntryHash, "item %d: returned id %d is another item's row", i, item.event.ID)
		assert.Equal(t, item.event.Description, row.Description, "item %d", i)
		if i > 0 {
			assert.Greater(t, item.event.ID, got[i-1].event.ID, "ids must ascend in VALUES order")
		}
		if item.accessLog != nil {
			lrow, ok := logByID[item.accessLog.ID]
			require.True(t, ok, "item %d: no access-log row with returned id %d", i, item.accessLog.ID)
			assert.Equal(t, item.accessLog.AccessedBy, lrow.AccessedBy, "item %d: returned access-log id is another item's row", i)
		}
	}

	// The id-DESC head the next attempt reads is the batch's last item.
	assert.Equal(t, got[n-1].event.EntryHash, chainHeadHash(t, multiRow))

	for _, ls := range []*LocalStorage{perRow, multiRow} {
		v, err := ls.VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		assert.True(t, v.Valid, "chain must verify: %s", v.Reason)
		assert.Equal(t, int64(n+3), v.ChainedEvents)
	}

	// A further batch links onto the multi-row batch's head on both stores.
	require.NoError(t, perRow.commitBatchAttemptPerRowForTest(ctx, buildMultiRowBatch(4, "after")))
	require.NoError(t, multiRow.commitBatchAttempt(ctx, buildMultiRowBatch(4, "after")))
	assertSameAuditRows(t, perRow, multiRow)
	v, err := multiRow.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify after a second batch: %s", v.Reason)
}

func TestCommitBatchAttempt_MultiRowMatchesPerRow_SQLite(t *testing.T) {
	for _, n := range []int{1, 2, 17, auditFlusherMaxBatch} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) { runMultiRowEquivalence(t, multiRowSQLiteStore, n) })
	}
}

func TestCommitBatchAttempt_MultiRowMatchesPerRow_Postgres(t *testing.T) {
	for _, n := range []int{1, 2, 17, auditFlusherMaxBatch} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) { runMultiRowEquivalence(t, multiRowPGStore, n) })
	}
}

// A full flusher batch fits one statement on both dialects, so "one INSERT per
// batch" holds at the maximum batch size and not only for small ones.
func TestAuditInsertRowsPerStatement_CoversAFullFlusherBatch(t *testing.T) {
	for _, model := range []any{&models.AuditEvent{}, &models.SecretAccessLog{}} {
		perStmt, err := auditInsertRowsPerStatement(model)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, perStmt, auditFlusherMaxBatch, "%T: a full batch would need more than one INSERT", model)
	}
}

// The bind-variable ceiling the chunking respects is real on the SQLite build
// this repo ships (modernc.org/sqlite): one INSERT of audit events just under it
// succeeds, one just over it fails. And the chunk size stays below it.
func TestAuditInsertRowsPerStatement_SQLiteVariableLimitIsReal(t *testing.T) {
	ls := multiRowSQLiteStore(t)
	const boundColumns = 16 // every audit_events column except the zero id GORM leaves out
	rowsAtLimit := auditInsertMaxBindVars / boundColumns

	mk := func(n int) []*models.AuditEvent {
		out := make([]*models.AuditEvent, n)
		for i := range out {
			out[i] = &models.AuditEvent{EventType: "x", EventTime: time.Unix(int64(i), 0), ActorType: "user"}
			normalizeAuditEventForHash(out[i])
		}
		return out
	}
	under := mk(rowsAtLimit)
	require.NoError(t, ls.db.Create(&under).Error, "%d rows x %d columns is within the limit", rowsAtLimit, boundColumns)
	over := mk(rowsAtLimit + 1)
	err := ls.db.Create(&over).Error
	require.Error(t, err, "%d rows x %d columns must exceed SQLite's variable limit", rowsAtLimit+1, boundColumns)
	assert.Contains(t, err.Error(), "too many SQL variables")

	perStmt, err := auditInsertRowsPerStatement(&models.AuditEvent{})
	require.NoError(t, err)
	assert.LessOrEqual(t, perStmt, rowsAtLimit, "the chunk size must stay under the real limit")
}

// A batch on either side of the derived row bound commits, split into exactly
// one and two event INSERTs, with ids ascending across the chunk seam and the
// chain verifying.
func runChunkBoundary(t *testing.T, newStore func(*testing.T) *LocalStorage) {
	perStmt, err := auditInsertRowsPerStatement(&models.AuditEvent{})
	require.NoError(t, err)
	for _, tc := range []struct{ n, inserts int }{{perStmt, 1}, {perStmt + 1, 2}} {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			ls := newStore(t)
			counter := countCreates(t, ls)
			batch := buildMultiRowBatch(tc.n, "boundary")
			require.NoError(t, ls.commitBatchAttempt(context.Background(), batch))
			assert.Equal(t, int64(tc.inserts), counter.events.Load())
			for i := 1; i < len(batch); i++ {
				require.Greater(t, batch[i].event.ID, batch[i-1].event.ID, "ids must ascend across chunks (item %d)", i)
			}
			assert.Equal(t, batch[tc.n-1].event.EntryHash, chainHeadHash(t, ls))
			v, err := ls.VerifyAuditChain(context.Background(), nil)
			require.NoError(t, err)
			assert.True(t, v.Valid, v.Reason)
			assert.Equal(t, int64(tc.n), v.ChainedEvents)
		})
	}
}

func TestCommitBatchAttempt_ChunksAtVariableLimitBoundary_SQLite(t *testing.T) {
	runChunkBoundary(t, multiRowSQLiteStore)
}

func TestCommitBatchAttempt_ChunksAtVariableLimitBoundary_Postgres(t *testing.T) {
	runChunkBoundary(t, multiRowPGStore)
}

// installPoisonTriggers makes the DATABASE reject one audit event (Description
// "POISON-EVENT") and one access log (AccessedBy "POISON-LOG") with a real
// statement error, so the whole multi-row INSERT carrying that row fails the
// way a constraint violation would. No GORM callback is involved, so the test
// does not depend on how commitBatchAttempt shapes its statements.
func installPoisonTriggers(t *testing.T, ls *LocalStorage) {
	t.Helper()
	if ls.db.Dialector.Name() == "postgres" {
		require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_poison_event() RETURNS trigger AS $$
BEGIN
  IF NEW.description = 'POISON-EVENT' THEN RAISE EXCEPTION 'poisoned audit row'; END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
		require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_poison_log() RETURNS trigger AS $$
BEGIN
  IF NEW.accessed_by = 'POISON-LOG' THEN RAISE EXCEPTION 'poisoned access-log row'; END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
		require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_poison_event BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_poison_event()`).Error)
		require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_poison_log BEFORE INSERT ON secret_access_logs FOR EACH ROW EXECUTE FUNCTION kx_poison_log()`).Error)
		return
	}
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_poison_event BEFORE INSERT ON audit_events
WHEN NEW.description = 'POISON-EVENT' BEGIN SELECT RAISE(ABORT, 'poisoned audit row'); END`).Error)
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_poison_log BEFORE INSERT ON secret_access_logs
WHEN NEW.accessed_by = 'POISON-LOG' BEGIN SELECT RAISE(ABORT, 'poisoned access-log row'); END`).Error)
}

// One poisoned event and one poisoned access log in a 9-item batch: only those
// two items fail, every other item's event and access log commit, the poisoned
// items leave no row of either kind, and the chain verifies.
func runRealDBErrorIsolation(t *testing.T, newStore func(*testing.T) *LocalStorage) {
	ctx := context.Background()
	ls := newStore(t)
	installPoisonTriggers(t, ls)

	const n, badEvent, badLog = 9, 4, 7
	batch := buildMultiRowBatch(n, "iso")
	batch[badEvent].event.Description = "POISON-EVENT"
	require.NotNil(t, batch[badLog].accessLog)
	batch[badLog].accessLog.AccessedBy = "POISON-LOG"

	errs := ls.commitAuditBatch(batch)
	require.Len(t, errs, n)
	for i, err := range errs {
		switch i {
		case badEvent:
			require.Error(t, err)
			assert.Contains(t, err.Error(), "poisoned audit row")
		case badLog:
			require.Error(t, err)
			assert.Contains(t, err.Error(), "poisoned access-log row")
		default:
			assert.NoError(t, err, "item %d shares a batch with poisoned rows and must still commit", i)
		}
	}

	events, logs := loadAuditRows(t, ls)
	wantLogs := 0
	for i, item := range batch {
		if i != badEvent && i != badLog && item.accessLog != nil {
			wantLogs++
		}
	}
	assert.Len(t, events, n-2, "exactly the unpoisoned events persisted")
	assert.Len(t, logs, wantLogs, "exactly the unpoisoned items' access logs persisted")
	for _, e := range events {
		assert.NotEqual(t, "POISON-EVENT", e.Description)
		assert.NotEqual(t, batch[badLog].event.Description, e.Description, "the event of an item whose access log failed must roll back with it")
	}
	for _, l := range logs {
		assert.NotEqual(t, batch[badEvent].accessLog.AccessedBy, l.AccessedBy, "the access log of an item whose event failed must roll back with it")
	}

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, int64(n-2), v.ChainedEvents)
}

func TestCommitAuditBatch_RealDBErrorOnOneRowIsolated_SQLite(t *testing.T) {
	runRealDBErrorIsolation(t, multiRowSQLiteStore)
}

func TestCommitAuditBatch_RealDBErrorOnOneRowIsolated_Postgres(t *testing.T) {
	runRealDBErrorIsolation(t, multiRowPGStore)
}

// The same through the real flusher and real callers: concurrent
// LogAuditEventWithAccessLog calls, one of them poisoned. Only that caller gets
// an error; every other caller returns nil with its rows committed.
func runFlusherPoisonedCaller(t *testing.T, newStore func(*testing.T) *LocalStorage) {
	ctx := context.Background()
	ls := newStore(t)
	installPoisonTriggers(t, ls)

	const n, bad = 48, 17
	batch := buildMultiRowBatch(n, "flusher")
	batch[bad].event.Description = "POISON-EVENT"
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range batch {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = ls.LogAuditEventWithAccessLog(ctx, batch[i].event, batch[i].accessLog)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if i == bad {
			require.Error(t, err)
			assert.Contains(t, err.Error(), "poisoned audit row")
			continue
		}
		require.NoError(t, err, "caller %d must get nil: its row committed", i)
		var count int64
		require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("entry_hash = ?", batch[i].event.EntryHash).Count(&count).Error)
		assert.Equal(t, int64(1), count, "caller %d returned nil, so its row must be committed", i)
	}
	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, int64(n-1), v.ChainedEvents)
}

func TestLogAuditEvent_FlusherPoisonedCallerIsolated_SQLite(t *testing.T) {
	runFlusherPoisonedCaller(t, multiRowSQLiteStore)
}

func TestLogAuditEvent_FlusherPoisonedCallerIsolated_Postgres(t *testing.T) {
	runFlusherPoisonedCaller(t, multiRowPGStore)
}

func TestCheckAuditInsertIDOrder(t *testing.T) {
	t.Parallel()
	ids := func(v ...uint) []*models.AuditEvent {
		out := make([]*models.AuditEvent, len(v))
		for i, id := range v {
			out[i] = &models.AuditEvent{ID: id}
		}
		return out
	}
	for name, tc := range map[string]struct {
		events []*models.AuditEvent
		ok     bool
	}{
		"empty":              {ids(), true},
		"single":             {ids(5), true},
		"ascending":          {ids(5, 6, 7), true},
		"ascending with gap": {ids(5, 9, 12), true},
		"zero id":            {ids(5, 0, 7), false},
		"single zero":        {ids(0), false},
		"repeated":           {ids(5, 5, 6), false},
		"reversed":           {ids(7, 6, 5), false},
		"one swap":           {ids(5, 7, 6, 8), false},
	} {
		err := checkAuditInsertIDOrder(tc.events)
		if tc.ok {
			assert.NoError(t, err, name)
		} else {
			assert.Error(t, err, name)
			assert.True(t, strings.Contains(err.Error(), "VALUES order"), name)
		}
	}
}
