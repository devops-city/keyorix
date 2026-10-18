// local_audit_chain_pipelined_batches_test.go — PERF-HIGHLOAD-1: pipelined
// audit batches (local_audit_chain_pipelined_batches.go). A batch chained onto
// a pending head commits only when that head committed and is still the head;
// a batch that fails while the next one is in flight fails closed for its own
// items only, the next one is retried after it and commits, and the chain stays
// one linear sequence. Postgres cases are pg-gated (KEYORIX_TEST_PG_DSN); the
// SQLite case proves the same outcome on the serial path SQLite keeps.
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// multiRowPGStoreInSchema is a second replica of a multiRowPGStore store: its
// own multi-connection pool and flusher on the same schema.
func multiRowPGStoreInSchema(t *testing.T, schema string) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return NewLocalStorage(db)
}

// enablePipeline lets this test's stores pipeline without a single-writer
// server (production pipelines only with single_writer on).
func enablePipeline(t *testing.T) {
	t.Helper()
	auditPipelineNeedsSingleWriter = false
	t.Cleanup(func() { auditPipelineNeedsSingleWriter = true })
}

// armForPipeline commits single-item batches through the flusher until the
// chain-head cache is armed, so the next batch can start a pipelined run.
func armForPipeline(t *testing.T, ls *LocalStorage, tag string) int {
	t.Helper()
	n := 0
	for !armedHead(ls) {
		require.Less(t, n, 8, "the chain-head cache did not arm")
		require.NoError(t, ls.LogAuditEvent(context.Background(), pipelinedEvent(fmt.Sprintf("%s arm %d", tag, n))))
		n++
	}
	return n
}

func pipelinedEvent(desc string) *models.AuditEvent {
	return &models.AuditEvent{EventType: "secret.read", Description: desc, EventTime: time.Now().UTC()}
}

// auditRowCount counts audit_events rows with description desc.
func auditRowCount(t *testing.T, ls *LocalStorage, desc string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("description = ?", desc).Count(&n).Error)
	return n
}

// sendPlan sends a one-flight plan on a pool connection and reads it.
func sendPlan(t *testing.T, ls *LocalStorage, plan *auditOneFlightPlan) (beforeCommit bool, err error) {
	t.Helper()
	connErr := ls.withAuditPipelineConn(context.Background(), func(pc *pgx.Conn) error {
		plan.f.send(pc)
		_, beforeCommit, err = plan.read()
		return nil
	})
	require.NoError(t, connErr)
	return beforeCommit, err
}

// A batch chained onto a pending head (entry_hash known, id not) commits only
// when the table's head is exactly that row. A hash that is not the head (an
// unknown one, or an older row's) must RAISE inside the transaction, so
// Postgres skips COMMIT and nothing is written: a NULL instead of a raise (a
// NULL message cast to int) would let COMMIT run on a forked chain.
func TestAuditInsertCheck_PendingHeadMismatchRaises(t *testing.T) {
	enablePipeline(t)
	ctx := context.Background()
	ls := multiRowPGStore(t)
	first := buildMultiRowBatch(3, "base")
	commitAll(t, ls, first)
	middleHash := first[1].event.EntryHash
	headHash := first[2].event.EntryHash

	for name, hash := range map[string]string{
		"unknown hash":     strings.Repeat("ab", 32),
		"older row's hash": middleHash,
	} {
		batch := buildMultiRowBatch(4, "mismatch "+name)
		plan, err := ls.prepareAuditOneFlight(ctx, batch, auditChainHead{hash: hash, pending: true})
		require.NoError(t, err, name)
		beforeCommit, err := sendPlan(t, ls, plan)
		require.Error(t, err, "%s: a batch chained onto a row that is not the head must not commit", name)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "%s: want the check's raise, got %v", name, err)
		assert.Equal(t, "22P02", pgErr.Code, name)
		assert.Contains(t, pgErr.Message, "pending "+hash, name)
		assert.True(t, beforeCommit, "%s: the raise belongs to a statement before COMMIT", name)
		assert.True(t, auditOneFlightRolledBack(err, beforeCommit), name)
		events, _ := loadAuditRows(t, ls)
		require.Len(t, events, 3, "%s: nothing may be written", name)
	}

	good := buildMultiRowBatch(4, "pending ok")
	plan, err := ls.prepareAuditOneFlight(ctx, good, auditChainHead{hash: headHash, pending: true})
	require.NoError(t, err)
	_, err = sendPlan(t, ls, plan)
	require.NoError(t, err, "a batch chained onto the real head must commit")
	requireChainValid(t, ls, nil, 7)
}

// Many concurrent readers through the flusher: batches are sent while the one
// before them is in flight, every caller that got nil has its row committed at
// that moment (audit before disclosure), and the chain is one linear sequence.
func TestPipelinedBatches_PostgresConcurrentReadersChainInOrder(t *testing.T) {
	enablePipeline(t)
	ctx := context.Background()
	ls := multiRowPGStore(t)
	armed := armForPipeline(t, ls, "concurrent")
	// A little database time per row, so readers queue up while a batch
	// executes: the next batch is then at least as large as the one in flight
	// and is pipelined (a batch smaller than it waits instead, by design).
	require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_slow_each_row() RETURNS trigger AS $$
BEGIN PERFORM pg_sleep(0.001); RETURN NEW; END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_slow_each_row BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_slow_each_row()`).Error)
	before := ls.auditHead.pipelinedSends.Load()

	const workers, each = 48, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := range workers {
		wg.Go(func() {
			for i := range each {
				desc := fmt.Sprintf("w%d i%d", w, i)
				log := &models.SecretAccessLog{SecretNodeID: uint(w + 1), AccessedBy: desc, AccessTime: time.Now(), Action: "read"}
				if err := ls.LogAuditEventWithAccessLog(ctx, pipelinedEvent(desc), log); err != nil {
					errs <- fmt.Errorf("%s: %w", desc, err)
					continue
				}
				if n := auditRowCount(t, ls, desc); n != 1 {
					errs <- fmt.Errorf("%s: answered before its row committed (%d rows)", desc, n)
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	assert.Positive(t, ls.auditHead.pipelinedSends.Load()-before, "no batch was sent while another was in flight: the pipeline was not exercised")
	requireChainValid(t, ls, nil, armed+workers*each)
	requireNoNullTextColumns(t, ls)
	_, logs := loadAuditRows(t, ls)
	assert.Len(t, logs, workers*each)
}

// requireNoNullTextColumns fails when a text column that the models always fill
// (a Go string, so "" at worst) is NULL in a stored row. Read with raw SQL, not
// through GORM, which would read a NULL back as "": the strict verifier
// (`admin verify-audit`) scans these columns into strings and cannot run on a
// NULL, and a NULL is not what the serial path stores for "".
func requireNoNullTextColumns(t *testing.T, ls *LocalStorage) {
	t.Helper()
	for table, cols := range map[string][]string{
		"audit_events":       {"event_type", "ip_address", "description", "diff", "actor_type", "prev_hash", "entry_hash"},
		"secret_access_logs": {"accessed_by", "action", "ip_address", "user_agent"},
	} {
		for _, col := range cols {
			var n int64
			require.NoError(t, ls.db.Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE %s IS NULL", table, col)).Scan(&n).Error)
			assert.Zero(t, n, "%s.%s: %d rows stored NULL where the value was a Go string", table, col, n)
		}
	}
}

// A pipelined batch stores exactly what the serial path stores: every empty
// string as "", not NULL (the parameters are re-encoded for the pipeline, and
// an empty encoded value must stay a zero-length value).
func TestPipelinedBatches_PostgresStoresEmptyStringsNotNull(t *testing.T) {
	enablePipeline(t)
	ls := multiRowPGStore(t)
	armForPipeline(t, ls, "empty")
	sends := ls.auditHead.pipelinedSends.Load()
	primePipeline(t, ls, 3) // its events and access logs carry empty IP, diff, user agent
	require.Greater(t, ls.auditHead.pipelinedSends.Load(), sends, "the pipeline was not exercised")
	log := &models.SecretAccessLog{SecretNodeID: 1, AccessTime: time.Now(), Action: "read"} // empty AccessedBy, IP, UA
	require.NoError(t, ls.LogAuditEventWithAccessLog(context.Background(), pipelinedEvent("with empty log fields"), log))
	requireNoNullTextColumns(t, ls)
}

// storedRows returns every row of table as JSON without its id, in id order,
// read with raw SQL so NULLs and exact stored values show.
func storedRows(t *testing.T, ls *LocalStorage, table string) []string {
	t.Helper()
	var rows []string
	require.NoError(t, ls.db.Raw(fmt.Sprintf("SELECT (to_jsonb(t) - 'id')::text FROM %s t ORDER BY id", table)).Scan(&rows).Error)
	return rows
}

// The same items in the same order store the same rows, byte for byte except
// the id, whether the flusher commits them serially or pipelined: the pipeline
// re-encodes the parameters itself, and the chain hashes depend only on the
// items and their order, not on the batch boundaries. Driven through the
// pipeline directly, so the order and the batches are fixed; every size goes
// through twice, so the second round is sent chained onto pending heads.
func TestPipelinedBatches_PostgresStoresTheSameRowsAsTheSerialPath(t *testing.T) {
	enablePipeline(t)
	serial, piped := multiRowPGStore(t), multiRowPGStore(t)
	sizes := []int{7, 13, 2, 9, 7, 13, 2, 9}
	commitAll(t, serial, buildMultiRowBatch(1, "eq-arm"))
	commitAll(t, piped, buildMultiRowBatch(1, "eq-arm"))
	for i, n := range sizes {
		commitAll(t, serial, buildMultiRowBatch(n, fmt.Sprintf("eq%d", i)))
	}
	require.True(t, armedHead(piped))
	p := piped.newAuditBatchPipeline()
	require.NotNil(t, p)
	var items []*auditBatchItem
	for i, n := range sizes {
		b := buildMultiRowBatch(n, fmt.Sprintf("eq%d", i))
		require.True(t, p.trySend(b), "batch %d was not sent pipelined", i)
		items = append(items, b...)
	}
	p.end()
	p.releaseConn()
	for i, it := range items {
		require.NoError(t, <-it.done, "item %d", i)
	}
	assert.Positive(t, piped.auditHead.pipelinedSends.Load(), "no batch was chained onto a pending head")
	for _, table := range []string{"audit_events", "secret_access_logs"} {
		assert.Equal(t, storedRows(t, serial, table), storedRows(t, piped, table), table)
	}
	requireChainValid(t, piped, nil, 1+62)
}

// One reader at a time (a lone item, nothing in flight): every batch goes the
// serial way, never through a pipelined send.
func TestPipelinedBatches_PostgresLoneReaderStaysSerial(t *testing.T) {
	enablePipeline(t)
	ls := multiRowPGStore(t)
	armed := armForPipeline(t, ls, "lone")
	commits := ls.auditHead.oneFlightCommits.Load()
	var sent atomic.Int64
	auditPipelineAfterSendHook = func(sent2 *LocalStorage, _ []*auditBatchItem) {
		if sent2 == ls {
			sent.Add(1)
		}
	}
	t.Cleanup(func() { auditPipelineAfterSendHook = nil })
	for i := range 20 {
		require.NoError(t, ls.LogAuditEvent(context.Background(), pipelinedEvent(fmt.Sprintf("lone %d", i))))
	}
	assert.Zero(t, sent.Load(), "a lone reader's batch was sent on the pipeline")
	assert.Greater(t, ls.auditHead.oneFlightCommits.Load(), commits, "the serial path keeps its one-flight commits")
	requireChainValid(t, ls, nil, armed+20)
}

// Without single_writer the flusher never pipelines (every read runs its
// credential statement too, so the flusher is not the bottleneck and more,
// smaller transactions would cost throughput): the same backlog that
// pipelines with it commits serially, and the flusher holds no connection.
func TestAuditPipeline_PostgresOffWithoutSingleWriter(t *testing.T) {
	ctx := context.Background()
	ls := multiRowPGStore(t)
	armed := armForPipeline(t, ls, "nosw")
	require.NoError(t, ls.db.Exec(`CREATE FUNCTION kx_slow_each_row() RETURNS trigger AS $$
BEGIN PERFORM pg_sleep(0.001); RETURN NEW; END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_slow_each_row BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_slow_each_row()`).Error)
	var wg sync.WaitGroup
	for w := range 24 {
		wg.Go(func() {
			for i := range 10 {
				assert.NoError(t, ls.LogAuditEvent(ctx, pipelinedEvent(fmt.Sprintf("nosw w%d i%d", w, i))))
			}
		})
	}
	wg.Wait()
	assert.Zero(t, ls.auditHead.pipelinedSends.Load(), "pipelined without single_writer")
	requireChainValid(t, ls, nil, armed+240)
}

// slowPoisonTriggers: an audit row described SLOW-POISON sleeps, then raises; one
// described SLOW sleeps and commits. The sleep keeps its batch in flight while
// the flusher sends the next batch.
func slowPoisonTriggers(t *testing.T, ls *LocalStorage, sleep time.Duration) {
	t.Helper()
	require.NoError(t, ls.db.Exec(fmt.Sprintf(`CREATE FUNCTION kx_slow_row() RETURNS trigger AS $$
BEGIN
  IF NEW.description IN ('SLOW-POISON', 'SLOW') THEN PERFORM pg_sleep(%f); END IF;
  IF NEW.description = 'SLOW-POISON' THEN RAISE EXCEPTION 'poisoned audit row (slow)'; END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql`, sleep.Seconds())).Error)
	require.NoError(t, ls.db.Exec(`CREATE TRIGGER kx_slow_row BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_slow_row()`).Error)
}

// waitForSleepingAppend waits until a backend is inside the trigger's pg_sleep,
// i.e. the slow batch is executing and holds KEYAUDIT, and returns its pid.
func waitForSleepingAppend(t *testing.T, ls *LocalStorage) int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var pid int64
		require.NoError(t, ls.db.Raw(`SELECT COALESCE(max(pid), 0) FROM pg_stat_activity WHERE wait_event = 'PgSleep' AND datname = current_database()`).Scan(&pid).Error)
		if pid != 0 {
			return pid
		}
		require.True(t, time.Now().Before(deadline), "the slow batch never started executing")
		time.Sleep(5 * time.Millisecond)
	}
}

// submitAsync logs desc through the flusher in a goroutine and returns its result channel.
func submitAsync(ls *LocalStorage, desc string) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- ls.LogAuditEvent(context.Background(), pipelinedEvent(desc)) }()
	return ch
}

// queueBehind arranges that, right after ls's flusher sends the batch carrying
// the event described marker, the events descs are queued so they make up the
// next batch, sent while that one is in flight. It returns their result
// channels.
func queueBehind(t *testing.T, ls *LocalStorage, marker string, descs ...string) []<-chan error {
	t.Helper()
	results := make([]chan error, len(descs))
	for i := range results {
		results[i] = make(chan error, 1)
	}
	var once sync.Once
	auditPipelineAfterSendHook = func(sent *LocalStorage, batch []*auditBatchItem) {
		if sent != ls || batch[0].event.Description != marker {
			return
		}
		once.Do(func() {
			for i, desc := range descs {
				go func() { results[i] <- ls.LogAuditEvent(context.Background(), pipelinedEvent(desc)) }()
			}
			deadline := time.Now().Add(5 * time.Second)
			for len(ls.auditFlusher.queue) < len(descs) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		})
	}
	auditPipelineSerialWhenIdle = false
	t.Cleanup(func() { auditPipelineAfterSendHook, auditPipelineSerialWhenIdle = nil, true })
	out := make([]<-chan error, len(results))
	for i, ch := range results {
		out[i] = ch
	}
	return out
}

// primePipeline commits a one-item batch and then a batch of k behind it
// through the pipeline, so both sizes' statements are prepared on the
// flusher's held connection, and returns the number of rows written. A batch
// whose statements are new is sent only after the batches in flight are read.
func primePipeline(t *testing.T, ls *LocalStorage, k int) int {
	t.Helper()
	descs := make([]string, k)
	for i := range descs {
		descs[i] = fmt.Sprintf("prime %d", i)
	}
	next := queueBehind(t, ls, "prime", descs...)
	require.NoError(t, <-submitAsync(ls, "prime"))
	for _, ch := range next {
		require.NoError(t, <-ch)
	}
	auditPipelineAfterSendHook = nil
	return 1 + k
}

// waitPipelinedSend waits until ls has sent one more batch chained onto a
// pending head than before.
func waitPipelinedSend(t *testing.T, ls *LocalStorage, before int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for ls.auditHead.pipelinedSends.Load() <= before {
		require.True(t, time.Now().Before(deadline), "the next batch was never sent while the slow one was in flight")
		time.Sleep(2 * time.Millisecond)
	}
}

// Batch N fails (a statement error) while batch N+1 is in flight, chained onto
// N's last row. N's reader is refused; N+1's check raises because N's rows are
// not there, so it is rolled back and retried AFTER N, and its readers get nil
// only once their rows committed. The chain stays linear.
func TestPipelinedBatches_PostgresBatchFailsWhileNextInFlight(t *testing.T) {
	enablePipeline(t)
	ls := multiRowPGStore(t)
	slowPoisonTriggers(t, ls, 300*time.Millisecond)
	armed := armForPipeline(t, ls, "fail")
	armed += primePipeline(t, ls, 5)
	sends, misses := ls.auditHead.pipelinedSends.Load(), ls.auditHead.oneFlightMisses.Load()

	next := queueBehind(t, ls, "SLOW-POISON", "after poison 0", "after poison 1", "after poison 2", "after poison 3", "after poison 4") // batch N+1
	poisoned := submitAsync(ls, "SLOW-POISON")                                                                                          // batch N
	waitPipelinedSend(t, ls, sends)

	err := <-poisoned
	require.Error(t, err, "the failed batch's reader must be refused")
	assert.Contains(t, err.Error(), "poisoned audit row (slow)")
	for i, ch := range next {
		require.NoError(t, <-ch, "reader %d of the batch after the failed one", i)
		assert.EqualValues(t, 1, auditRowCount(t, ls, fmt.Sprintf("after poison %d", i)))
	}
	assert.Zero(t, auditRowCount(t, ls, "SLOW-POISON"))
	assert.GreaterOrEqual(t, ls.auditHead.oneFlightMisses.Load()-misses, int64(2), "both the failed batch and the one chained onto it are rolled back and retried")
	requireChainValid(t, ls, nil, armed+len(next))
}

// Batch N's backend is terminated mid-transaction while batch N+1 is in flight.
// Postgres answers N's statement with a FATAL error before COMMIT ran, so
// nothing of N was written and N is retried, as a serial one-flight attempt is
// (TestOneFlight_PostgresBackendDiesMidFlight); N+1's check raises because N's
// rows are not there yet, and N+1 is retried after N. Each row is stored
// exactly once and the chain stays linear.
func TestPipelinedBatches_PostgresBackendDiesWhileNextInFlight(t *testing.T) {
	enablePipeline(t)
	ls := multiRowPGStore(t)
	slowPoisonTriggers(t, ls, 500*time.Millisecond)
	armed := armForPipeline(t, ls, "kill")
	armed += primePipeline(t, ls, 4)
	sends, misses := ls.auditHead.pipelinedSends.Load(), ls.auditHead.oneFlightMisses.Load()

	next := queueBehind(t, ls, "SLOW", "after kill 0", "after kill 1", "after kill 2", "after kill 3") // batch N+1
	slow := submitAsync(ls, "SLOW")                                                                    // batch N
	waitPipelinedSend(t, ls, sends)
	pid := waitForSleepingAppend(t, ls)
	var killed bool
	require.NoError(t, ls.db.Raw("SELECT pg_terminate_backend(?)", pid).Scan(&killed).Error)
	require.True(t, killed)

	require.NoError(t, <-slow, "nothing of the killed attempt was written, so it is retried and commits")
	for i, ch := range next {
		require.NoError(t, <-ch, "reader %d of the batch after the killed one", i)
		assert.EqualValues(t, 1, auditRowCount(t, ls, fmt.Sprintf("after kill %d", i)))
	}
	assert.EqualValues(t, 1, auditRowCount(t, ls, "SLOW"))
	assert.GreaterOrEqual(t, ls.auditHead.oneFlightMisses.Load()-misses, int64(2))
	requireChainValid(t, ls, nil, armed+1+len(next))
}

// lostConnPGStore is a multiRowPGStore whose client sockets close themselves
// 100 ms after sending a flight that carries an audit row described LOST-CONN:
// the client then sees a broken connection, not a Postgres error, while the
// server goes on running that flight, COMMIT included.
// It also returns the plain store on the same schema, for statements that must
// not trip the marker themselves.
func lostConnPGStore(t *testing.T) (lost, plain *LocalStorage) {
	t.Helper()
	ls := multiRowPGStore(t)
	cc, err := pgx.ParseConfig(pgdsn.PGSearchPathDSN(os.Getenv("KEYORIX_TEST_PG_DSN"), pipelinePGSchema(t, ls)))
	require.NoError(t, err)
	dial := cc.DialFunc
	cc.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &lostConn{Conn: c}, nil
	}
	sqlDB := stdlib.OpenDB(*cc)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return NewLocalStorage(db), ls
}

type lostConn struct{ net.Conn }

func (c *lostConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if bytes.Contains(p, []byte("LOST-CONN")) {
		time.AfterFunc(100*time.Millisecond, func() { _ = c.Conn.Close() })
	}
	return n, err
}

// Batch N's client connection breaks while N executes and batch N+1 is in
// flight: the flusher cannot know whether N committed, so N's reader is refused
// (fail closed). The server may still have committed N; N+1's check then finds
// N's rows and N+1 commits, or it does not and N+1 is retried. Either way N+1's
// readers get nil only with their rows committed and the chain is linear.
func TestPipelinedBatches_PostgresLostConnectionOutcomeUnknown(t *testing.T) {
	enablePipeline(t)
	ls, plain := lostConnPGStore(t)
	require.NoError(t, plain.db.Exec(`CREATE FUNCTION kx_lost_row() RETURNS trigger AS $$
BEGIN
  IF NEW.description = 'LOST-CONN' THEN PERFORM pg_sleep(0.3); END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql`).Error)
	require.NoError(t, plain.db.Exec(`CREATE TRIGGER kx_lost_row BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION kx_lost_row()`).Error)
	armed := armForPipeline(t, ls, "lost")
	armed += primePipeline(t, ls, 4)
	sends := ls.auditHead.pipelinedSends.Load()

	next := queueBehind(t, ls, "LOST-CONN", "after lost 0", "after lost 1", "after lost 2", "after lost 3") // batch N+1
	lost := submitAsync(ls, "LOST-CONN")                                                                    // batch N
	waitPipelinedSend(t, ls, sends)

	require.Error(t, <-lost, "a batch whose outcome is unknown must fail its reader")
	for i, ch := range next {
		require.NoError(t, <-ch, "reader %d of the batch after the lost one", i)
		assert.EqualValues(t, 1, auditRowCount(t, ls, fmt.Sprintf("after lost %d", i)))
	}
	// Wait for the server side of the lost flight to finish either way.
	require.Eventually(t, func() bool {
		var busy int64
		return ls.db.Raw(`SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'PgSleep' AND datname = current_database()`).Scan(&busy).Error == nil && busy == 0
	}, 5*time.Second, 10*time.Millisecond)
	stored := auditRowCount(t, plain, "LOST-CONN")
	assert.LessOrEqual(t, stored, int64(1))
	t.Logf("the lost flight committed on the server: %v", stored == 1)
	requireChainValid(t, ls, nil, armed+int(stored)+len(next))
}

// The mutation path (a transaction-scoped store's direct append, holding
// KEYAUDIT to its COMMIT) interleaved with pipelined reader batches: the head
// moves under in-flight batches, their checks catch it, and the chain stays one
// linear sequence with every row present.
func TestPipelinedBatches_PostgresInterleavedDirectAppends(t *testing.T) {
	enablePipeline(t)
	ctx := context.Background()
	ls := multiRowPGStore(t)
	armed := armForPipeline(t, ls, "mixed")

	const readers, reads, writers, writes = 24, 20, 3, 15
	var wg sync.WaitGroup
	errs := make(chan error, readers*reads+writers*writes)
	for r := range readers {
		wg.Go(func() {
			for i := range reads {
				if err := ls.LogAuditEvent(ctx, pipelinedEvent(fmt.Sprintf("r%d %d", r, i))); err != nil {
					errs <- err
				}
			}
		})
	}
	for w := range writers {
		wg.Go(func() {
			for i := range writes {
				if err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
					return tx.LogAuditEvent(ctx, pipelinedEvent(fmt.Sprintf("m%d %d", w, i)))
				}); err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	requireChainValid(t, ls, nil, armed+readers*reads+writers*writes)
}

// Two replicas (two stores, two pools, two flushers) pipelining into one table:
// each one's in-flight batches are overtaken by the other's, caught by the
// checks and retried; the chain is one linear sequence across both.
func TestPipelinedBatches_PostgresTwoReplicasConcurrent(t *testing.T) {
	enablePipeline(t)
	ctx := context.Background()
	a := multiRowPGStore(t)
	b := multiRowPGStoreInSchema(t, pipelinePGSchema(t, a))
	armedA := armForPipeline(t, a, "a")
	armedB := armForPipeline(t, b, "b")

	const workers, each = 16, 20
	var wg sync.WaitGroup
	errs := make(chan error, 2*workers*each)
	for _, ls := range []*LocalStorage{a, b} {
		for w := range workers {
			wg.Go(func() {
				for i := range each {
					if err := ls.LogAuditEvent(ctx, pipelinedEvent(fmt.Sprintf("%p w%d i%d", ls, w, i))); err != nil {
						errs <- err
					}
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	requireChainValid(t, a, nil, armedA+armedB+2*workers*each)
}

// SQLite keeps the serial flusher (its chain-head cache never arms, so no run
// starts): a failing batch still refuses only its own reader, the batch after
// it commits, and the chain stays linear.
func TestPipelinedBatches_SQLiteFailedBatchFailsClosedNextCommits(t *testing.T) {
	enablePipeline(t)
	ls := multiRowSQLiteStore(t)
	installPoisonTriggers(t, ls)
	for i := range 3 {
		require.NoError(t, ls.LogAuditEvent(context.Background(), pipelinedEvent(fmt.Sprintf("before %d", i))))
	}

	poisoned := submitAsync(ls, "POISON-EVENT")
	next := make([]<-chan error, 5)
	for i := range next {
		next[i] = submitAsync(ls, fmt.Sprintf("after poison %d", i))
	}
	err := <-poisoned
	require.Error(t, err)
	assert.Contains(t, err.Error(), "poisoned audit row")
	for i, ch := range next {
		require.NoError(t, <-ch, "reader %d", i)
	}
	assert.False(t, armedHead(ls), "SQLite must never arm the cache, so it never pipelines")
	assert.Zero(t, ls.auditHead.pipelinedSends.Load())
	assert.Zero(t, auditRowCount(t, ls, "POISON-EVENT"))
	requireChainValid(t, ls, nil, 3+len(next))
}
