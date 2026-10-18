// local_audit_chain_pipelined_batches.go — PERF-HIGHLOAD-1: up to
// auditPipelineDepth Postgres audit batches in flight on ONE connection, so the
// flusher builds and sends batch N+1 while Postgres executes batch N, and
// Postgres starts N+1 from its input buffer the moment N commits
// (docs/specs/audit-pipelined-commits.md).
//
// A run holds one pool connection in pgconn pipeline mode. Each batch is the
// one-flight transaction (local_audit_chain_one_flight.go: BEGIN, the fast-mode
// SET LOCAL, KEYAUDIT, the events INSERT with its head and link checks, the
// access-log INSERT, COMMIT) followed by its own Sync. The first batch of a run
// chains onto the armed chain-head cache; every later one onto the last row of
// the batch sent before it, whose id is not known yet (a pending head: the
// check compares its entry_hash). On one connection Postgres runs the batches
// strictly in send order, so the chain order is the send order and no batch
// can overtake its predecessor. (Sent on two connections, the second batch's
// backend could take KEYAUDIT first, fail its check and end the run: the first
// version of this change did, measured.)
//
// Results are read in send order. A batch whose result is an error ends the
// run: Postgres leaves its transaction block open and aborted, still holding
// KEYAUDIT, so every later batch in flight fails at its BEGIN and nothing of
// theirs is written. The run reads every result, closes the pipeline, rolls
// the connection back and gives it back, and only then resolves the batches in
// send order with the serial rules: a commit updates the cache; a failure that
// provably wrote nothing is retried in two flights (which re-reads the head
// under the lock) and then bisected (finishAuditBatch); any other failure fails
// its items. Every item gets nil only after its own batch's COMMIT was
// acknowledged. A run also ends as soon as the cache epoch moves (a miss, a
// failure, an invalidation by another in-process writer), when a batch needs a
// statement not yet prepared on the run's connection (statements are prepared
// outside pipeline mode, after the batches in flight are read), and at the
// flusher's idle exit.
//
// SQLite and a non-pgx Postgres pool never pipeline: their cache never arms
// (INV-STORE-audit-one-flight-commit rule 4), and only an armed cache starts a
// run. Nor does a store with a flusher linger window: lingering with a batch in
// flight would hold that batch's readers for the window.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditPipelineDepth is how many batches may be in flight at once: one
// executing, one waiting in Postgres' input buffer. A third would only wait
// longer behind the second.
const auditPipelineDepth = 2

// auditInflightBatch is one batch sent on a run's pipeline, not yet read.
type auditInflightBatch struct {
	batch []*auditBatchItem
	epoch uint64
	plan  *auditOneFlightPlan
	stop  func() bool // unregisters the deadline hook
}

// auditPipelineOutcome is one batch's read result, before it is resolved.
type auditPipelineOutcome struct {
	b            *auditInflightBatch
	last         auditChainHead
	beforeCommit bool
	err          error
}

// auditBatchPipeline is the flusher goroutine's pipeline state; only that
// goroutine uses it.
type auditBatchPipeline struct {
	ls       *LocalStorage
	epoch    uint64 // the cache epoch the current run began under
	conn     *auditPipelineConn
	run      *auditPipelineRun // nil when no run is open
	inflight []*auditInflightBatch
	tailHash string // entry_hash of the last row sent in the current run
}

// auditPipelineConn is the pool connection the flusher holds while it runs
// (until its idle exit), so the statements prepared on it stay prepared
// across runs: a statement is prepared once per text, not once per run.
type auditPipelineConn struct {
	pc      *pgx.Conn
	sds     map[string]*pgconn.StatementDescription // statements prepared on pc, by text
	eqb     pgx.ExtendedQueryBuilder
	release chan struct{} // closed to hand the connection back
	gone    chan struct{} // closed once it is back in the pool (or discarded)
}

// auditPipelineRun is one run: the held connection in pipeline mode.
type auditPipelineRun struct {
	pl     *pgconn.Pipeline
	ctx    context.Context // the pipeline's; cancelled when a batch's deadline passes
	cancel context.CancelFunc
}

// newAuditBatchPipeline returns the pipeline for one flusher run, or nil when
// this store never pipelines.
func (ls *LocalStorage) newAuditBatchPipeline() *auditBatchPipeline {
	if auditPipelineDepth < 2 || ls.db == nil || ls.db.Dialector.Name() != "postgres" || ls.auditFlusherLingerWindow > 0 {
		return nil
	}
	return &auditBatchPipeline{ls: ls}
}

// commitFlusherBatch commits batch for the flusher: pipelined when it can be,
// otherwise serially once the run (if any) has ended. Every item of batch gets
// exactly one result either way.
func (ls *LocalStorage) commitFlusherBatch(p *auditBatchPipeline, batch []*auditBatchItem) {
	if p.trySend(batch) {
		return
	}
	p.end()
	deliverAuditBatch(batch, ls.commitAuditBatch(batch))
}

func deliverAuditBatch(batch []*auditBatchItem, errs []error) {
	for i, item := range batch {
		item.done <- errs[i]
	}
}

// inFlight reports whether a batch awaits its result.
func (p *auditBatchPipeline) inFlight() bool { return p != nil && len(p.inflight) > 0 }

// end reads every batch in flight, resolves them, and closes the run. The
// connection stays held.
func (p *auditBatchPipeline) end() {
	if p == nil {
		return
	}
	for len(p.inflight) > 0 {
		p.completeOldest()
	}
	p.closeRun()
}

// shutdown ends the run and hands the held connection back (the flusher's
// idle exit).
func (p *auditBatchPipeline) shutdown() {
	if p == nil {
		return
	}
	p.end()
	p.releaseConn()
}

// auditPipelineFits reports whether batch's events fit one INSERT, the only
// shape whose check can chain onto a pending head. Every flusher batch does
// (TestAuditInsertRowsPerStatement_CoversAFullFlusherBatch).
func auditPipelineFits(batch []*auditBatchItem) bool {
	perStmt, err := auditInsertRowsPerStatement(&models.AuditEvent{})
	return err == nil && len(batch) <= perStmt
}

// trySend sends batch on the run's pipeline and reports whether it did. When
// it returns false nothing of batch was sent, and the caller commits it
// serially.
func (p *auditBatchPipeline) trySend(batch []*auditBatchItem) bool {
	if p == nil || !auditPipelineFits(batch) {
		return false
	}
	for len(p.inflight) >= auditPipelineDepth {
		p.completeOldest()
	}
	ls := p.ls
	ctx := batch[0].ctx
	var head auditChainHead
	if p.run != nil && ls.auditHead.currentEpoch() == p.epoch {
		head = auditChainHead{hash: p.tailHash, pending: len(p.inflight) > 0}
		if !head.pending {
			// Nothing in flight: the cache already holds the run's last row
			// with its id (committedOneFlight), so use it.
			epoch, cached, armed := ls.auditHead.begin()
			if !armed || epoch != p.epoch || cached.hash != p.tailHash {
				p.end()
				return false
			}
			head = cached
		}
	} else {
		p.end()
		epoch, cached, armed := ls.auditHead.begin()
		if !armed {
			return false
		}
		if err := p.openRun(ctx); err != nil {
			return false
		}
		head, p.epoch = cached, epoch
	}
	plan, err := ls.prepareAuditOneFlight(ctx, batch, head)
	if err != nil {
		p.end()
		return false
	}
	sds, ok := p.prepared(ctx, plan)
	if !ok {
		p.end()
		return false
	}
	if p.run == nil {
		// Preparing read the batches in flight, one of them failed, and the
		// run is over: batch was chained onto a head that may not exist.
		return false
	}
	if err := p.send(ctx, plan, sds); err != nil {
		// Encoding failed (nothing queued) or the connection broke while
		// sending. In the second case Postgres may have run the whole
		// transaction, COMMIT included, before the break; the serial commit
		// then appends batch again, so its reads are recorded twice at worst,
		// never not at all (as after an unknown outcome on the serial path,
		// whose bisection retries too).
		p.end()
		return false
	}
	b := &auditInflightBatch{batch: batch, epoch: p.epoch, plan: plan}
	b.stop = context.AfterFunc(ctx, p.run.cancel)
	p.inflight = append(p.inflight, b)
	p.tailHash = plan.tailHash()
	if head.pending {
		auditPipelinedBatches.Inc()
		ls.auditHead.pipelinedSends.Add(1)
	}
	if auditPipelineAfterSendHook != nil {
		auditPipelineAfterSendHook(ls, batch)
	}
	return true
}

// auditPipelineAfterSendHook, when set (tests only), runs on the flusher
// goroutine right after a batch was sent on a run's pipeline, before the
// flusher looks at its queue again: a test queues the next batch's items here
// to have it sent while this one is in flight.
var auditPipelineAfterSendHook func(ls *LocalStorage, batch []*auditBatchItem)

// openRun puts the held connection in pipeline mode, taking a pool
// connection first if none is held.
func (p *auditBatchPipeline) openRun(ctx context.Context) error {
	if p.conn != nil && p.conn.pc.IsClosed() {
		p.releaseConn()
	}
	if p.conn == nil {
		if err := p.acquireConn(ctx); err != nil {
			return err
		}
	}
	run := &auditPipelineRun{}
	run.ctx, run.cancel = context.WithCancel(context.Background())
	run.pl = p.conn.pc.PgConn().StartPipeline(run.ctx)
	p.run = run
	return nil
}

// acquireConn takes a pool connection for the flusher to hold.
func (p *auditBatchPipeline) acquireConn(ctx context.Context) error {
	sqlDB, ok := p.ls.db.Statement.ConnPool.(*sql.DB)
	if !ok {
		return errAuditPipelineUnavailable
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	held := &auditPipelineConn{
		sds:     map[string]*pgconn.StatementDescription{},
		release: make(chan struct{}),
		gone:    make(chan struct{}),
	}
	ready := make(chan *pgx.Conn, 1)
	// The driver connection is only ours inside Raw's callback, so the
	// callback stays open while the flusher holds it: it hands the
	// connection over, waits for the release, and leaves it idle (or closed)
	// before returning it to the pool.
	go func() {
		defer close(held.gone)
		defer func() { _ = conn.Close() }()
		_ = conn.Raw(func(driverConn any) error {
			sc, ok := driverConn.(*stdlib.Conn)
			if !ok {
				ready <- nil
				return errAuditPipelineUnavailable
			}
			pc := sc.Conn()
			ready <- pc
			<-held.release
			leaveAuditConnIdle(pc)
			return nil
		})
	}()
	if held.pc = <-ready; held.pc == nil {
		<-held.gone
		return errAuditPipelineUnavailable
	}
	p.conn = held
	p.ls.auditHeldConn.Store(held.pc)
	return nil
}

// releaseConn hands the held connection back to the pool.
func (p *auditBatchPipeline) releaseConn() {
	if p.conn == nil {
		return
	}
	p.ls.auditHeldConn.Store(nil)
	close(p.conn.release)
	<-p.conn.gone
	p.conn = nil
}

// closeRun ends the run's pipeline mode and leaves the held connection idle:
// a transaction a failed batch left open is rolled back (it holds KEYAUDIT),
// and a connection that cannot be brought back to idle is given up. Every
// batch in flight must have been read.
func (p *auditBatchPipeline) closeRun() {
	run := p.run
	if run == nil {
		return
	}
	p.run, p.tailHash = nil, ""
	_ = run.pl.Close()
	run.cancel()
	pc := p.conn.pc
	leaveAuditConnIdle(pc)
	if pc.IsClosed() {
		p.releaseConn()
	}
}

// prepared returns the statement descriptions of plan's statements on the
// held connection. A statement not prepared there yet is prepared outside
// pipeline mode: the batches in flight are read and resolved first, and if
// one of them failed the run is over (p.run is nil on return). ok is false
// when preparing failed; the caller ends the run.
func (p *auditBatchPipeline) prepared(ctx context.Context, plan *auditOneFlightPlan) (sds []*pgconn.StatementDescription, ok bool) {
	var missing []string
	for _, st := range plan.f.stmts {
		if _, have := p.conn.sds[st.sql]; !have {
			missing = append(missing, st.sql)
		}
	}
	if len(missing) > 0 {
		for len(p.inflight) > 0 {
			p.completeOldest()
		}
		run := p.run
		if run == nil {
			return nil, true
		}
		if err := run.pl.Close(); err != nil {
			return nil, false
		}
		for _, text := range missing {
			sd, err := p.conn.pc.Prepare(ctx, text, text)
			if err != nil {
				run.pl = p.conn.pc.PgConn().StartPipeline(run.ctx)
				return nil, false
			}
			p.conn.sds[text] = sd
		}
		run.pl = p.conn.pc.PgConn().StartPipeline(run.ctx)
	}
	sds = make([]*pgconn.StatementDescription, len(plan.f.stmts))
	for i, st := range plan.f.stmts {
		sds[i] = p.conn.sds[st.sql]
	}
	return sds, true
}

// send queues plan's statements and its Sync on the run's pipeline and flushes
// them. Every parameter is encoded before anything is queued, so an encoding
// error leaves nothing of the transaction behind.
func (p *auditBatchPipeline) send(ctx context.Context, plan *auditOneFlightPlan, sds []*pgconn.StatementDescription) error {
	run, held := p.run, p.conn
	type bound struct {
		values  [][]byte
		formats []int16
		results []int16
	}
	binds := make([]bound, len(sds))
	for i, sd := range sds {
		if err := held.eqb.Build(held.pc.TypeMap(), sd, plan.f.stmts[i].vars); err != nil {
			return fmt.Errorf("audit pipeline: encoding %q: %w", sd.SQL, err)
		}
		values := make([][]byte, len(held.eqb.ParamValues))
		for j, v := range held.eqb.ParamValues {
			if v != nil {
				values[j] = append([]byte(nil), v...)
			}
		}
		binds[i] = bound{values, append([]int16(nil), held.eqb.ParamFormats...), append([]int16(nil), held.eqb.ResultFormats...)}
	}
	for i, sd := range sds {
		run.pl.SendQueryStatement(sd, binds[i].values, binds[i].formats, binds[i].results)
	}
	run.pl.SendPipelineSync()
	res := &auditPipelineResults{pl: run.pl, tm: held.pc.TypeMap(), left: len(sds), stmts: plan.f.stmts, conn: held.pc}
	// A connection's batch tracer sees these statements as it sees a
	// SendBatch's: one start, one event per statement as its result is read,
	// one end.
	if bt, ok := held.pc.Config().Tracer.(pgx.BatchTracer); ok {
		res.tracer = bt
		res.tctx = bt.TraceBatchStart(ctx, held.pc, pgx.TraceBatchStartData{Batch: &plan.f.batch})
	}
	plan.f.attach(res)
	return run.pl.Flush()
}

// completeOldest reads the oldest batch in flight and resolves it. On an error
// it first reads every later batch and ends the run (see the file comment).
func (p *auditBatchPipeline) completeOldest() {
	b := p.inflight[0]
	p.inflight = p.inflight[1:]
	o := p.read(b)
	if o.err == nil {
		p.resolve(o)
		return
	}
	outcomes := []auditPipelineOutcome{o}
	for _, later := range p.inflight {
		lo := p.read(later)
		if backendEnded(o.err) && lo.err != nil && !isPgError(lo.err) {
			// The backend ended (FATAL) while running b, so it never ran
			// what was queued behind it; the connection error that ended
			// this batch's read says nothing more.
			lo.err, lo.beforeCommit = fmt.Errorf("%w: the backend ended before running it: %w", errAuditNothingSent, lo.err), true
		}
		outcomes = append(outcomes, lo)
	}
	p.inflight = nil
	p.closeRun()
	for _, o := range outcomes {
		p.resolve(o)
	}
}

// backendEnded reports whether err is a FATAL error from the server: the
// backend sends it and exits, so nothing queued after it on that connection
// ran.
func backendEnded(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Severity == "FATAL" || pgErr.Severity == "PANIC")
}

func isPgError(err error) bool {
	_, ok := errors.AsType[*pgconn.PgError](err)
	return ok
}

func (p *auditBatchPipeline) read(b *auditInflightBatch) auditPipelineOutcome {
	last, beforeCommit, err := b.plan.read()
	b.stop()
	return auditPipelineOutcome{b: b, last: last, beforeCommit: beforeCommit, err: err}
}

func (p *auditBatchPipeline) resolve(o auditPipelineOutcome) {
	deliverAuditBatch(o.b.batch, p.ls.completePipelinedBatch(o.b.batch[0].ctx, o.b, o.last, o.beforeCommit, o.err))
}

// completePipelinedBatch turns b's outcome into its items' results, as
// commitBatchAttemptPipelined and commitAuditBatch would for a serial
// one-flight attempt. It runs only after the run that sent b has ended or b
// committed, so a retry never waits on a KEYAUDIT the run still holds.
func (ls *LocalStorage) completePipelinedBatch(ctx context.Context, b *auditInflightBatch, last auditChainHead, beforeCommit bool, err error) []error {
	switch {
	case err == nil:
		ls.auditHead.committedOneFlight(b.epoch, last)
		return ls.finishAuditBatch(b.batch, nil)
	case auditOneFlightRolledBack(err, beforeCommit):
		// Nothing was written: a statement failed, the head moved, or the
		// batch before this one failed and left the connection's transaction
		// aborted. Retry once in two flights, then bisect, as a serial
		// one-flight miss does.
		ls.auditHead.missedOneFlight()
		return ls.finishAuditBatch(b.batch, ls.commitBatchTwoFlights(ctx, b.batch))
	default:
		// May have committed (a lost connection, an error on COMMIT): fail
		// closed, as a serial attempt does.
		ls.auditHead.failed()
		return ls.finishAuditBatch(b.batch, err)
	}
}

// auditPipelineResults reads one transaction's results off a run's pipeline,
// in order, as a pgx.BatchResults, so auditOneFlightPlan.read reads them as it
// reads a batch's. Once a statement failed, Postgres skips the rest of the
// transaction up to its Sync; so do the remaining calls, with that error.
type auditPipelineResults struct {
	pl     *pgconn.Pipeline
	tm     *pgtype.Map
	left   int // statements not read yet
	err    error
	closed bool

	stmts  []auditFlightStmt
	read   int // statements whose result was read
	conn   *pgx.Conn
	tracer pgx.BatchTracer // nil when the connection has none
	tctx   context.Context
}

// traced reports one statement's result to the batch tracer, if any.
func (r *auditPipelineResults) traced(tag pgconn.CommandTag, err error) {
	i := r.read
	r.read++
	if r.tracer == nil || i >= len(r.stmts) {
		return
	}
	r.tracer.TraceBatchQuery(r.tctx, r.conn, pgx.TraceBatchQueryData{SQL: r.stmts[i].sql, Args: r.stmts[i].vars, CommandTag: tag, Err: err})
}

func (r *auditPipelineResults) next() (*pgconn.ResultReader, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.left == 0 {
		r.err = errors.New("audit pipeline: read past the transaction's statements")
		return nil, r.err
	}
	r.left--
	res, err := r.pl.GetResults()
	if err != nil {
		r.err = err
		r.traced(pgconn.CommandTag{}, err)
		return nil, err
	}
	rr, ok := res.(*pgconn.ResultReader)
	if !ok {
		r.err = fmt.Errorf("audit pipeline: got %T where a statement result was due", res)
		return nil, r.err
	}
	return rr, nil
}

func (r *auditPipelineResults) Exec() (pgconn.CommandTag, error) {
	rr, err := r.next()
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	tag, err := rr.Close()
	if err != nil {
		r.err = err
	}
	r.traced(tag, err)
	return tag, err
}

func (r *auditPipelineResults) Query() (pgx.Rows, error) {
	rr, err := r.next()
	if err != nil {
		return nil, err
	}
	return &auditPipelineRows{Rows: pgx.RowsFromResultReader(r.tm, rr), r: r}, nil
}

func (r *auditPipelineResults) QueryRow() pgx.Row {
	rows, err := r.Query()
	return auditPipelineRow{rows: rows, err: err}
}

// Close reads what is left of the transaction, up to and including its Sync.
func (r *auditPipelineResults) Close() error {
	if r.closed {
		return r.err
	}
	r.closed = true
	if r.tracer != nil {
		defer func() { r.tracer.TraceBatchEnd(r.tctx, r.conn, pgx.TraceBatchEndData{Err: r.err}) }()
	}
	for {
		res, err := r.pl.GetResults()
		if err != nil {
			if r.err == nil {
				r.err = err
			}
			if isPgError(err) {
				continue // Postgres skips to the Sync; the next result is it
			}
			return r.err
		}
		switch res := res.(type) {
		case *pgconn.PipelineSync:
			return r.err
		case *pgconn.ResultReader:
			if _, err := res.Close(); err != nil && r.err == nil {
				r.err = err
			}
		case nil:
			if r.err == nil {
				r.err = errors.New("audit pipeline: no Sync after the transaction")
			}
			return r.err
		}
	}
}

// auditPipelineRows records a row-reading error on its transaction, so the
// rest of the transaction is skipped with it.
type auditPipelineRows struct {
	pgx.Rows
	r    *auditPipelineResults
	done bool
}

func (rows *auditPipelineRows) Close() {
	if rows.done {
		return
	}
	rows.done = true
	rows.Rows.Close()
	err := rows.Rows.Err()
	if err != nil && rows.r.err == nil {
		rows.r.err = err
	}
	rows.r.traced(rows.Rows.CommandTag(), err)
}

type auditPipelineRow struct {
	rows pgx.Rows
	err  error
}

func (row auditPipelineRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	defer row.rows.Close()
	if !row.rows.Next() {
		if err := row.rows.Err(); err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if err := row.rows.Scan(dest...); err != nil {
		return err
	}
	row.rows.Close()
	return row.rows.Err()
}
