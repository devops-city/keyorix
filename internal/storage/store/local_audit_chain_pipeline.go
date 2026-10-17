// local_audit_chain_pipeline.go — PERF-FIX-1: the Postgres audit group commit
// in two network flights instead of one round trip per statement.
//
// The GORM transaction (commitBatchAttemptTx) waits for each of BEGIN, the
// KEYAUDIT advisory lock, the chain-head read, the events INSERT, the
// access-log INSERT and COMMIT before sending the next. Only one of those waits
// is needed: the hashes depend on the head, so the head has to come back
// before the INSERTs can be built. Everything else is pipelined on the pgx
// connection underneath the pool:
//
//	flight 1: BEGIN; [SET LOCAL synchronous_commit = off;]
//	          SELECT pg_advisory_xact_lock(KEYAUDIT);
//	          SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1;
//	          SELECT nextval(<audit_events id sequence>) FROM generate_series(1, n)
//	flight 2: INSERT audit_events ... with the head and link checks (one
//	          statement, auditInsertCheckSQL); INSERT secret_access_logs ...; COMMIT
//
// The statements and their order inside the transaction are what the GORM
// path runs, and the INSERTs are GORM's own SQL (built in DryRun mode, hooks
// included). Postgres runs pipelined statements one after another, each with
// its own snapshot, so the head is still read after the lock is granted, and
// the lock is held until COMMIT as before.
//
// The one thing pipelining changes is that COMMIT is already on the wire when
// the INSERT results come back, so nothing may be checked between the INSERTs
// and COMMIT. The GORM path checks there that the ids came back in VALUES
// order (checkAuditInsertIDOrder). Here the event ids are allocated from the
// table's own sequence in flight 1, under the lock, and assigned in chain order
// before flight 2 is built, so that check (and a check that the first id sorts
// after the head) runs on the final ids before anything is written. An error
// in either flight makes Postgres skip the rest of it, COMMIT included, and the
// attempt fails closed exactly like a failed GORM transaction. What the INSERT
// actually stored is checked inside the transaction too: the events INSERT
// in flight 2 is one statement with the head and link checks
// (auditInsertCheckSQL), which raise unless the stored rows chain onto the
// head flight 1 read, in id order.
//
// When the flusher already knows the head, the whole transaction goes in one
// flight instead (local_audit_chain_one_flight.go).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// auditAllocateIDsSQL allocates $2 ids from table $1's id sequence. The
// sequence is looked up once per statement: OFFSET 0 keeps Postgres from
// pulling the subquery up into the outer query, where pg_get_serial_sequence
// (a pg_depend scan) would run once per allocated id.
const auditAllocateIDsSQL = "SELECT nextval(q.seq) FROM (SELECT pg_get_serial_sequence($1, 'id')::regclass AS seq OFFSET 0) q, generate_series(1, $2::int)"

// errAuditPipelineUnavailable means the pool is not a database/sql pool over
// pgx, so commitBatchAttempt uses the GORM transaction instead. Every
// production Postgres pool is one (storage.openPostgresGorm, and
// gorm.io/driver/postgres's own Open); TestCommitBatchAttempt_PostgresFlightCount
// fails if the pipelined path is not the one that runs.
var errAuditPipelineUnavailable = errors.New("audit pipeline: the connection pool is not a pgx pool")

// auditPipelineCleanupTimeout bounds the ROLLBACK that returns a connection to
// idle after a failed attempt. It runs on a fresh context because the
// attempt's own may be what expired.
const auditPipelineCleanupTimeout = 5 * time.Second

// commitBatchAttemptPipelined is commitBatchAttempt on Postgres: the same
// transaction as commitBatchAttemptTx, sent in two flights (see the file
// comment), or in one when the flusher's chain-head cache is armed
// (local_audit_chain_one_flight.go). A one-flight attempt that provably wrote
// nothing (errAuditOneFlightRolledBack: the head moved, or any other error
// Postgres reported before COMMIT) disarms the cache and is repeated once in
// two flights, which re-read the head under the lock; whatever that attempt
// returns is the result. Every other failure is returned as is.
func (ls *LocalStorage) commitBatchAttemptPipelined(ctx context.Context, batch []*auditBatchItem) error {
	epoch, head, armed := ls.auditHead.begin()
	if armed {
		err := ls.withAuditPipelineConn(ctx, func(pc *pgx.Conn) error {
			last, err := ls.runAuditOneFlight(ctx, pc, batch, head)
			if err == nil {
				ls.auditHead.committedOneFlight(epoch, last)
			}
			return err
		})
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, errAuditOneFlightRolledBack):
			ls.auditHead.failed()
			return err
		}
		ls.auditHead.missedOneFlight()
		epoch, _, _ = ls.auditHead.begin()
	}
	return ls.withAuditPipelineConn(ctx, func(pc *pgx.Conn) error {
		read, last, err := ls.runAuditPipeline(ctx, pc, batch)
		if err != nil {
			ls.auditHead.failed()
			return err
		}
		ls.auditHead.committedTwoFlights(epoch, read, last)
		return nil
	})
}

// withAuditPipelineConn runs fn on a pgx connection of its own from the pool.
// The connection goes back to the pool idle, or closed (and so discarded by
// database/sql) when it cannot be brought back to idle; it never goes back
// inside a transaction.
func (ls *LocalStorage) withAuditPipelineConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	sqlDB, ok := ls.db.Statement.ConnPool.(*sql.DB)
	if !ok {
		return errAuditPipelineUnavailable
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return conn.Raw(func(driverConn any) error {
		sc, ok := driverConn.(*stdlib.Conn)
		if !ok {
			return errAuditPipelineUnavailable
		}
		pc := sc.Conn()
		defer leaveAuditConnIdle(pc)
		return fn(pc)
	})
}

// leaveAuditConnIdle rolls back whatever a failed attempt left open, and
// closes the connection if that does not leave it idle.
func leaveAuditConnIdle(pc *pgx.Conn) {
	if pc.IsClosed() || pc.PgConn().TxStatus() == 'I' {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditPipelineCleanupTimeout)
	defer cancel()
	if _, err := pc.Exec(ctx, "ROLLBACK"); err == nil && pc.PgConn().TxStatus() == 'I' {
		return
	}
	_ = pc.Close(ctx)
}

// auditDryRun builds statements with GORM without running them. DryRun still
// runs the create hooks (BeforeSave) and fills defaults, as a real Create does;
// SkipDefaultTransaction keeps it from opening a transaction on the pool.
func (ls *LocalStorage) auditDryRun(ctx context.Context) *gorm.DB {
	return ls.db.Session(&gorm.Session{DryRun: true, SkipDefaultTransaction: true, NewDB: true, Context: ctx})
}

// auditPipelineInsert is one INSERT queued in flight 2 and the rows whose ids
// its RETURNING carries, in VALUES order.
type auditPipelineInsert struct {
	ids []*uint
	// assigned is true for audit_events, whose ids were set before the INSERT:
	// the returned ids must then equal them.
	assigned bool
}

// queueAuditInsert builds GORM's INSERT for rows and queues it on f. It fails
// before anything is sent unless the statement returns exactly the primary key,
// which is all flight 2 maps back, and unless the model has no after-create
// hooks (DryRun would run them before the row exists).
func queueAuditInsert[T any](f *auditFlight, rows []*T, ids []*uint, assigned bool) (auditPipelineInsert, error) {
	st := f.ls.auditDryRun(f.ctx).Create(&rows)
	if st.Error != nil {
		return auditPipelineInsert{}, st.Error
	}
	stmt := st.Statement
	if s := stmt.Schema; s == nil || s.AfterCreate || s.AfterSave || s.PrioritizedPrimaryField == nil {
		return auditPipelineInsert{}, fmt.Errorf("audit pipeline: %T has no single primary key or has after-create hooks", rows[0])
	}
	ret, ok := stmt.Clauses["RETURNING"].Expression.(clause.Returning)
	if !ok || len(ret.Columns) != 1 || ret.Columns[0].Name != stmt.Schema.PrioritizedPrimaryField.DBName {
		return auditPipelineInsert{}, fmt.Errorf("audit pipeline: INSERT into %s must return only its primary key, got %q", stmt.Schema.Table, stmt.SQL.String())
	}
	f.queue(stmt.SQL.String(), stmt.Vars...)
	return auditPipelineInsert{ids: ids, assigned: assigned}, nil
}

// readAuditInsert reads one queued INSERT's RETURNING ids back onto its rows.
func readAuditInsert(f *auditFlight, ins auditPipelineInsert) error {
	n, err := scanAuditInsertIDs(f.br, ins)
	return f.done(int64(n), err)
}

func scanAuditInsertIDs(br pgx.BatchResults, ins auditPipelineInsert) (int, error) {
	rows, err := br.Query()
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id uint
		if err := rows.Scan(&id); err != nil {
			return n, err
		}
		if n >= len(ins.ids) {
			return n, fmt.Errorf("audit pipeline: INSERT returned more than %d rows", len(ins.ids))
		}
		if ins.assigned {
			if *ins.ids[n] != id {
				return n, fmt.Errorf("audit pipeline: row %d was assigned id %d but stored as %d", n, *ins.ids[n], id)
			}
		} else {
			*ins.ids[n] = id
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	if n != len(ins.ids) {
		return n, fmt.Errorf("audit pipeline: INSERT returned %d rows, want %d", n, len(ins.ids))
	}
	return n, nil
}

// auditFlight is one pipelined batch of statements. It remembers each
// statement so it can be traced through GORM's logger once its result is in:
// the pipelined statements show up wherever the GORM path's statements did.
type auditFlight struct {
	ls    *LocalStorage
	ctx   context.Context
	batch pgx.Batch
	stmts []auditFlightStmt
	begin time.Time
	br    pgx.BatchResults
	next  int
}

type auditFlightStmt struct {
	sql  string
	vars []any
}

func (f *auditFlight) queue(sql string, vars ...any) {
	f.batch.Queue(sql, vars...)
	f.stmts = append(f.stmts, auditFlightStmt{sql: sql, vars: vars})
}

func (f *auditFlight) send(pc *pgx.Conn) {
	f.begin = time.Now()
	f.br = pc.SendBatch(f.ctx, &f.batch)
}

// done traces the next statement's outcome and passes err through.
func (f *auditFlight) done(rows int64, err error) error {
	st := f.stmts[f.next]
	f.next++
	db := f.ls.db
	db.Logger.Trace(f.ctx, f.begin, func() (string, int64) { return db.Dialector.Explain(st.sql, st.vars...), rows }, err)
	return err
}

func (f *auditFlight) exec() error {
	tag, err := f.br.Exec()
	return f.done(tag.RowsAffected(), err)
}

// close closes the batch results, keeping the first error.
func (f *auditFlight) close(err error) error {
	if cerr := f.br.Close(); err == nil {
		err = cerr
	}
	return err
}

// runAuditPipeline commits batch in two flights. It returns the head its
// first flight read and the batch's last row.
func (ls *LocalStorage) runAuditPipeline(ctx context.Context, pc *pgx.Conn, batch []*auditBatchItem) (read, last auditChainHead, err error) {
	// The head read's LIMIT is written into the text rather than bound (GORM's
	// Limit(1) binds it): Postgres cannot know a bound LIMIT is 1 when it
	// costs the cached statement's generic plan, so it re-plans the statement
	// on every flight instead of reusing that plan.
	headStmt := ls.auditDryRun(ctx).Model(&models.AuditEvent{}).
		Select("id", "entry_hash").
		Order("id DESC").
		Find(&[]models.AuditEvent{})
	if headStmt.Error != nil {
		return read, last, headStmt.Error
	}
	table := headStmt.Statement.Schema.Table

	// Flight 1: open the transaction, take the lock, read the head, allocate
	// the batch's event ids.
	open := &auditFlight{ls: ls, ctx: ctx}
	open.queue("BEGIN")
	if durability := auditCommitDurabilityStatement(ls.auditSkipDurableSync); durability != "" {
		open.queue(durability)
	}
	open.queue("SELECT pg_advisory_xact_lock($1)", int64(auditAdvisoryLockKey))
	open.queue(headStmt.Statement.SQL.String()+" LIMIT 1", headStmt.Statement.Vars...)
	open.queue(auditAllocateIDsSQL, table, len(batch))

	var (
		headID   uint
		headHash string
		ids      []uint
	)
	open.send(pc)
	err = func() error {
		for range len(open.stmts) - 2 {
			if err := open.exec(); err != nil {
				return err
			}
		}
		var hid *uint
		var hhash *string
		err := open.br.QueryRow().Scan(&hid, &hhash)
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		if err := open.done(1, err); err != nil {
			return err
		}
		if hid != nil {
			headID = *hid
		}
		if hhash != nil {
			headHash = *hhash
		}
		rows, err := open.br.Query()
		if err == nil {
			ids, err = pgx.CollectRows(rows, pgx.RowTo[uint])
		}
		return open.done(int64(len(ids)), err)
	}()
	if err := open.close(err); err != nil {
		return read, last, err
	}
	read = auditChainHead{id: headID, hash: headHash}

	events, accessLogs := chainAuditBatch(batch, headHash)
	if len(ids) != len(events) {
		return read, last, fmt.Errorf("audit pipeline: allocated %d ids for %d events", len(ids), len(events))
	}
	slices.Sort(ids)
	for i, e := range events {
		e.ID = ids[i]
	}
	if err := checkAuditInsertIDOrder(events); err != nil {
		return read, last, err
	}
	if events[0].ID <= headID {
		return read, last, fmt.Errorf("audit pipeline: first allocated id %d does not sort after the chain head %d", events[0].ID, headID)
	}

	// Flight 2: the INSERTs and COMMIT. Nothing below may be needed to decide
	// whether to commit: COMMIT runs unless a statement before it fails.
	commit := &auditFlight{ls: ls, ctx: ctx}
	// The ids were checked above, but only as assigned: what the INSERT stored
	// is known once its result is read, after COMMIT is on the wire. The checks
	// queued with it verify the stored rows inside the transaction instead.
	readEvents, err := queueAuditEvents(commit, table, events, read, true, false)
	if err != nil {
		return read, last, err
	}
	var logInserts []auditPipelineInsert
	if err := forEachAuditInsertChunk(accessLogs, func(chunk []*models.SecretAccessLog) error {
		ids := make([]*uint, len(chunk))
		for i, l := range chunk {
			ids[i] = &l.ID
		}
		ins, err := queueAuditInsert(commit, chunk, ids, false)
		logInserts = append(logInserts, ins)
		return err
	}); err != nil {
		return read, last, err
	}
	commit.queue("COMMIT")

	commit.send(pc)
	err = func() error {
		if err := readEvents(); err != nil {
			return err
		}
		for _, ins := range logInserts {
			if err := readAuditInsert(commit, ins); err != nil {
				return err
			}
		}
		tag, err := commit.br.Exec()
		if err == nil && tag.String() != "COMMIT" {
			err = fmt.Errorf("audit pipeline: COMMIT answered %q", tag.String())
		}
		return commit.done(0, err)
	}()
	if err := commit.close(err); err != nil {
		return read, last, err
	}
	tail := events[len(events)-1]
	return read, auditChainHead{id: tail.ID, hash: tail.EntryHash}, nil
}

// forEachAuditInsertChunk calls fn on rows in the same
// auditInsertRowsPerStatement-sized chunks createAuditRowsMultiRow uses.
func forEachAuditInsertChunk[T any](rows []*T, fn func([]*T) error) error {
	if len(rows) == 0 {
		return nil
	}
	perStmt, err := auditInsertRowsPerStatement(rows[0])
	if err != nil {
		return err
	}
	for start := 0; start < len(rows); start += perStmt {
		if err := fn(rows[start:min(start+perStmt, len(rows))]); err != nil {
			return err
		}
	}
	return nil
}
