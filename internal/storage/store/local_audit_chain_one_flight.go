// local_audit_chain_one_flight.go — AUDIT-1FLIGHT-1: the Postgres audit group
// commit in ONE network flight when the flusher already knows the chain head.
//
// The two-flight commit (local_audit_chain_pipeline.go) waits once, for the
// head row, because every hash in the batch depends on it. The flusher wrote
// that row itself in the previous batch unless something else appended or
// rewrote the chain since, so it keeps the last row it committed (id,
// entry_hash) in auditChainHeadCache and, while the cache is armed, chains the
// next batch onto it client-side and sends everything at once:
//
//	BEGIN; [SET LOCAL synchronous_commit = off;]
//	SELECT pg_advisory_xact_lock(KEYAUDIT);
//	WITH e AS (INSERT audit_events ... RETURNING ...) -- ids from the column default
//	  head check: raises unless the id-DESC head is exactly the cached row;
//	  link check: raises unless the stored rows are exactly this batch, above
//	              the cached head, linked prev_hash -> entry_hash in id order;
//	INSERT secret_access_logs ...; COMMIT
//
// The INSERT and both checks are one statement (auditInsertCheckSQL,
// OPT-AUDIT-RT-1); before that they were three, and a batch too large for one
// INSERT still sends them so (queueAuditEvents).
//
// The cache is a hint, never a source of truth. Both checks run inside the
// transaction, after the lock statement, so they see exactly what the
// two-flight path's head read would see; when either fails, Postgres skips
// every later statement, COMMIT included, and nothing is written. The flusher
// then drops the cache and repeats the attempt through the two-flight path,
// which re-reads the head under the lock (commitBatchAttempt). So any writer
// that moves the head without going through this flusher (another replica,
// a transaction-scoped store's direct append, a retention purge that empties
// the table, the encoding migration, an offline restore, hand-written SQL)
// costs one wasted flight, never a forked chain. The in-process ones also
// invalidate the cache so that flight is not spent (invalidateAuditChainHead).
//
// The link check replaces what the two-flight path does in Go between its
// flights: there the event ids are allocated under the lock and checked
// before the INSERT (checkAuditInsertIDOrder, first id above the head). Here
// the INSERT takes its ids from the column default, so the same two facts
// (each row's id above the previous row's, the first above the head) are
// checked in SQL, on the rows the INSERT stored, before COMMIT. Every
// entry_hash in the batch is distinct, so the rows link in id order only if
// their ids follow the batch order.
//
// The two checks raise by casting a message to int (SQLSTATE 22P02): there is
// no built-in RAISE outside PL/pgSQL, and creating a function would be a
// schema change. The cast operand depends on a column of the row being
// checked, so the planner cannot fold it to a constant and raise while
// planning a statement whose check would pass.
package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm/clause"
)

// auditChainHead is one audit_events row's place in the chain.
type auditChainHead struct {
	id   uint
	hash string
}

// auditChainHeadCache is the chain head the root LocalStorage's flusher last
// committed, and whether its next batch may go in one flight. Transaction-
// scoped clones share the root's pointer only so their own audit appends can
// invalidate it; they never read it (their appends run logAuditEventDirect).
// Every method is safe on a nil receiver, which never arms.
//
// Arming. The one-flight attempt pays off only when nothing else wrote since
// the flusher's previous batch, and a miss costs a wasted flight on top of the
// two-flight retry. So a batch goes in one flight only after evidence that
// this flusher is the only writer: `need` consecutive two-flight batches whose
// head read found exactly the row this flusher committed last arm the cache, a
// one-flight commit keeps it armed, and a miss disarms it. Each miss doubles
// need (up to auditOneFlightMaxQuiet) and a one-flight commit resets it to one,
// so replicas that keep appending in turn settle on two flights per batch, as
// before this cache existed, and spend at most one wasted flight per
// auditOneFlightMaxQuiet batches. Right after boot, or after an attempt failed
// in a way that leaves the last committed row unknown, there is nothing to
// compare with, and a successful two-flight batch counts as quiet.
//
// The epoch makes invalidation stick: an attempt that started before an
// invalidation cannot re-arm the cache when it commits after it.
type auditChainHeadCache struct {
	mu    sync.Mutex
	head  auditChainHead
	known bool // head is the last row this LocalStorage's flusher committed
	armed bool
	quiet int // consecutive two-flight batches that found head
	need  int // quiet batches that arm the cache; 0 means 1
	epoch uint64

	// oneFlightCommits and oneFlightMisses count one-flight attempts that
	// committed and that failed (and were retried in two flights).
	oneFlightCommits atomic.Int64
	oneFlightMisses  atomic.Int64
}

// auditOneFlightMaxQuiet caps how many quiet two-flight batches re-arm the
// cache after repeated misses.
const auditOneFlightMaxQuiet = 64

func newAuditChainHeadCache() *auditChainHeadCache { return &auditChainHeadCache{} }

// begin returns the epoch an attempt starts under and, when the cache is
// armed, the head to chain the batch onto in one flight.
func (c *auditChainHeadCache) begin() (epoch uint64, head auditChainHead, armed bool) {
	if c == nil {
		return 0, auditChainHead{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch, c.head, c.armed && c.known
}

// committedTwoFlights records a two-flight commit whose head read returned
// read and whose last row is last.
func (c *auditChainHeadCache) committedTwoFlights(epoch uint64, read, last auditChainHead) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epoch == epoch && (!c.known || read == c.head) {
		c.quiet++
	} else {
		c.quiet = 0
	}
	c.armed = c.quiet >= max(c.need, 1)
	c.head, c.known = last, true
}

// committedOneFlight records a one-flight commit whose last row is last.
func (c *auditChainHeadCache) committedOneFlight(epoch uint64, last auditChainHead) {
	if c == nil {
		return
	}
	c.oneFlightCommits.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.need = 1
	if c.epoch != epoch {
		c.armed, c.quiet = false, 0
	}
	c.head, c.known = last, true
}

// missedOneFlight records a failed one-flight attempt. The head stays known:
// the two-flight retry compares its head read with it, which keeps the cache
// disarmed while another writer is active.
func (c *auditChainHeadCache) missedOneFlight() {
	if c == nil {
		return
	}
	c.oneFlightMisses.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed, c.quiet = false, 0
	c.need = min(max(c.need, 1)*2, auditOneFlightMaxQuiet)
	c.epoch++
}

// failed records a failed two-flight attempt: whether it committed is not
// known (a lost COMMIT acknowledgement), so neither is the last row.
func (c *auditChainHeadCache) failed() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed, c.known, c.quiet = false, false, 0
	c.epoch++
}

// invalidate disarms the cache; see invalidateAuditChainHead.
func (c *auditChainHeadCache) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed, c.quiet = false, 0
	c.epoch++
}

// invalidateAuditChainHead is called by every in-process path that appends to,
// deletes from or rewrites audit_events outside the flusher, so the flusher's
// next batch re-reads the head instead of spending a flight on a check that
// would fail. Correctness never depends on it: the one-flight attempt checks
// the head inside its transaction either way.
func (ls *LocalStorage) invalidateAuditChainHead() {
	ls.auditHead.invalidate()
}

// auditHeadCheckSQL selects 0 when the id-DESC head of %[1]s is the row ($1,
// $2), and raises otherwise, an empty table included.
const auditHeadCheckSQL = `SELECT CASE WHEN h.id = $1::bigint AND h.entry_hash = $2::text THEN 0
 ELSE ('audit chain head moved: the head is row ' || COALESCE(h.id::text, 'none') || ', not the cached row ' || $1::bigint)::int END
 FROM (SELECT 1) AS one LEFT JOIN (SELECT id, entry_hash FROM %[1]s ORDER BY id DESC LIMIT 1) AS h ON true`

// auditLinkCheckSQL selects 0 when the top %[2]d rows of %[1]s by id are the
// row ($1, $2) followed by rows each linking prev_hash to the previous row's
// entry_hash in id order, and raises otherwise. A row after one with an empty
// entry_hash (an unchained pre-ADR-029 row) links to the genesis hash $3, as
// chainAuditBatch chains it. %[2]d is the batch size plus one, written into
// the text like the INSERTs' VALUES lists are: the inner query then has no
// parameter, so its cached generic plan (a backward primary key scan of %[2]d
// rows) is the one Postgres keeps.
const auditLinkCheckSQL = `SELECT CASE WHEN s.n = %[2]d AND s.unlinked = 0 AND s.base_id = $1::bigint AND s.base_hash = $2::text THEN 0
 ELSE ('audit batch rows not linked in id order above row ' || $1::bigint || ': ' || s.n || ' rows read, ' || s.unlinked || ' unlinked, lowest is row ' || COALESCE(s.base_id::text, 'none'))::int END
 FROM (SELECT count(*) AS n, count(*) FILTER (WHERE w.rn > 1 AND w.prev_hash IS DISTINCT FROM COALESCE(NULLIF(w.lp, ''), $3::text)) AS unlinked,
  min(w.id) AS base_id, (array_agg(w.entry_hash ORDER BY w.id))[1] AS base_hash
  FROM (SELECT id, prev_hash, entry_hash, lag(entry_hash) OVER (ORDER BY id) AS lp, row_number() OVER (ORDER BY id) AS rn
   FROM (SELECT id, prev_hash, entry_hash FROM %[1]s ORDER BY id DESC LIMIT %[2]d) AS t) AS w) AS s`

// auditLinkCheckGenesisSQL is auditLinkCheckSQL for a batch that starts the
// chain: the table holds exactly %[2]d rows (it reads up to %[3]d), linked in
// id order, the first one to the genesis hash $1.
const auditLinkCheckGenesisSQL = `SELECT CASE WHEN s.n = %[2]d AND s.unlinked = 0 THEN 0
 ELSE ('audit batch rows not linked in id order from genesis: ' || s.n || ' rows read, ' || s.unlinked || ' unlinked')::int END
 FROM (SELECT count(*) AS n, count(*) FILTER (WHERE w.prev_hash IS DISTINCT FROM COALESCE(w.lp, $1::text)) AS unlinked
  FROM (SELECT prev_hash, lag(entry_hash) OVER (ORDER BY id) AS lp
   FROM (SELECT id, prev_hash, entry_hash FROM %[1]s ORDER BY id DESC LIMIT %[3]d) AS t) AS w) AS s`

// auditLinkCheckStatement is the link check, with its arguments, for n events
// chained onto the head row (headID, headHash); headID 0 means the batch
// starts the chain at genesis. Row ids are passed as uint: pgx encodes them
// into the bigint parameter and refuses one that does not fit.
func auditLinkCheckStatement(table string, headID uint, headHash string, n int) (string, []any) {
	quoted := pgx.Identifier{table}.Sanitize()
	if headID == 0 {
		return fmt.Sprintf(auditLinkCheckGenesisSQL, quoted, n, n+1), []any{auditGenesisHash}
	}
	return fmt.Sprintf(auditLinkCheckSQL, quoted, n+1), []any{headID, headHash, auditGenesisHash}
}

// auditInsertCheckSQL is the events INSERT %[1]s and both checks in ONE
// statement (OPT-AUDIT-RT-1). %[1]s returns each stored row's id, prev_hash
// and entry_hash; h is the id-DESC head of %[2]s. Every part of a statement
// reads the same snapshot, and the rows a WITH INSERT writes are not in it, so
// h is exactly the row the separate head check would read after the lock
// statement, and e is exactly what the separate link check would read above
// it. The checks are auditLinkCheckSQL's, run over h followed by e instead of
// the top %[3]d rows of the table: the statement selects 0 when there are %[3]d
// rows (so h exists), the lowest is the row ($%[4]d, $%[5]d) (so h is that row
// and every stored id sorts above it), and each later row links prev_hash to
// the previous row's entry_hash in id order (genesis $%[6]d after an unchained
// row), and raises otherwise. It also returns the stored ids in ascending
// order. $%[4]d.. follow the INSERT's own parameters.
const auditInsertCheckSQL = `WITH e AS (%[1]s), h AS (SELECT id, prev_hash, entry_hash FROM %[2]s ORDER BY id DESC LIMIT 1)
 SELECT CASE WHEN s.n = %[3]d AND s.unlinked = 0 AND s.base_id = $%[4]d::bigint AND s.base_hash = $%[5]d::text THEN 0
 ELSE ('audit batch not chained onto row ' || $%[4]d::bigint || ' in id order: ' || s.n || ' rows read, ' || s.unlinked || ' unlinked, lowest is row ' || COALESCE(s.base_id::text, 'none'))::int END, s.ids
 FROM (SELECT count(*) AS n, count(*) FILTER (WHERE w.rn > 1 AND w.prev_hash IS DISTINCT FROM COALESCE(NULLIF(w.lp, ''), $%[6]d::text)) AS unlinked,
  min(w.id) AS base_id, (array_agg(w.entry_hash ORDER BY w.id))[1] AS base_hash, array_agg(w.id ORDER BY w.id) FILTER (WHERE w.rn > 1) AS ids
  FROM (SELECT id, prev_hash, entry_hash, lag(entry_hash) OVER (ORDER BY id) AS lp, row_number() OVER (ORDER BY id) AS rn
   FROM (SELECT id, prev_hash, entry_hash FROM h UNION ALL SELECT id, prev_hash, entry_hash FROM e) AS t) AS w) AS s`

// auditInsertCheckGenesisSQL is auditInsertCheckSQL for a batch that starts
// the chain: h must not exist (%[3]d rows, the batch alone), and the rows link
// in id order, the first one to the genesis hash $%[4]d.
const auditInsertCheckGenesisSQL = `WITH e AS (%[1]s), h AS (SELECT id, prev_hash, entry_hash FROM %[2]s ORDER BY id DESC LIMIT 1)
 SELECT CASE WHEN s.n = %[3]d AND s.unlinked = 0 THEN 0
 ELSE ('audit batch not chained from genesis in id order: ' || s.n || ' rows read, ' || s.unlinked || ' unlinked')::int END, s.ids
 FROM (SELECT count(*) AS n, count(*) FILTER (WHERE w.prev_hash IS DISTINCT FROM COALESCE(w.lp, $%[4]d::text)) AS unlinked, array_agg(w.id ORDER BY w.id) AS ids
  FROM (SELECT id, prev_hash, lag(entry_hash) OVER (ORDER BY id) AS lp
   FROM (SELECT id, prev_hash, entry_hash FROM h UNION ALL SELECT id, prev_hash, entry_hash FROM e) AS t) AS w) AS s`

// auditInsertCheckStatement wraps insertSQL (with its vars), the INSERT of n
// events chained onto base, in auditInsertCheckSQL; base.id 0 means the batch
// starts the chain at genesis.
func auditInsertCheckStatement(table, insertSQL string, insertVars []any, base auditChainHead, n int) (string, []any) {
	quoted := pgx.Identifier{table}.Sanitize()
	next := len(insertVars) + 1
	vars := slices.Clip(insertVars)
	if base.id == 0 {
		return fmt.Sprintf(auditInsertCheckGenesisSQL, insertSQL, quoted, n, next), append(vars, auditGenesisHash)
	}
	return fmt.Sprintf(auditInsertCheckSQL, insertSQL, quoted, n+1, next, next+1, next+2), append(vars, base.id, base.hash, auditGenesisHash)
}

// auditInsertCheckReturning is what the INSERT inside auditInsertCheckSQL
// returns.
var auditInsertCheckReturning = clause.Returning{Columns: []clause.Column{{Name: "id"}, {Name: "prev_hash"}, {Name: "entry_hash"}}}

// queueAuditEvents queues on f the INSERT of events, chained onto base, and
// the checks that the stored rows chain onto base in id order, and returns
// the function that reads those results in order. A batch that fits one
// INSERT (every flusher batch on Postgres:
// TestAuditInsertRowsPerStatement_CoversAFullFlusherBatch) goes as the one
// statement auditInsertCheckSQL. A larger one goes as before: the head check
// (headCheck: the one-flight path, whose base is the cache's), the INSERTs
// and the link check over the table. assigned means the events carry ids
// allocated under the lock, which the stored ids must equal; otherwise the
// stored ids are put back on the events in batch order, which the checks
// proved is their id order.
func queueAuditEvents(f *auditFlight, table string, events []*models.AuditEvent, base auditChainHead, assigned, headCheck bool) (func() error, error) {
	perStmt, err := auditInsertRowsPerStatement(events[0])
	if err != nil {
		return nil, err
	}
	if len(events) <= perStmt {
		st := f.ls.auditDryRun(f.ctx).Clauses(auditInsertCheckReturning).Create(&events)
		if st.Error != nil {
			return nil, st.Error
		}
		stmt := st.Statement
		if s := stmt.Schema; s == nil || s.AfterCreate || s.AfterSave {
			return nil, fmt.Errorf("audit pipeline: %T has after-create hooks", events[0])
		}
		if ret, ok := stmt.Clauses["RETURNING"].Expression.(clause.Returning); !ok || !slices.Equal(ret.Columns, auditInsertCheckReturning.Columns) {
			return nil, fmt.Errorf("audit pipeline: INSERT into %s must return id, prev_hash, entry_hash, got %q", table, stmt.SQL.String())
		}
		checkSQL, checkArgs := auditInsertCheckStatement(table, stmt.SQL.String(), stmt.Vars, base, len(events))
		f.queue(checkSQL, checkArgs...)
		return func() error { return readAuditInsertCheck(f, events, assigned) }, nil
	}

	if headCheck {
		f.queue(fmt.Sprintf(auditHeadCheckSQL, pgx.Identifier{table}.Sanitize()), base.id, base.hash)
	}
	var inserts []auditPipelineInsert
	if err := forEachAuditInsertChunk(events, func(chunk []*models.AuditEvent) error {
		ids := make([]*uint, len(chunk))
		for i, e := range chunk {
			ids[i] = &e.ID
		}
		ins, err := queueAuditInsert(f, chunk, ids, assigned)
		inserts = append(inserts, ins)
		return err
	}); err != nil {
		return nil, err
	}
	linkSQL, linkArgs := auditLinkCheckStatement(table, base.id, base.hash, len(events))
	f.queue(linkSQL, linkArgs...)
	return func() error {
		if headCheck {
			if err := f.exec(); err != nil {
				return err
			}
		}
		for _, ins := range inserts {
			if err := readAuditInsert(f, ins); err != nil {
				return err
			}
		}
		if err := f.exec(); err != nil {
			return err
		}
		if !assigned {
			sortAuditEventIDs(events)
		}
		return nil
	}, nil
}

// readAuditInsertCheck reads auditInsertCheckSQL's row: the check passed (it
// raises otherwise) and the stored ids, ascending, which go onto events in
// batch order.
func readAuditInsertCheck(f *auditFlight, events []*models.AuditEvent, assigned bool) error {
	var passed int32
	var ids []uint
	err := f.br.QueryRow().Scan(&passed, &ids)
	if err == nil && len(ids) != len(events) {
		err = fmt.Errorf("audit pipeline: INSERT stored %d rows, want %d", len(ids), len(events))
	}
	for i := 0; err == nil && i < len(ids); i++ {
		switch id := ids[i]; {
		case id == 0:
			err = fmt.Errorf("audit pipeline: row %d was stored with id 0", i)
		case assigned && events[i].ID != id:
			err = fmt.Errorf("audit pipeline: row %d was assigned id %d but stored as %d", i, events[i].ID, id)
		default:
			events[i].ID = id
		}
	}
	return f.done(int64(len(ids)), err)
}

// sortAuditEventIDs puts the ids RETURNING listed back on events in ascending
// order, the order the link check proved they were stored in.
func sortAuditEventIDs(events []*models.AuditEvent) {
	ids := make([]uint, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	slices.Sort(ids)
	for i, e := range events {
		e.ID = ids[i]
	}
}

// errAuditOneFlightRolledBack wraps a one-flight failure that provably wrote
// nothing: the attempt failed before anything was sent, or Postgres reported
// an error for a statement queued before COMMIT, so it ran COMMIT as a
// ROLLBACK (a statement that is never executed reports no error of its own).
// Only such a failure is retried in two flights. Any other failure (a lost
// connection, an expired context, an error answered for COMMIT itself) may
// have committed, so it is returned as is, like a failed two-flight attempt.
var errAuditOneFlightRolledBack = errors.New("audit one-flight commit rolled back")

// runAuditOneFlight commits batch on pc, chained onto head, in one flight (see
// the file comment). It returns the batch's last row on success.
func (ls *LocalStorage) runAuditOneFlight(ctx context.Context, pc *pgx.Conn, batch []*auditBatchItem, head auditChainHead) (auditChainHead, error) {
	last, beforeCommit, err := ls.runAuditOneFlightStatements(ctx, pc, batch, head)
	if auditOneFlightRolledBack(err, beforeCommit) {
		return auditChainHead{}, fmt.Errorf("%w: %w", errAuditOneFlightRolledBack, err)
	}
	return last, err
}

// auditOneFlightRolledBack reports whether a one-flight failure err provably
// wrote nothing (see errAuditOneFlightRolledBack). beforeCommit is true when
// err belongs to a statement queued before COMMIT, or to no statement at all.
func auditOneFlightRolledBack(err error, beforeCommit bool) bool {
	var pgErr *pgconn.PgError
	return err != nil && beforeCommit && (errors.As(err, &pgErr) || errors.Is(err, errAuditNothingSent))
}

// errAuditNothingSent marks a one-flight failure raised before the flight was
// sent.
var errAuditNothingSent = errors.New("audit one-flight: nothing sent")

func (ls *LocalStorage) runAuditOneFlightStatements(ctx context.Context, pc *pgx.Conn, batch []*auditBatchItem, head auditChainHead) (last auditChainHead, beforeCommit bool, err error) {
	table, err := ls.auditEventsTable(ctx)
	if err != nil {
		return auditChainHead{}, true, fmt.Errorf("%w: %w", errAuditNothingSent, err)
	}
	events, accessLogs := chainAuditBatch(batch, head.hash)

	f := &auditFlight{ls: ls, ctx: ctx}
	f.queue("BEGIN")
	if durability := auditCommitDurabilityStatement(ls.auditSkipDurableSync); durability != "" {
		f.queue(durability)
	}
	f.queue("SELECT pg_advisory_xact_lock($1)", int64(auditAdvisoryLockKey))
	preamble := len(f.stmts)

	readEvents, err := queueAuditEvents(f, table, events, head, false, true)
	if err != nil {
		return auditChainHead{}, true, fmt.Errorf("%w: %w", errAuditNothingSent, err)
	}
	var logInserts []auditPipelineInsert
	if err := forEachAuditInsertChunk(accessLogs, func(chunk []*models.SecretAccessLog) error {
		ids := make([]*uint, len(chunk))
		for i, l := range chunk {
			ids[i] = &l.ID
		}
		ins, err := queueAuditInsert(f, chunk, ids, false)
		logInserts = append(logInserts, ins)
		return err
	}); err != nil {
		return auditChainHead{}, true, fmt.Errorf("%w: %w", errAuditNothingSent, err)
	}
	f.queue("COMMIT")

	f.send(pc)
	beforeCommit = true
	err = func() error {
		for range preamble {
			if err := f.exec(); err != nil {
				return err
			}
		}
		if err := readEvents(); err != nil {
			return err
		}
		for _, ins := range logInserts {
			if err := readAuditInsert(f, ins); err != nil {
				return err
			}
		}
		beforeCommit = false
		tag, err := f.br.Exec()
		if err == nil && tag.String() != "COMMIT" {
			err = fmt.Errorf("audit pipeline: COMMIT answered %q", tag.String())
		}
		return f.done(0, err)
	}()
	if err := f.close(err); err != nil {
		return auditChainHead{}, beforeCommit, err
	}
	tail := events[len(events)-1]
	return auditChainHead{id: tail.ID, hash: tail.EntryHash}, false, nil
}

// auditEventsTable is the audit_events table name as GORM resolves it.
func (ls *LocalStorage) auditEventsTable(ctx context.Context) (string, error) {
	st := ls.auditDryRun(ctx).Model(&models.AuditEvent{}).Find(&[]models.AuditEvent{})
	if st.Error != nil {
		return "", st.Error
	}
	return st.Statement.Schema.Table, nil
}
