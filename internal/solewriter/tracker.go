package solewriter

// tracker.go — the server's own writes to the security tables, seen
// synchronously (docs/specs/single-writer-cache.md §1.6).
//
// Authoritative caches (PR 3) may skip their confirming read only if every
// write this process makes to a fenced table invalidates them before the call
// that made it returns. Per-call-site eviction has missed sites before
// (INV-MW-08, #2518), so this does not rely on it. Instead a pgx QueryTracer,
// installed on every connection a single-writer server opens
// (config.ResolvePostgresConnConfig), watches every statement's SQL:
//
//   - a statement that can write and names a fenced table (classifyWrite)
//     marks its connection dirty and raises Inflight at once, before it runs;
//   - when the connection's transaction ends (COMMIT/ROLLBACK, or the
//     statement itself when it runs outside a transaction), Gen is bumped and
//     Inflight lowered.
//
// A cache entry is valid only if Inflight is 0 and the entry was filled at the
// current Gen; a fill that overlapped any such write is not stored
// (Tracker.BeginFill). So a revocation through the server is effective for
// every request that starts after the revoking call returned.
//
// A savepoint rollback (ROLLBACK TO, GORM's failed nested Transaction) is not
// an end: the outer transaction goes on and its writes stay in flight until
// its COMMIT. COMMIT / ROLLBACK ... AND CHAIN ends one transaction and opens
// the next.
//
// What this does not see, stated: pgx batches (SendBatch: only the audit
// pipeline, which writes no fenced table), pgconn-level calls and SQL-level
// PREPARE / EXECUTE (unused). The database side catches anything missed:
// every fenced write bumps the epoch, and the poller flushes all entries on
// every epoch move it sees; one this process did not account for is also
// counted as an unattributed bump (Guard.UnattributedBumps). A
// cascading foreign key from an unfenced parent into a fenced table would be
// such a write; TestFencedTables_NoCascadeFromUnfencedParent forbids it.

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// Tracker counts this process's committed writes to fenced tables.
type Tracker struct {
	gen      atomic.Uint64
	inflight atomic.Int64
	// commits counts finished fenced transactions; the poller compares it with
	// epoch movement to find unattributed bumps.
	commits atomic.Uint64

	mu    sync.Mutex
	conns map[*pgx.Conn]*connState
}

type connState struct {
	inTx  bool
	dirty bool
}

// NewTracker returns an idle tracker.
func NewTracker() *Tracker { return &Tracker{conns: map[*pgx.Conn]*connState{}} }

// Gen is the current generation: it moves after every finished fenced write.
func (t *Tracker) Gen() uint64 { return t.gen.Load() }

// Inflight is the number of connections inside a fenced write right now.
func (t *Tracker) Inflight() int64 { return t.inflight.Load() }

// Flush invalidates every entry (an unattributed bump, a lapse).
func (t *Tracker) Flush() { t.gen.Add(1) }

// Fill is an in-progress cache fill: Store reports whether the result may be
// kept, i.e. no fenced write started or finished while it was read.
type Fill struct {
	t   *Tracker
	gen uint64
	ok  bool
}

// BeginFill starts a fill. Read the database after calling it.
func (t *Tracker) BeginFill() Fill {
	return Fill{t: t, gen: t.gen.Load(), ok: t.inflight.Load() == 0}
}

// Gen is the generation the entry is stored under.
func (f Fill) Gen() uint64 { return f.gen }

// Store reports whether the fill may be stored.
func (f Fill) Store() bool {
	return f.ok && f.t.inflight.Load() == 0 && f.t.gen.Load() == f.gen
}

// Valid reports whether an entry filled at gen may be served now.
func (t *Tracker) Valid(gen uint64) bool {
	return t.inflight.Load() == 0 && t.gen.Load() == gen
}

// TraceQueryStart implements pgx.QueryTracer.
func (t *Tracker) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	kind := classifyStatement(data.SQL, data.Args)
	if kind == stmtRead {
		return ctx
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.conns[conn]
	switch kind {
	case stmtBegin:
		if st == nil {
			st = &connState{}
			t.conns[conn] = st
		}
		st.inTx = true
	case stmtFencedWrite:
		if st == nil {
			st = &connState{}
			t.conns[conn] = st
		}
		if !st.dirty {
			st.dirty = true
			t.inflight.Add(1)
		}
	}
	return context.WithValue(ctx, traceKindKey{}, kind)
}

type traceKindKey struct{}

// TraceQueryEnd implements pgx.QueryTracer.
func (t *Tracker) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, _ pgx.TraceQueryEndData) {
	kind, _ := ctx.Value(traceKindKey{}).(stmtKind)
	if kind == stmtRead || kind == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.conns[conn]
	if st == nil {
		return
	}
	end := kind == stmtEnd || kind == stmtEndChain || (kind == stmtFencedWrite && !st.inTx) || conn.IsClosed()
	if !end {
		return
	}
	if st.dirty {
		// Gen moves before Inflight drops, so a reader never sees the write
		// finished at the old generation.
		t.gen.Add(1)
		t.commits.Add(1)
		t.inflight.Add(-1)
	}
	delete(t.conns, conn)
	if kind == stmtEndChain && !conn.IsClosed() {
		t.conns[conn] = &connState{inTx: true}
	}
}

type stmtKind int

const (
	stmtRead stmtKind = iota + 1
	stmtBegin
	stmtEnd
	stmtFencedWrite
	stmtOtherWrite
	// stmtEndChain ends the transaction and starts the next one at once
	// (COMMIT / ROLLBACK ... AND CHAIN).
	stmtEndChain
)

// endKind sorts a statement that starts with a transaction-ending verb.
// ROLLBACK TO [SAVEPOINT] (GORM's failed nested Transaction) undoes part of a
// transaction that goes on: not an end, or the outer transaction's writes
// would count as committed before its COMMIT (REVIEW-SINGLE-WRITER-1 F3).
func endKind(s string) stmtKind {
	f := strings.Fields(strings.ToLower(strings.TrimRight(s, "; \t\n")))
	if len(f) > 0 && f[0] == "rollback" {
		i := 1
		if i < len(f) && (f[i] == "work" || f[i] == "transaction") {
			i++
		}
		if i < len(f) && f[i] == "to" {
			return stmtRead
		}
	}
	if n := len(f); n >= 2 && f[n-2] == "and" && f[n-1] == "chain" {
		return stmtEndChain
	}
	return stmtEnd
}

var writeVerbs = map[string]bool{
	"insert": true, "update": true, "delete": true, "truncate": true, "merge": true,
	"with": true, "copy": true, "alter": true, "drop": true, "create": true, "call": true, "do": true,
}

var dmlInsideRE = regexp.MustCompile(`(?i)(^|[^a-z0-9_])(insert|update|delete|merge)([^a-z0-9_]|$)`)

var fencedNameRE = func() *regexp.Regexp {
	var alts []string
	for _, t := range FencedTables {
		alts = append(alts, regexp.QuoteMeta(t.Name))
	}
	return regexp.MustCompile(`(?i)(^|[^a-z0-9_])("?)(` + strings.Join(alts, "|") + `)("?)([^a-z0-9_]|$)`)
}()

// classifyStatement sorts one statement. Conservative: anything that can
// write and names a fenced table is a fenced write, except the two shapes the
// fence's triggers do not count either (an UPDATE of a table's bookkeeping
// columns only; a system_metadata write that does not touch the fenced key).
func classifyStatement(sql string, args []any) stmtKind {
	s := strings.TrimSpace(stripLeadingComments(sql))
	verb := strings.ToLower(firstWord(s))
	switch verb {
	case "begin", "start":
		return stmtBegin
	case "commit", "rollback", "end", "abort":
		return endKind(s)
	case "select", "show", "set", "savepoint", "release", "fetch", "explain", "values", "":
		return stmtRead
	}
	if !writeVerbs[verb] {
		return stmtRead
	}
	if verb == "with" && !dmlInsideRE.MatchString(s) {
		return stmtRead // a read-only CTE
	}
	m := fencedNameRE.FindAllStringSubmatch(s, -1)
	if m == nil {
		return stmtOtherWrite
	}
	for _, mm := range m {
		if fencedWriteOf(strings.ToLower(mm[3]), verb, s, args) {
			return stmtFencedWrite
		}
	}
	return stmtOtherWrite
}

func fencedWriteOf(table, verb, s string, args []any) bool {
	for _, t := range FencedTables {
		if t.Name != table {
			continue
		}
		if t.Key != "" && !mentionsKey(s, args, t.Key) {
			return false
		}
		if verb == "update" && len(t.UpdateIgnores) > 0 && onlySets(s, t.UpdateIgnores) {
			return false
		}
		return true
	}
	return false
}

func mentionsKey(s string, args []any, key string) bool {
	if strings.Contains(s, key) {
		return true
	}
	for _, a := range args {
		if v, ok := a.(string); ok && v == key {
			return true
		}
	}
	return false
}

// onlySets reports whether an UPDATE's SET list assigns only cols.
func onlySets(s string, cols []string) bool {
	low := strings.ToLower(s)
	_, after, ok := strings.Cut(low, " set ")
	if !ok {
		return false
	}
	setList, _, _ := strings.Cut(after, " where ")
	for part := range strings.SplitSeq(setList, ",") {
		lhs, _, ok := strings.Cut(part, "=")
		if !ok {
			return false
		}
		name := strings.Trim(strings.TrimSpace(lhs), `"`)
		allowed := false
		for _, c := range cols {
			if name == c {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func firstWord(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '(' || r == ';' {
			return s[:i]
		}
	}
	return s
}

func stripLeadingComments(s string) string {
	for {
		s = strings.TrimSpace(s)
		switch {
		case strings.HasPrefix(s, "--"):
			_, rest, ok := strings.Cut(s, "\n")
			if !ok {
				return ""
			}
			s = rest
		case strings.HasPrefix(s, "/*"):
			_, rest, ok := strings.Cut(s, "*/")
			if !ok {
				return ""
			}
			s = rest
		default:
			return s
		}
	}
}

var activeTracker atomic.Pointer[Tracker]

// ActiveTracker is the process's tracker, or nil when single_writer is off.
func ActiveTracker() *Tracker { return activeTracker.Load() }
