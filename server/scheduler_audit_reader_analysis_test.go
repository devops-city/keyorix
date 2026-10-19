package main

// scheduler_audit_reader_analysis_test.go — the static analysis behind
// TestSchedulerAuditReads_EveryJobThatReadsAnAuditTableDeclaresItsBound
// (AUDIT-READER-HYGIENE-1 item 3). It answers, from the code: which scheduler
// jobs can reach a read of an audit-sized table?
//
// 1. Jobs: every call to runScheduler / runSchedulerAfter in this package whose
//    name argument is a constant string, with its tick function (a function or
//    closure literal). A call whose name or tick is not one of those shapes is
//    an error, not a skip.
// 2. Readers: every function of internal/storage/store that issues a read whose
//    query names audit_events or secret_access_logs. Recognised read calls:
//    gorm's Find, First, Take, Last, Pluck, Count, Scan, Row, Rows,
//    FindInBatches, and database/sql's Query/QueryRow(Context) on *sql.DB,
//    *sql.Tx and *sql.Conn. A read names a table when the call's arguments or
//    the *gorm.DB chain it is called on (Where, Model, Table, Raw, Order, ...,
//    followed back through gorm methods, phis and up to three levels of
//    module functions that return the *gorm.DB) contain a constant string
//    mentioning the table, or a value whose type is (a pointer to, slice of,
//    ...) models.AuditEvent or models.SecretAccessLog. A query built in a
//    variable of another shape (a string concatenated at runtime from
//    non-constant parts, a model passed as `any` from far away) is not seen.
// 3. Reachability: a walk over the SSA of the whole program from each tick
//    function. Calls to a function value are resolved per call site: a
//    func-typed parameter, or a closure's captured variable (go/ssa captures
//    by reference: the walk follows the stores into the captured Alloc), is
//    bound to the function or closure literal actually passed. So
//    lockedRun → WithSchedulerLock → runProtected → fn() follows the job's own
//    fn, and WithTransaction(fn) → gorm's Transaction(fc) → fc → fn the
//    caller's own fn, not every closure ever passed there. Interface method
//    calls, and function values the walk cannot bind (stored in a field, a
//    map, a channel), use variable type analysis (callgraph/vta): an
//    over-approximation, so a job may be reported as reaching a reader it
//    never calls (its entry then says why that read is bounded). One
//    deliberate under-approximation: library (non-module) code reaches module
//    code only through function values the module passed in, not through the
//    library's own interface dispatch or unbound function values (fmt's
//    Stringer, the runtime's finalizers, net/http's Handler), which would
//    otherwise connect every job to every handler. A read reached only that
//    way (a GORM model hook, say) is not seen.
//
// Not covered: jobs started outside runScheduler/runSchedulerAfter (the SIEM
// forwarder, the audit flusher), reads outside internal/storage/store, and
// readers reached only through reflection.

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const (
	serverPkgPath = "github.com/keyorixhq/keyorix/server"
	storePkgPath  = "github.com/keyorixhq/keyorix/internal/storage/store"
	modelsPkgPath = "github.com/keyorixhq/keyorix/internal/storage/models"
	modulePrefix  = "github.com/keyorixhq/keyorix/"
)

// auditSizedTables maps each audit-sized table to its model type name.
var auditSizedTables = map[string]string{
	"audit_events":       "AuditEvent",
	"secret_access_logs": "SecretAccessLog",
}

var gormReadTerminals = map[string]bool{
	"Find": true, "First": true, "Take": true, "Last": true, "Pluck": true, "Count": true,
	"Scan": true, "Row": true, "Rows": true, "FindInBatches": true,
}

var sqlReadTerminals = map[string]bool{
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
}

// schedulerJob is one runScheduler/runSchedulerAfter call.
type schedulerJob struct {
	name string
	pos  string
	tick callable
}

// auditReadAnalysis is the derived inventory.
type auditReadAnalysis struct {
	jobs []schedulerJob
	// readers: store function → audit tables it reads.
	readers map[*ssa.Function][]string
	// reached: job name → reader function name → tables.
	reached map[string]map[string][]string
	// paths: job name → reader function name → one call path to it.
	paths map[string]map[string][]string
}

var (
	auditReadAnalysisOnce   sync.Once
	auditReadAnalysisResult *auditReadAnalysis
	auditReadAnalysisErr    error
)

func loadAuditReadAnalysis(t *testing.T) *auditReadAnalysis {
	t.Helper()
	auditReadAnalysisOnce.Do(func() {
		auditReadAnalysisResult, auditReadAnalysisErr = runAuditReadAnalysis()
	})
	if auditReadAnalysisErr != nil {
		t.Fatal(auditReadAnalysisErr)
	}
	return auditReadAnalysisResult
}

func runAuditReadAnalysis() (*auditReadAnalysis, error) {
	pkgs, err := packages.Load(&packages.Config{Mode: packages.LoadAllSyntax}, serverPkgPath)
	if err != nil {
		return nil, err
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("loading %s: %d package errors", serverPkgPath, n)
	}
	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()
	all := ssautil.AllFunctions(prog)

	a := &auditReadAnalysis{readers: map[*ssa.Function][]string{}, reached: map[string]map[string][]string{}, paths: map[string]map[string][]string{}}
	for fn := range all {
		if fn.Pkg != nil && fn.Pkg.Pkg.Path() == storePkgPath {
			if tables := auditTablesReadBy(fn); len(tables) > 0 {
				a.readers[fn] = tables
			}
		}
	}
	jobs, err := findSchedulerJobs(all)
	if err != nil {
		return nil, err
	}
	a.jobs = jobs

	w := newReachWalker(vta.CallGraph(all, cha.CallGraph(prog)))
	roots := make([]callable, 0, len(jobs))
	for _, j := range jobs {
		roots = append(roots, j.tick)
	}
	g := w.explore(roots)
	for _, j := range jobs {
		reached := g.reach(j.tick.key())
		hits := map[string][]string{}
		paths := map[string][]string{}
		for fn, path := range reached {
			if tables, ok := a.readers[fn]; ok {
				hits[readerName(fn)] = tables
				paths[readerName(fn)] = path
			}
		}
		a.reached[j.name] = hits
		a.paths[j.name] = paths
	}
	return a, nil
}

// readerName is a stable, human-readable name: (*LocalStorage).Method, with a
// closure suffix ($1) where the read sits in a closure.
func readerName(fn *ssa.Function) string {
	return strings.TrimPrefix(fn.String(), "(*"+storePkgPath+".")
}

// findSchedulerJobs returns every runScheduler/runSchedulerAfter call of the
// server package.
func findSchedulerJobs(all map[*ssa.Function]bool) ([]schedulerJob, error) {
	var jobs []schedulerJob
	var errs []string
	for fn := range all {
		if fn.Pkg == nil || fn.Pkg.Pkg.Path() != serverPkgPath {
			continue
		}
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				call, ok := ins.(ssa.CallInstruction)
				if !ok {
					continue
				}
				callee := call.Common().StaticCallee()
				if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg.Path() != serverPkgPath ||
					(callee.Name() != "runScheduler" && callee.Name() != "runSchedulerAfter") {
					continue
				}
				if fn.Name() == "runScheduler" {
					continue // runScheduler's own delegation to runSchedulerAfter
				}
				pos := prog(fn).Fset.Position(call.Pos()).String()
				args := call.Common().Args
				c, ok := args[1].(*ssa.Const)
				if !ok || c.Value == nil || c.Value.Kind() != constant.String {
					errs = append(errs, fmt.Sprintf("%s: %s with a non-constant job name", pos, callee.Name()))
					continue
				}
				tick := resolveFuncValue(args[len(args)-1], nil)
				if len(tick) != 1 {
					errs = append(errs, fmt.Sprintf("%s: job %q: tick is not a function or closure literal", pos, constant.StringVal(c.Value)))
					continue
				}
				jobs = append(jobs, schedulerJob{name: constant.StringVal(c.Value), pos: pos, tick: tick[0]})
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("scheduler calls this analysis cannot resolve:\n  %s", strings.Join(errs, "\n  "))
	}
	sort.Slice(jobs, func(i, k int) bool { return jobs[i].name < jobs[k].name })
	return jobs, nil
}

func prog(fn *ssa.Function) *ssa.Program { return fn.Prog }

// --- readers -----------------------------------------------------------------

// auditTablesReadBy returns the audit-sized tables fn reads (sorted, unique).
func auditTablesReadBy(fn *ssa.Function) []string {
	found := map[string]bool{}
	for _, b := range fn.Blocks {
		for _, ins := range b.Instrs {
			call, ok := ins.(ssa.CallInstruction)
			if !ok {
				continue
			}
			if !isReadTerminal(call.Common()) {
				continue
			}
			seen := map[ssa.Value]bool{}
			for _, arg := range call.Common().Args {
				collectAuditTables(arg, found, seen, 0)
			}
		}
	}
	out := make([]string, 0, len(found))
	for t := range found {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// isReadTerminal reports whether the call is a recognised read.
func isReadTerminal(c *ssa.CallCommon) bool {
	callee := c.StaticCallee()
	if callee == nil || callee.Signature.Recv() == nil {
		return false
	}
	recv := types.TypeString(callee.Signature.Recv().Type(), nil)
	switch recv {
	case "*gorm.io/gorm.DB":
		return gormReadTerminals[callee.Name()]
	case "*database/sql.DB", "*database/sql.Tx", "*database/sql.Conn":
		return sqlReadTerminals[callee.Name()]
	}
	return false
}

// collectAuditTables adds every audit-sized table v names, following v back
// through the *gorm.DB chain it came from.
func collectAuditTables(v ssa.Value, found map[string]bool, seen map[ssa.Value]bool, depth int) {
	if v == nil || seen[v] || depth > 3 {
		return
	}
	seen[v] = true
	if c, ok := v.(*ssa.Const); ok && c.Value != nil && c.Value.Kind() == constant.String {
		s := strings.ToLower(constant.StringVal(c.Value))
		for table := range auditSizedTables {
			if strings.Contains(s, table) {
				found[table] = true
			}
		}
		return
	}
	if table := auditTableOfType(v.Type()); table != "" {
		found[table] = true
	}
	switch x := v.(type) {
	case *ssa.MakeInterface:
		collectAuditTables(x.X, found, seen, depth)
	case *ssa.ChangeType:
		collectAuditTables(x.X, found, seen, depth)
	case *ssa.Slice:
		collectAuditTables(x.X, found, seen, depth)
	case *ssa.Phi:
		for _, e := range x.Edges {
			collectAuditTables(e, found, seen, depth)
		}
	case *ssa.Alloc:
		// a variadic []any slice: the values stored into it
		for _, ref := range *x.Referrers() {
			if ia, ok := ref.(*ssa.IndexAddr); ok {
				for _, r := range *ia.Referrers() {
					if st, ok := r.(*ssa.Store); ok {
						collectAuditTables(st.Val, found, seen, depth)
					}
				}
			}
		}
	case *ssa.Call:
		callee := x.Call.StaticCallee()
		if callee == nil {
			return
		}
		if callee.Signature.Recv() != nil && types.TypeString(callee.Signature.Recv().Type(), nil) == "*gorm.io/gorm.DB" {
			for _, arg := range x.Call.Args { // receiver first: the chain
				collectAuditTables(arg, found, seen, depth)
			}
			return
		}
		if callee.Pkg != nil && strings.HasPrefix(callee.Pkg.Pkg.Path(), modulePrefix) {
			for _, b := range callee.Blocks {
				if ret, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return); ok {
					for _, r := range ret.Results {
						collectAuditTables(r, found, seen, depth+1)
					}
				}
			}
		}
	}
}

// auditTableOfType returns the audit table whose model t is (through
// pointers, slices, arrays and maps), or "".
func auditTableOfType(t types.Type) string {
	for range 8 {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Slice:
			t = x.Elem()
		case *types.Array:
			t = x.Elem()
		case *types.Map:
			t = x.Elem()
		case *types.Named:
			obj := x.Obj()
			if obj.Pkg() == nil || obj.Pkg().Path() != modelsPkgPath {
				return ""
			}
			for table, model := range auditSizedTables {
				if obj.Name() == model {
					return table
				}
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

// --- reachability ------------------------------------------------------------

// callable is a function together with what its func-typed parameters and
// free variables are bound to at the call site that reached it.
type callable struct {
	fn  *ssa.Function
	env map[ssa.Value][]callable
}

func (c callable) key() string {
	if len(c.env) == 0 {
		return c.fn.String()
	}
	parts := make([]string, 0, len(c.env))
	for v, cs := range c.env {
		ks := make([]string, 0, len(cs))
		for _, x := range cs {
			ks = append(ks, x.key())
		}
		sort.Strings(ks)
		parts = append(parts, v.Name()+"="+strings.Join(ks, "|"))
	}
	sort.Strings(parts)
	return c.fn.String() + "{" + strings.Join(parts, ",") + "}"
}

type reachWalker struct {
	chaSites map[ssa.CallInstruction][]*ssa.Function
}

func newReachWalker(cg *callgraph.Graph) *reachWalker {
	w := &reachWalker{chaSites: map[ssa.CallInstruction][]*ssa.Function{}}
	for _, n := range cg.Nodes {
		for _, e := range n.Out {
			if e.Site != nil {
				w.chaSites[e.Site] = append(w.chaSites[e.Site], e.Callee.Func)
			}
		}
	}
	return w
}

// instanceGraph is every bound instance reachable from the walk's roots, with
// its outgoing calls. Exploring it once and answering each job by a plain
// graph search keeps the per-job cost off the call-site resolution.
type instanceGraph struct {
	nodes map[string]*instanceNode
}

type instanceNode struct {
	fn  *ssa.Function
	out []instanceEdge
}

type instanceEdge struct {
	to   string
	site ssa.CallInstruction
}

// explore builds the instance graph from roots.
func (w *reachWalker) explore(roots []callable) *instanceGraph {
	g := &instanceGraph{nodes: map[string]*instanceNode{}}
	stack := append([]callable(nil), roots...)
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		k := c.key()
		if _, ok := g.nodes[k]; ok {
			continue
		}
		n := &instanceNode{fn: c.fn}
		g.nodes[k] = n
		for _, b := range c.fn.Blocks {
			for _, ins := range b.Instrs {
				call, ok := ins.(ssa.CallInstruction)
				if !ok {
					continue
				}
				for _, callee := range w.callees(c.fn, call, c.env) {
					n.out = append(n.out, instanceEdge{to: callee.key(), site: call})
					stack = append(stack, callee)
				}
			}
		}
	}
	return g
}

// reach returns every function reachable from the instance root, each with
// one call path to it (breadth-first, so a shortest one).
func (g *instanceGraph) reach(root string) map[*ssa.Function][]string {
	type visit struct {
		parent string
		site   ssa.CallInstruction
	}
	parents := map[string]visit{root: {}}
	first := map[*ssa.Function]string{}
	queue := []string{root}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		n := g.nodes[k]
		if _, ok := first[n.fn]; !ok {
			first[n.fn] = k
		}
		for _, e := range n.out {
			if _, seen := parents[e.to]; !seen {
				parents[e.to] = visit{parent: k, site: e.site}
				queue = append(queue, e.to)
			}
		}
	}
	out := make(map[*ssa.Function][]string, len(first))
	for fn, k := range first {
		var path []string
		for cur := k; len(path) < 64; {
			v := parents[cur]
			site := ""
			if v.site != nil {
				site = " (called at " + fn.Prog.Fset.Position(v.site.Pos()).String() + ")"
			}
			path = append(path, g.nodes[cur].fn.String()+site)
			if cur == root {
				break
			}
			cur = v.parent
		}
		out[fn] = path
	}
	return out
}

// callees resolves one call site under env and binds the callee's func-typed
// parameters to what the call passes.
func (w *reachWalker) callees(caller *ssa.Function, call ssa.CallInstruction, env map[ssa.Value][]callable) []callable {
	common := call.Common()
	inModule := inModulePkg(caller)
	var targets []callable
	switch {
	case common.IsInvoke():
		for _, fn := range w.chaSites[call] {
			// Library code reaches module code only through function values
			// the module passed in, not through its own interface dispatch
			// (fmt's Stringer, the runtime's finalizers, net/http's Handler).
			if inModule || !inModulePkg(fn) {
				targets = append(targets, callable{fn: fn})
			}
		}
	default:
		targets = resolveFuncValue(common.Value, env)
		if targets == nil && inModule {
			for _, fn := range w.chaSites[call] {
				targets = append(targets, callable{fn: fn})
			}
		}
	}
	args := common.Args
	out := make([]callable, 0, len(targets))
	for _, tgt := range targets {
		if tgt.fn == nil {
			continue
		}
		params := tgt.fn.Params
		if common.IsInvoke() && len(params) > 0 {
			params = params[1:] // the receiver is not in Args
		}
		for i, p := range params {
			if i >= len(args) || !isFuncTyped(p.Type()) {
				continue
			}
			if bound := resolveFuncValue(args[i], env); len(bound) > 0 {
				if tgt.env == nil {
					tgt.env = map[ssa.Value][]callable{}
				} else {
					tgt.env = copyEnv(tgt.env)
				}
				tgt.env[p] = bound
			}
		}
		out = append(out, tgt)
	}
	return out
}

// inModulePkg reports whether fn is module code; a synthetic wrapper (a
// value-receiver method called through a pointer, a bound method) counts as
// the package of the method it wraps.
func inModulePkg(fn *ssa.Function) bool {
	if fn.Pkg != nil {
		return strings.HasPrefix(fn.Pkg.Pkg.Path(), modulePrefix)
	}
	if obj := fn.Object(); obj != nil && obj.Pkg() != nil {
		return strings.HasPrefix(obj.Pkg().Path(), modulePrefix)
	}
	return false
}

func copyEnv(env map[ssa.Value][]callable) map[ssa.Value][]callable {
	out := make(map[ssa.Value][]callable, len(env)+1)
	maps.Copy(out, env)
	return out
}

func isFuncTyped(t types.Type) bool {
	_, ok := t.Underlying().(*types.Signature)
	return ok
}

func isFuncOrFuncPtrTyped(t types.Type) bool {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		return isFuncTyped(p.Elem())
	}
	return isFuncTyped(t)
}

// storedFuncValues is every function value stored into a local variable (flow
// insensitive), or nil when one of them is unknown or nothing is stored.
func storedFuncValues(alloc *ssa.Alloc, env map[ssa.Value][]callable, seen map[ssa.Value]bool) []callable {
	var out []callable
	stores := 0
	for _, ref := range *alloc.Referrers() {
		st, ok := ref.(*ssa.Store)
		if !ok || st.Addr != alloc {
			continue
		}
		stores++
		r := resolveFuncValueSeen(st.Val, env, seen)
		if r == nil {
			return nil
		}
		out = append(out, r...)
	}
	if stores == 0 {
		return nil
	}
	return out
}

// resolveFuncValue returns what a func-typed value can be, or nil when the
// walk cannot tell (the caller then falls back to CHA).
func resolveFuncValue(v ssa.Value, env map[ssa.Value][]callable) []callable {
	return resolveFuncValueSeen(v, env, map[ssa.Value]bool{})
}

func resolveFuncValueSeen(v ssa.Value, env map[ssa.Value][]callable, seen map[ssa.Value]bool) []callable {
	if seen[v] {
		return []callable{} // a loop back-edge adds nothing new (non-nil: not "unknown")
	}
	seen[v] = true
	switch x := v.(type) {
	case *ssa.Function:
		return []callable{{fn: x}}
	case *ssa.MakeClosure:
		c := callable{fn: x.Fn.(*ssa.Function)}
		for i, fv := range c.fn.FreeVars {
			if i >= len(x.Bindings) || !isFuncOrFuncPtrTyped(fv.Type()) {
				continue
			}
			// go/ssa captures a variable by reference: the binding is the
			// variable's Alloc, and the closure loads *fv to call it.
			var bound []callable
			if alloc, ok := x.Bindings[i].(*ssa.Alloc); ok {
				bound = storedFuncValues(alloc, env, seen)
			} else {
				bound = resolveFuncValueSeen(x.Bindings[i], env, seen)
			}
			if len(bound) > 0 {
				if c.env == nil {
					c.env = map[ssa.Value][]callable{}
				}
				c.env[fv] = bound
			}
		}
		return []callable{c}
	case *ssa.Parameter, *ssa.FreeVar:
		return env[v]
	case *ssa.ChangeType:
		return resolveFuncValueSeen(x.X, env, seen)
	case *ssa.UnOp:
		if x.Op != token.MUL {
			return nil
		}
		switch ptr := x.X.(type) {
		case *ssa.FreeVar:
			return env[ptr]
		case *ssa.Alloc:
			return storedFuncValues(ptr, env, seen)
		}
	case *ssa.Phi:
		out := []callable{}
		for _, e := range x.Edges {
			r := resolveFuncValueSeen(e, env, seen)
			if r == nil {
				return nil // one unknown edge: the whole value is unknown
			}
			out = append(out, r...)
		}
		return out
	}
	return nil
}
