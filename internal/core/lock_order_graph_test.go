// lock_order_graph_test.go — the static lock-acquisition graph behind
// TestLockOrder_InProcessLocksFollowDeclaredOrder (#2694). The table it is
// checked against, and what it does not see, are in
// lock_order_inprocess_static_test.go.
//
// A node ("lock class") is one of:
//
//   - a sync.Mutex / sync.RWMutex, named by where it lives: a struct field
//     ("core.KeyorixCore.accountStateMu"), an element of a field array
//     ("core.KeyorixCore.loginFailureMu[]"), a package variable
//     ("storage.migrationMu"), a mutex embedded in a type
//     ("core.T.(embedded)"), or the mutex a function returns
//     ("core.KeyorixCore.rotationBackendLock()") when a local variable holds
//     it. Acquired by Lock / RLock (blocking) and TryLock / TryRLock (held
//     afterwards, but never waited on, so never the target of an edge);
//   - a WithNamedLock key family, "named:<prefix>" from storage.NamedLockOrder,
//     resolved from the key argument (a *LockKey const or constructor, the
//     shapes TestNamedLockOrder_EveryCallSiteKeyHasAFamily already requires);
//   - "WithTransaction" (storage.Storage.WithTransaction, LocalStorage's, and
//     gorm's (*DB).Transaction): on SQLite it takes the process's write gate,
//     on Postgres it pins a request-pool connection, so it is a lock for
//     ordering purposes;
//   - every other With*Lock primitive (WithBootstrapLock,
//     WithAuditCheckpointLock, WithSchedulerLock), named by its method.
//
// An edge A -> B means some call chain acquires B while it holds A. Edges
// are found by walking every function body with the set of locks held at
// each point, following:
//
//   - calls to functions and methods of the loaded packages (types, not
//     names, decide the callee), transitively: a call made while holding A
//     adds A -> every class the callee may acquire;
//   - storage.Storage interface calls, resolved to *store.LocalStorage's
//     method of the same name (the only real implementation; the fault and
//     mock wrappers delegate to it or are test-only);
//   - callbacks: the closure passed to WithNamedLock / WithTransaction /
//     With*Lock runs under that lock, and a closure (or method value) passed
//     to a helper of the loaded packages runs under whatever that helper
//     holds where it invokes its func parameter (computed to a fixpoint, so
//     withGroupMemberSoDLocks(…, fn)-style wrappers are followed);
//   - a local variable bound to a func literal, at the places it is called or
//     passed.
//
// Hold regions are tracked per statement list: Lock adds the class for the
// statements after it, Unlock removes it, defer Unlock keeps it to the end
// of the function; at if/switch/select/loops the held set afterwards is the
// UNION of the branches (an early-return Unlock in one branch does not end
// the hold on the fall-through path). A goroutine (`go` statement) starts
// with nothing held and does not contribute to its spawner's acquisitions.
package core

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	lockClassTx          = "WithTransaction"
	lockClassNamedPrefix = "named:"
	coreStoragePkgPath   = "github.com/keyorixhq/keyorix/internal/core/storage"
	localStorageRecv     = "(*github.com/keyorixhq/keyorix/internal/storage/store.LocalStorage)."
	lockModule           = "github.com/keyorixhq/keyorix/"
)

// lockAsyncCallbackAPIs run their func argument on another goroutine: what
// the caller holds is not held there.
var lockAsyncCallbackAPIs = map[string]bool{
	"time.AfterFunc":                                 true,
	"context.AfterFunc":                              true,
	"(*sync.WaitGroup).Go":                           true,
	"(*golang.org/x/sync/errgroup.Group).Go":         true,
	"(*golang.org/x/sync/singleflight.Group).DoChan": true,
}

// lockOnceAPIs make every concurrent caller wait for the one running fn, so
// they are locks: (full name) -> index of the func argument.
var lockOnceAPIs = map[string]int{
	"(*sync.Once).Do": 0,
	"(*golang.org/x/sync/singleflight.Group).Do": 1,
}

type lockEdge struct{ from, to string }

// lockWitness says where a function (or an edge) first acquires a class: at
// pos, either directly or through a call to via.
type lockWitness struct {
	pos string
	via string // callee key, "" when acquired directly at pos
}

type lockGraph struct {
	edges map[lockEdge]lockWitness
	// classes is every lock class acquired anywhere, edge or not.
	classes map[string]bool
	// unresolved lists WithNamedLock call sites whose key family could not be
	// determined statically; each is a hole in the graph.
	unresolved []string
	// acq is each function's acquisitions, for rendering witness chains.
	acq map[string]map[string]lockWitness
}

type lockFuncBody struct {
	key  string
	decl *ast.FuncDecl
	info *types.Info
}

type lockAnalyzer struct {
	handoffs map[string]string
	fset     *token.FileSet
	root     string // positions are printed relative to this directory
	bodies   map[string]*lockFuncBody
	// ctorFormat maps a key-constructor function key to its Sprintf format.
	ctorFormat map[string]string
	acq        map[string]map[string]lockWitness // func key -> classes it may acquire
	paramHeld  map[string]map[int]map[string]bool
	graph      *lockGraph
	changed    bool
	seenUnres  map[string]bool
}

// lockFullKey turns a key written without the module prefix
// ("(*internal/storage/store.LocalStorage).X") into a lockFuncKey.
func lockFullKey(short string) string {
	for _, p := range []string{"(*", "("} {
		if rest, ok := strings.CutPrefix(short, p); ok {
			return p + lockModule + rest
		}
	}
	return lockModule + short
}

// lockShortKey is lockFullKey's inverse, for messages.
func lockShortKey(full string) string { return strings.Replace(full, lockModule, "", 1) }

// lockFuncKey is the stable identity of a function across separately
// type-checked packages (a package loaded from source and the same package
// seen through another's export data have different *types.Func objects).
func lockFuncKey(fn *types.Func) string { return fn.Origin().FullName() }

func loadLockOrderPackages(t *testing.T, patterns ...string) (*token.FileSet, []*packages.Package) {
	t.Helper()
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Dir:  ".",
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("lock-order scan: a package failed to type-check")
	}
	if !slices.ContainsFunc(patterns, func(p string) bool { return strings.HasSuffix(p, "...") }) && len(pkgs) != len(patterns) {
		t.Fatalf("lock-order scan: loaded %d packages for %d patterns", len(pkgs), len(patterns))
	}
	return fset, pkgs
}

// buildLockGraph builds the graph over pkgs. handoffs maps a function that
// blocks on a channel until another goroutine has done its work to that
// goroutine's function (keys as lockFuncKey, without the module prefix): a
// call to the first is treated as also running the second, under the
// caller's locks. That is the only way channel hand-offs enter the graph.
func buildLockGraph(t *testing.T, fset *token.FileSet, pkgs []*packages.Package, handoffs map[string]string) *lockGraph {
	t.Helper()
	root, _ := filepath.Abs(".")
	a := &lockAnalyzer{
		handoffs:   map[string]string{},
		fset:       fset,
		root:       root,
		bodies:     map[string]*lockFuncBody{},
		ctorFormat: map[string]string{},
		acq:        map[string]map[string]lockWitness{},
		paramHeld:  map[string]map[int]map[string]bool{},
		graph:      &lockGraph{edges: map[lockEdge]lockWitness{}, classes: map[string]bool{}},
		seenUnres:  map[string]bool{},
	}
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				k := lockFuncKey(fn)
				a.bodies[k] = &lockFuncBody{key: k, decl: fd, info: p.TypesInfo}
				if format, ok := sprintfFormat(fd); ok {
					a.ctorFormat[k] = format
				}
			}
		}
	}
	for from, to := range handoffs {
		from, to = lockFullKey(from), lockFullKey(to)
		if a.bodies[from] == nil || a.bodies[to] == nil {
			t.Fatalf("lock-order hand-off %s -> %s names a function the scan did not find — update the hand-off table", from, to)
		}
		a.handoffs[from] = to
	}
	keys := slices.Sorted(maps.Keys(a.bodies))
	for range 100 {
		a.changed = false
		for _, k := range keys {
			a.walkFunc(a.bodies[k])
		}
		if !a.changed {
			a.graph.acq = a.acq
			return a.graph
		}
	}
	t.Fatalf("lock-order scan did not reach a fixpoint")
	return nil
}

// sprintfFormat recognises `return fmt.Sprintf("<format>", ...)` as a
// function's whole body (the lock-key constructor shape).
func sprintfFormat(fd *ast.FuncDecl) (string, bool) {
	if len(fd.Body.List) != 1 {
		return "", false
	}
	ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "", false
	}
	ce, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || len(ce.Args) == 0 {
		return "", false
	}
	if sel, ok := ce.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Sprintf" {
		return "", false
	}
	bl, ok := ce.Args[0].(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

type litVisit struct {
	lit       *ast.FuncLit
	held      string
	goroutine bool
}

// walkState is the per-function context of one walk.
type walkState struct {
	body      *lockFuncBody
	params    map[*types.Var]int
	defs      map[*types.Var]ast.Expr
	goroutine bool // inside a `go` statement: acquisitions are not the function's
	litVisits map[litVisit]bool
}

func (a *lockAnalyzer) walkFunc(b *lockFuncBody) {
	ws := &walkState{body: b, params: map[*types.Var]int{}, defs: map[*types.Var]ast.Expr{}, litVisits: map[litVisit]bool{}}
	idx := 0
	if b.decl.Type.Params != nil {
		for _, f := range b.decl.Type.Params.List {
			names := f.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, n := range names {
				if v, ok := b.info.Defs[n].(*types.Var); ok {
					if _, isFn := v.Type().Underlying().(*types.Signature); isFn {
						ws.params[v] = idx
					}
				}
				idx++
			}
		}
	}
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) != len(s.Rhs) {
				return true
			}
			for i, l := range s.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok {
					continue
				}
				obj := b.info.Defs[id]
				if obj == nil {
					obj = b.info.Uses[id]
				}
				if v, ok := obj.(*types.Var); ok {
					ws.defs[v] = s.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			if len(s.Names) != len(s.Values) {
				return true
			}
			for i, id := range s.Names {
				if v, ok := b.info.Defs[id].(*types.Var); ok {
					ws.defs[v] = s.Values[i]
				}
			}
		}
		return true
	})
	a.walkStmts(ws, b.decl.Body.List, nil)
}

func (a *lockAnalyzer) pos(p token.Pos) string {
	position := a.fset.Position(p)
	if rel, err := filepath.Rel(a.root, position.Filename); err == nil {
		position.Filename = rel
	}
	return position.Filename + ":" + strconv.Itoa(position.Line)
}

func heldUnion(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		for _, c := range s {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

func heldWith(held []string, c string) []string {
	if slices.Contains(held, c) {
		return held
	}
	return append(slices.Clip(held), c)
}

func heldWithout(held []string, c string) []string {
	i := slices.Index(held, c)
	if i < 0 {
		return held
	}
	return slices.Delete(slices.Clone(held), i, i+1)
}

func (a *lockAnalyzer) walkStmts(ws *walkState, stmts []ast.Stmt, held []string) []string {
	for _, s := range stmts {
		held = a.walkStmt(ws, s, held)
	}
	return held
}

func (a *lockAnalyzer) walkStmt(ws *walkState, s ast.Stmt, held []string) []string {
	if s == nil {
		return held
	}
	switch s := s.(type) {
	case *ast.ExprStmt:
		return a.exprThenApply(ws, held, s.X)
	case *ast.AssignStmt:
		// A closure bound to a local variable is walked where it is called or
		// passed (runUnder), with what is held THERE, not where it is defined.
		var exprs []ast.Expr
		for i, r := range s.Rhs {
			if _, ok := ast.Unparen(r).(*ast.FuncLit); ok && len(s.Lhs) == len(s.Rhs) {
				if _, ok := s.Lhs[i].(*ast.Ident); ok {
					continue
				}
			}
			exprs = append(exprs, r)
		}
		return a.exprThenApply(ws, held, append(exprs, s.Lhs...)...)
	case *ast.DeclStmt:
		gd, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return held
		}
		var exprs []ast.Expr
		for _, sp := range gd.Specs {
			if vs, ok := sp.(*ast.ValueSpec); ok {
				for _, v := range vs.Values {
					if _, ok := ast.Unparen(v).(*ast.FuncLit); !ok || len(vs.Names) != len(vs.Values) {
						exprs = append(exprs, v)
					}
				}
			}
		}
		return a.exprThenApply(ws, held, exprs...)
	case *ast.DeferStmt:
		// A deferred Unlock keeps the class held to the end of the function;
		// any other deferred call runs (at the latest) with what is held now.
		if c, op := a.mutexOp(ws, s.Call); op == mutexUnlock && c != "" {
			return held
		}
		return a.exprThenApply(ws, held, s.Call)
	case *ast.GoStmt:
		for _, arg := range s.Call.Args {
			a.walkExpr(ws, held, arg)
		}
		inner := *ws
		inner.goroutine = true
		if lit, ok := ast.Unparen(s.Call.Fun).(*ast.FuncLit); ok {
			a.walkStmts(&inner, lit.Body.List, nil)
		}
		return held
	case *ast.ReturnStmt:
		// A returned closure runs after this function has returned (its
		// deferred unlocks done), on the caller's terms: walk it holding
		// nothing, and do not count what it takes as this function's.
		var exprs []ast.Expr
		for _, r := range s.Results {
			if lit, ok := ast.Unparen(r).(*ast.FuncLit); ok {
				detached := *ws
				detached.goroutine = true
				a.walkStmts(&detached, lit.Body.List, nil)
				continue
			}
			exprs = append(exprs, r)
		}
		return a.exprThenApply(ws, held, exprs...)
	case *ast.SendStmt:
		return a.exprThenApply(ws, held, s.Chan, s.Value)
	case *ast.IncDecStmt:
		return a.exprThenApply(ws, held, s.X)
	case *ast.BlockStmt:
		return a.walkStmts(ws, s.List, held)
	case *ast.LabeledStmt:
		return a.walkStmt(ws, s.Stmt, held)
	case *ast.IfStmt:
		held = a.walkStmt(ws, s.Init, held)
		held = a.exprThenApply(ws, held, s.Cond)
		then := a.walkStmts(ws, s.Body.List, held)
		els := held
		if s.Else != nil {
			els = a.walkStmt(ws, s.Else, held)
		}
		return heldUnion(then, els)
	case *ast.ForStmt:
		held = a.walkStmt(ws, s.Init, held)
		if s.Cond != nil {
			held = a.exprThenApply(ws, held, s.Cond)
		}
		body := a.walkStmts(ws, s.Body.List, held)
		body = a.walkStmt(ws, s.Post, body)
		return heldUnion(held, body)
	case *ast.RangeStmt:
		held = a.exprThenApply(ws, held, s.X)
		return heldUnion(held, a.walkStmts(ws, s.Body.List, held))
	case *ast.SwitchStmt:
		held = a.walkStmt(ws, s.Init, held)
		if s.Tag != nil {
			held = a.exprThenApply(ws, held, s.Tag)
		}
		return a.walkClauses(ws, s.Body, held, false)
	case *ast.TypeSwitchStmt:
		held = a.walkStmt(ws, s.Init, held)
		held = a.walkStmt(ws, s.Assign, held)
		return a.walkClauses(ws, s.Body, held, false)
	case *ast.SelectStmt:
		return a.walkClauses(ws, s.Body, held, true)
	}
	return held
}

// walkClauses walks a switch or select body. Exactly one clause of a select
// runs; a switch with no default may run none, so what was held on entry
// also flows out of it.
func (a *lockAnalyzer) walkClauses(ws *walkState, body *ast.BlockStmt, held []string, isSelect bool) []string {
	var out []string
	hasDefault := isSelect
	for _, c := range body.List {
		switch cc := c.(type) {
		case *ast.CaseClause:
			if cc.List == nil {
				hasDefault = true
			}
			h := a.exprThenApply(ws, held, cc.List...)
			out = heldUnion(out, a.walkStmts(ws, cc.Body, h))
		case *ast.CommClause:
			h := a.walkStmt(ws, cc.Comm, held)
			out = heldUnion(out, a.walkStmts(ws, cc.Body, h))
		}
	}
	if !hasDefault || len(body.List) == 0 {
		out = heldUnion(out, held)
	}
	return out
}

// exprThenApply walks exprs with held, then applies the mutex Lock/Unlock
// calls they contain to the held set for the statements that follow.
func (a *lockAnalyzer) exprThenApply(ws *walkState, held []string, exprs ...ast.Expr) []string {
	var got, rel []string
	for _, e := range exprs {
		g, r := a.walkExpr(ws, held, e)
		got = append(got, g...)
		rel = append(rel, r...)
	}
	for _, c := range rel {
		held = heldWithout(held, c)
	}
	for _, c := range got {
		held = heldWith(held, c)
	}
	return held
}

// walkExpr walks one expression, recording every acquisition it makes under
// held, and returns the mutex classes it locks and unlocks.
func (a *lockAnalyzer) walkExpr(ws *walkState, held []string, e ast.Expr) (got, rel []string) {
	if e == nil {
		return nil, nil
	}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			g, r := a.walkCall(ws, held, x)
			got = append(got, g...)
			rel = append(rel, r...)
			return false
		case *ast.FuncLit:
			// A closure in any other position (stored, returned, assigned):
			// assume it may run with what is held now.
			a.runLit(ws, held, x)
			return false
		}
		return true
	})
	return got, rel
}

type mutexOpKind int

const (
	mutexNone mutexOpKind = iota
	mutexLock
	mutexTryLock
	mutexUnlock
)

func (a *lockAnalyzer) mutexOp(ws *walkState, call *ast.CallExpr) (string, mutexOpKind) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", mutexNone
	}
	fn, ok := ws.body.info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return "", mutexNone
	}
	var kind mutexOpKind
	switch fn.FullName() {
	case "(*sync.Mutex).Lock", "(*sync.RWMutex).Lock", "(*sync.RWMutex).RLock":
		kind = mutexLock
	case "(*sync.Mutex).TryLock", "(*sync.RWMutex).TryLock", "(*sync.RWMutex).TryRLock":
		kind = mutexTryLock
	case "(*sync.Mutex).Unlock", "(*sync.RWMutex).Unlock", "(*sync.RWMutex).RUnlock":
		kind = mutexUnlock
	default:
		return "", mutexNone
	}
	return a.mutexClass(ws, sel.X, 0, true), kind
}

// lockClassReentrant reports whether holding c and acquiring c again in the
// same call chain is legal (and so not an edge): named-lock families and
// transactions. A mutex is not re-entrant: holding it and locking it again
// is a self-deadlock, reported as a self-edge.
func lockClassReentrant(c string) bool {
	return c == lockClassTx || strings.HasPrefix(c, lockClassNamedPrefix)
}

func lockTypeName(t types.Type) string {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil {
		return n.Obj().Pkg().Name() + "." + n.Obj().Name()
	}
	return t.String()
}

func isSyncMutexType(t types.Type) bool {
	switch lockTypeName(t) {
	case "sync.Mutex", "sync.RWMutex":
		return true
	}
	return false
}

// mutexClass names the lock x denotes. promoted is set when x is the
// receiver of a sync.Mutex/RWMutex method, so an x that is not itself a mutex
// holds one embedded.
func (a *lockAnalyzer) mutexClass(ws *walkState, x ast.Expr, depth int, promoted bool) string {
	info := ws.body.info
	x = ast.Unparen(x)
	if u, ok := x.(*ast.UnaryExpr); ok && u.Op == token.AND {
		x = ast.Unparen(u.X)
	}
	if tv, ok := info.Types[x]; ok && promoted && !isSyncMutexType(tv.Type) {
		// Lock promoted from a mutex embedded in x's type.
		return lockTypeName(tv.Type) + ".(embedded)"
	}
	switch v := x.(type) {
	case *ast.SelectorExpr:
		if s, ok := info.Selections[v]; ok && s.Kind() == types.FieldVal {
			return lockTypeName(s.Recv()) + "." + v.Sel.Name
		}
		if obj, ok := info.Uses[v.Sel].(*types.Var); ok && obj.Pkg() != nil {
			return obj.Pkg().Name() + "." + obj.Name()
		}
	case *ast.IndexExpr:
		return a.mutexClass(ws, v.X, depth+1, false) + "[]"
	case *ast.CallExpr:
		if fn := a.callee(ws, v); fn != nil {
			return strings.TrimPrefix(lockFuncKey(fn), "github.com/keyorixhq/keyorix/") + "()"
		}
	case *ast.Ident:
		obj, ok := info.Uses[v].(*types.Var)
		if !ok {
			break
		}
		if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
			return obj.Pkg().Name() + "." + obj.Name()
		}
		if def, ok := ws.defs[obj]; ok && depth < 8 {
			return a.mutexClass(ws, def, depth+1, promoted)
		}
		return ws.body.key + "#" + obj.Name()
	}
	return ws.body.key + "#" + types.ExprString(x)
}

// callee resolves a call to the function it runs: a declared function or
// method by type information, and a storage.Storage interface method to
// LocalStorage's method of the same name.
func (a *lockAnalyzer) callee(ws *walkState, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.IndexExpr: // generic instantiation
		switch g := f.X.(type) {
		case *ast.Ident:
			id = g
		case *ast.SelectorExpr:
			id = g.Sel
		}
	}
	if id == nil {
		return nil
	}
	fn, _ := ws.body.info.Uses[id].(*types.Func)
	return fn
}

func (a *lockAnalyzer) bodyKeyFor(fn *types.Func) string {
	k := lockFuncKey(fn)
	if _, ok := a.bodies[k]; ok {
		return k
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return ""
	}
	if !types.IsInterface(sig.Recv().Type()) || fn.Pkg() == nil || fn.Pkg().Path() != coreStoragePkgPath {
		return ""
	}
	if _, ok := a.bodies[localStorageRecv+fn.Name()]; ok {
		return localStorageRecv + fn.Name()
	}
	return ""
}

// primitiveClass reports whether fn is a lock primitive whose last func
// argument runs under the lock, and which class (named families need the
// call's key, see namedFamily).
func primitiveClass(fn *types.Func) (string, bool) {
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return "", false
	}
	name := fn.Name()
	switch {
	case name == "WithNamedLock":
		return lockClassNamedPrefix, true
	case name == "WithTransaction":
		return lockClassTx, true
	case name == "Transaction" && lockTypeName(sig.Recv().Type()) == "gorm.DB":
		return lockClassTx, true
	case strings.HasPrefix(name, "With") && strings.HasSuffix(name, "Lock"):
		return name, true
	}
	return "", false
}

func (a *lockAnalyzer) namedFamily(ws *walkState, key ast.Expr) string {
	info := ws.body.info
	key = ast.Unparen(key)
	var text string
	exact := false
	if tv, ok := info.Types[key]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		text, exact = constant.StringVal(tv.Value), true
	} else if ce, ok := key.(*ast.CallExpr); ok {
		fn := a.callee(ws, ce)
		if fn == nil {
			return ""
		}
		format, ok := a.ctorFormat[lockFuncKey(fn)]
		if !ok {
			return ""
		}
		var b strings.Builder
		argi := 0
		for i := 0; i < len(format); i++ {
			if format[i] != '%' {
				b.WriteByte(format[i])
				continue
			}
			if i+1 < len(format) && format[i+1] == 's' && argi < len(ce.Args) {
				if tv, ok := info.Types[ce.Args[argi]]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
					b.WriteString(constant.StringVal(tv.Value))
					argi++
					i++
					continue
				}
			}
			break
		}
		text = b.String()
	} else {
		return ""
	}
	for _, fam := range storage.NamedLockOrder {
		if fam.Exact == exact && fam.Prefix == text {
			return lockClassNamedPrefix + fam.Prefix
		}
	}
	return ""
}

func (a *lockAnalyzer) addAcq(ws *walkState, class string, w lockWitness) {
	if ws.goroutine {
		return
	}
	m := a.acq[ws.body.key]
	if m == nil {
		m = map[string]lockWitness{}
		a.acq[ws.body.key] = m
	}
	if _, ok := m[class]; !ok {
		m[class] = w
		a.changed = true
	}
}

func (a *lockAnalyzer) addEdge(from, to string, w lockWitness) {
	e := lockEdge{from, to}
	if _, ok := a.graph.edges[e]; !ok {
		a.graph.edges[e] = w
	}
}

// acquire records a direct acquisition of class at p under held.
func (a *lockAnalyzer) acquire(ws *walkState, held []string, class string, p token.Pos, blocking bool) {
	a.graph.classes[class] = true
	w := lockWitness{pos: a.pos(p)}
	a.addAcq(ws, class, w)
	if !blocking {
		return
	}
	for _, h := range held {
		a.addEdge(h, class, w)
	}
}

// callUnder records that the function with body key k runs (at p) under held.
func (a *lockAnalyzer) callUnder(ws *walkState, held []string, k string, p token.Pos) {
	w := lockWitness{pos: a.pos(p), via: k}
	for _, c := range slices.Sorted(maps.Keys(a.acq[k])) {
		a.addAcq(ws, c, w)
		if lockClassReentrant(c) && slices.Contains(held, c) {
			continue // re-entry acquires nothing new: see walkCall's note
		}
		for _, h := range held {
			a.addEdge(h, c, w)
		}
	}
}

func (a *lockAnalyzer) addParamHeld(ws *walkState, idx int, held []string) {
	m := a.paramHeld[ws.body.key]
	if m == nil {
		m = map[int]map[string]bool{}
		a.paramHeld[ws.body.key] = m
	}
	s := m[idx]
	if s == nil {
		s = map[string]bool{}
		m[idx] = s
	}
	for _, h := range held {
		if !s[h] {
			s[h] = true
			a.changed = true
		}
	}
}

// runLit walks a closure once per distinct held set per walk: a closure
// reached twice with the same locks adds nothing, and one that (through a
// variable) reaches itself under the same locks would otherwise recurse
// forever.
func (a *lockAnalyzer) runLit(ws *walkState, held []string, lit *ast.FuncLit) {
	k := litVisit{lit, strings.Join(slices.Sorted(slices.Values(held)), "\x00"), ws.goroutine}
	if ws.litVisits[k] {
		return
	}
	ws.litVisits[k] = true
	a.walkStmts(ws, lit.Body.List, held)
}

// runUnder runs a callback expression (a closure, a variable bound to one, a
// func-typed parameter of the walked function, or a function value) under
// held.
func (a *lockAnalyzer) runUnder(ws *walkState, held []string, fnExpr ast.Expr) {
	fnExpr = ast.Unparen(fnExpr)
	switch f := fnExpr.(type) {
	case *ast.FuncLit:
		a.runLit(ws, held, f)
		return
	case *ast.Ident:
		if v, ok := ws.body.info.Uses[f].(*types.Var); ok {
			if idx, ok := ws.params[v]; ok {
				a.addParamHeld(ws, idx, held)
				return
			}
			if lit, ok := ws.defs[v].(*ast.FuncLit); ok {
				a.runLit(ws, held, lit)
			}
			return
		}
	}
	var id *ast.Ident
	switch f := fnExpr.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	}
	if id == nil {
		a.walkExpr(ws, held, fnExpr)
		return
	}
	if fn, ok := ws.body.info.Uses[id].(*types.Func); ok {
		if k := a.bodyKeyFor(fn); k != "" {
			a.callUnder(ws, held, k, fnExpr.Pos())
		}
	}
}

// isCallback reports whether arg is a closure or a local variable bound to one.
func (a *lockAnalyzer) isCallback(ws *walkState, arg ast.Expr) bool {
	switch x := ast.Unparen(arg).(type) {
	case *ast.FuncLit:
		return true
	case *ast.Ident:
		if v, ok := ws.body.info.Uses[x].(*types.Var); ok {
			_, isLit := ws.defs[v].(*ast.FuncLit)
			return isLit
		}
	}
	return false
}

func (a *lockAnalyzer) walkCall(ws *walkState, held []string, call *ast.CallExpr) (got, rel []string) {
	if class, op := a.mutexOp(ws, call); op != mutexNone {
		switch op {
		case mutexLock:
			a.acquire(ws, held, class, call.Pos(), true)
			return []string{class}, nil
		case mutexTryLock:
			a.acquire(ws, held, class, call.Pos(), false)
			return []string{class}, nil
		case mutexUnlock:
			return nil, []string{class}
		}
	}
	// The receiver chain may itself contain calls (c.x().Y()).
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		a.walkExpr(ws, held, sel.X)
	}
	fn := a.callee(ws, call)
	full := ""
	if fn != nil {
		full = fn.FullName()
	}
	if lockAsyncCallbackAPIs[full] {
		inner := *ws
		inner.goroutine = true
		for _, arg := range call.Args {
			if lit, ok := ast.Unparen(arg).(*ast.FuncLit); ok {
				a.walkStmts(&inner, lit.Body.List, nil)
				continue
			}
			a.walkExpr(ws, held, arg)
		}
		return nil, nil
	}
	if fnIdx, ok := lockOnceAPIs[full]; ok && fnIdx < len(call.Args) {
		sel, _ := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		class := a.mutexClass(ws, sel.X, 0, false)
		for i, arg := range call.Args {
			if i != fnIdx {
				a.walkExpr(ws, held, arg)
			}
		}
		a.acquire(ws, held, class, call.Pos(), true)
		a.runUnder(ws, heldWith(held, class), call.Args[fnIdx])
		return nil, nil
	}
	if fn != nil {
		if class, ok := primitiveClass(fn); ok && len(call.Args) > 0 {
			if class == lockClassNamedPrefix {
				class = ""
				if len(call.Args) == 3 {
					class = a.namedFamily(ws, call.Args[1])
				}
				if class == "" {
					p := a.pos(call.Pos())
					if !a.seenUnres[p] {
						a.seenUnres[p] = true
						a.graph.unresolved = append(a.graph.unresolved, p)
					}
					class = lockClassNamedPrefix + "?"
				}
			}
			last := len(call.Args) - 1
			if lockTypeName(fn.Type().(*types.Signature).Recv().Type()) == "gorm.DB" {
				last = 0
			}
			for i, arg := range call.Args {
				if i != last {
					a.walkExpr(ws, held, arg)
				}
			}
			// Re-entering a named family or a transaction this chain already
			// holds acquires nothing new: WithNamedLock is re-entrant per key
			// (a different key of the same family is the runtime check's
			// business), and WithTransaction on a transaction handle is a
			// SAVEPOINT (one on the outer store is INV-CORE-36's
			// TestAtomicityGuard_TransactionEscape's business).
			if !slices.Contains(held, class) {
				a.acquire(ws, held, class, call.Pos(), true)
			}
			a.runUnder(ws, heldWith(held, class), call.Args[last])
			return nil, nil
		}
		if k := a.bodyKeyFor(fn); k != "" {
			a.callUnder(ws, held, k, call.Pos())
			if to, ok := a.handoffs[k]; ok {
				a.callUnder(ws, held, to, call.Pos())
			}
			sig := fn.Type().(*types.Signature)
			for i, arg := range call.Args {
				pi := min(i, sig.Params().Len()-1)
				if pi >= 0 {
					if _, isFn := sig.Params().At(pi).Type().Underlying().(*types.Signature); isFn {
						var under []string
						for c := range a.paramHeld[k][pi] {
							under = append(under, c)
						}
						slices.Sort(under)
						a.runUnder(ws, heldUnion(held, under), arg)
						continue
					}
				}
				a.walkExpr(ws, held, arg)
			}
			return nil, nil
		}
	}
	// A call to one of the walked function's own func-typed parameters, or to
	// a local variable bound to a closure.
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if v, ok := ws.body.info.Uses[id].(*types.Var); ok {
			if idx, ok := ws.params[v]; ok {
				a.addParamHeld(ws, idx, held)
			} else if lit, ok := ws.defs[v].(*ast.FuncLit); ok {
				a.runLit(ws, held, lit)
			}
		}
	}
	if lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		a.runLit(ws, held, lit)
	}
	// Anything else (stdlib, another package, a func value): its closure
	// arguments are assumed to run synchronously, under held.
	for _, arg := range call.Args {
		if a.isCallback(ws, arg) {
			a.runUnder(ws, held, arg)
			continue
		}
		g, r := a.walkExpr(ws, held, arg)
		got = append(got, g...)
		rel = append(rel, r...)
	}
	return got, rel
}

// witnessChain renders where an edge's target is acquired: the edge site,
// then each callee down to the direct acquisition.
func (g *lockGraph) witnessChain(e lockEdge) string {
	w := g.edges[e]
	parts := []string{w.pos}
	seen := map[string]bool{}
	for w.via != "" && !seen[w.via] {
		seen[w.via] = true
		parts = append(parts, strings.TrimPrefix(w.via, "github.com/keyorixhq/keyorix/"))
		next, ok := g.acq[w.via][e.to]
		if !ok {
			break
		}
		w = next
		parts = append(parts, w.pos)
	}
	return strings.Join(parts, " -> ")
}
