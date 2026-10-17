// besteffort_callsite_guard_test.go — INV-CORE-34's structural completeness
// guard: every call to a function this package treats as a best-effort,
// post-commit step is either panic-protected at the call site, calls a function
// that recovers its own panic, or sits in an allowlist row with a reason.
//
// Why this exists next to besteffort_guard_test.go (GUARD-1). GUARD-1 answers a
// positional question ("is a call whose result is dropped, textually after the
// last storage write in the same function, protected?"). It never asks which
// functions ARE best-effort, so a best-effort step that is wrapped in
// besteffort.Run at five call sites and called bare at a sixth is invisible to
// it whenever the sixth call is not a discard after a write. This guard keys on
// the callee instead: the set of best-effort functions is established first,
// then every call to a member is checked wherever it sits.
//
// HOW THE BEST-EFFORT SET IS ESTABLISHED (and why it is complete for this
// package). A function is best-effort if any of three things holds:
//
//  1. SELF-RECOVERING: its own body defers a recover (idioms below), or its whole
//     body is one besteffort.Run(...) statement, or its whole body is one tail
//     call to such a function (pure delegation, the same narrow transitivity
//     GUARD-1's panicSafetyIndex allows; the delegating call's arguments are
//     not inspected). A function that
//     recovers its own panic is best-effort by declaration: nobody writes that
//     defer for a step the caller needs to see fail loudly. Every recover() in
//     internal/core non-test files was read to enumerate the idioms; the ones
//     in a top-level defer are all recognised, the rest are listed as a blind
//     spot below. Deleting such a defer turns every caller that is not itself
//     protected red, which is the mutation this guard is proven with.
//  2. DERIVED: a call to it is the ONE statement (expression, return or
//     assignment) of the func literal passed to
//     besteffort.Run(ctx, step, func() error {...}) (a trailing `return nil` is
//     ignored), i.e. the closure exists to run just that call. Multi-statement closures declare nothing: their other
//     calls are incidental steps of a larger best-effort body (writeAuditEventFailed
//     inside session_undelivered.go's recovery steps is one; it is also called
//     from ~20 deny-path audits that are not post-commit).
//     goSafe closures protect their body but do NOT declare their callees
//     best-effort: goSafe also detaches PRIMARY work (the password-reset link
//     provisioning in auth.go), whose synchronous siblings must keep their
//     error. Someone already decided it must not fail its
//     caller, so every other call must honour that decision. Calls nested in
//     argument expressions are NOT taken as declarations (a first draft took
//     every call anywhere in a closure and pulled in 150+ helpers such as
//     actorPtr that were merely evaluated inside one).
//  3. SEEDED: it is named in INV-CORE-34's text (bestEffortSeeds below). The
//     seeds keep the set from silently shrinking if the derivation breaks, and
//     a seed that is renamed or deleted fails
//     TestBestEffortCallSites_SeedsAreDeclared instead of dropping out.
//
// The idioms the code uses to RECOVER, enumerated by reading every recover()
// in internal/core non-test files (33 sites at time of writing):
//
//   - besteffort.Run(ctx, step, fn)            closure argument is protected
//   - goSafe(fn)                               closure argument is protected
//   - defer besteffort.RunRecover(step)()      function-wide, top-level defer
//   - defer func() { ... recover() ... }()     function-wide, top-level defer
//   - defer <local func>(...)                  where the local function calls
//     recover() directly (recoverPostCommitNotifyPanic is the one such helper)
//
// A call is PROTECTED if it sits inside a protecting closure, or its enclosing
// declaration has a top-level recovering defer, or its callee itself has one
// (so a panic in the callee cannot reach the caller).
//
// WHAT THIS GUARD DOES NOT SEE (stated because "what does it silently skip, and
// does it say so?" is the question a guard must answer):
//
//   - Call forms recognised: `f(...)` for a package-level f declared in
//     internal/core, and `r.f(...)` where r is the enclosing function's own
//     receiver identifier. NOT recognised: `c.storage.X(...)` and any other
//     multi-hop selector (storage methods are not declared here, and matching
//     them by bare name collided with same-named KeyorixCore wrappers), method
//     values, calls through a func-typed variable or struct field, calls via an
//     interface, and calls made from another package.
//   - Callees resolve by BARE NAME. Two declarations sharing a name are one
//     entry; the callee counts as self-recovering only if EVERY declaration
//     with that name recovers (fail-closed), and as best-effort if ANY call to
//     any same-named declaration sits in a protecting closure.
//   - A recovering defer is credited only as a TOP-LEVEL statement of the
//     function body. A defer nested in an if/for/closure is not credited, so
//     such a function can show up here and needs an allowlist row.
//   - Protection is lexical. A function whose every caller is itself wrapped
//     (so the call is transitively protected) still needs a row; transitivity
//     is deliberately not inferred, for the reason panicSafetyIndex documents
//     ("calls something that recovers" marked 365 of 1430 functions safe).
//   - Only *.go files directly under internal/core, non-test and not
//     generated. Subpackages (internal/core/storage, ...) are not scanned.
//   - A function that is best-effort but is never called inside a protecting
//     closure and is not a seed is not in the set. Adding it to bestEffortSeeds
//     is the fix.
//   - It cannot tell whether an unprotected call runs after a commit; a hit
//     means "this function is treated as best-effort elsewhere", and the
//     allowlist row says why this call is allowed to differ.
//
// Proof it can go red: see the commit message of the commit that added it, and
// TestBestEffortCallSites_ScannerFixture, which plants one violation of each
// kind in a temp package on every run so the guard cannot pass merely because
// it finds nothing.
package core

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// bestEffortSeeds are the best-effort post-commit steps named in INV-CORE-34's
// text. Each must be declared in this package (see
// TestBestEffortCallSites_SeedsAreDeclared). Value = the invariant's wording.
var bestEffortSeeds = map[string]string{
	"evictUserSessionCache":            "account/break-glass session cache eviction",
	"deleteSessionsForUserAndEvict":    "account session revocation + cache eviction",
	"evictMachineIdentityCacheOrFlush": "TransitionMachineIdentity's auth-cache eviction",
	"revokeProjectDynamicSecretLeases": "DeleteProject's lease revocation after commit",
	"notifyBreakGlassAdmins":           "break-glass activation notify fan-out",
	"notifyOverdueBreakGlassReviewers": "break-glass review reminder notify fan-out",
	"emitAudit":                        "emitAudit's own LogAuditEvent call funnel",
	"writeAuditEventFull":              "audit emission after a committed write",
	"writeAuditEventDiff":              "audit emission after a committed write",
	"emitDependencyLifecycleEvents":    "secret delete/restore dependency emission",
}

// bestEffortCallAllowEntry is one reviewed exception: the call is not
// panic-protected and the reason it may stay that way.
type bestEffortCallAllowEntry struct {
	reason string
}

// bestEffortCallAllowlist is keyed "internal/core/<file>:<enclosing func>:<callee>".
// One file per row: besteffort_callsite_allow_entry_<slug>_test.go calling
// registerBestEffortCallAllow. This literal is empty on purpose.
var bestEffortCallAllowlist = map[string]bestEffortCallAllowEntry{}

var bestEffortCallAllowReg = mapRegistry[bestEffortCallAllowEntry]{table: bestEffortCallAllowlist, label: "bestEffortCallAllowlist"}

func registerBestEffortCallAllow(key string, e bestEffortCallAllowEntry) {
	bestEffortCallAllowReg.add(key, e)
}

// Floors under which a green result means the scanner broke. Values at time of
// writing are in the comment; floors sit well under them.
const (
	bestEffortMinProtectedClosures = 20 // 33 besteffort.Run / goSafe closures
	bestEffortMinSetSize           = 15
	bestEffortMinCallsChecked      = 40
)

type beCallSite struct {
	file      string // base name
	fn        string // enclosing declaration label, "(*T).m" or "f"
	callee    string // bare callee name
	line      int
	protected bool // inside a protecting closure or a recovering function
}

func (s beCallSite) key() string { return "internal/core/" + s.file + ":" + s.fn + ":" + s.callee }

type beScan struct {
	declNames      map[string]bool
	selfRecovering map[string]bool // bare name -> every declaration recovers
	set            map[string]string
	sites          []beCallSite
	closures       int
}

func beScanDir(t *testing.T, dir string) *beScan {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("best-effort call-site guard: %v", err)
	}
	files := map[string]*ast.File{}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || strings.Contains(n, "generated") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if perr != nil {
			t.Fatalf("best-effort call-site guard: parse %s: %v", n, perr)
		}
		files[n] = f
		names = append(names, n)
	}
	sort.Strings(names)

	s := &beScan{declNames: map[string]bool{}, selfRecovering: map[string]bool{}, set: map[string]string{}}

	// recoverers: local funcs that call recover() directly, so `defer f()` recovers.
	recoverers := map[string]bool{}
	decls := map[string][]*ast.FuncDecl{}
	for _, n := range names {
		for _, d := range files[n].Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				s.declNames[fd.Name.Name] = true
				decls[fd.Name.Name] = append(decls[fd.Name.Name], fd)
				if callsRecoverDirectly(fd.Body) {
					recoverers[fd.Name.Name] = true
				}
			}
		}
	}
	// selfRecovering: EVERY declaration of the name recovers (top-level defer) or
	// is a pure tail delegation to a self-recovering name. Fixpoint, so a chain
	// of one-line wrappers resolves; a cycle never becomes true.
	for changed := true; changed; {
		changed = false
		for name, fds := range decls {
			if s.selfRecovering[name] {
				continue
			}
			all := true
			for _, fd := range fds {
				if hasRecoveringTopLevelDefer(fd.Body, recoverers) || beBodyIsSingleRun(fd.Body) {
					continue
				}
				if callee, ok := bePureTailCallee(fd.Body); ok && s.selfRecovering[callee] {
					continue
				}
				all = false
				break
			}
			if all {
				s.selfRecovering[name] = true
				s.set[name] = "self-recovering"
				changed = true
			}
		}
	}

	for _, n := range names {
		for _, d := range files[n].Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			recv := ""
			if fd.Recv != nil && len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
				recv = fd.Recv.List[0].Names[0].Name
			}
			fnSafe := hasRecoveringTopLevelDefer(fd.Body, recoverers)
			label := beFuncLabel(fd)
			var visit func(node ast.Node, prot bool)
			visit = func(node ast.Node, prot bool) {
				ast.Inspect(node, func(m ast.Node) bool {
					call, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					if beIsProtectingCall(call) {
						s.closures++
						visit(call.Fun, prot)
						for _, a := range call.Args {
							lit, isLit := a.(*ast.FuncLit)
							if isLit && beIsRunCall(call) {
								// Only a closure that is ONE statement declares its callee:
								// in a multi-statement closure (session_undelivered.go's
								// recovery steps) the other calls are incidental steps of a
								// larger best-effort body, not functions declared best-effort.
								if stmts := beDropTrailingReturnNil(lit.Body.List); len(stmts) == 1 {
									st := stmts[0]
									if c, ok := beStatementCall(st); ok {
										if callee, ok := beLocalCallee(c, recv, s.declNames); ok {
											if _, have := s.set[callee]; !have {
												s.set[callee] = "derived: run by a protecting closure at " + n + ":" + fmt.Sprint(fset.Position(c.Pos()).Line)
											}
										}
									}
								}
							}
							visit(a, prot || isLit)
						}
						return false
					}
					if callee, ok := beLocalCallee(call, recv, s.declNames); ok {
						s.sites = append(s.sites, beCallSite{
							file: n, fn: label, callee: callee,
							line:      fset.Position(call.Pos()).Line,
							protected: prot || fnSafe,
						})
					}
					return true
				})
			}
			visit(fd.Body, false)
		}
	}
	for name, why := range bestEffortSeeds {
		if _, ok := s.set[name]; !ok {
			s.set[name] = "seeded: " + why
		}
	}
	return s
}

// violations returns the unprotected calls to best-effort functions that do not
// recover themselves, sorted.
func (s *beScan) violations() []beCallSite {
	var out []beCallSite
	for _, c := range s.sites {
		if _, member := s.set[c.callee]; !member || c.protected || s.selfRecovering[c.callee] {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].key() != out[j].key() {
			return out[i].key() < out[j].key()
		}
		return out[i].line < out[j].line
	})
	return out
}

// beDropTrailingReturnNil strips a final `return nil`, so the common closure
// shape `func() error { f(); return nil }` counts as one statement.
func beDropTrailingReturnNil(stmts []ast.Stmt) []ast.Stmt {
	if n := len(stmts); n > 1 {
		if r, ok := stmts[n-1].(*ast.ReturnStmt); ok && len(r.Results) == 1 {
			if id, ok := r.Results[0].(*ast.Ident); ok && id.Name == "nil" {
				return stmts[:n-1]
			}
		}
	}
	return stmts
}

// beStatementCall returns the call a closure statement exists to run: an
// expression statement, `return f(...)`, or `x := f(...)` / `_ = f(...)`.
func beStatementCall(st ast.Stmt) (*ast.CallExpr, bool) {
	switch v := st.(type) {
	case *ast.ExprStmt:
		c, ok := v.X.(*ast.CallExpr)
		return c, ok
	case *ast.ReturnStmt:
		if len(v.Results) == 1 {
			c, ok := v.Results[0].(*ast.CallExpr)
			return c, ok
		}
	case *ast.AssignStmt:
		if len(v.Rhs) == 1 {
			c, ok := v.Rhs[0].(*ast.CallExpr)
			return c, ok
		}
	}
	return nil, false
}

// bePureTailCallee: body is exactly one statement, a (returned) call to a bare
// name. Arguments are NOT inspected (documented blind spot).
func bePureTailCallee(body *ast.BlockStmt) (string, bool) {
	if len(body.List) != 1 {
		return "", false
	}
	c, ok := beStatementCall(body.List[0])
	if !ok {
		return "", false
	}
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name, true
	case *ast.SelectorExpr:
		return fn.Sel.Name, true
	}
	return "", false
}

func beLocalCallee(call *ast.CallExpr, recv string, decls map[string]bool) (string, bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, decls[fn.Name]
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok && recv != "" && x.Name == recv {
			return fn.Sel.Name, decls[fn.Sel.Name]
		}
	}
	return "", false
}

func beIsRunCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "besteffort" && sel.Sel.Name == "Run"
}

// beBodyIsSingleRun: the whole body is one besteffort.Run(...) statement, so
// nothing in the function can panic outside the recovering helper.
func beBodyIsSingleRun(body *ast.BlockStmt) bool {
	if len(body.List) != 1 {
		return false
	}
	es, ok := body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	c, ok := es.X.(*ast.CallExpr)
	return ok && beIsRunCall(c)
}

func beIsProtectingCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "goSafe"
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		return ok && x.Name == "besteffort" && fn.Sel.Name == "Run"
	}
	return false
}

// callsRecoverDirectly: body calls recover() itself, not inside a nested func literal.
func callsRecoverDirectly(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "recover" {
				found = true
			}
		}
		return !found
	})
	return found
}

// hasRecoveringTopLevelDefer implements the three recovering-defer idioms
// listed in the file header, as top-level statements of body only.
func hasRecoveringTopLevelDefer(body *ast.BlockStmt, recoverers map[string]bool) bool {
	for _, st := range body.List {
		d, ok := st.(*ast.DeferStmt)
		if !ok {
			continue
		}
		switch fn := d.Call.Fun.(type) {
		case *ast.FuncLit:
			if callsRecoverDirectly(fn.Body) {
				return true
			}
		case *ast.CallExpr: // defer besteffort.RunRecover("x")()
			if sel, ok := fn.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "besteffort" && sel.Sel.Name == "RunRecover" {
					return true
				}
			}
		case *ast.Ident:
			if recoverers[fn.Name] {
				return true
			}
		case *ast.SelectorExpr:
			if recoverers[fn.Sel.Name] {
				return true
			}
		}
	}
	return false
}

func beFuncLabel(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + beTypeStr(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}

func beTypeStr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + beTypeStr(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return beTypeStr(t.X)
	}
	return "?"
}

// TestBestEffortCallSites_EveryCallProtectedOrAllowlisted is the guard proper.
func TestBestEffortCallSites_EveryCallProtectedOrAllowlisted(t *testing.T) {
	t.Parallel()
	s := beScanDir(t, ".")
	var bad []string
	seen := map[string]bool{}
	for _, c := range s.violations() {
		if _, ok := bestEffortCallAllowlist[c.key()]; ok || seen[c.key()] {
			continue
		}
		seen[c.key()] = true
		bad = append(bad, fmt.Sprintf("%s (line %d; %s)", c.key(), c.line, s.set[c.callee]))
	}
	if len(bad) > 0 {
		t.Fatalf("INV-CORE-34: %d call(s) to a best-effort post-commit function are neither panic-protected "+
			"(besteffort.Run / goSafe closure, a top-level recovering defer in the caller) nor to a callee that recovers "+
			"its own panic. A panic there misreports an already-committed write as a failure. Prefer wrapping the call or "+
			"giving the callee its own deferred recover(); otherwise add ONE NEW FILE "+
			"besteffort_callsite_allow_entry_<slug>_test.go calling registerBestEffortCallAllow with a reason:\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestBestEffortCallSites_NoStaleAllowlistRows: a row that pardons nothing
// reads like a load-bearing one and silently pre-approves the shape coming back.
func TestBestEffortCallSites_NoStaleAllowlistRows(t *testing.T) {
	t.Parallel()
	s := beScanDir(t, ".")
	live := map[string]bool{}
	for _, c := range s.violations() {
		live[c.key()] = true
	}
	var stale []string
	for k, e := range bestEffortCallAllowlist {
		if strings.TrimSpace(e.reason) == "" {
			t.Errorf("allowlist row %q has no reason", k)
		}
		if !live[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("INV-CORE-34: allowlist row(s) match no current unprotected call; delete them:\n  %s", strings.Join(stale, "\n  "))
	}
}

// TestBestEffortCallSites_SeedsAreDeclared guards the condition behind the
// SEEDED half of the set: every seed must still be declared in internal/core.
func TestBestEffortCallSites_SeedsAreDeclared(t *testing.T) {
	t.Parallel()
	s := beScanDir(t, ".")
	for name := range bestEffortSeeds {
		if !s.declNames[name] {
			t.Errorf("seed %q is not declared in internal/core any more: it was renamed or removed, so INV-CORE-34's "+
				"guard no longer covers it. Update bestEffortSeeds (and the invariant text) to the new name", name)
		}
	}
}

// TestBestEffortCallSites_ScanPreconditionHolds: green results above are vacuous
// when the scan finds nothing, so guard the population, not just the verdict.
func TestBestEffortCallSites_ScanPreconditionHolds(t *testing.T) {
	t.Parallel()
	s := beScanDir(t, ".")
	if s.closures < bestEffortMinProtectedClosures {
		t.Errorf("only %d besteffort.Run/goSafe call(s) found, floor %d: the protecting-call matcher stopped matching",
			s.closures, bestEffortMinProtectedClosures)
	}
	if len(s.set) < bestEffortMinSetSize {
		t.Errorf("best-effort set has %d member(s), floor %d: derivation collapsed", len(s.set), bestEffortMinSetSize)
	}
	if len(s.sites) < bestEffortMinCallsChecked {
		t.Errorf("only %d local call(s) resolved, floor %d: the callee resolver stopped matching", len(s.sites), bestEffortMinCallsChecked)
	}
	protected := 0
	for _, c := range s.sites {
		if _, m := s.set[c.callee]; m && (c.protected || s.selfRecovering[c.callee]) {
			protected++
		}
	}
	if protected < bestEffortMinCallsChecked/2 {
		t.Errorf("only %d call(s) to set members classified protected: protection derivation collapsed", protected)
	}
}

// TestBestEffortCallSites_ScannerFixture plants one violation and one safe
// example of every recognised form in a temp package, so the guard is proven
// to go red and green independent of the repository's contents.
func TestBestEffortCallSites_ScannerFixture(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package fixture

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/besteffort"
)

type C struct{}

func goSafe(fn func()) { defer besteffort.RunRecover("x")(); fn() }

func recoverPostCommitX() { _ = recover() }

// bare: not self-recovering, wrapped in Run below, called bare in Violator.
func (c *C) notify() {}

// selfSafe recovers itself: calls to it are never violations.
func (c *C) selfSafe() { defer func() { _ = recover() }() }

func (c *C) Wrapped(ctx context.Context) {
	besteffort.Run(ctx, "w", func() error { c.notify(); return nil })
	goSafe(func() { c.notify() })
}

func (c *C) Violator(ctx context.Context) { c.notify() }

func (c *C) ViolatorPkgLevel() { pkgNotify() }

func pkgNotify() {}

func (c *C) usesPkg(ctx context.Context) {
	besteffort.Run(ctx, "p", func() error { pkgNotify(); return nil })
}

func (c *C) Safe1(ctx context.Context) { defer recoverPostCommitX(); c.notify() }

func (c *C) Safe2() { defer besteffort.RunRecover("s")(); c.notify() }

func (c *C) Safe3() { defer func() { _ = recover() }(); c.notify() }

func (c *C) Safe4(ctx context.Context) { c.selfSafe(); besteffort.Run(ctx, "s", func() error { c.selfSafe(); return nil }) }

// NestedDefer: a defer inside an if is NOT credited (documented blind spot).
func (c *C) NestedDefer(ok bool) {
	if ok {
		defer func() { _ = recover() }()
	}
	c.notify()
}

// MultiHop: c.x.notify() is not a recognised form and is never flagged.
type D struct{ c *C }

func (d *D) MultiHop() { d.c.notify() }
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	s := beScanDir(t, dir)
	got := map[string]bool{}
	for _, v := range s.violations() {
		got[v.fn+":"+v.callee] = true
	}
	for _, want := range []string{
		"(*C).Violator:notify",
		"(*C).ViolatorPkgLevel:pkgNotify",
		"(*C).NestedDefer:notify",
	} {
		if !got[want] {
			t.Errorf("fixture violation %s not reported (guard cannot go red); got %v", want, got)
		}
	}
	for _, safe := range []string{"Safe1", "Safe2", "Safe3", "Safe4", "Wrapped", "MultiHop"} {
		for k := range got {
			if strings.Contains(k, "."+safe+":") {
				t.Errorf("fixture safe form %s was reported (guard cannot go green): %s", safe, k)
			}
		}
	}
	if len(got) != 3 {
		t.Errorf("expected exactly 3 fixture violations, got %d: %v", len(got), got)
	}
}

// TestBestEffortCallSites_MutationKillsRecoverWrapper is the red proof, kept as
// a permanent test instead of a one-off: it copies internal/core's non-test
// sources into a temp dir, breaks ONE recovery mechanism in the copy (the
// production tree is never touched), and requires the guard to report the
// callers that lose their protection. Each mutation also asserts its anchor text
// still exists exactly once, so a refactor that moves the code fails here
// instead of turning the proof into a vacuous no-op.
func TestBestEffortCallSites_MutationKillsRecoverWrapper(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		file       string
		anchor     string // must occur exactly once in file
		replace    string
		wantCallee string // a violation whose key ends ":<wantCallee>" must appear
	}{
		{
			name:       "delete evictUserSessionCache's recover",
			file:       "account.go",
			anchor:     "if r := recover(); r != nil {\n\t\t\tlog.Printf(\"SECURITY: evictUserSessionCache panicked",
			replace:    "if r := noRecover(); r != nil {\n\t\t\tlog.Printf(\"SECURITY: evictUserSessionCache panicked",
			wantCallee: "evictUserSessionCache",
		},
		{
			name:       "delete writeAuditEventDiffOn's recover (breaks the whole audit wrapper chain)",
			file:       "audit.go",
			anchor:     "if r := recover(); r != nil {\n\t\t\tlogging.Event(ctx, logging.LevelError, fmt.Sprintf(\"SECURITY: writeAuditEventDiffOn panicked",
			replace:    "if r := noRecover(); r != nil {\n\t\t\tlogging.Event(ctx, logging.LevelError, fmt.Sprintf(\"SECURITY: writeAuditEventDiffOn panicked",
			wantCallee: "writeAuditEventFull",
		},
		{
			name:       "unwrap a besteffort.Run call site",
			file:       "sso.go",
			anchor:     `besteffort.Run(ctx, "sso.CompleteSSO.clearLoginFailures", func() error { c.clearLoginFailures(ctx, user); return nil })`,
			replace:    "c.clearLoginFailures(ctx, user)",
			wantCallee: "clearLoginFailures",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			entries, err := os.ReadDir(".")
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				n := e.Name()
				if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
					continue
				}
				b, rerr := os.ReadFile(n)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if n == tc.file {
					if got := strings.Count(string(b), tc.anchor); got != 1 {
						t.Fatalf("mutation anchor occurs %d times in %s (want exactly 1): the code moved, update the anchor", got, n)
					}
					b = []byte(strings.Replace(string(b), tc.anchor, tc.replace, 1))
				}
				if werr := os.WriteFile(filepath.Join(tmp, n), b, 0o600); werr != nil {
					t.Fatal(werr)
				}
			}
			base := map[string]bool{}
			for _, v := range beScanDir(t, ".").violations() {
				base[v.key()+fmt.Sprint(v.line)] = true
			}
			var fresh []string
			found := false
			for _, v := range beScanDir(t, tmp).violations() {
				if base[v.key()+fmt.Sprint(v.line)] {
					continue
				}
				fresh = append(fresh, v.key())
				if strings.HasSuffix(v.key(), ":"+tc.wantCallee) {
					found = true
				}
			}
			if !found {
				t.Errorf("breaking %q did not make the guard report a call to %s (new violations: %v) -- the guard cannot go red for this mechanism",
					tc.name, tc.wantCallee, fresh)
			}
		})
	}
}
