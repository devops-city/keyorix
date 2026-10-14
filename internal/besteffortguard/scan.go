// Package besteffortguard is the AST scanner behind the best-effort-after-commit
// structural guard (GUARD-1, #2561). It is test-support code: the three
// packages that run the guard (internal/core, server/http/handlers,
// server/grpc/services) import it from their own _test.go files only, so it is
// never linked into the server binary.
//
// # What the guard is for
//
// QA-1 found the same defect 12+ times, one call site at a time: a best-effort
// step that runs AFTER a storage write has already committed (evict a cache,
// notify an admin, emit an audit event) panics, the panic escapes, and the
// caller reports failure for an operation that actually succeeded. The guard
// makes the shape structural rather than something a reviewer has to spot: a
// call whose result is dropped, textually after the last storage write in the
// same function, must either be routed through goSafe/besteffort.Run (which
// recover) or carry a reviewed exemption saying why its callee already
// recovers internally.
//
// # Why this lives in one package instead of three copies
//
// It used to be three near-identical copies of one AST walk, differing only in
// a receiver-field name. #2561's review required a type-of-callee lookup, a
// planted-positive fixture and a stale-exemption check on top of that, which is
// more logic than is sensible to maintain in triplicate. The per-package
// differences are now Options fields.
//
// # What this scanner does NOT see
//
// Stated explicitly, because a guard that is silent about its blind spots is
// how the previous version came to be trusted further than it had earned
// (CLAUDE.md: "Ask of any mechanism: what does it silently skip, and does it
// say so?"). In particular:
//
//   - It is CONTROL-FLOW BLIND. "After the last write" is textual position, so
//     a discard in one arm of a mutually-exclusive if/else is flagged exactly
//     like a true sequential case. Same documented caveat as
//     atomicity_guard_test.go's write-count scan.
//   - It is CALLER-SIDE ONLY. It cannot see that a callee recovers its own
//     panic; that is precisely what the exemption file records.
//   - It scans only *.go files DIRECTLY under the root, not subpackages.
//   - Its "is this a storage write" test is a verb-prefix regex on the method
//     name (optionally restricted to one receiver field), not a type-checked
//     resolution to a storage interface method.
//   - For bare calls, it resolves the callee's return arity only for functions
//     and methods DECLARED IN THE SCANNED PACKAGE, by the three call forms
//     listed on resolveLocalReturns. A call it cannot resolve is not flagged,
//     so this half of the guard under-reports by construction rather than
//     guessing.
//   - panicSafetyIndex resolves a callee by its BARE name only, never by
//     receiver type -- two methods on different types sharing a name are the
//     SAME entry in the index (#2561 round 2). A collision resolves toward
//     unsafe (every declaration sharing the name must itself be safe), which
//     is the conservative direction, but it also means a genuinely-safe
//     method can be denied the derivation solely because an unrelated,
//     unsafe, same-named method exists elsewhere in the same package -- that
//     site would then need a reviewed exemption despite being fine on its
//     own. Resolving by (package, receiver type, name) instead would need a
//     type-checked pass this scanner does not do.
package besteffortguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// writeVerbRe matches a method name that looks like a storage write. A prefix
// regex, not a type-checked resolution to storage.Storage -- see the package
// doc's blind-spot list.
var writeVerbRe = regexp.MustCompile(`^(Create|Update|Delete|Assign|Unassign|Set|Remove|Add|Revoke|Insert|Upsert|Save|Mark|Record|Increment|Rotate|Restore|Purge|Archive|Grant|Link|Unlink|Replace|Put|Store|Clear|Reset|Enable|Disable|Lock|Unlock|Consume|Approve|Reject|Expire|Touch|Bump|Append|Move|Rename|Transfer|Finalize|Complete|Cancel|Provision|Deprovision|Patch|Activate|Deactivate|Issue|Open|Close|Withdraw)`)

// DiscardKind distinguishes the two shapes the guard flags.
type DiscardKind string

const (
	// KindBlank is `_ = f(...)` / `_, _ = f(...)`: an explicit discard.
	KindBlank DiscardKind = "blank"
	// KindBare is `f(...)` as a statement, where f is declared in the scanned
	// package and returns at least one value -- an IMPLICIT discard (#2561).
	// The original guard saw only KindBlank, so a post-commit step whose author
	// simply never assigned the result was invisible to it, even though the
	// panic-escape risk is identical.
	KindBare DiscardKind = "bare"
)

// Hit is one flagged discard.
type Hit struct {
	Func        string // "Name", or "(*Type).Name" for a method
	File        string // base name, within the scanned root
	Kind        DiscardKind
	WriteLine   int
	WriteCall   string
	DiscardLine int
	// DiscardCall is the callee as written, e.g. "c.evictUserSessionCache".
	DiscardCall string
	// Callee is just the final name segment, e.g. "evictUserSessionCache" --
	// this is what an exemption key is matched on, so an exemption survives a
	// receiver rename but NOT a change of which function is being discarded.
	Callee string
}

// Key identifies an exemption: the enclosing function AND the specific callee
// whose result it discards.
//
// Keying on the function alone (the original scheme) made an exemption a
// blanket pardon for the whole function body: once `(*KeyorixCore).ActivateMFA`
// was exempt for discarding one already-self-recovering callee, a NEW
// unprotected discard of a DIFFERENT callee added to that same function was
// silently absorbed by the existing row. That is the opposite of what the
// exemption records, which is always a claim about one specific callee.
type Key struct {
	Func   string
	Callee string
}

func (k Key) String() string { return k.Func + "#" + k.Callee }

// Options configures a scan for one package.
type Options struct {
	// WriteReceiverField, when non-empty, restricts write-verb matching to
	// calls of the form `<x>.<WriteReceiverField>.<Method>(...)`. internal/core
	// leaves it empty (it calls c.storage.X and its own helpers directly);
	// server/http/handlers sets "coreService" and server/grpc/services sets
	// "core", because those packages call Header().Set(...),
	// csv.Writer.Write(...) and json.Encoder.Encode(...) constantly, none of
	// which is a storage commit.
	WriteReceiverField string
}

// Stats describes what the scan actually looked at. It exists so a caller can
// guard the scan's own PRECONDITION rather than only its conclusion.
//
// "Zero unclassified hits" is a vacuous result if no writes were detected at
// all: the population is empty precisely because the scan found nothing to
// populate it with, and the guard then passes forever regardless of whether
// the property still holds (CLAUDE.md: "when a verdict depends on a condition,
// guard the condition, not the conclusion"). server/http/handlers and
// server/grpc/services both legitimately produce zero hits today, so for those
// two packages FuncsWithWrite is the only number that can tell a clean scan
// apart from a broken one.
type Stats struct {
	// Files/Funcs scanned.
	Files int
	Funcs int
	// FuncsWithWrite is how many functions contained at least one call the
	// write-verb matcher recognised (after any WriteReceiverField restriction).
	// If this collapses, the scan has stopped finding writes and every "0 hits"
	// downstream means nothing.
	FuncsWithWrite int
	// DiscardSites is how many discards were found anywhere in the package,
	// irrespective of position relative to a write -- the other half of the
	// precondition. Hits are the subset that follow the last write.
	DiscardSites int
	// ProtectedDiscards is how many post-write discards were classified as
	// already panic-safe (see panicSafetyIndex) and so are NOT hits.
	//
	// This is the number that keeps the guard honest once the codebase is
	// clean. With protection DERIVED rather than exempted, a correct package
	// legitimately has zero hits, so a hit floor cannot distinguish "clean"
	// from "the scanner resolved nothing". A non-zero ProtectedDiscards proves
	// the scanner is still resolving callees AND still finding their recovers
	// -- the two steps that produce the "safe" verdict.
	ProtectedDiscards int
}

// Result is a scan's output.
type Result struct {
	Hits  []Hit
	Stats Stats
	// SafeCallees lists the package-local functions the scan classified as
	// panic-safe, so a guard can assert the specific ones its correctness
	// depends on are still being recognised.
	SafeCallees []string
}

// Scan walks every non-test, non-generated *.go file directly under root and
// returns every unprotected post-write discard, sorted deterministically,
// alongside the Stats needed to tell a clean scan from a broken one.
func Scan(root string, opts Options) (*Result, error) {
	fset := token.NewFileSet()
	files, err := parsePackageFiles(fset, root)
	if err != nil {
		return nil, err
	}
	localReturns := buildLocalReturnArity(files)

	safe := newPanicSafetyIndex(files)

	res := &Result{Stats: Stats{Files: len(files)}}
	for name, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			res.Stats.Funcs++
			hits, st := scanFunc(fset, name, fd, localReturns, safe, opts)
			if st.sawWrite {
				res.Stats.FuncsWithWrite++
			}
			res.Stats.DiscardSites += st.discards
			res.Stats.ProtectedDiscards += st.protected
			if funcHasRunRecoverGuard(fd.Body) {
				continue // the whole function recovers any panic in itself
			}
			res.Hits = append(res.Hits, hits...)
		}
	}
	res.SafeCallees = safe.SafeCallees()
	hits := res.Hits
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Func != hits[j].Func {
			return hits[i].Func < hits[j].Func
		}
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].DiscardLine < hits[j].DiscardLine
	})
	return res, nil
}

// DistinctPairs counts the (function, callee) pairs among hits -- the unit an
// exemption answers for, and so the unit a minimum-count floor is stated in.
func DistinctPairs(hits []Hit) int {
	seen := map[Key]bool{}
	for _, h := range hits {
		seen[Key{Func: h.Func, Callee: h.Callee}] = true
	}
	return len(seen)
}

func parsePackageFiles(fset *token.FileSet, root string) (map[string]*ast.File, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("besteffortguard: cannot read %s: %w", root, err)
	}
	out := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if perr != nil {
			return nil, fmt.Errorf("besteffortguard: cannot parse %s: %w", filepath.Join(root, name), perr)
		}
		out[name] = f
	}
	return out, nil
}

// buildLocalReturnArity maps each function/method NAME declared in the scanned
// package to its number of return values. Keyed by bare name, so two methods
// of the same name on different types collide; the collision is resolved
// toward "has returns" (max), which is the fail-closed direction for a guard --
// it can over-flag, never under-flag, on an ambiguous name.
func buildLocalReturnArity(files map[string]*ast.File) map[string]int {
	out := map[string]int{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			n := 0
			if fd.Type.Results != nil {
				for _, fld := range fd.Type.Results.List {
					if len(fld.Names) == 0 {
						n++
					} else {
						n += len(fld.Names)
					}
				}
			}
			if n > out[fd.Name.Name] {
				out[fd.Name.Name] = n
			}
		}
	}
	return out
}

type discardSite struct {
	pos    token.Pos
	call   string
	callee string
	kind   DiscardKind
}

// panicSafetyIndex answers "is a panic inside this package-local function
// already recovered before it can reach its caller?"
//
// This is #2561's main structural change, and it is why the exemption file has
// no rows. v1 (and this PR's first draft) recorded "the callee recovers its own
// panic" as a human-vouched exemption ROW. That is strictly weaker than
// deriving it: an exemption keeps pardoning the call site even after someone
// deletes the recover() it was premised on, which is the exact shape of a guard
// that certifies a real bug as correct. Derived, the same fact fails loudly the
// moment it stops being true -- CLAUDE.md's "derive and check it" over "assert
// it in prose".
//
// A function is panic-safe here if its OWN body defers a recover() (directly,
// or via besteffort.RunRecover), OR -- #2561 round 2 -- its ENTIRE body is a
// single statement that does nothing but tail-call another package-local,
// already-safe function (pureTailDelegationCallee). Nothing broader than that
// is transitive.
//
// That restriction is the whole correctness of this index, and it cost a draft
// to learn. The obvious generalisation -- "safe if it CALLS something that
// recovers" -- marked 365 of internal/core's 1430 functions safe, because
// almost every function eventually calls an audit helper that funnels into
// emitAudit's recover(). It is simply false: a recover() in a callee protects
// only that callee. A panic in any other part of the caller's body still
// escapes, so the generalisation would have suppressed exactly the reports this
// guard exists to make.
//
// The pure-tail-delegation exception is narrow enough to not be that bug: it
// requires the body to be NOTHING ELSE -- no argument construction beyond
// forwarding the exact same values, no other statement before or after. A
// wrapper shaped that way adds zero panic surface of its own, so its safety
// is IDENTICAL to its sole callee's, not inferred from a pattern that could
// coexist with real, unprotected risk elsewhere in a larger body. Added when
// main's #2827 turned writeAuditEventFull/writeAuditEventDiff into exactly
// this shape (-> writeAuditEventFullOn/writeAuditEventDiffOn) and moved the
// #2561 recover to the new choke point (writeAuditEventDiffOn, which now
// protects its own argument/struct construction too, unlike the pre-#2827
// writeAuditEventDiff this comment used to cite as the reason an exemption
// was still needed) -- without it, those two thin wrappers regressed to
// "not derived-safe" despite genuinely being so, which would have reopened
// 42 call sites across internal/core to either a real fix or a reviewed
// exemption for a risk that no longer exists.
type panicSafetyIndex struct {
	// bodies maps a bare function/method name to EVERY declaration sharing it
	// -- see isSafe's doc comment for why a collision requires all of them.
	bodies map[string][]*ast.FuncDecl
	memo   map[string]bool
}

func newPanicSafetyIndex(files map[string]*ast.File) *panicSafetyIndex {
	idx := &panicSafetyIndex{bodies: map[string][]*ast.FuncDecl{}, memo: map[string]bool{}}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				// Keyed by bare name, so same-named methods on different types
				// collide -- every declaration sharing the name is kept, not
				// just the first one (#2561 round 2; see isSafe).
				idx.bodies[fd.Name.Name] = append(idx.bodies[fd.Name.Name], fd)
			}
		}
	}
	return idx
}

// isSafe reports whether name is a package-local function whose panics cannot
// escape. A name that is not declared in this package is never "safe": the
// scanner cannot see it, so it must not claim anything about it.
//
// A name is safe only if EVERY declaration sharing it is safe (#2561 round
// 2). The pre-fix version kept only the FIRST declaration encountered while
// building the index -- map iteration over `files` has no defined order, so
// which declaration "won" was nondeterministic, and whichever one won
// decided the verdict for every OTHER same-named declaration too, including
// ones the index never even looked at. A same-named method on a second type
// that genuinely does not recover would have been silently credited as safe
// whenever the OTHER same-named method's declaration happened to be visited
// first.
func (p *panicSafetyIndex) isSafe(name string) bool {
	if v, ok := p.memo[name]; ok {
		return v
	}
	fds, ok := p.bodies[name]
	if !ok || len(fds) == 0 {
		p.memo[name] = false
		return false
	}
	// Cycle guard: memoize false BEFORE recursing into pureTailDelegationCallee,
	// so a self- or mutually-recursive pure delegation (which could never
	// actually recover anything -- it would tail-call itself forever) resolves
	// to not-safe instead of infinite-looping isSafe.
	p.memo[name] = false
	safe := true
	for _, fd := range fds {
		if p.isSafeDecl(fd) {
			continue
		}
		safe = false
		break
	}
	p.memo[name] = safe
	return safe
}

// isSafeDecl reports whether one specific declaration is panic-safe, by
// itself -- either its own body defers a recover, or it is a pure tail
// delegation to another already-safe name.
func (p *panicSafetyIndex) isSafeDecl(fd *ast.FuncDecl) bool {
	if bodyDefersRecover(fd.Body) {
		return true
	}
	callee, ok := pureTailDelegationCallee(fd.Body)
	return ok && p.isSafe(callee)
}

// pureTailDelegationCallee reports the bare function/method name body
// delegates to, when body is EXACTLY one statement -- `return callee(...)` or
// a bare `callee(...)` expression statement -- with nothing else before or
// after it. Resolved to a bare name (fn.Sel.Name for a method/package call,
// fn.Name for a plain call), the same callee-resolution shape
// deferIsRunRecoverGuard and funcHasRunRecoverGuard already use, consistent
// with this package's documented bare-name collision caveat.
func pureTailDelegationCallee(body *ast.BlockStmt) (string, bool) {
	if len(body.List) != 1 {
		return "", false
	}
	var call *ast.CallExpr
	switch s := body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(s.Results) != 1 {
			return "", false
		}
		call, _ = s.Results[0].(*ast.CallExpr)
	case *ast.ExprStmt:
		call, _ = s.X.(*ast.CallExpr)
	}
	if call == nil {
		return "", false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, true
	case *ast.SelectorExpr:
		return fn.Sel.Name, true
	}
	return "", false
}

// SafeCallees returns the package-local functions this index considers
// panic-safe, sorted. Exposed so a package's guard can assert that the specific
// callees its correctness depends on are still being recognised -- guarding the
// condition rather than the conclusion.
func (p *panicSafetyIndex) SafeCallees() []string {
	var out []string
	for name := range p.bodies {
		if p.isSafe(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// funcStats is scanFunc's precondition reporting (see Stats).
type funcStats struct {
	sawWrite  bool
	discards  int
	protected int
}

func scanFunc(fset *token.FileSet, file string, fd *ast.FuncDecl, localReturns map[string]int, safe *panicSafetyIndex, opts Options) ([]Hit, funcStats) {
	var lastWrite token.Pos
	var lastWriteName string
	var discards []discardSite
	// discardedWrites are write-verb calls whose result is itself blank-
	// discarded (`_ = c.storage.AddPasswordHistory(...)`). Such a write is a
	// best-effort step, not the operation's commit, so it must not become the
	// "last write" anchor -- otherwise it hides itself (the discard sits AT the
	// anchor, never after it) and, with no checked write after it, the guard
	// never fires. Found by FuzzStorageFaultOperations: CreateUserWithRoles'
	// `_ = c.storage.AddPasswordHistory` panicked past an already-committed
	// user create and reported failure (GRPC UserService.CreateUser,
	// AddPasswordHistory#1/panic, oracle (a), [User UserRole]).
	discardedWrites := map[token.Pos]bool{}

	var walk func(n ast.Node, protected bool)
	walk = func(n ast.Node, protected bool) {
		ast.Inspect(n, func(m ast.Node) bool {
			if call, ok := m.(*ast.CallExpr); ok && isProtectingCall(call) {
				for _, a := range call.Args {
					walk(a, true)
				}
				return false
			}
			if assign, ok := m.(*ast.AssignStmt); ok && isBlankDiscard(assign) {
				if !protected {
					call, callee := discardCallName(assign)
					discards = append(discards, discardSite{pos: assign.Pos(), call: call, callee: callee, kind: KindBlank})
				}
				for _, rhs := range assign.Rhs {
					if call, ok := rhs.(*ast.CallExpr); ok {
						discardedWrites[call.Pos()] = true
					}
				}
				return true
			}
			// #2561: a bare call statement whose result is dropped. Only
			// package-local callees with a non-zero return arity -- see
			// resolveLocalReturns for the exact call forms recognised.
			if es, ok := m.(*ast.ExprStmt); ok {
				if call, ok := es.X.(*ast.CallExpr); ok && !protected && !isProtectingCall(call) {
					if name, callee, n, ok := resolveLocalReturns(call, localReturns); ok && n > 0 {
						discards = append(discards, discardSite{pos: es.Pos(), call: name, callee: callee, kind: KindBare})
					}
				}
				return true
			}
			if call, ok := m.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
					writeVerbRe.MatchString(sel.Sel.Name) && matchesWriteReceiver(sel, opts) &&
					!discardedWrites[call.Pos()] {
					if call.Pos() > lastWrite {
						lastWrite, lastWriteName = call.Pos(), sel.Sel.Name
					}
				}
			}
			return true
		})
	}
	walk(fd.Body, false)

	st := funcStats{sawWrite: lastWrite != 0, discards: len(discards)}
	if lastWrite == 0 {
		return nil, st
	}
	fn := funcLabel(fd)
	var hits []Hit
	for _, d := range discards {
		if d.pos <= lastWrite {
			continue
		}
		// The callee already recovers (itself, or through a package-local
		// funnel), so a panic in it cannot reach this already-committed
		// caller. Derived, not exempted -- see panicSafetyIndex.
		if safe.isSafe(d.callee) {
			st.protected++
			continue
		}
		hits = append(hits, Hit{
			Func: fn, File: file, Kind: d.kind,
			WriteLine: fset.Position(lastWrite).Line, WriteCall: lastWriteName,
			DiscardLine: fset.Position(d.pos).Line, DiscardCall: d.call, Callee: d.callee,
		})
	}
	return hits, st
}

// resolveLocalReturns reports the callee's name, its final name segment, and
// its return arity, for the call forms this scanner recognises:
//
//  1. `foo(...)`        -- a package-level function or a method called on an
//     implicit receiver is not expressible in Go, so this is
//     always a package-level func (or a func-typed variable,
//     which will simply not be in the map).
//  2. `x.foo(...)`      -- a method call on a one-level receiver, including the
//     common `c.foo(...)` on the package's own type.
//  3. `x.y.foo(...)`    -- a method call through one field hop.
//
// The name is looked up in localReturns, which only contains functions
// DECLARED IN THE SCANNED PACKAGE. A call into another package (log.Printf,
// json.NewEncoder(w).Encode) therefore never resolves and is never flagged --
// deliberately, since those are not this codebase's own best-effort steps, and
// resolving them would need full type information.
//
// Enumerating the recognised forms explicitly, rather than leaving them
// implicit in the code, is CLAUDE.md's "an enumeration is only as complete as
// the idioms it knows about" applied to this scanner: a reviewer can check this
// list. Forms deliberately NOT recognised (and so NOT flagged): a call through
// a func-typed struct field or local variable, a method value, a deeper
// selector chain than one hop, and anything behind an interface whose dynamic
// type is in this package.
func resolveLocalReturns(call *ast.CallExpr, localReturns map[string]int) (name, callee string, arity int, ok bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		n, found := localReturns[fn.Name]
		return fn.Name, fn.Name, n, found
	case *ast.SelectorExpr:
		switch fn.X.(type) {
		case *ast.Ident, *ast.SelectorExpr:
			n, found := localReturns[fn.Sel.Name]
			return exprStr(fn.X) + "." + fn.Sel.Name, fn.Sel.Name, n, found
		}
	}
	return "", "", 0, false
}

func matchesWriteReceiver(sel *ast.SelectorExpr, opts Options) bool {
	if opts.WriteReceiverField == "" {
		return true
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && inner.Sel.Name == opts.WriteReceiverField
}

// isProtectingCall reports whether call is goSafe(...) or besteffort.Run(...)
// -- both take a func literal whose body is already panic-protected, so a
// discard inside that literal needs no further protection.
func isProtectingCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "goSafe"
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		return ok && x.Name == "besteffort" && (fn.Sel.Name == "Run" || fn.Sel.Name == "RunRecover")
	}
	return false
}

// funcHasRunRecoverGuard reports whether body contains, as a TOP-LEVEL defer
// statement, a call shaped like besteffort.RunRecover("...")() -- the
// function-wide guard shape (used by goSafe's own goroutine body) that
// recovers a panic anywhere later in the same function, not just inside a
// nested closure.
//
// Scoped via collectTopLevelDefers (#2561 round 2), not a full ast.Inspect
// walk: the pre-fix version matched this call shape anywhere in body,
// including nested inside an unrelated spawned `go func(){...}()` elsewhere
// in the function -- which recovers only THAT goroutine's own panics, not a
// panic from any other, unprotected statement in this function's own
// synchronous body. Crediting that nested match as "the whole function
// recovers any panic in itself" (this function's sole caller, Scan) would
// have suppressed every real discard finding for the rest of the function.
func funcHasRunRecoverGuard(body *ast.BlockStmt) bool {
	return slices.ContainsFunc(collectTopLevelDefers(body), deferIsRunRecoverGuard)
}

// isBlankDiscard reports whether assign is `_ = f(...)` or `_, _ = f(...)`.
func isBlankDiscard(assign *ast.AssignStmt) bool {
	if len(assign.Lhs) == 0 || len(assign.Rhs) == 0 {
		return false
	}
	for _, l := range assign.Lhs {
		id, ok := l.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	for _, r := range assign.Rhs {
		if _, ok := r.(*ast.CallExpr); !ok {
			return false
		}
	}
	return true
}

func discardCallName(assign *ast.AssignStmt) (name, callee string) {
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "?", "?"
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return exprStr(fn.X) + "." + fn.Sel.Name, fn.Sel.Name
	case *ast.Ident:
		return fn.Name, fn.Name
	}
	return "?", "?"
}

func exprStr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + exprStr(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprStr(t.X) + "." + t.Sel.Name
	}
	return "?"
}

func funcLabel(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + exprStr(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}
