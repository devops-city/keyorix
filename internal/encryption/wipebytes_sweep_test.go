// wipebytes_sweep_test.go: INV-ENCRYPTION-25's completeness sweep. Every
// key-shaped []byte local in this package (a variable assigned from a call
// that yields KEK, DEK, or KEK-derived key material) must be wiped with
// wipeBytes, or have its ownership handed off, on every return path after the
// assignment.
//
// An AST walk in the style of internal/core's atomicity_guard_test.go, with no
// type checking and only a lexical notion of "path". What it recognises,
// stated explicitly so a reviewer can check it:
//
// Sources. A call is a candidate when its callee name (a local identifier, or
// the selector of x.Name(...)) matches keyishCalleeRe and its first result is
// bound to a named variable. Every candidate callee name must be classified in
// keyMaterialSources (yields key material: tracked) or notKeyMaterialCallees
// (yields something else: ignored, with a reason). An unclassified name fails
// the test, so a new key-producing helper or provider method cannot slip past
// by having a name this file has not seen. Separately, every package-level
// function in this package whose name matches keyishCalleeRe and whose first
// result is []byte must be classified the same way, even if nothing calls it
// yet.
//
// What counts as handled, for each return statement reachable after the
// assignment (and the implicit return at the end of a function body):
//   - a `wipeBytes(v)` statement, or a `defer wipeBytes(v)` (directly or inside
//     a deferred func literal), earlier on the same lexical path;
//   - an ownership hand-off earlier on the path: `x.field = v`;
//   - the return statement itself returning v (the caller now owns it);
//   - the return sits inside the `if err != nil` that immediately follows the
//     assignment, where err is the assignment's own error result (v is nil or
//     unusable there);
//   - v passed to a retainingCallees function (it keeps the slice), except on
//     the `if err != nil` right after that call, where nothing kept it;
//   - the (function, variable) pair is listed in wipeSweepExempt with a reason.
//
// Real gaps found on main are listed in knownWipeGaps (#2512) and reported by
// the skipped TestWipeBytesSweep_KnownGaps instead of failing the sweep.
//
// What it does not check, by construction:
//   - control flow beyond nesting: a wipe inside one branch of an if does not
//     count for code after the if, and loops are walked once;
//   - wipes through any helper other than wipeBytes itself;
//   - sources bound by a `var v = f()` declaration or a multi-call assignment
//     (only `v, ... := f(...)` / `v, ... = f(...)` with one call is a source);
//   - key material that reaches a variable without a call (slicing, copy,
//     make+fill, struct field reads such as km.currentDEK);
//   - that a struct field holding key material is wiped before it is
//     overwritten or on shutdown (keymanager_io.go's Wipe and
//     g62_dek_safety_test.go cover the fields individually);
//   - plaintext secret values (sweep.go/sweep_auth.go wipe those, but they are
//     not key material and are not tracked here);
//   - test files, and packages other than internal/encryption.
package encryption

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
	"testing"
)

var keyishCalleeRe = regexp.MustCompile(`(?i)(kek|dek|key)`)

// keyMaterialSources are callee names whose first result is key material the
// caller owns and must wipe.
var keyMaterialSources = map[string]string{
	"GenerateRandomKey":        "fresh random DEK",
	"KEK":                      "crypto.KeyProvider.KEK(): the plaintext KEK",
	"deriveKEK":                "plaintext KEK from the configured provider or passphrase",
	"unwrapDEK":                "plaintext DEK unwrapped under the KEK",
	"unwrapKey":                "plaintext key unwrapped under the KEK",
	"deriveEvidenceSignKey":    "KEK-derived evidence-signing key",
	"deriveAuditCheckpointKey": "KEK-derived audit-checkpoint key",
	"DeriveBackupManifestKey":  "auditverify.DeriveBackupManifestKey: KEK-derived backup-manifest key",
	"GenerateKEK":              "PBKDF2-derived KEK",
	"GetDEK":                   "returns a fresh copy of the DEK; the caller owns the copy",
	"GetEvidenceSignKey":       "returns a fresh copy of the evidence-signing key",
	"GetAuditCheckpointKey":    "returns a fresh copy of the audit-checkpoint key",
	"GetBackupManifestKey":     "returns a fresh copy of the backup-manifest key",
	"AuditCheckpointKey":       "Service getter, forwards GetAuditCheckpointKey's copy",
	"BackupManifestKey":        "Service getter, forwards GetBackupManifestKey's copy",
	"EvidenceSignKey":          "Service getter, forwards GetEvidenceSignKey's copy",
}

// notKeyMaterialCallees match keyishCalleeRe but do not yield key material.
var notKeyMaterialCallees = map[string]string{
	"ensureSaltExists":         "KEK salt: public by design (stored next to the wrapped DEK)",
	"wrapKey":                  "wrapped (encrypted) key: ciphertext, safe to persist",
	"GetKeyVersion":            "key version label string",
	"readDEKEpoch":             "DEK epoch: a DEK fingerprint (HMAC output) stored in the database, not key bytes",
	"casDEKEpoch":              "DEK epoch compare-and-set: returns whether it applied",
	"lockRelPath":              "lock file path",
	"openKeyLockFile":          "lock file handle",
	"keyFileSpecs":             "file permission specs",
	"normalizeKeyPaths":        "file paths",
	"buildKeyProvider":         "provider object, not key bytes",
	"acquireExclusiveKeyLock":  "lock handle",
	"acquireSharedKeyLock":     "lock handle",
	"tryAcquireSharedKeyLock":  "lock handle (non-blocking shared lock; returns *keyFileLock, never key bytes)",
	"NewKeyProviderFromConfig": "provider object, not key bytes",
	"newKeyProviderFromConfig": "provider object, not key bytes",
	"NewKeyManager":            "KeyManager object",
}

// retainingCallees keep the key slice they are passed: passing v to one hands
// ownership off, except on the `if err != nil` path right after the call,
// where nothing retained it.
var retainingCallees = map[string]string{
	"NewEncryptionService": "aead.EncryptionService stores the slice as its dek; wiped by WipeDEK on rotation/shutdown",
}

// wipeSweepExempt lists (function, variable) pairs the sweep flags but that
// are correct for a reason it cannot see. Key: "<func>:<var>".
var wipeSweepExempt = map[string]string{}

// knownWipeGaps are real violations present on main when this sweep was
// written. They are crypto code, so this test-only change does not fix them;
// they are reported on #2512 and skipped (not passed) by
// TestWipeBytesSweep_KnownGaps. An entry that stops reproducing fails the
// sweep, so this list can only shrink.
var knownWipeGaps = map[string]string{
	"(KeyManager).unwrapDEK:dek": "wrong-size branch returns without wiping the unwrapped DEK; reachable only with a " +
		"wrapped DEK that authenticates under the KEK but has the wrong length (#2512)",
	"(Service).Initialize:dek": "NewEncryptionService error path drops the GetDEK copy unwiped; practically unreachable " +
		"since the DEK is validated to 32 bytes on unwrap (#2512)",
	"(Service).RotateDEKWithSweep:dek": "same as (Service).Initialize, after rotation (#2512)",
}

type wipeSource struct {
	fn, file, v, callee string
	line                int
}

type wipeViolation struct {
	src     wipeSource
	retLine int
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func funcDeclName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		t := fd.Recv.List[0].Type
		if st, ok := t.(*ast.StarExpr); ok {
			t = st.X
		}
		if id, ok := t.(*ast.Ident); ok {
			return fmt.Sprintf("(%s).%s", id.Name, fd.Name.Name)
		}
	}
	return fd.Name.Name
}

func isByteSlice(e ast.Expr) bool {
	at, ok := e.(*ast.ArrayType)
	if !ok || at.Len != nil {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "byte"
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// isWipeCall reports whether call is wipeBytes(v).
func isWipeCall(call *ast.CallExpr, v string) bool {
	return isIdent(call.Fun, "wipeBytes") && len(call.Args) == 1 && isIdent(call.Args[0], v)
}

// handlesVar reports whether stmt wipes v, defers its wipe, or hands it off.
func handlesVar(stmt ast.Stmt, v string) bool {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		if c, ok := s.X.(*ast.CallExpr); ok && isWipeCall(c, v) {
			return true
		}
	case *ast.DeferStmt:
		if isWipeCall(s.Call, v) {
			return true
		}
		if fl, ok := s.Call.Fun.(*ast.FuncLit); ok {
			found := false
			ast.Inspect(fl.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok && isWipeCall(c, v) {
					found = true
				}
				return !found
			})
			return found
		}
	case *ast.AssignStmt:
		for i, lhs := range s.Lhs {
			if _, ok := lhs.(*ast.SelectorExpr); ok && i < len(s.Rhs) && isIdent(s.Rhs[i], v) {
				return true
			}
		}
	}
	return false
}

// retainingAssign reports whether st passes v to a retainingCallees call,
// returning the assignment's error variable (empty if none).
func retainingAssign(st ast.Stmt, v string) (string, bool) {
	as, ok := st.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return "", false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", false
	}
	if _, ok := retainingCallees[calleeName(call)]; !ok {
		return "", false
	}
	passes := false
	for _, a := range call.Args {
		if isIdent(a, v) {
			passes = true
		}
	}
	if !passes {
		return "", false
	}
	errVar := ""
	if e, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident); ok && e.Name != "_" && len(as.Lhs) > 1 {
		errVar = e.Name
	}
	return errVar, true
}

func returnsVar(r *ast.ReturnStmt, v string) bool {
	for _, res := range r.Results {
		if isIdent(res, v) {
			return true
		}
	}
	return false
}

// isErrGuard reports whether stmt is `if <errVar> != nil { ... }`.
func isErrGuard(stmt ast.Stmt, errVar string) bool {
	is, ok := stmt.(*ast.IfStmt)
	if !ok || errVar == "" || is.Init != nil {
		return false
	}
	be, ok := is.Cond.(*ast.BinaryExpr)
	return ok && be.Op == token.NEQ && isIdent(be.X, errVar) && isIdent(be.Y, "nil")
}

type wipeChecker struct {
	fset *token.FileSet
	src  wipeSource
	v    string
	out  *[]wipeViolation
}

// walkList checks stmts in order with the current handled state, returning the
// state at the end of the list and whether the list ends in a return.
func (c *wipeChecker) walkList(stmts []ast.Stmt, handled bool, errVar string) (bool, bool) {
	for i, st := range stmts {
		if handled {
			return true, false
		}
		if handlesVar(st, c.v) {
			handled = true
			continue
		}
		if retErr, ok := retainingAssign(st, c.v); ok {
			if i+1 < len(stmts) && isErrGuard(stmts[i+1], retErr) {
				c.walkList(stmts[i+1].(*ast.IfStmt).Body.List, false, "")
			}
			return true, false
		}
		if i == 0 && isErrGuard(st, errVar) {
			continue // v is nil/unusable on the immediate error path
		}
		if r, ok := st.(*ast.ReturnStmt); ok {
			if !returnsVar(r, c.v) {
				c.report(r.Pos())
			}
			return handled, true
		}
		c.walkNested(st, handled)
	}
	return handled, false
}

// walkNested checks the bodies of a compound statement. A wipe inside a
// nested body does not carry out of it.
func (c *wipeChecker) walkNested(st ast.Stmt, handled bool) {
	switch s := st.(type) {
	case *ast.BlockStmt:
		c.walkList(s.List, handled, "")
	case *ast.IfStmt:
		c.walkList(s.Body.List, handled, "")
		if s.Else != nil {
			if eb, ok := s.Else.(*ast.BlockStmt); ok {
				c.walkList(eb.List, handled, "")
			} else {
				c.walkNested(s.Else, handled)
			}
		}
	case *ast.ForStmt:
		c.walkList(s.Body.List, handled, "")
	case *ast.RangeStmt:
		c.walkList(s.Body.List, handled, "")
	case *ast.SwitchStmt:
		for _, cc := range s.Body.List {
			c.walkList(cc.(*ast.CaseClause).Body, handled, "")
		}
	case *ast.TypeSwitchStmt:
		for _, cc := range s.Body.List {
			c.walkList(cc.(*ast.CaseClause).Body, handled, "")
		}
	case *ast.SelectStmt:
		for _, cc := range s.Body.List {
			c.walkList(cc.(*ast.CommClause).Body, handled, "")
		}
	case *ast.LabeledStmt:
		c.walkNested(s.Stmt, handled)
	}
}

func (c *wipeChecker) report(pos token.Pos) {
	*c.out = append(*c.out, wipeViolation{src: c.src, retLine: c.fset.Position(pos).Line})
}

// sourceAssign returns (var, errVar, callee) when st binds a candidate call's
// first result to a named variable.
func sourceAssign(st ast.Stmt) (string, string, string, bool) {
	as, ok := st.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
		return "", "", "", false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", "", "", false
	}
	name := calleeName(call)
	if !keyishCalleeRe.MatchString(name) {
		return "", "", "", false
	}
	id, ok := as.Lhs[0].(*ast.Ident)
	if !ok || id.Name == "_" {
		return "", "", "", false
	}
	errVar := ""
	if len(as.Lhs) > 1 {
		if e, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident); ok && e.Name != "_" {
			errVar = e.Name
		}
	}
	return id.Name, errVar, name, true
}

type stmtFrame struct {
	list []ast.Stmt
	idx  int
}

type wipeScan struct {
	fset         *token.FileSet
	violations   []wipeViolation
	unclassified map[string]string // callee -> first position seen
	sources      []wipeSource
}

// checkBody finds every source assignment in body and checks every path out
// of it. Func literals are checked as independent bodies.
func (ws *wipeScan) checkBody(file, fn string, body *ast.BlockStmt, mayFallOff bool) {
	var visit func(list []ast.Stmt, stack []stmtFrame)
	visit = func(list []ast.Stmt, stack []stmtFrame) {
		for i, st := range list {
			here := append(append([]stmtFrame(nil), stack...), stmtFrame{list, i})
			if v, errVar, callee, ok := sourceAssign(st); ok {
				_, isSrc := keyMaterialSources[callee]
				_, notSrc := notKeyMaterialCallees[callee]
				switch {
				case isSrc:
					src := wipeSource{fn: fn, file: file, v: v, callee: callee, line: ws.fset.Position(st.Pos()).Line}
					ws.sources = append(ws.sources, src)
					if _, ex := wipeSweepExempt[fn+":"+v]; !ex {
						ws.checkFrom(src, here, errVar, mayFallOff, body.Rbrace)
					}
				case !notSrc:
					if _, seen := ws.unclassified[callee]; !seen {
						ws.unclassified[callee] = fmt.Sprintf("%s:%d", file, ws.fset.Position(st.Pos()).Line)
					}
				}
			}
			forEachChildList(st, func(child []ast.Stmt) { visit(child, here) })
			ast.Inspect(st, func(n ast.Node) bool {
				if fl, ok := n.(*ast.FuncLit); ok {
					ws.checkBody(file, fn+".func", fl.Body, fl.Type.Results == nil || len(fl.Type.Results.List) == 0)
					return false
				}
				return true
			})
		}
	}
	visit(body.List, nil)
}

// checkFrom walks the statements after the source, then the statements after
// each enclosing statement in turn, out to the function body. Falling off the
// end of a function with no results is an implicit return.
func (ws *wipeScan) checkFrom(src wipeSource, stack []stmtFrame, errVar string, mayFallOff bool, end token.Pos) {
	c := &wipeChecker{fset: ws.fset, src: src, v: src.v, out: &ws.violations}
	handled := false
	for d, fr := range slices.Backward(stack) {

		eg := ""
		if d == len(stack)-1 {
			eg = errVar
		}
		h, ended := c.walkList(fr.list[fr.idx+1:], handled, eg)
		if h || ended {
			return
		}
	}
	if mayFallOff {
		c.report(end)
	}
}

// forEachChildList calls f with each statement list directly nested in st.
func forEachChildList(st ast.Stmt, f func([]ast.Stmt)) {
	switch s := st.(type) {
	case *ast.BlockStmt:
		f(s.List)
	case *ast.IfStmt:
		f(s.Body.List)
		if s.Else != nil {
			forEachChildList(s.Else, f)
		}
	case *ast.ForStmt:
		f(s.Body.List)
	case *ast.RangeStmt:
		f(s.Body.List)
	case *ast.SwitchStmt:
		for _, cc := range s.Body.List {
			f(cc.(*ast.CaseClause).Body)
		}
	case *ast.TypeSwitchStmt:
		for _, cc := range s.Body.List {
			f(cc.(*ast.CaseClause).Body)
		}
	case *ast.SelectStmt:
		for _, cc := range s.Body.List {
			f(cc.(*ast.CommClause).Body)
		}
	case *ast.LabeledStmt:
		forEachChildList(s.Stmt, f)
	}
}

// scanWipeSweep parses every non-test .go file in dir.
func scanWipeSweep(t *testing.T, dir string) (*wipeScan, map[string]string) {
	t.Helper()
	ws := &wipeScan{fset: token.NewFileSet(), unclassified: map[string]string{}}
	localKeyFuncs := map[string]string{} // name -> file:line, []byte-first-result key-ish funcs
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("wipe sweep: read %s: %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(ws.fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("wipe sweep: parse %s: %v", name, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if keyishCalleeRe.MatchString(fd.Name.Name) && fd.Type.Results != nil && len(fd.Type.Results.List) > 0 &&
				isByteSlice(fd.Type.Results.List[0].Type) {
				localKeyFuncs[fd.Name.Name] = fmt.Sprintf("%s:%d", name, ws.fset.Position(fd.Pos()).Line)
			}
			mayFallOff := fd.Type.Results == nil || len(fd.Type.Results.List) == 0
			ws.checkBody(name, funcDeclName(fd), fd.Body, mayFallOff)
		}
	}
	return ws, localKeyFuncs
}

// TestWipeBytesSweep_EveryKeyLocalIsWipedOnEveryReturn is the guard.
func TestWipeBytesSweep_EveryKeyLocalIsWipedOnEveryReturn(t *testing.T) {
	ws, localKeyFuncs := scanWipeSweep(t, ".")

	for name, pos := range localKeyFuncs {
		_, isSrc := keyMaterialSources[name]
		_, notSrc := notKeyMaterialCallees[name]
		if !isSrc && !notSrc {
			t.Errorf("%s: func %s returns []byte and has a key-shaped name; classify it in keyMaterialSources or notKeyMaterialCallees", pos, name)
		}
	}
	var unclassified []string
	for name, pos := range ws.unclassified {
		unclassified = append(unclassified, fmt.Sprintf("%s (first at %s)", name, pos))
	}
	sort.Strings(unclassified)
	for _, u := range unclassified {
		t.Errorf("unclassified key-shaped callee %s: classify it in keyMaterialSources or notKeyMaterialCallees", u)
	}

	// Premise: the sweep actually found the sources it exists to check.
	if len(ws.sources) < 10 {
		t.Fatalf("wipe sweep found only %d key-material assignments; the scanner is broken or the package moved", len(ws.sources))
	}

	gapHits := map[string]int{}
	for _, v := range ws.violations {
		if _, known := knownWipeGaps[v.src.fn+":"+v.src.v]; known {
			gapHits[v.src.fn+":"+v.src.v]++
			continue
		}
		t.Errorf("%s:%d: %s: key material %q (from %s at line %d) is neither wiped, handed off, nor returned on the path to this return — add wipeBytes(%s) (or defer it), or list %q in wipeSweepExempt with a reason",
			v.src.file, v.retLine, v.src.fn, v.src.v, v.src.callee, v.src.line, v.src.v, v.src.fn+":"+v.src.v)
	}
	for key := range knownWipeGaps {
		if gapHits[key] == 0 {
			t.Errorf("knownWipeGaps entry %q no longer reproduces: the gap was fixed, so remove the entry (and update #2512)", key)
		}
	}
	for key := range wipeSweepExempt {
		found := false
		for _, src := range ws.sources {
			if src.fn+":"+src.v == key {
				found = true
			}
		}
		if !found {
			t.Errorf("wipeSweepExempt entry %q matches no key-material assignment; remove it", key)
		}
	}
}

// TestWipeBytesSweep_KnownGaps reports the real gaps the sweep found on main.
// It is skipped, not passed: the fix touches crypto code and is tracked on
// #2512. The main sweep fails if any of these stops reproducing.
func TestWipeBytesSweep_KnownGaps(t *testing.T) {
	ws, _ := scanWipeSweep(t, ".")
	var lines []string
	for _, v := range ws.violations {
		key := v.src.fn + ":" + v.src.v
		if reason, known := knownWipeGaps[key]; known {
			lines = append(lines, fmt.Sprintf("%s:%d %s: %s", v.src.file, v.retLine, key, reason))
		}
	}
	sort.Strings(lines)
	if len(lines) > 0 {
		t.Skipf("#2512: %d known wipeBytes gap(s) on main, not fixed here (crypto code):\n  %s", len(lines), strings.Join(lines, "\n  "))
	}
}
