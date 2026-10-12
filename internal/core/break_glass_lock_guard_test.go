package core

// break_glass_lock_guard_test.go — the default-ci half of #2722, and the
// PRIMARY guard for it: the two pg-gated tests in
// concurrency_break_glass_activate_vs_revoke_postgres_test.go are the
// behavioural evidence, but one of them is probabilistic by construction and
// neither runs in the DSN-less CI leg.
//
// What it asserts, and why that is the right thing to assert: the defect was
// that ActivateBreakGlass's record insert and role grant were two unsynchronized
// operations, while RevokeBreakGlassActivationAtomic performed its own pair
// under projectAdminGuardLockKey. The fix is that BOTH writes now happen inside
// one acquisition of that same key. So the checkable condition is "the function
// that performs the two writes is only reachable from inside that lock" — which
// is a property of the call structure, not of any return value.
//
// It is deliberately NOT written as "ActivateBreakGlass calls WithNamedLock
// somewhere": that would stay green if a later refactor moved one of the two
// writes back outside the callback, which is precisely the bug. Instead the
// writes live in a named helper (activateBreakGlassLocked), and this guard
// asserts (a) the helper performs both writes, (b) ActivateBreakGlass's only
// call to it is inside a WithNamedLock callback keyed by
// projectAdminGuardLockKey, and (c) ActivateBreakGlass itself performs neither
// write directly.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// The two writes that must not be separable, by the name each is called under.
const (
	bgInsertCall = "CreateBreakGlassActivation"
	bgGrantCall  = "AssignRoleWithExpiry"
)

// bgInsertAndGrantShareOneTransaction reports whether a single WithTransaction
// callback in body contains both the insert and the grant (#3109): the helper
// calling both is not enough, they must not be separable commits.
func bgInsertAndGrantShareOneTransaction(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithTransaction" {
			return true
		}
		for _, a := range ce.Args {
			if fl, ok := a.(*ast.FuncLit); ok {
				names := bgCallNames(fl.Body)
				hasInsert, hasGrant := false, false
				for _, nm := range names {
					hasInsert = hasInsert || nm == bgInsertCall
					hasGrant = hasGrant || nm == bgGrantCall
				}
				if hasInsert && hasGrant {
					found = true
				}
			}
		}
		return true
	})
	return found
}

func TestActivateBreakGlass_InsertAndGrantShareTheRevokeLock(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "break_glass.go", nil, 0)
	require.NoError(t, err)

	activate := bgFindFunc(t, f, "ActivateBreakGlass")
	locked := bgFindFunc(t, f, "activateBreakGlassLocked")

	// (a) the helper does both writes.
	lockedCalls := bgCallNames(locked.Body)
	require.Contains(t, lockedCalls, bgInsertCall,
		"activateBreakGlassLocked must perform the activation insert — if it moved out, the lock no longer "+
			"covers it and a concurrent revoke can land between the two writes again (#2722)")
	require.Contains(t, lockedCalls, bgGrantCall,
		"activateBreakGlassLocked must perform the role grant — see above (#2722)")
	require.True(t, bgInsertAndGrantShareOneTransaction(locked.Body),
		"activateBreakGlassLocked must run the activation insert and the role grant inside ONE WithTransaction "+
			"callback — separate commits leave a record without its grant behind an error (#3109)")

	// (c) ActivateBreakGlass does neither directly. This is the assertion that
	// actually prevents the regression: a write moved back up here would be
	// outside the lock even though the WithNamedLock call still exists.
	outerCalls := bgCallNames(activate.Body)
	require.NotContains(t, outerCalls, bgInsertCall,
		"ActivateBreakGlass must not perform the activation insert itself — it belongs inside the "+
			"projectAdminGuardLockKey callback, with the grant (#2722)")
	require.NotContains(t, outerCalls, bgGrantCall,
		"ActivateBreakGlass must not perform the role grant itself — see above (#2722)")

	// (b) the one call to the helper is inside a WithNamedLock callback keyed by
	// projectAdminGuardLockKey. Found by walking the WithNamedLock call
	// expressions and looking for the helper inside their function-literal
	// argument, so a call to the helper from anywhere else in the function body
	// is not mistaken for a locked one.
	found := false
	ast.Inspect(activate.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithNamedLock" {
			return true
		}
		keyed := false
		for _, a := range ce.Args {
			if kc, ok := a.(*ast.CallExpr); ok {
				if id, ok := kc.Fun.(*ast.Ident); ok && id.Name == "projectAdminGuardLockKey" {
					keyed = true
				}
			}
		}
		if !keyed {
			return true
		}
		for _, a := range ce.Args {
			fl, ok := a.(*ast.FuncLit)
			if !ok {
				continue
			}
			for _, name := range bgCallNames(fl.Body) {
				if name == "activateBreakGlassLocked" {
					found = true
				}
			}
		}
		return true
	})
	require.True(t, found,
		"ActivateBreakGlass must call activateBreakGlassLocked from inside a WithNamedLock callback keyed by "+
			"projectAdminGuardLockKey — the SAME key RevokeBreakGlassActivationAtomic takes, which is what "+
			"serializes the insert-then-grant pair against a concurrent revoke (#2722)")
}

// TestRevokeBreakGlass_StillTakesTheSameLock pins the other half of the pair.
// The fix above is worthless if the revoke stops taking this key: the two would
// no longer exclude each other, and nothing else would go red — which is exactly
// the "guard the condition, not the conclusion" case in CLAUDE.md.
func TestRevokeBreakGlass_StillTakesTheSameLock(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "break_glass.go", nil, 0)
	require.NoError(t, err)
	revoke := bgFindFunc(t, f, "RevokeBreakGlassActivationAtomic")

	keyed := false
	ast.Inspect(revoke.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := ce.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "WithNamedLock" {
			return true
		}
		for _, a := range ce.Args {
			if kc, ok := a.(*ast.CallExpr); ok {
				if id, ok := kc.Fun.(*ast.Ident); ok && id.Name == "projectAdminGuardLockKey" {
					keyed = true
				}
			}
		}
		return true
	})
	require.True(t, keyed,
		"RevokeBreakGlassActivationAtomic must still take projectAdminGuardLockKey — ActivateBreakGlass's "+
			"#2722 fix serializes against THIS key specifically, so dropping it here silently reopens the "+
			"race with nothing else going red")
}

func bgFindFunc(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name && fd.Body != nil {
			return fd
		}
	}
	t.Fatalf("break_glass.go: %s not found — the guard's subject was renamed or moved; update the guard", name)
	return nil
}

func bgCallNames(b *ast.BlockStmt) []string {
	var names []string
	ast.Inspect(b, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := ce.Fun.(type) {
		case *ast.Ident:
			names = append(names, fun.Name)
		case *ast.SelectorExpr:
			names = append(names, fun.Sel.Name)
		}
		return true
	})
	return names
}
