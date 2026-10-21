// sweep_clock_wiring_test.go — #1983: RemoveExpiredShares and
// RevokeExpiredLeases both take an explicit `before time.Time` parameter
// (KeyorixCore methods, internal/core), which is a real, pre-existing seam —
// but the server's own scheduler wiring is what determines whether that seam is
// actually used: passing a bare time.Now() as the argument silently defeats
// it, exactly as it did before #1983 sourced these two calls from
// coreService.ShareEffectiveNow()/EffectiveNow() instead (the same
// watermarked/injected clock every other in-process share-active or
// dynamic-secret-sweep decision uses). This guard checks the actual argument
// expression at each call site, not just that the parameter exists.
package main

import (
	"go/ast"
	"testing"
)

// sweepClockWiringGuardedCalls maps each guarded scheduler-call method name
// to the exact argument expression it must use.
var sweepClockWiringGuardedCalls = map[string]string{
	"RemoveExpiredShares": "coreService.ShareEffectiveNow",
	"RevokeExpiredLeases": "coreService.EffectiveNow",
}

// exprString renders the minimal "X.Y" / "X" shape sweepClockWiringGuardedCalls'
// values use — enough to recognize the expected call, without pulling in
// go/printer for a full source dump.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "(...)"
	default:
		return ""
	}
}

// TestSweepSchedulerCallsUseInjectedClock fails if any non-test file of this
// package (the scheduler wiring, one scheduler_<job>.go per job) calls
// RemoveExpiredShares or RevokeExpiredLeases with any argument other than
// the exact expected coreService.<Method>() clock call — most importantly,
// a bare time.Now() (or anything else) reintroduced in its place.
func TestSweepSchedulerCallsUseInjectedClock(t *testing.T) {
	fset, files := parseServerPackage(t)

	found := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			wantArg, guarded := sweepClockWiringGuardedCalls[sel.Sel.Name]
			if !guarded {
				return true
			}
			found[sel.Sel.Name] = true
			if len(call.Args) < 2 {
				t.Errorf("%s: %s call has %d argument(s), expected at least 2 (ctx, clock)",
					fset.Position(call.Pos()), sel.Sel.Name, len(call.Args))
				return true
			}
			clockArg := call.Args[len(call.Args)-1]
			got := exprString(clockArg)
			if got != wantArg+"(...)" {
				t.Errorf("%s: %s's clock argument is %q, want %q(...) -- a bare time.Now() (or "+
					"anything else) here silently defeats the injected/watermarked clock seam",
					fset.Position(call.Pos()), sel.Sel.Name, got, wantArg)
			}
			return true
		})
	}
	for name := range sweepClockWiringGuardedCalls {
		if !found[name] {
			t.Errorf("expected call to %s not found in package main (server/*.go) -- guard is stale, update "+
				"sweepClockWiringGuardedCalls or investigate why the call moved/was removed", name)
		}
	}
}
