// account_state_exhaustiveness_guard_test.go — a structural guard, in the
// same family as server/http's raw_storage_bypass_guard_test.go, statically
// proving every ADR-025 account-state constant declared in account_state.go
// is explicitly listed in AccountLoginBlocked's switch statement.
//
// This is what makes "a future account state added without updating this
// switch" (the scenario AccountLoginBlocked's own doc names as the reason a
// blanket fail-open default used to seem safer) impossible to ship silently:
// a state that falls through to AccountLoginBlocked's default case gets
// blocked, not silently allowed -- but ONLY if a developer actually intended
// that. This test forces the decision to be explicit and visible in the
// diff, not an accident of switch-statement omission.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestAccountLoginBlocked_ExhaustsStateRegistry parses account_state.go,
// collects every top-level `AccountXxx = "..."` constant declared there, then
// confirms each one is referenced as a case value somewhere in
// AccountLoginBlocked's switch statement (either the "not blocked" or the
// "blocked" case group). Adding a new AccountXxx constant without adding it
// to one of those two groups fails this test.
func TestAccountLoginBlocked_ExhaustsStateRegistry(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../account_state.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing account_state.go: %v", err)
	}

	constants := accountStateConstants(f)
	if len(constants) == 0 {
		t.Fatal("found zero AccountXxx constants in account_state.go -- the const-collection logic itself is broken")
	}

	switchCases := accountLoginBlockedSwitchCaseIdents(f)
	if switchCases == nil {
		t.Fatal("could not find AccountLoginBlocked's switch statement in account_state.go")
	}

	var missing []string
	for _, c := range constants {
		if !switchCases[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		t.Errorf("AccountLoginBlocked's switch does not explicitly list: %v -- add each to either the "+
			"not-blocked or blocked case group (never rely on the default case for a real, valid state)", missing)
	}
}

// accountStateConstants returns every top-level constant identifier declared
// in f whose name starts with "Account" (matching AccountActive,
// AccountSuspended, etc.) and whose value is a string literal.
func accountStateConstants(f *ast.File) []string {
	var names []string
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if len(vs.Values) <= i {
					continue
				}
				if _, ok := vs.Values[i].(*ast.BasicLit); !ok {
					continue
				}
				if len(name.Name) > 7 && name.Name[:7] == "Account" {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}

// accountLoginBlockedSwitchCaseIdents finds AccountLoginBlocked's func decl
// and returns the set of identifier names referenced in any of its switch
// statement's (non-default) case clauses. Returns nil if the function or its
// switch statement can't be found.
func accountLoginBlockedSwitchCaseIdents(f *ast.File) map[string]bool {
	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		cand, ok := decl.(*ast.FuncDecl)
		if ok && cand.Name.Name == "AccountLoginBlocked" {
			fd = cand
			break
		}
	}
	if fd == nil {
		return nil
	}

	var sw *ast.SwitchStmt
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if s, ok := n.(*ast.SwitchStmt); ok {
			sw = s
			return false
		}
		return true
	})
	if sw == nil {
		return nil
	}

	idents := map[string]bool{}
	for _, stmt := range sw.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok || cc.List == nil { // nil List is the default case
			continue
		}
		for _, expr := range cc.List {
			if id, ok := expr.(*ast.Ident); ok {
				idents[id.Name] = true
			}
		}
	}
	return idents
}

// TestAccountStateExhaustivenessScannerDetectsAMissingCase is this guard's
// red-proof.
//
// TestAccountLoginBlocked_ExhaustsStateRegistry asserts that every ADR-025
// account state is currently listed in AccountLoginBlocked's switch. Both of
// its inputs are derived by AST walks that can silently return nothing:
// accountStateConstants filters on a "Account" name prefix and a basic-literal
// value, and accountLoginBlockedSwitchCaseIdents returns nil outright if it
// cannot find the function or its switch. A nil-versus-empty mistake, a
// renamed function, or a switch refactored into an if/else chain all produce
// "no missing states" — the same answer as being correct.
//
// This is the guard whose entire purpose is to make one specific accident
// impossible: a new account state added without a corresponding case, silently
// falling through to the default. It should be able to show that it would
// still notice.
func TestAccountStateExhaustivenessScannerDetectsAMissingCase(t *testing.T) {
	// Parsed, never compiled. AccountSuspended is deliberately absent from the
	// switch — that omission is the defect being planted.
	const src = `package fixture

const (
	AccountActive    = "active"
	AccountSuspended = "suspended"
	AccountLocked    = "locked"

	// Not a state: no "Account" prefix, and must not be collected.
	DefaultTimeout = "30s"
)

func AccountLoginBlocked(state string) bool {
	switch state {
	case AccountActive:
		return false
	case AccountLocked:
		return true
	default:
		return true
	}
}
`

	f, err := parser.ParseFile(token.NewFileSet(), "account_state_fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the synthetic fixture: %v", err)
	}

	states := accountStateConstants(f)
	got := map[string]bool{}
	for _, s := range states {
		got[s] = true
	}

	for _, want := range []string{"AccountActive", "AccountSuspended", "AccountLocked"} {
		if !got[want] {
			t.Errorf("accountStateConstants missed %s — if the constant scan stops finding states, the "+
				"exhaustiveness check has nothing to be exhaustive over and passes trivially. Found: %v",
				want, states)
		}
	}
	if got["DefaultTimeout"] {
		t.Errorf("accountStateConstants collected DefaultTimeout, which is not an account state — the "+
			"prefix filter has stopped discriminating, and the guard will start demanding switch cases "+
			"for unrelated constants. Found: %v", states)
	}

	cases := accountLoginBlockedSwitchCaseIdents(f)
	if cases == nil {
		t.Fatal("accountLoginBlockedSwitchCaseIdents returned nil for a fixture that plainly contains " +
			"AccountLoginBlocked with a switch — the function or switch lookup has broken, and a nil " +
			"result reads downstream as 'no cases', which is indistinguishable from a real finding")
	}
	if !cases["AccountActive"] || !cases["AccountLocked"] {
		t.Errorf("the switch-case scan missed a case that is plainly present: %v", cases)
	}

	// The verdict: exactly the planted omission, and nothing else.
	var missing []string
	for _, s := range states {
		if !cases[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) != 1 || missing[0] != "AccountSuspended" {
		t.Errorf("the guard's own comparison must report exactly the one state deliberately left out of "+
			"the fixture's switch (AccountSuspended); got %v. This is the accident the guard exists to "+
			"prevent — a new state falling through to default without anyone deciding it should.", missing)
	}
}
