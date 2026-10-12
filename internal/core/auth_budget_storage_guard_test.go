// auth_budget_storage_guard_test.go — every auth budget's login_attempts
// access goes through the shared limiter (auth_budget.go), so no budget can
// read or write its count with its own error handling and fail open again
// (AUTH-AUDIT-1 item 5).
//
// It parses every non-test file in this package and finds each call to a
// login_attempts storage method in the two forms this package reaches storage
// by: <x>.storage.M(...) (c.storage, lc.c.storage, ...) and tx.M(...) inside a
// WithTransaction callback. Calls on core itself (c.ReleaseLoginAttempt, the
// exported wrapper) are not storage calls. The only storage caller allowed
// outside auth_budget.go is RecordLoginAttemptRelay, which is not a budget
// decision: it relays a downstream server's attempt and returns the error to
// that caller.
//
// What it does NOT see: a budget kept in a different table. The per-account
// lockout is one (the user row's lockout columns); its fallback is proved by
// account_lockout_storage_fallback_test.go instead.
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var loginAttemptsStorageMethods = map[string]bool{
	"CountRecentLoginAttempts": true,
	"RecordLoginAttempt":       true,
	"ReserveLoginAttempt":      true,
	"ReleaseLoginAttempt":      true,
}

// loginAttemptsCallersOutsideTheLimiter: "file:function" -> why it is not a
// budget decision.
var loginAttemptsCallersOutsideTheLimiter = map[string]string{
	"rate_limit.go:RecordLoginAttemptRelay": "relays a downstream server's attempt; returns the storage error to that caller",
}

func TestAuthBudgetStorage_OnlyThroughTheSharedLimiter(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var bad []string
	inLimiter := 0
	used := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !loginAttemptsStorageMethods[sel.Sel.Name] {
					return true
				}
				if !isStorageValue(sel.X) {
					return true // e.g. lc.c.ReleaseLoginAttempt: core's own wrapper
				}
				site := name + ":" + fd.Name.Name
				switch {
				case name == "auth_budget.go":
					inLimiter++
				case loginAttemptsCallersOutsideTheLimiter[site] != "":
					used[site] = true
				default:
					bad = append(bad, fset.Position(call.Pos()).String()+" "+fd.Name.Name+" calls "+sel.Sel.Name)
				}
				return true
			})
		}
	}
	require.Positive(t, inLimiter, "found no login_attempts storage call in auth_budget.go: this guard no longer recognises the shared limiter's calls and would pass vacuously")
	sort.Strings(bad)
	assert.Empty(t, bad, "login_attempts storage reached outside the shared limiter: route it through budgetLimited/budgetRecord/budgetReserve so a storage error falls back instead of failing open")
	for site := range loginAttemptsCallersOutsideTheLimiter {
		assert.True(t, used[site], "%s no longer calls login_attempts storage: remove it from the allowlist", site)
	}
}

// isStorageValue reports whether x is how this package names a storage value:
// <anything>.storage, or the tx parameter of a WithTransaction callback.
func isStorageValue(x ast.Expr) bool {
	switch v := x.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == "storage"
	case *ast.Ident:
		return v.Name == "tx"
	}
	return false
}
