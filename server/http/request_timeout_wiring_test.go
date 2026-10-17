package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestRouterAppliesRequestTimeout: NewRouter's global middleware.Timeout is
// RequestTimeout, the constant keyorix-server's http.Server WriteTimeout is derived
// from (server/http_server.go, TestNewHTTPServer_Timeouts). A literal here would let
// the two drift apart again, and a timed-out request would end in a reset connection
// instead of a 504. Checked on router.go's AST because waiting out a 60s deadline in
// a unit test is not practical.
func TestRouterAppliesRequestTimeout(t *testing.T) {
	path := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var timeoutCalls, viaConst int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Timeout" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "middleware" {
			return true
		}
		timeoutCalls++
		if len(call.Args) == 1 {
			if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "RequestTimeout" {
				viaConst++
			}
		}
		return true
	})
	if timeoutCalls == 0 {
		t.Fatal("router.go no longer calls middleware.Timeout: requests have no handler deadline")
	}
	if viaConst != timeoutCalls {
		t.Fatalf("%d of %d middleware.Timeout calls in router.go do not pass RequestTimeout", timeoutCalls-viaConst, timeoutCalls)
	}
}
