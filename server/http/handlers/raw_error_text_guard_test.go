package handlers

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rawErrorTextExempt lists sendError call sites (file:func) that still pass a raw
// err.Error() with a run-time status, each with the reason it is not fixed here.
var rawErrorTextExempt = map[string]string{
	"auth.go:InitSystem": "auth handler owned by FIX-3277 (HARDEN-HTTP-1 brief: report, do not change); reported in the HARDEN-HTTP-1 session report",
}

// TestNoRawErrorTextOnServerErrors: no handler in this package may send an error's
// raw text (x.Error()) as the client message unless the status argument is a
// constant 4xx. With a run-time status (status := 500; if ... { status = 400 }) the
// same raw text reaches the client on the 500 branch, where it is a storage or
// driver error. Such sites use errorMessageFor(status, err) or clientSafe(err).
//
// A call on a line carrying semgrep's reviewed `nosemgrep: keyorix-raw-error-to-client`
// marker (a fixed sentinel's message) is accepted; that rule only matches a literal
// http.StatusInternalServerError, which is how the run-time-status sites got past it.
//
// Recognised: calls to sendError / x.sendError whose third argument is a call to
// .Error(). Not recognised: the raw text laundered through a variable or
// fmt.Sprintf first (none exist today: rg for `%v", err), http.StatusInternalServerError`
// and `err.Error(), http.StatusInternalServerError` finds nothing).
func TestNoRawErrorTextOnServerErrors(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	calls := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path) // #nosec G304 -- this package's own source
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isSendErrorCall(call) || len(call.Args) < 4 {
					return true
				}
				calls++
				if !isErrorTextCall(call.Args[2]) || isConstant4xx(call.Args[3]) {
					return true
				}
				// A reviewed exemption already carries semgrep's marker on the line
				// (a fixed sentinel's message, not a backend error).
				line := fset.Position(call.Pos()).Line
				if strings.Contains(sourceLine(src, line), "nosemgrep: keyorix-raw-error-to-client") {
					return true
				}
				key := path + ":" + fn.Name.Name
				if _, ok := rawErrorTextExempt[key]; ok {
					seen[key] = true
					return true
				}
				t.Errorf("%s: %s passes raw error text with a status that can be 5xx; use errorMessageFor(status, err) or clientSafe(err)",
					fset.Position(call.Pos()), key)
				return true
			})
		}
	}
	if calls < 100 {
		t.Fatalf("found only %d sendError calls: the scan is not seeing the handlers", calls)
	}
	for key := range rawErrorTextExempt {
		if !seen[key] {
			t.Errorf("rawErrorTextExempt has %s, which no longer sends raw error text: remove it", key)
		}
	}
}

func isSendErrorCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "sendError"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "sendError"
	}
	return false
}

func isErrorTextCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Error"
}

// isConstant4xx: http.StatusXxx naming a 4xx code.
func isConstant4xx(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "http" {
		return false
	}
	switch sel.Sel.Name {
	case "StatusBadRequest", "StatusUnauthorized", "StatusPaymentRequired", "StatusForbidden", "StatusNotFound",
		"StatusMethodNotAllowed", "StatusNotAcceptable", "StatusRequestTimeout", "StatusConflict", "StatusGone",
		"StatusLengthRequired", "StatusPreconditionFailed", "StatusRequestEntityTooLarge", "StatusUnsupportedMediaType",
		"StatusUnprocessableEntity", "StatusLocked", "StatusFailedDependency", "StatusPreconditionRequired",
		"StatusTooManyRequests", "StatusRequestHeaderFieldsTooLarge", "StatusUnavailableForLegalReasons", "StatusTeapot":
		return true
	}
	return false
}

func sourceLine(src []byte, line int) string {
	lines := strings.Split(string(src), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}

// TestErrorMessageFor_FiveXXIsGeneric: a 4xx keeps core's message (the caller needs
// it to fix the request), a 5xx never carries the error text.
func TestErrorMessageFor_FiveXXIsGeneric(t *testing.T) {
	err := errors.New(`pq: duplicate key value violates unique constraint "secret_nodes_pkey"`)
	if got := errorMessageFor(http.StatusBadRequest, err); got != err.Error() {
		t.Errorf("4xx message = %q, want the error text", got)
	}
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable} {
		if got := errorMessageFor(status, err); strings.Contains(got, "pq:") || got != clientSafe(err) {
			t.Errorf("%d message = %q, want the generic text", status, got)
		}
	}
}
