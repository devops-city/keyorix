// column_scoped_write_guard_helpers_test.go — shared AST helpers for the
// C-RACE-FIX-B structural guards (#2648, #2650, #2653, #2654): an operation
// that read a row, checked something, and then persisted the whole pre-read
// row (GORM Save, which upserts and so resurrects a soft-deleted row, or
// Select("*").Updates, which reverts every column a narrower concurrent writer
// changed) is a cross-replica lost update. The fixed operations write only the
// columns they own, through a conditional UPDATE. These helpers let one guard
// per operation assert that shape on the source, so it cannot quietly come back.
//
// What this checks, and what it does not: it walks ONE function body
// syntactically. It recognises calls written as `<expr>.Name(...)`. It does not
// follow calls into other functions (each guard names every hop it relies on
// explicitly), does not see a Save reached through a helper with a different
// name, and does not evaluate a Select argument that is not a string literal.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// columnScopedCall is one `<recv>.<Name>(args...)` call found in a function
// body. Recv is the receiver expression rendered as a dotted path ("c",
// "c.storage", "ls.db.WithContext(ctx)" renders as "ls.db.WithContext()").
type columnScopedCall struct {
	Recv string
	Name string
	Args []ast.Expr
}

// columnScopedFuncCalls parses path (relative to this package directory) and
// returns every selector call inside the body of the function or method named
// name (recvType "" for a plain function; otherwise the receiver's type name
// without '*'). Fails the test if the function is not found, so a rename turns
// the guard red rather than vacuous.
func columnScopedFuncCalls(t *testing.T, path, recvType, name string) []columnScopedCall {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name || fd.Body == nil {
			continue
		}
		if columnScopedRecvType(fd) != recvType {
			continue
		}
		var calls []columnScopedCall
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
				calls = append(calls, columnScopedCall{Recv: columnScopedRender(sel.X), Name: sel.Sel.Name, Args: ce.Args})
			}
			return true
		})
		return calls
	}
	t.Fatalf("%s: function %s (receiver %q) not found — the guard's subject was renamed or moved; update the guard", path, name, recvType)
	return nil
}

func columnScopedRecvType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	x := fd.Recv.List[0].Type
	if st, ok := x.(*ast.StarExpr); ok {
		x = st.X
	}
	if id, ok := x.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func columnScopedRender(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return columnScopedRender(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return columnScopedRender(v.Fun) + "()"
	}
	return "?"
}

// assertColumnScopedStorageWrite asserts that the LocalStorage method name in
// path persists through a conditional, column-scoped UPDATE: it calls Where and
// Updates/UpdateColumns, and never calls Save (an upsert) or Select("*") (a
// full-row write).
func assertColumnScopedStorageWrite(t *testing.T, path, name string) {
	t.Helper()
	var where, updates bool
	for _, c := range columnScopedFuncCalls(t, path, "LocalStorage", name) {
		switch c.Name {
		case "Save":
			t.Errorf("%s: LocalStorage.%s calls %s.Save — a full-row upsert that resurrects a soft-deleted row and reverts concurrent column writes", path, name, c.Recv)
		case "Select":
			for _, a := range c.Args {
				if bl, ok := a.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if s, _ := strconv.Unquote(bl.Value); s == "*" {
						t.Errorf("%s: LocalStorage.%s calls Select(\"*\") — a full-row write that reverts concurrent column writes", path, name)
					}
				}
			}
		case "Where":
			where = true
		case "Updates", "UpdateColumns":
			updates = true
		}
	}
	if !where || !updates {
		t.Errorf("%s: LocalStorage.%s no longer issues a conditional column-scoped UPDATE (Where=%v, Updates/UpdateColumns=%v)", path, name, where, updates)
	}
}

// assertCoreWritesOnlyVia asserts that the KeyorixCore method name in path
// makes no storage call named in forbidden (on any receiver other than the
// bare core receiver "c", so c.UpdateUser — the core method — is not confused
// with c.storage.UpdateUser), and does call required on a receiver ending in
// requiredRecv ("storage", "tx", or "c" for a core method).
func assertCoreWritesOnlyVia(t *testing.T, path, name, requiredRecv, required string, forbidden ...string) {
	t.Helper()
	assertWritesOnlyVia(t, path, "KeyorixCore", name, requiredRecv, required, forbidden...)
}

// assertStorageWritesOnlyVia is assertCoreWritesOnlyVia for a LocalStorage
// method. It exists because some entry points this family guards are in
// internal/storage/store rather than internal/core (AdvanceWebAuthnCredentialCounter),
// and the earlier claim that those "cannot be reached by these core-scoped
// helpers" was about the WRAPPER's hardcoded receiver type, not about the AST
// walk — columnScopedFuncCalls already takes an arbitrary path and receiver
// type (#2836).
func assertStorageWritesOnlyVia(t *testing.T, path, name, requiredRecv, required string, forbidden ...string) {
	t.Helper()
	assertWritesOnlyVia(t, path, "LocalStorage", name, requiredRecv, required, forbidden...)
}

func assertWritesOnlyVia(t *testing.T, path, recvType, name, requiredRecv, required string, forbidden ...string) {
	t.Helper()
	bad := map[string]bool{}
	for _, f := range forbidden {
		bad[f] = true
	}
	found := false
	for _, c := range columnScopedFuncCalls(t, path, recvType, name) {
		if bad[c.Name] && c.Recv != "c" {
			t.Errorf("%s: %s.%s calls %s.%s — a full-row write of its pre-read snapshot", path, recvType, name, c.Recv, c.Name)
		}
		if c.Name == required && (c.Recv == requiredRecv || len(c.Recv) > len(requiredRecv) && c.Recv[len(c.Recv)-len(requiredRecv)-1:] == "."+requiredRecv) {
			found = true
		}
	}
	if !found {
		t.Errorf("%s: %s.%s no longer calls %s.%s — the column-scoped write this guard depends on", path, recvType, name, requiredRecv, required)
	}
}
