package guards

// tx_closure_outer_storage_guard_test.go — DEADLOCK-SHAPE-1 item 3
// (INV-CORE-no-outer-storage-in-transaction-closure).
//
// A transaction closure runs on the transaction's own storage handle (`tx`). Any
// write issued from inside it through the receiver's OUTER handle -- c.storage
// directly, or an audit / log / notify helper that writes through c.storage --
// is a second writer. On SQLite the open transaction holds the single write gate,
// so that writer queues behind its own caller until the gate's bounded wait gives
// up (UpdateUser's deactivation cleanup audit was the live instance); on Postgres
// it takes a second pool connection and is not rolled back with the rest.
//
// atomicity_guard_test.go's TestAtomicityGuard_TransactionEscape already catches
// the literal `.storage.X(...)` call form. It cannot see an audit/log/notify
// helper, because those are `c.writeAuditEventFailed(...)`, not `c.storage.X`;
// that is exactly the call UpdateUser made. This guard covers those forms.
//
// WHAT COUNTS AS A TRANSACTION CLOSURE (the idioms recognised, stated so a
// reviewer can check them rather than assume them):
//  1. a function literal passed as the last argument of any `<x>.WithTransaction`
//     call (the receiver may be c.storage, st, or a tx handle for a savepoint);
//  2. ANY function literal whose first parameter is typed `storage.Storage`
//     (func(tx storage.Storage) error). This is the shape of every transaction
//     callback and also catches the ones that never appear as a WithTransaction
//     argument: commitOwingAudit's `effect`, and the `inTx` callbacks that
//     storeNextSecretVersion / updateSecretWithNewVersion run inside their
//     transaction.
//  3. a non-literal last argument to WithTransaction (a named closure variable or
//     method value) is reported as OPAQUE: its body cannot be inspected here.
//
// WHAT IS REPORTED inside such a closure:
//   - any selector `<x>.storage` (c.storage, k.storage, ...);
//   - a call on the enclosing method's receiver whose name starts with
//     writeAudit / Log<Upper> / notify / Notify / emitAudit and does NOT end in
//     "On" (the `...On` variants take an explicit auditTarget and are the correct
//     in-transaction form -- but see the next item);
//   - any call to auditNow() (the outer-handle audit target), including as the
//     argument of an `...On` helper.
//
// WHAT IT DOES NOT SEE: a helper method that reaches c.storage on its own
// (`c.someHelper(ctx)` where someHelper writes through c.storage); an outer
// handle aliased before the closure (`st := c.storage` then `st.X` inside); a
// writer reached through another struct's field. The sweep that accompanied this
// guard ran a transitive pass over the receiver's own methods for the first
// (docs of the invariant fragment); the guard itself is lexical.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// txClosureOuterCallRe matches receiver methods that write an audit/log/notify
// row through the receiver's own (outer) storage handle.
var txClosureOuterCallRe = regexp.MustCompile(`^(writeAudit|Log[A-Z]|notify|Notify|emitAudit)`)

// txClosureAllowlist holds reviewed exceptions, keyed "file.go:Func:call". Each
// value is a one-line reason. An entry that matches nothing fails the test, so
// the list cannot go stale. Empty by design: every hit the sweep found was fixed.
var txClosureAllowlist = map[string]string{}

type txClosureHit struct {
	file, fn string
	line     int
	call     string
}

func (h txClosureHit) key() string { return fmt.Sprintf("%s:%s:%s", h.file, h.fn, h.call) }

// scanTxClosureOuterCalls reports outer-handle uses inside the transaction
// closures of one parsed file.
func scanTxClosureOuterCalls(fset *token.FileSet, f *ast.File, file string) []txClosureHit {
	var hits []txClosureHit
	seen := map[token.Pos]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		recv := ""
		if fd.Recv != nil && len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
			recv = fd.Recv.List[0].Names[0].Name
		}
		add := func(pos token.Pos, call string) {
			if seen[pos] {
				return
			}
			seen[pos] = true
			hits = append(hits, txClosureHit{file: file, fn: fd.Name.Name, line: fset.Position(pos).Line, call: call})
		}
		inspectClosure := func(fl *ast.FuncLit) {
			ast.Inspect(fl.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if x.Sel.Name == "storage" {
						add(x.Pos(), txClosureExprString(x))
					}
				case *ast.CallExpr:
					switch fun := x.Fun.(type) {
					case *ast.SelectorExpr:
						if id, ok := fun.X.(*ast.Ident); ok && id.Name == recv && recv != "" &&
							txClosureOuterCallRe.MatchString(fun.Sel.Name) && !strings.HasSuffix(fun.Sel.Name, "On") {
							add(x.Pos(), recv+"."+fun.Sel.Name)
						}
						if fun.Sel.Name == "auditNow" {
							add(x.Pos(), txClosureExprString(fun))
						}
					}
				}
				return true
			})
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "WithTransaction" && len(x.Args) > 0 {
					last := x.Args[len(x.Args)-1]
					if _, isLit := last.(*ast.FuncLit); !isLit {
						add(last.Pos(), "OPAQUE:"+txClosureExprString(last))
					}
				}
			case *ast.FuncLit:
				if txClosureTakesStorage(x) {
					inspectClosure(x)
				}
			}
			return true
		})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].line < hits[j].line })
	return hits
}

// txClosureTakesStorage reports whether fl's first parameter is a storage.Storage.
func txClosureTakesStorage(fl *ast.FuncLit) bool {
	if fl.Type.Params == nil || len(fl.Type.Params.List) == 0 {
		return false
	}
	sel, ok := fl.Type.Params.List[0].Type.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Storage"
}

func txClosureExprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return txClosureExprString(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		return txClosureExprString(x.Fun) + "()"
	default:
		return fmt.Sprintf("%T", e)
	}
}

func TestNoOuterStorageInTransactionClosure(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	var hits []txClosureHit
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join("..", name), nil, 0)
		if perr != nil {
			t.Fatalf("cannot parse %s: %v", name, perr)
		}
		hits = append(hits, scanTxClosureOuterCalls(fset, f, name)...)
	}

	used := map[string]bool{}
	var bad []string
	for _, h := range hits {
		if _, ok := txClosureAllowlist[h.key()]; ok {
			used[h.key()] = true
			continue
		}
		bad = append(bad, fmt.Sprintf("%s:%d (%s): %s", h.file, h.line, h.fn, h.call))
	}
	for k, reason := range txClosureAllowlist {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("allowlist entry %q has no reason", k)
		}
		if !used[k] {
			t.Errorf("allowlist entry %q matches nothing: remove it", k)
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d use(s) of the receiver's OUTER storage handle (or an audit/log/notify helper that writes through it) "+
			"inside a transaction closure. On SQLite that is a second writer behind the write gate the open transaction "+
			"holds (a self-deadlock); on Postgres it is not rolled back with the transaction. Use the closure's tx "+
			"parameter, or record the outcome and write it AFTER the commit "+
			"(INV-CORE-no-outer-storage-in-transaction-closure):\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
}

// TestTxClosureGuard_SelfTest calibrates the scanner in both directions on
// planted source: every planted violation form must be reported, and the
// corrected forms must not be.
func TestTxClosureGuard_SelfTest(t *testing.T) {
	scan := func(src string) []string {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "planted.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, h := range scanTxClosureOuterCalls(fset, f, "planted.go") {
			out = append(out, h.call)
		}
		return out
	}
	const head = "package core\nfunc (c *KeyorixCore) F(ctx context.Context) error {\n"

	violations := map[string]string{
		"audit helper":     head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { c.writeAuditEventFailed(ctx, "x"); return nil })}`,
		"log helper":       head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { c.LogSomething(ctx); return nil })}`,
		"notify helper":    head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { c.notifyAdmins(ctx); return nil })}`,
		"outer storage":    head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { return c.storage.DeleteThing(ctx) })}`,
		"auditNow target":  head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { c.logThingOn(ctx, c.auditNow()); return nil })}`,
		"savepoint":        head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { return tx.WithTransaction(ctx, func(sp storage.Storage) error { c.writeAuditEvent(ctx); return nil }) })}`,
		"opaque closure":   head + `fn := func(tx storage.Storage) error { return nil }; return c.storage.WithTransaction(ctx, fn)}`,
		"callback literal": head + `return c.commitOwingAudit(ctx, func(st storage.Storage) error { c.emitAudit(ctx); return nil }, nil)}`,
	}
	for name, src := range violations {
		if len(scan(src)) == 0 {
			t.Errorf("%s: planted violation was NOT reported (the guard is blind to this form)", name)
		}
	}

	clean := map[string]string{
		"tx handle only":      head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { return tx.DeleteThing(ctx) })}`,
		"On variant with tx":  head + `return c.storage.WithTransaction(ctx, func(tx storage.Storage) error { c.writeAuditEventFullOn(ctx, auditInto(tx, sink)); return nil })}`,
		"audit after commit":  head + `err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error { return nil }); c.writeAuditEventFailed(ctx, "x"); return err}`,
		"non-tx func literal": head + `f := func(n int) error { c.writeAuditEvent(ctx); return nil }; return f(1)}`,
	}
	for name, src := range clean {
		if got := scan(src); len(got) != 0 {
			t.Errorf("%s: clean source was reported: %v", name, got)
		}
	}
}
