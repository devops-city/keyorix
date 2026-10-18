package besteffort

// Guard for the package doc's "post-commit only" contract (REAUTH-GRANT-TESTS-1,
// #3227 review leftover): besteffort.Run swallows a failed step, which is only
// correct AFTER the primary write has committed. Inside a transaction it is
// wrong twice over: a Postgres statement that failed is not recoverable (the
// transaction is already aborted and the later COMMIT silently becomes a
// ROLLBACK), and the swallowed error hides that from the caller.
//
// The scan flags, in every non-test, non-generated .go file of the module, any
// besteffort.Run / besteffort.RunRecover call that sits lexically inside a
// func literal passed to a WithTransaction call, plus -- one hop -- a call
// inside such a literal to a same-package function that itself calls
// besteffort.Run / RunRecover directly (e.g. purgeStepUpGrants).
//
// What it does NOT see (stated, not hidden): calls more than one hop away;
// calls through func values or interfaces; a helper with the same bare name in
// another package; a transaction opened by anything other than a method named
// WithTransaction (WithNamedLock is a lock, not a transaction, and is not
// scanned); and a function that is only ever called from inside a transaction
// but is itself called from a plain statement list (the scan is lexical).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type txHit struct{ file, fn, what string }

func (h txHit) String() string { return h.file + ": " + h.fn + ": " + h.what }

func isBestEffortRun(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "besteffort" && (sel.Sel.Name == "Run" || sel.Sel.Name == "RunRecover")
}

// isSavepointStep reports whether call (a besteffort.Run) wraps a nested
// WithTransaction: its func-literal argument's body is a single
// `return x.WithTransaction(...)`. That is the one sanctioned in-transaction
// shape (a SAVEPOINT on PostgreSQL), see the package doc.
func isSavepointStep(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
	if !ok || len(lit.Body.List) != 1 {
		return false
	}
	ret, ok := lit.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	inner, ok := ret.Results[0].(*ast.CallExpr)
	return ok && isWithTransaction(inner)
}

func isWithTransaction(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name == "WithTransaction"
	case *ast.Ident:
		return fn.Name == "WithTransaction"
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above " + dir)
		}
		dir = parent
	}
}

// scanTxMisuse parses every package under root and returns the hits plus how
// many WithTransaction closures and besteffort.Run call sites it inspected (the
// scan's own precondition: zero of either would make "no hits" vacuous).
func scanTxMisuse(t *testing.T, root string) (hits []txHit, txClosures, runCalls int) {
	t.Helper()
	byDir := map[string][]*ast.File{}
	names := map[*ast.File]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor", ".scratch", ".gopath", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		n := d.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || strings.Contains(n, "generated") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return nil // not this guard's job to fail on an unparsable file
		}
		byDir[filepath.Dir(p)] = append(byDir[filepath.Dir(p)], f)
		rel, _ := filepath.Rel(root, p)
		names[f] = rel
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, files := range byDir {
		// Same-package functions whose own body (closures included) calls besteffort.Run.
		runners := map[string]bool{}
		for _, f := range files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok && isBestEffortRun(c) {
						runners[fd.Name.Name] = true
						runCalls++
					}
					return true
				})
			}
		}
		for _, f := range files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				recv := ""
				if fd.Recv != nil && len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
					recv = fd.Recv.List[0].Names[0].Name
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					outer, ok := n.(*ast.CallExpr)
					if !ok || !isWithTransaction(outer) {
						return true
					}
					for _, a := range outer.Args {
						lit, ok := a.(*ast.FuncLit)
						if !ok {
							continue
						}
						txClosures++
						ast.Inspect(lit.Body, func(m ast.Node) bool {
							c, ok := m.(*ast.CallExpr)
							if !ok {
								return true
							}
							line := fset.Position(c.Pos()).Line
							if isBestEffortRun(c) {
								if isSavepointStep(c) {
									return false // sanctioned: nested savepoint, nothing inside is a hit
								}
								hits = append(hits, txHit{names[f], fd.Name.Name, "besteffort.Run inside WithTransaction at line " + strconv.Itoa(line)})
								return true
							}
							// One hop, resolved by bare name, so restrict to calls that
							// can only be the package's own helper: a plain call or a
							// call on the enclosing method's receiver. (tx.CreateUser
							// is a storage method that merely shares a name with the
							// core CreateUser that runs besteffort.Run.)
							var callee string
							switch fn := c.Fun.(type) {
							case *ast.Ident:
								callee = fn.Name
							case *ast.SelectorExpr:
								if x, ok := fn.X.(*ast.Ident); ok && recv != "" && x.Name == recv {
									callee = fn.Sel.Name
								}
							}
							if callee != "" && runners[callee] {
								hits = append(hits, txHit{names[f], fd.Name.Name, "calls " + callee + " (runs besteffort.Run) inside WithTransaction at line " + strconv.Itoa(line)})
							}
							return true
						})
					}
					return true
				})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].String() < hits[j].String() })
	return hits, txClosures, runCalls
}

func TestNoBestEffortRunInsideTransaction(t *testing.T) {
	hits, txClosures, runCalls := scanTxMisuse(t, repoRoot(t))
	// Precondition: a scan that saw no transactions or no Run calls proves nothing.
	if txClosures < 20 || runCalls < 20 {
		t.Fatalf("scan looks broken: saw %d WithTransaction closures and %d besteffort.Run calls", txClosures, runCalls)
	}
	for _, h := range hits {
		t.Errorf("besteffort.Run is post-commit only (see package doc): %s", h)
	}
}

// Planted positives and a known-good: the scan must flag the direct and the
// one-hop shapes and stay quiet for a post-commit use.
func TestTxGuardScanFlagsPlantedMisuse(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("bad.go", `package p
func helper() { besteffort.Run(nil, "x", func() error { return nil }) }
func direct(s S) {
	s.WithTransaction(nil, func(tx S) error {
		besteffort.Run(nil, "x", func() error { return nil })
		return nil
	})
}
func hop(s S) {
	s.WithTransaction(nil, func(tx S) error {
		helper()
		return nil
	})
}
func sp(s S) {
	s.WithTransaction(nil, func(tx S) error {
		besteffort.Run(nil, "x", func() error {
			return tx.WithTransaction(nil, func(sv S) error { return nil })
		})
		return nil
	})
}
func (c *C) viaRecv(s S) {
	s.WithTransaction(nil, func(tx S) error {
		c.helper()
		tx.helper()
		return nil
	})
}
func ok(s S) {
	_ = s.WithTransaction(nil, func(tx S) error { return nil })
	besteffort.Run(nil, "x", func() error { return nil })
	helper()
}
`)
	hits, closures, _ := scanTxMisuse(t, dir)
	if closures != 6 { // five outer closures plus the savepoint's nested one
		t.Fatalf("closures = %d, want 6", closures)
	}
	// direct, one-hop, and the receiver call; NOT the savepoint step, tx.helper() or ok().
	if len(hits) != 3 {
		t.Fatalf("hits = %v, want exactly the direct, one-hop and receiver-hop cases", hits)
	}
}
