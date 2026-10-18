package srcpath

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoTestOpensFilesViaRuntimeCallerPath is the static guard for the
// -trimpath contract (see the package comment): under `go build -trimpath`
// runtime.Caller's file name is module-relative, so a test that feeds it to
// filepath.Dir/os.ReadFile/... passes on a plain build and breaks with
// -trimpath. Use srcpath.RepoRoot()/PkgDir() instead.
//
// What it checks: every *_test.go in the repo's root module, plus the
// non-test helper packages under internal/testutil and
// server/http/handlers/contracttest (loaded into test binaries), is parsed and
// any `runtime.Caller(...)` call whose second result (the file name) is bound
// to a name other than `_` is reported. Callers that only want the program
// counter or the line number (`pc, _, line, _ := runtime.Caller(1)`) stay legal.
//
// What it does NOT check: file names taken from runtime.CallersFrames
// (Frame.File), reflect/debug.Stack parsing, or a package that shadows the
// identifier `runtime`. None of those occur in the repo today; widen the
// matcher if one appears. Nested modules (cli, operator, migrate, devtools)
// have no test-time runtime.Caller file lookups and are not scanned.
func TestNoTestOpensFilesViaRuntimeCallerPath(t *testing.T) {
	root := RepoRoot()
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".scratch", "vendor":
				return filepath.SkipDir
			}
			// Nested modules are scanned by their own `go test`, not this guard.
			if path != root {
				if modulePath(filepath.Join(path, "go.mod")) != "" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		inScope := strings.HasSuffix(rel, "_test.go") ||
			strings.HasPrefix(rel, "internal/testutil/") ||
			strings.HasPrefix(rel, "server/http/handlers/contracttest/")
		if !inScope || rel == "internal/testutil/srcpath/runtime_caller_guard_test.go" {
			return nil
		}
		src, err := parseFile(path)
		if err != nil {
			t.Errorf("parse %s: %v", rel, err)
			return nil
		}
		for _, v := range runtimeCallerFileUses(src.fset, src.file) {
			violations = append(violations, rel+":"+v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Errorf("%s: runtime.Caller file name is not a filesystem path under -trimpath; "+
			"use srcpath.RepoRoot()/srcpath.PkgDir() (internal/testutil/srcpath)", v)
	}
}

// TestRuntimeCallerGuardCatchesAndSpares is the red/green calibration of the
// matcher above: it must flag the file-name shapes and spare pc/line-only use.
func TestRuntimeCallerGuardCatchesAndSpares(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"file via define", `_, thisFile, _, ok := runtime.Caller(0); _, _ = thisFile, ok`, 1},
		{"file via assign", `var f string; _, f, _, _ = runtime.Caller(0); _ = f`, 1},
		{"file via var", `var _, f, _, _ = runtime.Caller(0); _ = f`, 1},
		{"pc and line only", `pc, _, line, _ := runtime.Caller(1); _, _ = pc, line`, 0},
		{"all blank", `_, _, _, _ = runtime.Caller(0)`, 0},
		{"single-value call", `_ = runtime.NumCPU()`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", "package x\nimport \"runtime\"\nfunc f() { "+c.body+" }\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(runtimeCallerFileUses(fset, f)); got != c.want {
				t.Fatalf("got %d violations, want %d", got, c.want)
			}
		})
	}
}

type parsedFile struct {
	fset *token.FileSet
	file *ast.File
}

func parseFile(path string) (parsedFile, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	return parsedFile{fset, f}, err
}

// runtimeCallerFileUses returns "line" strings for each runtime.Caller call
// whose second result is bound to a non-blank name.
func runtimeCallerFileUses(fset *token.FileSet, f *ast.File) []string {
	var out []string
	isCaller := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Caller" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "runtime"
	}
	secondIsNamed := func(lhs []*ast.Ident) bool {
		return len(lhs) >= 2 && lhs[1].Name != "_"
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && isCaller(x.Rhs[0]) && len(x.Lhs) >= 2 {
				if id, ok := x.Lhs[1].(*ast.Ident); !ok || id.Name != "_" {
					out = append(out, lineOf(fset, x.Pos()))
				}
			}
		case *ast.ValueSpec:
			if len(x.Values) == 1 && isCaller(x.Values[0]) && secondIsNamed(x.Names) {
				out = append(out, lineOf(fset, x.Pos()))
			}
		}
		return true
	})
	return out
}

func lineOf(fset *token.FileSet, p token.Pos) string {
	return strconv.Itoa(fset.Position(p).Line)
}
