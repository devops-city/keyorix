package statemap

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

// FLAKE-TZ-1: time.Local is a package-level global that the runtime's timers and
// every time.Now() caller read without synchronisation. A test that assigns it
// (even with a t.Cleanup restore, even without t.Parallel) races with any
// goroutine alive in the process: timers, servers and background workers left
// by earlier subtests, other tests in the package. It failed the merge queue
// for #3168 (server/admin TestAdminBackupRestore_SQLite_RoundTripAcrossHostTZ).
//
// To exercise a host time zone, run the case in a subprocess of the test
// binary started with TZ=<zone> (see runInHostTZ in
// server/admin/backup_restore_tz_test.go), or pass a *time.Location explicitly.
//
// Recognised forms, all resolved through the file's actual import name for
// "time" (so an alias or a dot import cannot hide it):
//   - time.Local = x, time.Local, y = ..., (also op-assign forms)
//   - &time.Local (its address can be written through)
//
// Not recognised: writes through a copied pointer obtained elsewhere
// (p := &time.Local is caught at the &time.Local; passing that p on is not
// followed) and reflection/unsafe. Production (non-_test) files are out of scope.
func TestNoTestAssignsTimeLocal(t *testing.T) {
	root := repoRoot(t)
	skipDirs := map[string]bool{".git": true, "node_modules": true, "vendor": true, "web": true}
	var violations []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		for _, pos := range timeLocalWrites(f, fset) {
			rel, _ := filepath.Rel(root, path)
			violations = append(violations, rel+":"+strconv.Itoa(pos.Line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d _test.go files under %s: the walk is not covering the repo", scanned, root)
	}
	for _, v := range violations {
		t.Errorf("%s writes time.Local. time.Local is a process-wide global read by timers and time.Now() "+
			"on other goroutines, so assigning it in a test is a data race under -race even with a restoring "+
			"t.Cleanup. Run the host-TZ case in a subprocess with TZ=<zone> (runInHostTZ in "+
			"server/admin/backup_restore_tz_test.go) or pass a *time.Location explicitly", v)
	}
}

// timeLocalWrites returns the positions in f where time.Local is assigned or has
// its address taken.
func timeLocalWrites(f *ast.File, fset *token.FileSet) []token.Position {
	name := ""
	dot := false
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p != "time" {
			continue
		}
		switch {
		case imp.Name == nil:
			name = "time"
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name == "_":
		default:
			name = imp.Name.Name
		}
	}
	if name == "" && !dot {
		return nil
	}
	isLocal := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && name != "" && id.Name == name && x.Sel.Name == "Local"
		case *ast.Ident:
			return dot && x.Name == "Local"
		}
		return false
	}
	var out []token.Position
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if isLocal(lhs) {
					out = append(out, fset.Position(lhs.Pos()))
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && isLocal(x.X) {
				out = append(out, fset.Position(x.Pos()))
			}
		}
		return true
	})
	return out
}

// The detector must see each shape it claims to, and must not flag reads.
func TestTimeLocalWriteDetector(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"assign", "package p\nimport \"time\"\nfunc f(l *time.Location) { time.Local = l }", 1},
		{"alias", "package p\nimport tm \"time\"\nfunc f(l *tm.Location) { tm.Local = l }", 1},
		{"address", "package p\nimport \"time\"\nfunc f() { p := &time.Local; _ = p }", 1},
		{"tuple", "package p\nimport \"time\"\nfunc f(l *time.Location) { var x int; time.Local, x = l, 1; _ = x }", 1},
		{"read", "package p\nimport \"time\"\nfunc f() { _ = time.Now().In(time.Local) }", 0},
		{"other pkg named time", "package p\nimport time \"example.com/faketime\"\nfunc f() { time.Local = nil }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x_test.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(timeLocalWrites(f, fset)); got != c.want {
			t.Errorf("%s: got %d writes, want %d", c.name, got, c.want)
		}
	}
}
