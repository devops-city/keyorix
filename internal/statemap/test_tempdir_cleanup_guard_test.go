package statemap

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TEST-TMP-LEAK-1: server/admin_integration_test.go built a ~99 MB keyorix-server
// binary into os.MkdirTemp("", ...) on every run and never removed it; 98 of them
// (9.7 GB) piled up in one developer's TMPDIR. A directory or file made with
// os.MkdirTemp / os.CreateTemp (or the ioutil equivalents) outlives the test
// unless something removes it, unlike t.TempDir().
//
// This guard fails when a top-level declaration in a *_test.go file calls one of
// those functions and the same declaration (closures included) has no cleanup:
// a call to os.Remove / os.RemoveAll, or any `.Cleanup(` method call (t.Cleanup,
// tb.Cleanup, f.Cleanup). Prefer t.TempDir() when the lifetime is one test.
//
// Justified exceptions (cleanup lives in another function, typically a TestMain)
// go in testdata/test_tempdir_allowlist.txt as `path/to/file_test.go:FuncName  # reason`.
// An allowlist entry is itself checked: it must still point at a declaration
// that creates a temp resource without same-declaration cleanup, so it cannot go stale.
//
// Recognised forms, resolved through the file's actual import name (an alias or
// a dot import cannot hide them): os.MkdirTemp, os.CreateTemp, ioutil.TempDir,
// ioutil.TempFile (io/ioutil).
//
// Not recognised: any cleanup call in the same declaration counts, whether or not it
// targets the created path (it is a name-level check, not data flow); temp paths made
// by other means (os.Mkdir under os.TempDir(), subprocesses writing to TMPDIR); and
// non-_test.go helper files (internal/testhelper, scripts/e2e/harness), which are
// reviewed by hand. The empirical check for those is running the package with a fresh
// TMPDIR and listing it afterwards.
const testTempdirAllowlistPath = "testdata/test_tempdir_allowlist.txt"

func TestNoTestLeaksTempResources(t *testing.T) {
	root := repoRoot(t)
	allow := loadTempdirAllowlist(t)
	skipDirs := map[string]bool{".git": true, "node_modules": true, "vendor": true, "web": true}
	var violations []string
	creators := map[string]bool{} // "rel:Decl" -> true when the decl creates a temp resource
	uncleaned := map[string]bool{}
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
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, u := range tempResourceUses(f, fset) {
			key := rel + ":" + u.decl
			creators[key] = true
			if u.cleaned {
				continue
			}
			uncleaned[key] = true
			if _, ok := allow[key]; !ok {
				violations = append(violations, rel+":"+strconv.Itoa(u.line)+" in "+u.decl)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d _test.go files under %s: the walk is not covering the repo", scanned, root)
	}
	if len(creators) == 0 {
		t.Fatal("found no os.MkdirTemp/os.CreateTemp use in any test: the detector is not seeing the repo")
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("%s creates a temp dir/file (os.MkdirTemp/os.CreateTemp) with no os.Remove/os.RemoveAll/"+
			"t.Cleanup in the same declaration, so it is left behind in $TMPDIR on every run. Use t.TempDir() "+
			"if the lifetime is one test, otherwise remove it (t.Cleanup or TestMain) or add a reasoned entry "+
			"to internal/statemap/%s", v, testTempdirAllowlistPath)
	}
	// Premise check, both directions: an allowlist entry must still be needed.
	for key, reason := range allow {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("allowlist entry %s has no reason", key)
		}
		if !uncleaned[key] {
			t.Errorf("allowlist entry %s no longer names a declaration that creates a temp resource without "+
				"same-declaration cleanup; remove it from %s", key, testTempdirAllowlistPath)
		}
	}
}

type tempUse struct {
	decl    string
	line    int
	cleaned bool
}

// tempResourceUses returns one entry per top-level declaration in f that creates a
// temp dir/file, with whether that declaration also contains a cleanup call.
func tempResourceUses(f *ast.File, fset *token.FileSet) []tempUse {
	osName, ioutilName := "", ""
	osDot, ioutilDot := false, false
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != "os" && p != "io/ioutil" {
			continue
		}
		name := ""
		switch {
		case imp.Name == nil:
			name = filepath.Base(p)
		case imp.Name.Name == ".":
			if p == "os" {
				osDot = true
			} else {
				ioutilDot = true
			}
		case imp.Name.Name == "_":
		default:
			name = imp.Name.Name
		}
		if p == "os" {
			osName = name
		} else {
			ioutilName = name
		}
	}
	if osName == "" && ioutilName == "" && !osDot && !ioutilDot {
		return nil
	}
	isPkgFunc := func(e ast.Expr, pkg string, dot bool, names ...string) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && pkg != "" && id.Name == pkg && slices.Contains(names, x.Sel.Name)
		case *ast.Ident:
			return dot && slices.Contains(names, x.Name)
		}
		return false
	}
	var out []tempUse
	for _, decl := range f.Decls {
		name := "<var>"
		switch d := decl.(type) {
		case *ast.FuncDecl:
			name = d.Name.Name
			if d.Recv != nil && len(d.Recv.List) == 1 {
				name = recvTypeName(d.Recv.List[0].Type) + "." + name
			}
		case *ast.GenDecl:
		default:
			continue
		}
		firstLine, cleaned := 0, false
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch {
			case isPkgFunc(call.Fun, osName, osDot, "MkdirTemp", "CreateTemp"),
				isPkgFunc(call.Fun, ioutilName, ioutilDot, "TempDir", "TempFile"):
				if firstLine == 0 {
					firstLine = fset.Position(call.Pos()).Line
				}
			case isPkgFunc(call.Fun, osName, osDot, "Remove", "RemoveAll"):
				cleaned = true
			default:
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Cleanup" {
					cleaned = true
				}
			}
			return true
		})
		if firstLine != 0 {
			out = append(out, tempUse{decl: name, line: firstLine, cleaned: cleaned})
		}
	}
	return out
}

func recvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(x.X)
	case *ast.IndexExpr:
		return recvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return "?"
}

func loadTempdirAllowlist(t *testing.T) map[string]string {
	t.Helper()
	fh, err := os.Open(testTempdirAllowlistPath)
	if err != nil {
		t.Fatalf("open allowlist: %v", err)
	}
	defer func() { _ = fh.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, reason, _ := strings.Cut(line, "#")
		key := strings.Join(strings.Fields(entry), "")
		if _, dup := out[key]; dup {
			t.Errorf("duplicate allowlist entry %s", key)
		}
		out[key] = strings.TrimSpace(reason)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The detector must flag each leaking shape and accept each cleaned one.
func TestTempResourceDetector(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		wantUses    int
		wantCleaned bool
	}{
		{"leak mkdirtemp", "package p\nimport \"os\"\nfunc f() { _, _ = os.MkdirTemp(\"\", \"x\") }", 1, false},
		{"leak createtemp", "package p\nimport \"os\"\nfunc f() { _, _ = os.CreateTemp(\"\", \"x\") }", 1, false},
		{"leak ioutil", "package p\nimport \"io/ioutil\"\nfunc f() { _, _ = ioutil.TempDir(\"\", \"x\") }", 1, false},
		{"leak ioutil tempfile", "package p\nimport \"io/ioutil\"\nfunc f() { _, _ = ioutil.TempFile(\"\", \"x\") }", 1, false},
		{"leak aliased", "package p\nimport o \"os\"\nfunc f() { _, _ = o.MkdirTemp(\"\", \"x\") }", 1, false},
		{"leak dot import", "package p\nimport . \"os\"\nfunc f() { _, _ = MkdirTemp(\"\", \"x\") }", 1, false},
		{"leak method", "package p\nimport \"os\"\ntype w struct{}\nfunc (x *w) f() { _, _ = os.MkdirTemp(\"\", \"x\") }", 1, false},
		{"removeall", "package p\nimport \"os\"\nfunc f() { d, _ := os.MkdirTemp(\"\", \"x\"); defer os.RemoveAll(d) }", 1, true},
		{"remove", "package p\nimport \"os\"\nfunc f() { fh, _ := os.CreateTemp(\"\", \"x\"); _ = os.Remove(fh.Name()) }", 1, true},
		{"t.Cleanup", "package p\nimport \"testing\"\nimport \"os\"\nfunc f(t *testing.T) { _, _ = os.MkdirTemp(\"\", \"x\"); t.Cleanup(func() {}) }", 1, true},
		{"cleanup in closure", "package p\nimport \"os\"\nfunc f() { func() { d, _ := os.MkdirTemp(\"\", \"x\"); _ = func() { _ = os.RemoveAll(d) } }() }", 1, true},
		{"t.TempDir is fine", "package p\nimport \"testing\"\nfunc f(t *testing.T) { _ = t.TempDir() }", 0, false},
		{"other pkg named os", "package p\nimport os \"example.com/fakeos\"\nfunc f() { _, _ = os.MkdirTemp(\"\", \"x\") }", 0, false},
		{"cleanup in other decl does not count", "package p\nimport \"os\"\nfunc f() { _, _ = os.MkdirTemp(\"\", \"x\") }\nfunc g() { _ = os.RemoveAll(\"y\") }", 1, false},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x_test.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := tempResourceUses(f, fset)
		if len(got) != c.wantUses {
			t.Errorf("%s: got %d uses, want %d", c.name, len(got), c.wantUses)
			continue
		}
		if c.wantUses == 1 && got[0].cleaned != c.wantCleaned {
			t.Errorf("%s: cleaned=%v, want %v", c.name, got[0].cleaned, c.wantCleaned)
		}
	}
}
