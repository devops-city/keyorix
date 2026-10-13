package regularfile

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

// TestCLIFileReadsGoThroughRegularfile is the class guard for "an operator-named
// input file read blocks on a FIFO" in the cli module (FIFO-5). It is the cli twin of
// internal/secretenv's TestSecretFileReadsGoThroughOpenRegular, which does not scan
// this module (its own go.mod; ADR-108 forbids importing the main module's internals,
// so the helper and the guard are copies, kept in step).
//
// A plain os.Open / os.ReadFile / os.OpenFile(O_RDONLY) blocks in open(2) on a FIFO
// until a writer appears. regularfile.Open opens non-blocking and refuses a
// non-regular file on the same descriptor.
//
// It walks every non-test Go file of the cli module and fails on any read-side
// os.Open, os.OpenFile (no write/create flag) or os.ReadFile / ioutil.ReadFile that is
// neither inside regularfile.OpenFlags nor listed in nonOperatorFileReads with a
// reason. A new read therefore has to use regularfile or be added to the list (a
// reviewable, one-line decision). Stdin ("-") is not a file open and is unaffected.
//
// What it recognises: calls spelled os.Open, os.OpenFile, os.ReadFile and
// ioutil.ReadFile through the file's own import name for "os" / "io/ioutil". It does
// not see a read hidden behind a function value, a reflected call, golang.org/x/sys/unix
// opens (unix.Open/Openat, used by cli/internal/securefiles on its own directory
// walk), or a different package that wraps os.ReadFile. Write-side OpenFile calls
// (O_WRONLY, O_RDWR, O_CREATE, O_APPEND, O_TRUNC) are skipped.
func TestCLIFileReadsGoThroughRegularfile(t *testing.T) {
	root := moduleRoot(t)
	found := scanFileReads(t, root)

	allowed := map[string]bool{}
	for k := range nonOperatorFileReads {
		allowed[k] = false
	}
	var bypass []string
	for _, site := range found {
		if _, ok := allowed[site.key]; ok {
			allowed[site.key] = true
			continue
		}
		bypass = append(bypass, site.String())
	}
	if len(bypass) > 0 {
		t.Errorf("file read(s) bypass regularfile.Open (a FIFO at that path would hang open(2)).\n"+
			"Use regularfile.Open / regularfile.ReadFile, or, if the path is not operator-supplied, add \"<file>:<func>\" to nonOperatorFileReads with the reason:\n  %s",
			strings.Join(bypass, "\n  "))
	}
	var stale []string
	for k, used := range allowed {
		if !used {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("nonOperatorFileReads has entries that match no file read any more (remove them): %s", strings.Join(stale, ", "))
	}
}

// nonOperatorFileReads lists the read sites deliberately not routed through regularfile,
// keyed "<module-relative file>:<enclosing func>". Every read of a path the operator
// (or a scanned tree) names goes through regularfile; what is left is not a runtime
// operator input. Do NOT add an operator-supplied path here: use regularfile.
var nonOperatorFileReads = map[string]string{
	"internal/apiclient/gen/filterspec.go:run": "build-time codegen tool (`make client`), argv from the Makefile, not shipped in the CLI binary",
}

type readSite struct {
	file, fn, call string
	line           int
	key            string
}

func (s readSite) String() string {
	return s.file + ":" + strconv.Itoa(s.line) + " " + s.call + " in " + s.fn + " (key " + s.key + ")"
}

func moduleRoot(t *testing.T) string {
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
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// fileReadsIn returns the read-side file opens in one parsed file, except those
// inside regularfile.OpenFlags itself.
func fileReadsIn(fset *token.FileSet, af *ast.File, rel string) []readSite {
	osName, ioutilName := "", ""
	for _, imp := range af.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch p {
		case "os":
			osName = name
		case "io/ioutil":
			ioutilName = name
		}
	}
	var out []readSite
	for _, decl := range af.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if rel == "internal/regularfile/regularfile.go" && fd.Name.Name == "OpenFlags" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := pkg.Name + "." + sel.Sel.Name
			switch {
			case osName != "" && pkg.Name == osName && (sel.Sel.Name == "Open" || sel.Sel.Name == "ReadFile"):
			case osName != "" && pkg.Name == osName && sel.Sel.Name == "OpenFile":
				if flagNames(call, 1).write {
					return true
				}
			case ioutilName != "" && pkg.Name == ioutilName && sel.Sel.Name == "ReadFile":
			default:
				return true
			}
			out = append(out, readSite{
				file: rel, fn: fd.Name.Name, call: name,
				line: fset.Position(call.Pos()).Line,
				key:  rel + ":" + fd.Name.Name,
			})
			return true
		})
	}
	return out
}

// openFlags is what a call's flags argument spells: the O_* names, and whether any
// is write-side (O_WRONLY, O_RDWR, O_CREATE, O_APPEND, O_TRUNC). A flags expression
// not spelled as pkg.O_* identifiers yields no names and write=false, which is
// treated as a read (the conservative direction: it is flagged).
type openFlags struct {
	names map[string]bool
	write bool
}

func flagNames(call *ast.CallExpr, argIdx int) openFlags {
	out := openFlags{names: map[string]bool{}}
	if len(call.Args) <= argIdx {
		return out
	}
	ast.Inspect(call.Args[argIdx], func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "O_") {
			out.names[sel.Sel.Name] = true
			switch sel.Sel.Name {
			case "O_WRONLY", "O_RDWR", "O_CREATE", "O_APPEND", "O_TRUNC":
				out.write = true
			}
		}
		return true
	})
	return out
}

func scanFileReads(t *testing.T, root string) []readSite {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var out []readSite
	fset := token.NewFileSet()
	for _, path := range files {
		af, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, fileReadsIn(fset, af, filepath.ToSlash(rel))...)
	}
	return out
}

// The guard must fire on a violation and stay quiet on a conforming file: both
// directions, on synthetic sources.
func TestFileReadScanner_RedGreen(t *testing.T) {
	scan := func(src string) []readSite {
		t.Helper()
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return fileReadsIn(fset, af, "pkg/x.go")
	}
	const imp = "package p\nimport \"os\"\n"
	for name, src := range map[string]string{
		"ReadFile":      imp + "func f(p string) { _, _ = os.ReadFile(p) }",
		"Open":          imp + "func f(p string) { _, _ = os.Open(p) }",
		"OpenFile read": imp + "func f(p string) { _, _ = os.OpenFile(p, os.O_RDONLY, 0) }",
		"aliased os":    "package p\nimport o \"os\"\nfunc f(p string) { _, _ = o.ReadFile(p) }",
		"ioutil":        "package p\nimport \"io/ioutil\"\nfunc f(p string) { _, _ = ioutil.ReadFile(p) }",
	} {
		if got := scan(src); len(got) != 1 {
			t.Errorf("%s: want 1 site flagged, got %d", name, len(got))
		}
	}
	for name, src := range map[string]string{
		"write open":  imp + "func f(p string) { _, _ = os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o600) }",
		"regularfile": "package p\nimport \"x/regularfile\"\nfunc f(p string) { _, _ = regularfile.ReadFile(\"w\", p) }",
		"unrelated":   imp + "func f() { _ = os.Getenv(\"X\") }",
	} {
		if got := scan(src); len(got) != 0 {
			t.Errorf("%s: want no site flagged, got %v", name, got)
		}
	}
}
