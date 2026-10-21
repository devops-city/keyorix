package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// serverPackageSources returns every non-test .go file of this package
// (server/, package main), sorted. The structural guards that used to read
// main.go alone read these instead: the boot wiring is split over one file per
// domain (main.go keeps the ordered lists), so a guard over main.go only would
// pass vacuously the moment the code it checks lives in another file.
func serverPackageSources(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(srcpath.PkgDir(), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range paths {
		if !strings.HasSuffix(p, "_test.go") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	if len(out) < 2 || !containsBase(out, "main.go") {
		t.Fatalf("serverPackageSources found %d files without main.go: the guards would be vacuous", len(out))
	}
	return out
}

func containsBase(paths []string, base string) bool {
	for _, p := range paths {
		if filepath.Base(p) == base {
			return true
		}
	}
	return false
}

// parseServerPackage parses serverPackageSources into one FileSet.
func parseServerPackage(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	for _, p := range serverPackageSources(t) {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", p, err)
		}
		files = append(files, f)
	}
	return fset, files
}

// readServerPackage returns the concatenated source of serverPackageSources.
func readServerPackage(t *testing.T) []byte {
	t.Helper()
	var all []byte
	for _, p := range serverPackageSources(t) {
		src, err := os.ReadFile(p) // #nosec G304 -- this package's own source files
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, src...)
		all = append(all, '\n')
	}
	return all
}
