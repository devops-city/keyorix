package webauthnparse

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestWebauthnparseStaysALeaf fails when a non-test file in this package imports
// anything outside the standard library. See internal/core/rules/leaf_test.go —
// same shape, copied rather than reinvented. Currently only doc.go exists as a
// non-test file (this package has no production wrapper — see doc.go for why);
// if a real Keyorix wrapper is ever added here, it must stay stdlib-only too.
func TestWebauthnparseStaysALeaf(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if !strings.Contains(first, ".") {
				continue
			}
			t.Errorf("%s imports %q: package webauthnparse must stay a leaf (stdlib only)", f, p)
		}
	}
	if checked == 0 {
		t.Fatal("no production files found; is the test running in the package dir?")
	}
}
