package dsn

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestDSNStaysALeaf fails when a non-test file in this package imports anything
// outside the standard library. See internal/core/rules/leaf_test.go — same shape,
// copied rather than reinvented (this package needs no module imports at all).
func TestDSNStaysALeaf(t *testing.T) {
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
			t.Errorf("%s imports %q: package dsn must stay a leaf (stdlib only)", f, p)
		}
	}
	if checked == 0 {
		t.Fatal("no production files found; is the test running in the package dir?")
	}
}
