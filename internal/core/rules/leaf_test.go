package rules

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedModuleImports are the only packages from this module that rules'
// production code may import. Everything else from the module (core, i18n,
// storage, connectors, ...) would pull its dependency tree into every fuzz
// binary built here and undo the point of the package (see doc.go).
var allowedModuleImports = map[string]bool{
	"github.com/keyorixhq/keyorix/internal/storage/models": true,
}

// TestRulesStaysALeaf fails when a non-test file in this package imports
// anything outside the standard library except allowedModuleImports.
// Third-party modules are refused too: a stdlib import path has no dot in its
// first element.
func TestRulesStaysALeaf(t *testing.T) {
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
			if !strings.Contains(first, ".") || allowedModuleImports[p] {
				continue
			}
			t.Errorf("%s imports %q: package rules must stay a leaf (stdlib + %v only)", f, p, keys(allowedModuleImports))
		}
	}
	if checked == 0 {
		t.Fatal("no production files found; is the test running in the package dir?")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
