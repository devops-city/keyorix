// package_stays_light_guard_test.go — keeps this package the cheap place to run
// source-scanning guards (CACHE-GUARDS-1).
//
// The reason these tests live here and not in internal/core is the size of
// core's test archive: every test double that embeds the ~1,000-method
// storage.Storage interface adds ~2.5 MB of promoted-method wrappers, and core
// has over a hundred of them (hundreds of MB per source state). Preflight runs
// every static guard on every PR tree, so a guard that drifted back into core
// (or a guard here that grew an embedded-Storage fake, or imported core and so
// its test-visible surface) would quietly bring that cost back with nothing red.
// This test makes the two ways of undoing the move fail the build.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const corePkgImportPath = "github.com/keyorixhq/keyorix/internal/core"

// packageStaysLightViolations returns one line per violation in the given Go
// sources (file name -> source): an import of internal/core itself, or a struct
// type that embeds a Storage (the shape that generates a wrapper per promoted
// method).
func packageStaysLightViolations(t *testing.T, sources map[string]string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	for name, src := range sources {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == corePkgImportPath {
				out = append(out, name+": imports "+corePkgImportPath+" -- a guard that needs core's types or mocks belongs in internal/core")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				if len(field.Names) != 0 {
					continue // a named field is not promoted
				}
				typ := field.Type
				if star, ok := typ.(*ast.StarExpr); ok {
					typ = star.X
				}
				switch e := typ.(type) {
				case *ast.SelectorExpr:
					if e.Sel.Name == "Storage" {
						out = append(out, name+": a struct embeds "+e.Sel.Name+" -- a test double of the 1,000-method storage interface costs ~2.5 MB of object code; keep it in internal/core or use a named field")
					}
				case *ast.Ident:
					if e.Name == "Storage" {
						out = append(out, name+": a struct embeds Storage -- a test double of the 1,000-method storage interface costs ~2.5 MB of object code; keep it in internal/core or use a named field")
					}
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestGuardsPackageStaysLight(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(".", e.Name())) // #nosec G304 -- this package's own files
		if rerr != nil {
			t.Fatal(rerr)
		}
		sources[e.Name()] = string(b)
	}
	if len(sources) < 40 {
		t.Fatalf("read only %d files from the package directory; the scan is not looking at the package", len(sources))
	}
	if got := packageStaysLightViolations(t, sources); len(got) > 0 {
		t.Errorf("internal/core/guards must stay light (see package doc):\n  %s", strings.Join(got, "\n  "))
	}
}

// TestGuardsPackageStaysLight_Calibration proves the check can go red: each
// forbidden shape is reported, and the permitted ones (a named Storage field,
// an import of a core subpackage) are not.
func TestGuardsPackageStaysLight_Calibration(t *testing.T) {
	bad := map[string]string{
		"imports_core.go": "package x\nimport _ \"github.com/keyorixhq/keyorix/internal/core\"\n",
		"embeds_pkg.go":   "package x\nimport \"a/storage\"\ntype fake struct{ storage.Storage }\n",
		"embeds_ptr.go":   "package x\nimport \"a/storage\"\ntype fake struct{ *storage.Storage; n int }\n",
		"embeds_bare.go":  "package x\ntype fake struct{ Storage }\n",
	}
	got := packageStaysLightViolations(t, bad)
	if len(got) != 4 {
		t.Fatalf("want 4 violations (one per planted file), got %d: %v", len(got), got)
	}
	ok := map[string]string{
		"named_field.go": "package x\nimport \"a/storage\"\ntype holder struct{ store storage.Storage }\n",
		"subpackage.go":  "package x\nimport _ \"github.com/keyorixhq/keyorix/internal/core/storage\"\n",
	}
	if got := packageStaysLightViolations(t, ok); len(got) != 0 {
		t.Fatalf("permitted shapes were reported: %v", got)
	}
}
