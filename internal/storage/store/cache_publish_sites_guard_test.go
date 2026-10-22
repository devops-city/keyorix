// cache_publish_sites_guard_test.go — RIG-GUARD6-CHECK-1 (GUARD-6 item 3's
// completeness check, the part of GUARD-6 that never landed).
//
// The bug class (#2764/#2767 review): a read-path cache entry is published
// under a generation stamp read AFTER the data, so a write committing between
// the two leaves the pre-change answer cached under the post-change stamp.
// Each cache has a race test that commits the write between data query and
// cache write. What nothing checked is that a NEW call site publishing into a
// cache comes with such a test.
//
// This guard enumerates every non-test call of a cache's publish method
// (secretMetaCache.setNode/setVersion/setSchedule, rolePermCache.set,
// foldMemo.set) by receiver-field name, requires the enclosing function to be
// registered below with the name of the test that proves its ordering, and
// requires that test to exist in this package. It does NOT prove the named test
// is a race test: that stays a review obligation, stated here so the registry
// is read as "who is accountable", not "verified".
//
// Recognised call forms: `<expr>.<field>.<method>(...)` where field is one of
// the cache fields below. A cache reached through a local alias
// (`c := ls.rolePermCache; c.set(...)`) is not recognised; the cache types are
// unexported, so the alias would have to be written inside this package, where
// the second assertion (the registry covers every publish method DECLARED on
// the cache types) still fails if a method is added without a registry row.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cachePublishers: cache field name -> publishing methods on that cache type.
var cachePublishers = map[string]map[string]bool{
	"secretMetaCache": {"setNode": true, "setVersion": true, "setSchedule": true},
	"rolePermCache":   {"set": true},
	"foldMemo":        {"set": true},
}

// cachePublisherTypes: receiver type -> field it is held in (for the
// declared-methods completeness check).
var cachePublisherTypes = map[string]string{
	"secretMetadataCache": "secretMetaCache",
	"rolePermissionCache": "rolePermCache",
	"foldMemo":            "foldMemo",
}

// cachePublishSites: function that publishes -> test that proves the stamp is
// read before the data (or, for the same-row case, comes from the same query).
var cachePublishSites = map[string]string{
	"GetSecret":                           "TestGetSecret_NodeReadCountIncrementInvalidatesCache",
	"readLatestSecretVersionRow":          "TestGetLatestSecretVersion_RotationDuringResolveIsNotCachedStale",
	"GetSecretAccessSchedule":             "TestGetSecretAccessSchedule_CacheReflectsSetAndDelete",
	"GetSecretScheduleAndLatestVersion":   "TestGetSecretScheduleAndLatestVersion_OneStatementAndSharedCaches",
	"RoleSetHasPermission":                "TestRoleSetHasPermission_RevokeDuringResolveIsNotCachedStale",
	"roleSetHasPermissionUnderGeneration": "TestResolvePrincipalPermission_GenerationReadBeforeTheJoin",
	"foldedStatement":                     "TestFoldedNodeStamp_StaleStampIsAMiss",
}

func parsePackageFiles(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	var files []*ast.File
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", n), nil, 0)
		require.NoError(t, err)
		files = append(files, f)
	}
	require.NotEmpty(t, files)
	return fset, files
}

func TestCachePublishSites_EveryPublisherIsRegisteredWithAProvingTest(t *testing.T) {
	fset, files := parsePackageFiles(t)

	found := map[string][]string{} // enclosing func -> positions
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if cachePublishers[recv.Sel.Name][sel.Sel.Name] {
					found[fn.Name.Name] = append(found[fn.Name.Name], fset.Position(call.Pos()).String())
				}
				return true
			})
		}
	}
	require.NotEmpty(t, found, "no publish call found: the guard's recognised call forms no longer match the code")

	var unregistered []string
	for fn, pos := range found {
		if _, ok := cachePublishSites[fn]; !ok {
			unregistered = append(unregistered, fn+" at "+strings.Join(pos, ", "))
		}
	}
	sort.Strings(unregistered)
	require.Empty(t, unregistered,
		"these functions publish into a read-path cache but are not in cachePublishSites. Read the generation/stamp BEFORE the data "+
			"(or take it from the same row), and register the function with a test that commits a write between the data query and the cache write")

	// A registry row whose function no longer publishes is dead weight that
	// would excuse a future bypass under the same name.
	for fn := range cachePublishSites {
		require.Contains(t, found, fn, "cachePublishSites row %q no longer publishes into a cache: remove it", fn)
	}

	// The named proving tests must exist.
	have := map[string]bool{}
	tfset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(tfset, e.Name(), nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
				have[fn.Name.Name] = true
			}
		}
	}
	for fn, test := range cachePublishSites {
		require.True(t, have[test], "%s: proving test %s does not exist", fn, test)
	}
}

// Every publishing method DECLARED on a cache type must be in cachePublishers,
// so adding setFoo to a cache cannot dodge the call-site scan above.
func TestCachePublishSites_EveryDeclaredPublisherMethodIsScanned(t *testing.T) {
	_, files := parsePackageFiles(t)
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok {
				continue
			}
			field, isCache := cachePublisherTypes[id.Name]
			if !isCache {
				continue
			}
			name := fn.Name.Name
			if strings.HasPrefix(name, "set") || strings.HasPrefix(name, "merge") || strings.HasPrefix(name, "put") || strings.HasPrefix(name, "store") {
				require.True(t, cachePublishers[field][name],
					"%s.%s looks like a cache write but is not in cachePublishers: the call-site scan would not see it", id.Name, name)
			}
		}
	}
}
