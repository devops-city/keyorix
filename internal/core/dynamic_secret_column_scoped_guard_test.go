package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDynamicSecretWrites_AreColumnScoped pins the #2698 fix structurally, so it
// holds in a DSN-less run too (the two
// TestCTAReview_{ClassifyDynamicSecretConfig,RenewLease}_vs_* Postgres tests are
// the behavioural proof, and they need real Postgres).
//
// Hops checked: ClassifyDynamicSecretConfig -> c.storage.SetDynamicSecretConfigClassification;
// RenewLease -> c.storage.ExtendDynamicSecretLeaseExpiry; both -> their LocalStorage bodies.
func TestDynamicSecretWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../storage/store/local_dynamic.go", "SetDynamicSecretConfigClassification")
	assertColumnScopedStorageWrite(t, "../storage/store/local_dynamic.go", "ExtendDynamicSecretLeaseExpiry")
	assertColumnScopedStorageWrite(t, "../storage/store/local_dynamic.go", "RecordDynamicSecretLeaseRevocation")

	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "ClassifyDynamicSecretConfig", "storage",
		"SetDynamicSecretConfigClassification", "Save", "UpdateDynamicSecretConfig")
	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "RenewLease", "storage",
		"ExtendDynamicSecretLeaseExpiry", "Save", "UpdateDynamicSecretLease")
	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "RevokeLease", "storage",
		"RecordDynamicSecretLeaseRevocation", "Save", "UpdateDynamicSecretLease")
}

// TestUpdateDynamicSecretLease_HasNoProductionCaller is the half that does NOT
// depend on anyone remembering to update a per-function guard.
//
// #2698 could not DELETE the two full-row primitives the way #2696 and #2697
// deleted theirs when this test was first written: `UpdateDynamicSecretConfig`
// had one production caller, CreateDynamicSecretConfig's encrypted-DSN write,
// a #2651 call site. #2675 has since landed SetDynamicSecretConfigAdminDSN and
// moved that write off UpdateDynamicSecretConfig, so the allowance below is now
// empty — both full-row methods are production-callerless and can be deleted
// in a follow-up.
//
// So the property is enforced by derivation instead of by removal, which is the
// stronger form anyway: a sweep over every non-test file under internal/core and
// server/ asserting that NOTHING calls the full-row lease writer, with any
// future caller named explicitly here so the count going up fails loudly.
//
// What this does not cover: a call reached through a helper that itself takes a
// storage.Storage, or reflection. Both are absent from this repo's storage call
// style, and this test's own job is the direct-call shape the defect took.
func TestUpdateDynamicSecretLease_HasNoProductionCaller(t *testing.T) {
	// Keyed file:ENCLOSING FUNC -> called method, with the exact number of call
	// sites expected, for the one deliberately-remaining caller.
	//
	// #2836 review: the first version of this list keyed on file:CALLED METHOD
	// and merely collected the enclosing function names into an unchecked value.
	// Two consequences, both of which defeat the guard's purpose: a SECOND
	// full-row caller added anywhere in the same file mapped onto the same
	// allowed key and passed silently, and a second call added to the SAME
	// already-allowed function did too. An allowlist whose granularity is
	// coarser than the thing it allows is an allow-the-file rule wearing an
	// allow-the-call-site label. Keying on the enclosing function and asserting
	// the count makes both cases red.
	allowed := map[string]struct {
		count int
		why   string
	}{}

	root := dynGuardRepoRoot(t)
	found := map[string]int{} // "file:enclosing func -> called method" -> number of call sites
	for _, dir := range []string{"internal/core", "internal/storage/store", "server"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			require.NoError(t, rerr)
			// The implementations themselves are the definitions, not callers.
			if rel == filepath.Join("internal", "storage", "store", "local_dynamic.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Logf("skipping unparseable %s: %v", rel, perr)
				return nil
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := ce.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "UpdateDynamicSecretLease", "UpdateDynamicSecretConfig":
						found[rel+":"+fd.Name.Name+" -> "+sel.Sel.Name]++
					}
					return true
				})
			}
			return nil
		})
		require.NoError(t, err)
	}

	for key, n := range found {
		want, ok := allowed[key]
		if !ok {
			t.Errorf("%s is still called from production code — #2698 moved every write of these two "+
				"models onto column-scoped conditional methods; a full-row Save here reverts whatever a "+
				"narrower concurrent writer changed (the dynamic-secret kill switch, a lease revocation)", key)
			continue
		}
		if n != want.count {
			t.Errorf("%s now has %d call site(s), not the %d reviewed — a full-row write added to an "+
				"already-allowed function is exactly as much of a lost update as one in a new function. "+
				"Reason the reviewed one is allowed: %s", key, n, want.count, want.why)
		}
	}
	for key, want := range allowed {
		if _, ok := found[key]; !ok {
			t.Errorf("allowed entry %q no longer matches any call site — delete it (and, if both full-row "+
				"methods are now callerless, delete the methods). Reason it was allowed: %s", key, want.why)
		}
	}
}

// dynGuardRepoRoot walks up from this package to the directory holding go.mod.
func dynGuardRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for range 8 {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate the repo root (no go.mod found walking up from the test's working directory)")
	return ""
}
