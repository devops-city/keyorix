package core

// update_secret_column_scoped_guard_test.go — the default-ci half of #2695, so
// the fix is guarded in the DSN-less CI leg too (the three
// TestCTAReview_*_CrossReplicaPostgres tests are the behavioural proof and need
// real Postgres).

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

// TestUpdateSecretWrites_AreColumnScoped checks the storage body and every one of
// the eight call sites #2695 moved. Naming all eight is the point: the defect
// lived in the shared primitive, so a guard covering only the one the issue
// titles would leave seven live.
func TestUpdateSecretWrites_AreColumnScoped(t *testing.T) {
	assertColumnScopedStorageWrite(t, "../storage/store/local_secrets.go", "UpdateSecretFields")

	for _, c := range []struct{ file, fn string }{
		{"classification.go", "ClassifySecret"},
		{"secret_description.go", "SetSecretDescription"},
		{"secret_ownership.go", "transferOwnership"},
		{"secret_move.go", "MoveSecret"},
		{"secret_bulk_rename.go", "BulkRenameSecrets"},
		{"secret_extend_expiring.go", "ExtendExpiringSecrets"},
		{"secrets.go", "UpdateSecret"},
		{"secrets_versions.go", "updateSecretWithNewVersion"},
	} {
		// updateSecretWithNewVersion and transferOwnership (#3102: the owner write and
		// the share re-stamp share one transaction) write through their transaction
		// handle, so the required receiver is "tx" there and "storage" everywhere else.
		recv := "storage"
		if c.fn == "updateSecretWithNewVersion" || c.fn == "transferOwnership" {
			recv = "tx"
		}
		assertCoreWritesOnlyVia(t, c.file, c.fn, recv, "UpdateSecretFields", "Save", "UpdateSecret")
	}
}

// TestUpdateSecretRequest_FieldSetsMatch is the guard the comment on
// secretFieldUpdateFromRequest promises, rather than a comment asking the next
// reader to keep two functions in step by hand.
//
// applyUpdateSecretFields mutates the in-memory struct (for the value returned
// to the caller, and for the new-version path); secretFieldUpdateFromRequest
// names the columns that may actually be written. If a field is added to
// UpdateSecretRequest and wired into only the first, the API appears to accept
// it and silently never persists it. If only into the second, the returned
// object disagrees with the row. Both are silent, so this compares the set of
// `req.<Field>` reads in the two bodies.
func TestUpdateSecretRequest_FieldSetsMatch(t *testing.T) {
	apply := reqFieldsRead(t, "secrets.go", "applyUpdateSecretFields")
	derive := reqFieldsRead(t, "secrets.go", "secretFieldUpdateFromRequest")
	require.NotEmpty(t, apply, "sanity: applyUpdateSecretFields must read at least one request field")
	require.Equal(t, apply, derive,
		"applyUpdateSecretFields and secretFieldUpdateFromRequest must read the SAME UpdateSecretRequest "+
			"fields — a field wired into only one of them is either accepted-and-never-persisted or "+
			"persisted-but-not-reflected in the returned object, both silently (#2695)")
}

// reqFieldsRead returns the sorted set of `req.<Field>` selector names read in
// the named function's body.
func reqFieldsRead(t *testing.T, file, fn string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "req" {
				seen[sel.Sel.Name] = true
			}
			return true
		})
		out := make([]string, 0, len(seen))
		for k := range seen {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	t.Fatalf("%s: function %s not found — the guard's subject was renamed; update the guard", file, fn)
	return nil
}

// TestUpdateSecret_HasNoProductionCallerBeyond2668 is the derived half: a sweep
// asserting nothing calls the full-row UpdateSecret except the ONE call site
// #2695 deliberately left alone.
//
// #2695 could not delete the primitive the way #2696/#2697 deleted theirs when
// this test was first written: SetSecretAutoRotate (rotation_executor.go) was
// #2650's site. #2668 has since landed the column-scoped UpdateSecretRotationConfig
// and moved that call off UpdateSecret, so the allowance below is now empty —
// UpdateSecret is production-callerless and can be deleted, along with this
// test, in a follow-up.
//
// So the property is derived rather than achieved by removal — the stronger
// form anyway, because it fails in BOTH directions: a new caller appearing, and
// any future allowance going stale the same way this one just did.
//
// What this does not cover: a call reached through a helper that itself takes a
// storage.Storage, or reflection. Neither occurs in this repo's storage call
// style, and the direct-call shape is the one the defect took.
func TestUpdateSecret_HasNoProductionCallerBeyond2668(t *testing.T) {
	allowed := map[string]string{}

	root := updateSecretGuardRepoRoot(t)
	found := map[string][]string{}
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
			// The implementation itself is the definition, not a caller.
			if rel == filepath.Join("internal", "storage", "store", "local_secrets.go") {
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
					if !ok || sel.Sel.Name != "UpdateSecret" {
						return true
					}
					// core.UpdateSecret — the EXPORTED core method — shares its
					// name with the storage one and has entirely legitimate
					// callers (UpdateSecretWithPermissionCheck, the HTTP handler,
					// the gRPC service, the generated dispatcher). Discriminate
					// by RECEIVER, not by name: the storage method is only ever
					// reached through a storage handle. Recognised storage-handle
					// shapes, which is the complete set this repo uses:
					//   c.storage / <anything>.storage   (core, holding the interface)
					//   tx                               (inside WithTransaction)
					//   ls                               (LocalStorage's own receiver)
					//   <anything>.Storage()             (the accessor)
					if !isStorageReceiver(columnScopedRender(sel.X)) {
						return true
					}
					key := rel + ":" + fd.Name.Name
					found[key] = append(found[key], fd.Name.Name)
					return true
				})
			}
			return nil
		})
		require.NoError(t, err)
	}

	for key := range found {
		if _, ok := allowed[key]; ok {
			continue
		}
		t.Errorf("%s still calls the full-row storage.UpdateSecret — #2695 moved every secret-row write onto "+
			"UpdateSecretFields; a Save here resurrects a concurrently deleted secret (shares and ACLs already "+
			"revoked) and reverts a concurrent suspend, read-count increment or ownership clear", key)
	}
	for key, why := range allowed {
		if _, ok := found[key]; !ok {
			t.Errorf("allowed entry %q no longer matches any call site — delete it, and delete UpdateSecret "+
				"itself plus this test if it is now callerless. Reason it was allowed: %s", key, why)
		}
	}
}

// isStorageReceiver reports whether a rendered receiver path is a storage
// handle, so a call named UpdateSecret on it is the STORAGE method rather than
// the identically-named exported core method. Stated explicitly (rather than
// "anything that isn't c") so the recognised set is itself reviewable — the
// enumeration-completeness discipline CLAUDE.md asks for.
func isStorageReceiver(recv string) bool {
	switch recv {
	case "tx", "ls", "c.storage":
		return true
	}
	return strings.HasSuffix(recv, ".storage") || strings.HasSuffix(recv, ".Storage()")
}

func updateSecretGuardRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate the repo root (no go.mod walking up from the test's working directory)")
	return ""
}
