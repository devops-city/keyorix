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

	"github.com/stretchr/testify/require"
)

// TestRestoreSecret_IsColumnScoped pins the one DELIBERATE secret undelete.
// RestoreSecret (ADR-033) clears deleted_at and nothing else: through
// LocalStorage.RestoreSecret, a conditional `WHERE id = ? AND deleted_at IS NOT
// NULL` update of the one column inside a transaction that re-checks the parent
// project, never a Save of a pre-read row (whose upsert would also revert
// concurrent column writes), and core.RestoreSecret persists only through it.
//
// Hops checked: KeyorixCore.RestoreSecret -> tx.RestoreSecret -> its
// LocalStorage body. The helper's required Update/Updates is satisfied by
// Update("deleted_at", nil) (a single named column).
func TestRestoreSecret_IsColumnScoped(t *testing.T) {
	var where, update bool
	for _, c := range columnScopedFuncCalls(t, "../../storage/store/local_secrets.go", "LocalStorage", "RestoreSecret") {
		switch c.Name {
		case "Save":
			t.Errorf("LocalStorage.RestoreSecret calls %s.Save — a full-row upsert", c.Recv)
		case "Select":
			for _, a := range c.Args {
				if bl, ok := a.(*ast.BasicLit); ok && bl.Value == `"*"` {
					t.Errorf("LocalStorage.RestoreSecret calls Select(\"*\") — a full-row write")
				}
			}
		case "Where":
			where = true
		case "Update", "Updates", "UpdateColumns":
			update = true
		}
	}
	if !where || !update {
		t.Errorf("LocalStorage.RestoreSecret no longer issues a conditional column-scoped UPDATE (Where=%v, Update*=%v)", where, update)
	}
	// RESTORE-SECRET-AUDIT-TX: the restore runs inside WithTransaction, so the call
	// is tx.RestoreSecret (the transaction-scoped storage), not c.storage.RestoreSecret.
	assertCoreWritesOnlyVia(t, "../secrets.go", "RestoreSecret", "tx", "RestoreSecret",
		"Save", "UpdateSecret", "UpdateSecretFields", "TransitionSecretStatus")
}

// TestUpdateSecretFullRowSave_HasNoProductionCaller is the sweep half of #2650
// (a stale full-row Save undeleting a secret, SetSecretAutoRotate being the
// instance). TestSetSecretAutoRotate_IsColumnScoped and
// TestUpdateSecretWrites_AreColumnScoped name the call sites that were moved
// onto UpdateSecretFields; this asserts the primitive itself is not called from
// production code at all, so a NEW writer cannot reintroduce the undelete
// without turning this red, whether or not anyone remembered a per-function guard.
//
// Call forms recognised: `<recv>.UpdateSecret(...)` in a non-test file under
// internal/core where recv is anything but the bare core receiver `c` (so
// c.storage.UpdateSecret, tx.UpdateSecret and st.UpdateSecret all count while
// the core method c.UpdateSecret does not); in internal/storage/store any such
// call; in server/ a call whose receiver chain contains `Storage()`.
//
// What it does not see: a call through a method value or a helper taking a
// storage.Storage and calling it under another name, a storage reached under a
// receiver named `c` that is not the core, and callers outside the three roots
// (cli/ has no storage access).
func TestUpdateSecretFullRowSave_HasNoProductionCaller(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)

	var found []string
	scanned := 0
	for _, dir := range []string{"internal/core", "internal/storage/store", "server"} {
		werr := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			require.NoError(t, perr, rel)
			scanned++
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
					recv := columnScopedRender(sel.X)
					switch {
					case strings.HasPrefix(rel, "internal/core/"):
						if recv != "c" {
							found = append(found, rel+":"+fd.Name.Name+" -> "+recv+".UpdateSecret")
						}
					case strings.HasPrefix(rel, "internal/storage/store/"):
						found = append(found, rel+":"+fd.Name.Name+" -> "+recv+".UpdateSecret")
					case strings.Contains(recv, "Storage()"):
						found = append(found, rel+":"+fd.Name.Name+" -> "+recv+".UpdateSecret")
					}
					return true
				})
			}
			return nil
		})
		require.NoError(t, werr)
	}
	// Precondition: the sweep looked at real code.
	require.Greater(t, scanned, 300, "the sweep scanned only %d files; its roots moved", scanned)

	sort.Strings(found)
	for _, f := range found {
		t.Errorf("%s: LocalStorage.UpdateSecret is a full-row GORM Save of a pre-read snapshot. Against a secret "+
			"soft-deleted in the meantime its UPDATE matches 0 rows and the upsert fallback writes deleted_at = NULL "+
			"(#2650: a deleted secret live again, no secret.restored event, no parent-liveness check). Use "+
			"UpdateSecretFields (named columns, conditional on the live row) or a purpose-built method like "+
			"UpdateSecretRotationConfig.", f)
	}
}
