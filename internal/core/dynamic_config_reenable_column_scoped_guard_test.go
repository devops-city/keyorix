package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCreateDynamicSecretConfig_IsColumnScoped pins the #2651 fix structurally.
// CreateDynamicSecretConfig inserts the config row, then encrypts the admin DSN
// (it is bound to the row id, so the row must exist first) and persists it in a
// second write. The inserted row is visible between the two writes, and
// DeleteProject's #369 cascade sets disabled = true on every config of the
// project; a full-row Save of the stale struct wrote disabled = false back over
// it: an enabled config inside a deleted project.
//
// The condition the fix depends on, guarded rather than its conclusion: the
// second write names exactly the DSN columns and updated_at and NOT `disabled`.
// So this checks (1) core persists the DSN only through
// tx.SetDynamicSecretConfigAdminDSN and never Save/UpdateDynamicSecretConfig,
// (2) that method is a conditional Updates with no Save/Select("*"), and (3) the
// map it passes to Updates has exactly the keys admin_dsn_enc, admin_dsn_meta,
// updated_at.
//
// Hops checked: KeyorixCore.CreateDynamicSecretConfig -> tx.SetDynamicSecretConfigAdminDSN
// -> its LocalStorage body. insertDynamicSecretConfigRow is the INSERT, not an
// update, and is not walked. That no production code calls the full-row
// UpdateDynamicSecretConfig at all is TestUpdateDynamicSecretLease_HasNoProductionCaller.
func TestCreateDynamicSecretConfig_IsColumnScoped(t *testing.T) {
	const path = "../storage/store/local_dynamic.go"
	assertColumnScopedStorageWrite(t, path, "SetDynamicSecretConfigAdminDSN")
	assertCoreWritesOnlyVia(t, "dynamic_secrets.go", "CreateDynamicSecretConfig", "tx",
		"SetDynamicSecretConfigAdminDSN", "Save", "UpdateDynamicSecretConfig")

	got := updatesMapKeys(t, path, "SetDynamicSecretConfigAdminDSN")
	want := []string{"admin_dsn_enc", "admin_dsn_meta", "updated_at"}
	require.Equal(t, want, got,
		"SetDynamicSecretConfigAdminDSN must write only the DSN columns and updated_at; any other column (above all `disabled`) lets a concurrent DeleteProject's kill switch be overwritten")
}

// updatesMapKeys returns the sorted string-literal keys of the map-literal
// argument of every Updates(...) call in LocalStorage.name. Fails the test when
// there is none, so a switch to a struct-form update turns the guard red rather
// than vacuous.
func updatesMapKeys(t *testing.T, path, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	var keys []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name || fd.Body == nil || columnScopedRecvType(fd) != "LocalStorage" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Updates" {
				return true
			}
			for _, a := range ce.Args {
				lit, ok := a.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if bl, ok := kv.Key.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						k, _ := strconv.Unquote(bl.Value)
						keys = append(keys, k)
					}
				}
			}
			return true
		})
	}
	require.NotEmpty(t, keys, "%s: LocalStorage.%s has no Updates(map[string]any{...}) literal to read column names from", path, name)
	sort.Strings(keys)
	return keys
}
