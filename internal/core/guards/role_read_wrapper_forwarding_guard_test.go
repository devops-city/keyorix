package guards

// role_read_wrapper_forwarding_guard_test.go — PERF-FIX-6.
//
// Authorize / AuthorizePrincipal read a principal's roles through ONE storage
// method (ResolveUserPermissionAt / ResolveMachinePermissionAt). A Storage
// wrapper that embeds a real store and overrides one of the per-statement role
// reads (GetUserRoleIDsAt, GetUserGroupRoleIDsAt, RoleSetBypassesPermissionChecks,
// RoleSetHasPermission, GetMachineRoleIDsAt) — the usual way a test injects a
// fault into authorization — would otherwise be bypassed silently: the
// embedded store's combined method never calls the wrapper's override, so the
// fault never reaches the decision and a fail-closed test can pass without
// exercising anything. Four such wrappers existed when the combined method
// landed (bulk_delete_authz_fault_test.go, authz_any_scope_fail_closed_test.go,
// sod_admin_role_getrole_error_test.go, server/grpc/services'
// user_service_role_scopes_fault_test.go); each now forwards the combined
// method to storage.Compose*PermissionAt over itself.
//
// This guard keeps the class closed: every type, in any Go file of the module,
// that declares one of those methods must also declare the combined method it
// feeds. What it recognises: methods declared directly on a named type (value
// or pointer receiver), grouped per package directory. What it does not see: a
// wrapper that injects faults by method NAME through one generic hook (that is
// faultstorage.FaultyStorage's shape; it is generated with every method, so it
// declares both and passes), or a fault injected below the Storage interface
// (SQL-level hooks) — those reach the combined statement directly.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var roleReadFeeds = map[string][]string{
	"GetUserRoleIDsAt":                {"ResolveUserPermissionAt"},
	"GetUserGroupRoleIDsAt":           {"ResolveUserPermissionAt"},
	"RoleSetBypassesPermissionChecks": {"ResolveUserPermissionAt"},
	"RoleSetHasPermission":            {"ResolveUserPermissionAt", "ResolveMachinePermissionAt"},
	"GetMachineRoleIDsAt":             {"ResolveMachinePermissionAt"},
}

// roleReadForwardingViolations returns "dir: Type overrides M but not R" for
// every receiver type in files (path -> source) that misses a combined method.
func roleReadForwardingViolations(t *testing.T, files map[string][]byte) []string {
	t.Helper()
	methods := map[string]map[string]bool{} // "dir\x00Type" -> method set
	fset := token.NewFileSet()
	for path, src := range files {
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		require.NoError(t, err, path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			typ := fn.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			ident, ok := typ.(*ast.Ident)
			if !ok {
				continue
			}
			key := filepath.Dir(path) + "\x00" + ident.Name
			if methods[key] == nil {
				methods[key] = map[string]bool{}
			}
			methods[key][fn.Name.Name] = true
		}
	}
	var out []string
	for key, set := range methods {
		for m, feeds := range roleReadFeeds {
			if !set[m] {
				continue
			}
			for _, r := range feeds {
				if !set[r] {
					dir, typ, _ := strings.Cut(key, "\x00")
					out = append(out, dir+": "+typ+" overrides "+m+" but not "+r)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestRoleReadWrappersForwardTheCombinedRoleRead(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "vendor", "testdata", ".scratch":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, rerr := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path from filepath.WalkDir below, not external input
		if rerr != nil {
			return rerr
		}
		if !strings.Contains(string(src), "RoleSetHasPermission") && !strings.Contains(string(src), "RoleIDsAt") &&
			!strings.Contains(string(src), "RoleSetBypassesPermissionChecks") {
			return nil
		}
		files[path] = src
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, files, "the walk found no candidate files: the guard would pass vacuously")

	// Green on the known-good implementations it must recognise.
	seen := map[string]bool{}
	for path := range files {
		switch filepath.Base(path) {
		case "local_principal_permission.go", "faulty_storage_generated.go", "mock_storage_principal_permission_test.go":
			seen[filepath.Base(path)] = true
		}
	}
	require.Len(t, seen, 3, "the scan must cover LocalStorage, FaultyStorage and MockStorage (found %v)", seen)

	require.Empty(t, roleReadForwardingViolations(t, files),
		"a type that overrides a per-statement role read must also override the combined read it feeds "+
			"(forward it to storage.ComposeUserPermissionAt / ComposeMachinePermissionAt over itself), "+
			"or Authorize never meets the override")
}

// Calibration: the checker flags a wrapper missing the combined method, and
// accepts it once the forward is there.
func TestRoleReadWrappersForwardTheCombinedRoleRead_Calibration(t *testing.T) {
	bad := []byte(`package x
type w struct{ Storage }
func (s *w) GetUserGroupRoleIDsAt() {}
type m struct{ Storage }
func (s m) RoleSetHasPermission() {}
func (s m) ResolveUserPermissionAt() {}
`)
	got := roleReadForwardingViolations(t, map[string][]byte{"a/x.go": bad})
	require.Equal(t, []string{
		"a: m overrides RoleSetHasPermission but not ResolveMachinePermissionAt",
		"a: w overrides GetUserGroupRoleIDsAt but not ResolveUserPermissionAt",
	}, got)

	good := []byte(`package x
type w struct{ Storage }
func (s *w) GetUserGroupRoleIDsAt() {}
`)
	goodForward := []byte(`package x
func (s *w) ResolveUserPermissionAt() {}
`)
	require.Empty(t, roleReadForwardingViolations(t, map[string][]byte{"a/x.go": good, "a/y.go": goodForward}),
		"methods of one type are collected across the files of its package")
	require.NotEmpty(t, roleReadForwardingViolations(t, map[string][]byte{"a/x.go": good, "b/y.go": goodForward}),
		"a same-named type in another package does not count")
}
