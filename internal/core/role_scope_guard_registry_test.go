package core

// role_scope_guard_registry_test.go — GROUP-ROLE-SCOPE-1 (#3546): the proof
// that the role-scope guard is on EVERY grant write in internal/core, derived
// from the code rather than from a list someone remembered to update.
//
// What it recognises: a call `X.M(...)` where M is one of the storage grant
// writers (storageGrantWriters) and X is anything but the bare core receiver
// `c` (core has same-named methods, e.g. c.AssignRoleToGroup, which are entry
// points, not writes). That covers c.storage.M, tx.M, savepoint.M and any other
// storage handle. The enclosing FUNCTION DECLARATION (closures count toward the
// function they are written in) must call one of roleScopeCheckFuncs, or be in
// roleScopeExemptGrantWriters with its reason.
//
// What it does NOT see, and why that is fine here: a grant write outside
// internal/core. Transports reach storage only through core
// (server/http raw_storage_bypass_guard_test.go and
// role_grant_authority_guard_test.go fail on a handler persisting a role grant
// through Storage() directly), and internal/storage is the writer itself.

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

// storageGrantWriters are every storage.Storage method that writes a user,
// group or machine-identity role grant row (internal/core/storage/interface.go;
// the row constructors in internal/storage/store are local_rbac.go AssignRole*/
// AssignRoleToGroup*, local_users.go CreateUserWithRoleGrants and
// local_machine_credentials.go AssignMachineRole — nothing else creates a
// UserRole/GroupRole/MachineIdentityRole row).
var storageGrantWriters = map[string]bool{
	"AssignRole":                  true,
	"AssignRoleWithExpiry":        true,
	"AssignRoleToGroup":           true,
	"AssignRoleToGroupWithExpiry": true,
	"AssignMachineRole":           true,
	"CreateUserWithRoleGrants":    true,
}

// roleScopeCheckFuncs are the role-scope checks (role_scope_guard.go).
var roleScopeCheckFuncs = map[string]bool{
	"requireScopeValidForRole":     true,
	"requireScopeValidForRoleName": true,
	"validateRoleScope":            true,
}

// roleScopeExemptGrantWriters are functions that write a grant without the
// check, each for a reason that makes the scope valid by construction.
var roleScopeExemptGrantWriters = map[string]string{
	"bootstrapSystemLocked": "first-boot grants of the fixed global-tier roles system_viewer and admin at Scope{}",
	"createUser":            "the fixed baseline system_viewer (global tier) at Scope{}",
	"ProvisionSCIMUser":     "the fixed baseline system_viewer (global tier) at Scope{}",
}

// minRoleScopeGrantWriteFuncs is a tripwire against a walker that silently
// finds nothing (a renamed method, a parse change): 10 functions write grants
// today.
const minRoleScopeGrantWriteFuncs = 10

func TestEveryRoleGrantWriteChecksRoleScope(t *testing.T) {
	writers, checked := scanRoleGrantWrites(t, ".")
	if len(writers) < minRoleScopeGrantWriteFuncs {
		t.Fatalf("found only %d function(s) writing a role grant (want >= %d): the scan is probably broken: %v",
			len(writers), minRoleScopeGrantWriteFuncs, writers)
	}
	t.Logf("role-scope guard: %d grant-writing function(s): %v", len(writers), writers)
	var bad []string
	for _, fn := range writers {
		if checked[fn] {
			continue
		}
		if _, ok := roleScopeExemptGrantWriters[fn]; ok {
			continue
		}
		bad = append(bad, fn)
	}
	if len(bad) > 0 {
		t.Errorf("function(s) writing a role grant with no role-scope check (#3546): %v\n"+
			"Call requireScopeValidForRole/requireScopeValidForRoleName/validateRoleScope before the write, "+
			"or route the write through grantUserRoleAudited/grantGroupRoleAudited. Add an entry to "+
			"roleScopeExemptGrantWriters only when the scope is valid by construction, and say why.", bad)
	}
	written := map[string]bool{}
	for _, fn := range writers {
		written[fn] = true
	}
	for fn := range roleScopeExemptGrantWriters {
		if !written[fn] {
			t.Errorf("roleScopeExemptGrantWriters entry %q no longer writes a role grant; remove it", fn)
		} else if checked[fn] {
			t.Errorf("roleScopeExemptGrantWriters entry %q now calls the role-scope check; remove the exemption", fn)
		}
	}
}

// TestRoleScopeRegistryScanCatchesSyntheticShapes is the scanner's own
// red/green: an unguarded write (including one in a closure and one through a
// tx handle) is found, a guarded one is not, and a call to the same-named core
// entry point on the receiver is not a write.
func TestRoleScopeRegistryScanCatchesSyntheticShapes(t *testing.T) {
	dir := t.TempDir()
	src := `package core
func (c *KeyorixCore) unguarded(ctx context.Context) error {
	return c.storage.WithTransaction(ctx, func(tx Storage) error { return tx.AssignRole(ctx, 1, 2, Scope{}) })
}
func (c *KeyorixCore) guarded(ctx context.Context) error {
	if err := c.requireScopeValidForRole(ctx, 2, Scope{}); err != nil { return err }
	return c.storage.AssignRoleToGroup(ctx, 1, 2, Scope{})
}
func (c *KeyorixCore) entryPointCaller(ctx context.Context) error {
	return c.AssignRoleToGroup(ctx, 0, 1, 2, Scope{}, false)
}
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	writers, checked := scanRoleGrantWrites(t, dir)
	if strings.Join(writers, ",") != "guarded,unguarded" {
		t.Fatalf("writers = %v, want [guarded unguarded]", writers)
	}
	if !checked["guarded"] || checked["unguarded"] {
		t.Fatalf("checked = %v, want only guarded", checked)
	}
}

// scanRoleGrantWrites parses every non-test .go file in dir and returns the
// sorted names of functions containing a storage grant write, and which
// functions call a role-scope check.
func scanRoleGrantWrites(t *testing.T, dir string) (writers []string, checked map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked = map[string]bool{}
	seen := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			ast.Inspect(fd.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if roleScopeCheckFuncs[fun.Sel.Name] {
						checked[name] = true
					}
					if storageGrantWriters[fun.Sel.Name] && !isBareIdent(fun.X, "c") && !seen[name] {
						seen[name] = true
						writers = append(writers, name)
					}
				case *ast.Ident:
					if roleScopeCheckFuncs[fun.Name] {
						checked[name] = true
					}
				}
				return true
			})
		}
	}
	sort.Strings(writers)
	return writers, checked
}

func isBareIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
