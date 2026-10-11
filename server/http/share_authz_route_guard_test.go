// share_authz_route_guard_test.go — #2941 guard, HTTP half: every per-secret REST
// operation must be authorized by the share-aware per-secret check
// (core.AuthorizeSecretPrincipalForSecret → AuthorizeSecret, which includes the share
// term). The behavioural proof is share_elevation_2941_test.go; this is the
// family-wide structural guard that stops a new or re-gated route from silently
// falling back to role-only RequireScopedPermission(…, ScopeFromSecretParam), where a
// share-elevated member is denied on that one route (DEMO-WALK-1's "a write share
// didn't let a viewer update" was every route at once).
//
// How the operation list is derived (not hand-listed): buildRouteInventory walks
// router.go's NewRouter AST (the same walker TestRouteInventoryIsCurrent and the
// permission sweep use) and every route whose mounted path starts with
// /api/v1/secrets/{id} is a per-secret operation. Each must name
// RequireScopedSecretPermission in its gate chain, or be listed in
// secretRouteShareGuardExempt with a written reason.
//
// What it does NOT cover: per-secret operations mounted elsewhere (project-scoped bulk
// routes under /projects/{id}/secrets/*, which act on many secrets and are gated by
// project role by design; /shares/{id}, which is share MANAGEMENT and owner-only in
// core). The middleware half — that RequireScopedSecretPermission and
// RequireScopedSecretRefPermission actually call the share-aware core check — is
// TestSecretGates_CallShareAwareCheck below.
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretRouteShareGuardExempt: per-secret routes that legitimately do not use
// RequireScopedSecretPermission. Keyed by "<METHOD> <pattern>".
var secretRouteShareGuardExempt = map[string]string{
	"POST /api/v1/secrets/{id}/restore": "a soft-deleted secret is invisible to GetSecret, so scope resolves via " +
		"ScopeFromDeletedSecretParam; restore needs project secrets.write by role. A share on a deleted secret " +
		"deliberately does not authorize restoring it.",
	"DELETE /api/v1/secrets/{id}/self-share": "a recipient removing their OWN share: authenticated only, the core " +
		"removes only a share whose RecipientID is the caller. Gating it on a permission the share itself grants " +
		"would be circular.",
}

func TestEveryPerSecretRoute_UsesShareAwareGate(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	entries := buildRouteInventory(t, filepath.Join(root, "server", "http", "router.go"))

	const prefix = "/api/v1/secrets/{id}"
	seen := map[string]bool{}
	checked := 0
	for _, e := range entries {
		if e.Pattern != prefix && !strings.HasPrefix(e.Pattern, prefix+"/") {
			continue
		}
		key := e.key()
		seen[key] = true
		if _, exempt := secretRouteShareGuardExempt[key]; exempt {
			continue
		}
		checked++
		assert.Contains(t, e.GateFns, "RequireScopedSecretPermission",
			"%s (router.go:%d) is a per-secret operation but is not gated by RequireScopedSecretPermission "+
				"(gates: %v): it would ignore shares (#2941) and per-secret ACLs. Use "+
				"RequireScopedSecretPermission(perm, \"id\"), or add a justified secretRouteShareGuardExempt entry.",
			key, e.Line, e.GateFns)
	}
	// Calibration: the walk must actually find the family (≈45 routes today), so a
	// path-resolution regression cannot turn this into a vacuous pass.
	assert.Greater(t, checked, 30, "expected the per-secret route family; the inventory walk found %d", checked)
	for key := range secretRouteShareGuardExempt {
		assert.True(t, seen[key], "stale exemption %q: no such route in router.go", key)
	}

	var byRef *routeInventoryEntry
	for i := range entries {
		if entries[i].key() == "GET /api/v1/secrets/value" {
			byRef = &entries[i]
		}
	}
	require.NotNil(t, byRef, "GET /api/v1/secrets/value must exist")
	assert.Contains(t, byRef.GateFns, "RequireScopedSecretRefPermission",
		"reading a secret by reference must use the per-secret gate too")
}

// TestSecretGates_CallShareAwareCheck: the two per-secret middleware gates must make
// their decision with core's share-aware per-secret check, never the role-only
// AuthorizePrincipal.
func TestSecretGates_CallShareAwareCheck(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	path := filepath.Join(root, "server", "middleware", "auth.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)

	for _, fn := range []string{"handleScopedSecretPermissionRequest", "handleScopedSecretRefPermissionRequest"} {
		calls := calledSelectors(f, fn)
		require.NotNil(t, calls, "server/middleware/auth.go must declare %s", fn)
		assert.True(t, calls["AuthorizeSecretPrincipalForSecret"] || calls["AuthorizeSecretPrincipalForSecretAction"],
			"%s must authorize with core.AuthorizeSecretPrincipalForSecret[Action] (role + ACL + share term)", fn)
		assert.False(t, calls["AuthorizePrincipal"],
			"%s must not make a role-only AuthorizePrincipal decision: it ignores shares (#2941)", fn)
		// #3001 follow-up: a share elevation is audited when the action is performed,
		// so the gate must give the request a recorder and commit it after a 2xx.
		assert.True(t, calls["WithShareElevationRecorder"], "%s must give the request a ShareElevationRecorder", fn)
		assert.True(t, bareCalls(f, fn)["serveAndCommitShareElevations"],
			"%s must serve through serveAndCommitShareElevations (audit on a performed action)", fn)
	}
	assert.True(t, calledSelectors(f, "handleScopedSecretPermissionRequest")["AuthorizeSecretPrincipalForSecretAction"],
		"the per-secret gate must pass the route's SecretAction to core (write-share allowlist)")
}

// TestShareAwareWriteRoutes_NameTheirAction (#3001 follow-up): every
// RequireScopedSecretPermission(permSecretsWrite, ...) in router.go must name its
// core.SecretAction as the third argument — that is the route's explicit write-share
// allowlist decision (core.secretActionShareElevates decides it; the middleware panics
// on an unknown action). No other permission may name one.
func TestShareAwareWriteRoutes_NameTheirAction(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	path := filepath.Join(root, "server", "http", "router.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)

	writeGates := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RequireScopedSecretPermission" || len(call.Args) == 0 {
			return true
		}
		perm, _ := call.Args[0].(*ast.Ident)
		line := fset.Position(call.Pos()).Line
		if perm == nil || perm.Name != "permSecretsWrite" {
			assert.Len(t, call.Args, 2, "router.go:%d: only a secrets.write gate names a SecretAction", line)
			return true
		}
		writeGates++
		if !assert.Len(t, call.Args, 3, "router.go:%d: a secrets.write per-secret gate must name its core.SecretAction "+
			"(the write-share allowlist decision for this route)", line) {
			return true
		}
		act, ok := call.Args[2].(*ast.SelectorExpr)
		var pkg *ast.Ident
		if ok {
			pkg, _ = act.X.(*ast.Ident)
		}
		assert.True(t, pkg != nil && pkg.Name == "core" && strings.HasPrefix(act.Sel.Name, "SecretAction"),
			"router.go:%d: the third argument must be a core.SecretAction* constant", line)
		return true
	})
	assert.Greater(t, writeGates, 10, "calibration: expected the per-secret secrets.write family")
}

// bareCalls returns the set of plain identifiers called (name(...)) in fn's body.
func bareCalls(f *ast.File, fn string) map[string]bool {
	out := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
			return true
		})
	}
	return out
}

// calledSelectors returns the set of selector names (x.Name(...)) called inside the
// body of the top-level function named fn, or nil if fn is not declared in f.
func calledSelectors(f *ast.File, fn string) map[string]bool {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		out := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					out[sel.Sel.Name] = true
				}
			}
			return true
		})
		return out
	}
	return nil
}
