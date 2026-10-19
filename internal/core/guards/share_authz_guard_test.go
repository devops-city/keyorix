// share_authz_guard_test.go — #2941 guard, core half, source-scanning part. The
// share term lives in exactly one function (sharePermissionFor, share_authz.go);
// both per-secret decision functions must call it, and the actor-aware entry
// points must route human users to AuthorizeSecret. The behavioural
// counterparts (TestShareTerm_AuthorizeSecret_*, real storage) need the core
// package and stay in internal/core/share_authz_guard_test.go.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShareTerm_DecisionFunctionsConsultIt(t *testing.T) {
	bodies := map[string]*ast.BlockStmt{}
	for _, file := range []string{"../authz.go", "../permissions.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				bodies[fd.Name.Name] = fd.Body
			}
		}
	}
	for _, fn := range []string{"AuthorizeSecretAction", "checkSecretPermission"} {
		require.Contains(t, bodies, fn)
		assert.True(t, bodyCalls(bodies[fn], "sharePermissionFor"),
			"%s must consult the share term (sharePermissionFor) — #2941", fn)
	}
	// The action-less entry points delegate to the action-aware ones (so they get the
	// share term with no action: read elevation only).
	assert.True(t, bodyCalls(bodies["AuthorizeSecret"], "AuthorizeSecretAction"), "AuthorizeSecret must delegate to AuthorizeSecretAction")
	assert.True(t, bodyCalls(bodies["CheckSecretPermission"], "checkSecretPermission"), "CheckSecretPermission must delegate to checkSecretPermission")
	for _, fn := range []string{"AuthorizeSecretPrincipal", "AuthorizeSecretPrincipalForSecret", "AuthorizeSecretPrincipalForSecretAction"} {
		require.Contains(t, bodies, fn)
		assert.True(t, bodyCalls(bodies[fn], "AuthorizeSecret") || bodyCalls(bodies[fn], "AuthorizeSecretAction") ||
			bodyCalls(bodies[fn], "AuthorizeSecretPrincipalForSecret") || bodyCalls(bodies[fn], "AuthorizeSecretPrincipalForSecretAction"),
			"%s must route human users through AuthorizeSecret(Action)", fn)
	}
}

func bodyCalls(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}
