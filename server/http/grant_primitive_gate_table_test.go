// grant_primitive_gate_table_test.go — AUTHZ-GUARDS-1 item 4: the neighbours of the
// SecretACL (#3423) and ShareSecret (#3422) gaps. Each core primitive below grants access
// to a principal. For every one, this table NAMES the gate that makes it safe and checks
// both halves structurally:
//
//   - in core: the call that must precede the write (requireGranterHoldsRolePermissions,
//     which itself demands roles.assign at the scope and the role's bundled permissions),
//     or an explicit "none" with the reason, in which case the function must not have
//     acquired a gate unnoticed;
//   - at the transports: every non-test caller outside internal/core is registered here
//     with its route middleware (router.go) or its gRPC authorizer call. A caller that is
//     not in the table, or whose route lost its middleware, fails.
//
// Rows: roles.assign (user and group grants), project membership add/set/remove,
// machine-identity role grant, break-glass activation, connect ref-grants.
//
// What it does NOT cover: callers inside internal/core (they inherit the callee's in-core
// gate, which is what the "core" half checks); the behavioural denial itself (the router
// middleware's own tests and the per-primitive authz tests); grants that do not go through
// these primitives (invitation acceptance, SSO reconciliation: assignUserRoleSystemGrant
// and grantBaselineRoleBackfill skip the ceiling by design and are unexported).
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type coreSpec struct {
	file   string   // under internal/core/
	fn     string   // method name
	gates  []string // call names that must all appear, each before the first write
	writes []string // call names; the gates must precede the first one found
	none   string   // non-empty: no in-core authorization, with the reason
}

type routeGate struct {
	handler string   // method name registered in router.go
	tokens  []string // middleware tokens every registration must carry: "Name" or "Name:firstArgIdent"
	forbid  []string // token prefixes that must NOT be present (documents a deliberate absence)
}

type grpcGate struct {
	authorizer string // authorizeScoped | authorizeGlobal
	perm       string // string literal passed to it
	none       bool   // true: self-service by design, no authorizer may be present
}

type callerGate struct {
	routes []routeGate
	grpc   *grpcGate
}

type grantPrimitive struct {
	name    string
	symbols []string
	core    []coreSpec
	callers map[string]callerGate // "repo/relative/file.go#EnclosingFunc"
}

var coreGateCalls = []string{"requireGranterHoldsRolePermissions", "RequireRolesAssignAuthority", "AuthorizePrincipal", "Authorize"}

var grantPrimitives = []grantPrimitive{
	{
		name:    "roles.assign: user role grant",
		symbols: []string{"AssignUserRole", "AssignUserRoleWithExpiry"},
		core: []coreSpec{
			{file: "rbac_management.go", fn: "AssignUserRole", gates: []string{"requireGranterHoldsRolePermissions"}, writes: []string{"WithNamedLock"}},
			{file: "jit_access.go", fn: "AssignUserRoleWithExpiry", gates: []string{"requireGranterHoldsRolePermissions"}, writes: []string{"WithNamedLock"}},
		},
		callers: map[string]callerGate{
			"server/http/handlers/rbac.go#AssignRole": {
				routes: []routeGate{{handler: "AssignRole", tokens: []string{"RequireScopedPermission:permRolesAssign"}}},
			},
			"server/grpc/services/role_service.go#AssignRole": {grpc: &grpcGate{authorizer: "authorizeScoped", perm: "roles.assign"}},
		},
	},
	{
		name:    "roles.assign: group role grant",
		symbols: []string{"AssignRoleToGroup", "AssignGroupRoleWithExpiry"},
		core: []coreSpec{
			{file: "rbac_management.go", fn: "AssignRoleToGroup", gates: []string{"requireGranterHoldsRolePermissions"}, writes: []string{"WithNamedLock"}},
			{file: "jit_access.go", fn: "AssignGroupRoleWithExpiry", gates: []string{"requireGranterHoldsRolePermissions"}, writes: []string{"WithNamedLock"}},
		},
		callers: map[string]callerGate{
			"server/http/handlers/rbac.go#AssignRoleToGroup": {
				routes: []routeGate{{handler: "AssignRoleToGroup", tokens: []string{"RequirePermission:permRolesAssign"}}},
			},
		},
	},
	{
		name:    "project member add / set role / remove",
		symbols: []string{"AddProjectMember", "SetProjectMemberRole", "RemoveProjectMember"},
		core: []coreSpec{
			// AddProjectMember has no gate of its own; its only write is AssignUserRole (gated above).
			{file: "project_members.go", fn: "AddProjectMember", gates: []string{"AssignUserRole"}},
			{file: "project_members.go", fn: "SetProjectMemberRole", none: "removes the member's existing roles (removeUserRoleUnguarded) BEFORE AssignUserRole's " +
				"roles.assign/ceiling check runs, so the removal half is protected only by the route gate; reachable from no other caller today"},
			{file: "project_members.go", fn: "RemoveProjectMember", none: "removal; protected only by the route's roles.assign gate"},
		},
		callers: map[string]callerGate{
			"server/http/handlers/project_members.go#AddProjectMember": {
				routes: []routeGate{{handler: "AddProjectMember", tokens: []string{"RequireScopedPermission:permRolesAssign"}}},
			},
			"server/http/handlers/project_members.go#UpdateProjectMember": {
				routes: []routeGate{{handler: "UpdateProjectMember", tokens: []string{"RequireScopedPermission:permRolesAssign"}}},
			},
			"server/http/handlers/project_members.go#RemoveProjectMember": {
				routes: []routeGate{{handler: "RemoveProjectMember", tokens: []string{"RequireScopedPermission:permRolesAssign"}}},
			},
		},
	},
	{
		name:    "machine-identity role grant",
		symbols: []string{"AssignMachineRole"},
		core: []coreSpec{
			{file: "machine_token.go", fn: "AssignMachineRole", gates: []string{"requireGranterHoldsRolePermissions"}, writes: []string{"WithNamedLock"}},
		},
		callers: map[string]callerGate{
			// changeMachineRole serves both verbs; both routes carry the gate.
			"server/http/handlers/machine_identities.go#changeMachineRole": {
				routes: []routeGate{
					{handler: "GrantMachineRole", tokens: []string{"RequireScopedPermission:permRolesAssign"}},
					{handler: "RemoveMachineRole", tokens: []string{"RequireScopedPermission:permRolesAssign"}},
				},
			},
		},
	},
	{
		name:    "break-glass activation (self-service by design)",
		symbols: []string{"ActivateBreakGlass"},
		core: []coreSpec{
			// The gate is the activator's own project membership, the policy switch and the
			// restricted-PAT refusal, all in core; no RBAC permission, because emergency access
			// must not depend on a permission the incident may have removed.
			{file: "break_glass.go", fn: "ActivateBreakGlass", gates: []string{"patRestrictionFromContext", "IsProjectMember"}, writes: []string{"WithNamedLock"}},
		},
		callers: map[string]callerGate{
			"server/http/handlers/break_glass.go#ActivateBreakGlass": {
				routes: []routeGate{{handler: "ActivateBreakGlass", tokens: []string{"BlockWhenImpersonating"},
					forbid: []string{"RequirePermission", "RequireScopedPermission"}}},
			},
			"server/grpc/services/break_glass_service.go#ActivateBreakGlass": {grpc: &grpcGate{none: true}},
		},
	},
	{
		name:    "connect ref-grants",
		symbols: []string{"CreateConnectRefGrant", "DeleteConnectRefGrant"},
		core: []coreSpec{
			{file: "connect.go", fn: "CreateConnectRefGrant", none: "validates the connector and role only; roles.write is enforced by the transports"},
			{file: "connect.go", fn: "DeleteConnectRefGrant", none: "deletes by id; roles.write is enforced by the transports"},
		},
		callers: map[string]callerGate{
			"server/http/handlers/connect.go#CreateRefGrant": {
				routes: []routeGate{{handler: "CreateRefGrant", tokens: []string{"RequirePermission:permRolesWrite"}}},
			},
			"server/http/handlers/connect.go#DeleteRefGrant": {
				routes: []routeGate{{handler: "DeleteRefGrant", tokens: []string{"RequirePermission:permRolesWrite"}}},
			},
			"server/grpc/services/connect_service.go#CreateRefGrant": {grpc: &grpcGate{authorizer: "authorizeGlobal", perm: "roles.write"}},
			"server/grpc/services/connect_service.go#DeleteRefGrant": {grpc: &grpcGate{authorizer: "authorizeGlobal", perm: "roles.write"}},
		},
	},
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// firstCall returns the position of the first call named name in fd, or token.NoPos.
func firstCall(fd *ast.FuncDecl, name string) token.Pos {
	pos := token.NoPos
	ast.Inspect(fd, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && callName(c) == name {
			if pos == token.NoPos || c.Pos() < pos {
				pos = c.Pos()
			}
		}
		return true
	})
	return pos
}

// routerTokens maps a handler method name to the middleware tokens of each of its
// registrations in router.go: `<r>.With(m1(arg0,...), m2).<Verb>(path, x.Handler)`.
func routerTokens(f *ast.File) map[string][][]string {
	out := map[string][][]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		verb, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		vsel, ok := verb.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		var tokens []string
		if with, ok := vsel.X.(*ast.CallExpr); ok && callName(with) == "With" {
			for _, a := range with.Args {
				switch m := a.(type) {
				case *ast.CallExpr:
					tok := callName(m)
					if len(m.Args) > 0 {
						if id, ok := m.Args[0].(*ast.Ident); ok {
							tok += ":" + id.Name
						}
					}
					tokens = append(tokens, tok)
				case *ast.SelectorExpr:
					tokens = append(tokens, m.Sel.Name)
				}
			}
		}
		for _, a := range verb.Args {
			if s, ok := a.(*ast.SelectorExpr); ok {
				out[s.Sel.Name] = append(out[s.Sel.Name], tokens)
			}
		}
		return true
	})
	return out
}

func hasAll(have []string, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			found = found || h == w
		}
		if !found {
			return false
		}
	}
	return true
}

func hasPrefix(have []string, prefixes []string) string {
	for _, h := range have {
		for _, p := range prefixes {
			if strings.HasPrefix(h, p) {
				return h
			}
		}
	}
	return ""
}

func authorizerCalls(fd *ast.FuncDecl) (calls []*ast.CallExpr) {
	ast.Inspect(fd, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if nm := callName(c); nm == "authorizeScoped" || nm == "authorizeGlobal" {
				calls = append(calls, c)
			}
		}
		return true
	})
	return calls
}

func stringArgs(c *ast.CallExpr) (out []string) {
	for _, a := range c.Args {
		if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			out = append(out, strings.Trim(lit.Value, "\""))
		}
	}
	return out
}

func TestGrantPrimitives_NameTheirGate(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	parseFile := func(rel string) *ast.File {
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		require.NoError(t, err, rel)
		return f
	}
	router := routerTokens(parseFile("server/http/router.go"))
	require.NotEmpty(t, router["AssignRole"], "calibration: router.go registers rbacHandler.AssignRole")

	// Census of every non-test reference to a primitive outside internal/core.
	wantSymbols := map[string]string{} // symbol -> row name
	for _, row := range grantPrimitives {
		for _, s := range row.symbols {
			wantSymbols[s] = row.name
		}
	}
	found := map[string]map[string]bool{} // row name -> "file#fn" seen
	scanned := 0
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipSecretACLDir(root, path, d) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		// internal/core callers inherit the callee's in-core gate; router.go only names the
		// handler methods (checked via routerTokens).
		if strings.HasPrefix(rel, "internal/core/") || rel == "server/http/router.go" {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, perr, rel)
		scanned++
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if row, ok := wantSymbols[sel.Sel.Name]; ok {
					if found[row] == nil {
						found[row] = map[string]bool{}
					}
					found[row][rel+"#"+fd.Name.Name] = true
				}
				return true
			})
		}
		return nil
	}))
	require.Greater(t, scanned, 300, "calibration: walk (internal/core excluded) saw %d files", scanned)

	for _, row := range grantPrimitives {
		t.Run(row.name, func(t *testing.T) {
			// 1. The caller census equals the registered callers, both ways.
			var seen, registered []string
			for k := range found[row.name] {
				seen = append(seen, k)
			}
			for k := range row.callers {
				registered = append(registered, k)
			}
			sort.Strings(seen)
			sort.Strings(registered)
			assert.Equal(t, registered, seen, "callers of %v outside internal/core must be exactly the registered ones: "+
				"a new caller needs a named gate here, a vanished one a table update", row.symbols)

			// 2. The in-core half.
			for _, cs := range row.core {
				fd := findFunc(parseFile("internal/core/"+cs.file), cs.fn)
				require.NotNil(t, fd, "%s: core func %s not found", cs.file, cs.fn)
				if cs.none != "" {
					for _, g := range coreGateCalls {
						assert.Equal(t, token.NoPos, firstCall(fd, g),
							"%s now calls %s: it has an in-core gate, so its \"none\" row (%s) is stale; name the gate instead", cs.fn, g, cs.none)
					}
					continue
				}
				firstWrite := token.NoPos
				for _, w := range cs.writes {
					if p := firstCall(fd, w); p != token.NoPos && (firstWrite == token.NoPos || p < firstWrite) {
						firstWrite = p
					}
				}
				if len(cs.writes) > 0 {
					require.NotEqual(t, token.NoPos, firstWrite, "%s: none of the write calls %v found", cs.fn, cs.writes)
				}
				for _, g := range cs.gates {
					p := firstCall(fd, g)
					require.NotEqual(t, token.NoPos, p, "%s must call %s", cs.fn, g)
					if firstWrite != token.NoPos {
						assert.Less(t, p, firstWrite, "%s: %s must run before the write", cs.fn, g)
					}
				}
			}

			// 3. The transport half.
			for key, gate := range row.callers {
				for _, rg := range gate.routes {
					regs := router[rg.handler]
					require.NotEmpty(t, regs, "%s: router.go does not register a handler named %s", key, rg.handler)
					for _, tokens := range regs {
						assert.True(t, hasAll(tokens, rg.tokens), "%s: route for %s lacks middleware %v (has %v)", key, rg.handler, rg.tokens, tokens)
						if bad := hasPrefix(tokens, rg.forbid); bad != "" {
							t.Errorf("%s: route for %s now carries %s; the table says it is deliberately ungated by permission", key, rg.handler, bad)
						}
					}
				}
				if gate.grpc != nil {
					file, fn, _ := strings.Cut(key, "#")
					fd := findFunc(parseFile(file), fn)
					require.NotNil(t, fd, key)
					calls := authorizerCalls(fd)
					if gate.grpc.none {
						assert.Empty(t, calls, "%s now calls an authorizer; update the table (the row says self-service)", key)
						continue
					}
					ok := false
					for _, c := range calls {
						if callName(c) == gate.grpc.authorizer && contains(stringArgs(c), gate.grpc.perm) {
							before := true
							for _, s := range row.symbols {
								if p := firstCall(fd, s); p != token.NoPos && p < c.Pos() {
									before = false
								}
							}
							ok = ok || before
						}
					}
					assert.True(t, ok, "%s must call %s(..., %q) before the core call", key, gate.grpc.authorizer, gate.grpc.perm)
				}
			}
		})
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The in-core gate the table leans on: requireGranterHoldsRolePermissions must still demand
// roles.assign at the scope itself (the F6 baseline), not only the role's bundled permissions.
func TestRequireGranterHoldsRolePermissions_DemandsRolesAssignBaseline(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "internal", "core", "authz.go"), nil, 0)
	require.NoError(t, err)
	fd := findFunc(f, "requireGranterHoldsRolePermissions")
	require.NotNil(t, fd)
	ok := false
	ast.Inspect(fd, func(n ast.Node) bool {
		if c, isCall := n.(*ast.CallExpr); isCall && callName(c) == "checkGranterHoldsPermission" {
			ok = ok || contains(stringArgs(c), "roles.assign")
		}
		return true
	})
	assert.True(t, ok, "requireGranterHoldsRolePermissions must call checkGranterHoldsPermission(..., \"roles.assign\", ...)")
}
