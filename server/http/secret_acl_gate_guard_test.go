// secret_acl_gate_guard_test.go — #3423 (AUTHZ-GUARDS-1): core.GrantSecretACL,
// RevokeSecretACL and ListSecretACLs do no authorization of their own (their doc
// comment says "Requires secrets.manage ... enforced at the HTTP layer"). Their safety is
// therefore a property of every CALLER. Today there are exactly two transports: the HTTP
// handlers in server/http/handlers/secret_acl_handler.go (gated by the router's
// RequireScopedSecretPermission(permSecretsManage, "id")) and the gRPC methods in
// server/grpc/services/secret_service.go (gated by authorizeSecretScoped(...,
// permSecretsManage)). A third caller that forgot the gate would hand any authenticated
// user the ability to grant themselves access to any secret.
//
// The population is derived, not hand-listed: every selector reference to one of the three
// method names in the root module's non-test code (call OR method value, so
// `mux.Post(p, h.GrantSecretACL)` counts), outside the storage layer. Each must sit in a
// (file, function) registered in secretACLCallers with the gate that protects it, and the
// gate is then verified structurally:
//
//   - gateGRPC:    the enclosing function calls authorizeSecretScoped(..., permSecretsManage)
//     textually before the core call;
//   - gateHandler: the enclosing function is an HTTP handler; router.go must register
//     secretHandler.<same name> behind RequireScopedSecretPermission(permSecretsManage, ...);
//   - gateRouter:  every reference in router.go is such a gated registration.
//
// What it does NOT cover: a caller that reaches core through reflection or a function value
// assigned elsewhere; the behavioural proof that the gate itself denies (see
// TestEverySecretRPC_UsesShareAwareGate and the router's own permission tests). It also
// stops at the root module: cli/ is a separate module that only speaks HTTP.
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var secretACLSymbols = map[string]bool{
	"GrantSecretACL":  true,
	"RevokeSecretACL": true,
	"ListSecretACLs":  true,
}

type secretACLGate int

const (
	gateGRPC secretACLGate = iota + 1
	gateHandler
	gateRouter
)

// secretACLCallers is the exhaustive list of non-test callers. "file#*" matches any
// function in that file. Add a row only together with a gate that the checker below can
// verify; a new transport needs a new gate kind, not a free pass.
var secretACLCallers = map[string]secretACLGate{
	"server/http/handlers/secret_acl_handler.go#GrantSecretACL":  gateHandler,
	"server/http/handlers/secret_acl_handler.go#RevokeSecretACL": gateHandler,
	"server/http/handlers/secret_acl_handler.go#ListSecretACLs":  gateHandler,
	"server/http/router.go#*":                                    gateRouter,
	"server/grpc/services/secret_service.go#GrantSecretACL":      gateGRPC,
	"server/grpc/services/secret_service.go#RevokeSecretACL":     gateGRPC,
	"server/grpc/services/secret_service.go#ListSecretACLs":      gateGRPC,
}

type secretACLRef struct {
	file string
	fn   string
	sel  *ast.SelectorExpr
	fd   *ast.FuncDecl
}

// collectSecretACLRefs returns every selector reference to a SecretACL symbol in f.
// Inside internal/core a `c.storage.X` / `tx.X` style reference (receiver is itself a
// selector) is the storage layer, not the core method, and is skipped.
func collectSecretACLRefs(rel string, f *ast.File) []secretACLRef {
	var refs []secretACLRef
	inspect := func(root ast.Node, fn string, fd *ast.FuncDecl) {
		ast.Inspect(root, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !secretACLSymbols[sel.Sel.Name] {
				return true
			}
			if strings.HasPrefix(rel, "internal/core/") {
				if _, isIdent := sel.X.(*ast.Ident); !isIdent {
					return true
				}
			}
			refs = append(refs, secretACLRef{file: rel, fn: fn, sel: sel, fd: fd})
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			inspect(fd, fd.Name.Name, fd)
		} else {
			inspect(d, "<package level>", nil)
		}
	}
	return refs
}

func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// gatedRouterSelectors returns the handler selectors that router source registers as
// `<r>.With(...RequireScopedSecretPermission(permSecretsManage, ...)...).<Verb>(path, handler)`.
func gatedRouterSelectors(f *ast.File) map[*ast.SelectorExpr]bool {
	gated := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		verb, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		vsel, ok := verb.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		with, ok := vsel.X.(*ast.CallExpr)
		if !ok || callName(with) != "With" {
			return true
		}
		hasGate := false
		for _, a := range with.Args {
			if c, ok := a.(*ast.CallExpr); ok && callName(c) == "RequireScopedSecretPermission" &&
				len(c.Args) > 0 && isIdentNamed(c.Args[0], "permSecretsManage") {
				hasGate = true
			}
		}
		if !hasGate {
			return true
		}
		for _, a := range verb.Args {
			if s, ok := a.(*ast.SelectorExpr); ok {
				gated[s] = true
			}
		}
		return true
	})
	return gated
}

// grpcManageGateBefore reports whether fd calls authorizeSecretScoped with
// permSecretsManage as its permission argument at a position before pos.
func grpcManageGateBefore(fd *ast.FuncDecl, pos token.Pos) bool {
	found := false
	ast.Inspect(fd, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if ok && callName(c) == "authorizeSecretScoped" && len(c.Args) >= 5 &&
			isIdentNamed(c.Args[4], "permSecretsManage") && c.End() <= pos {
			found = true
		}
		return !found
	})
	return found
}

// checkSecretACLCallers returns one message per violation. parsed maps repo-relative file
// to its AST (only files that contain refs, plus router.go, are needed).
func checkSecretACLCallers(refs []secretACLRef, parsed map[string]*ast.File, registry map[string]secretACLGate) []string {
	var bad []string
	routerGated := map[string]bool{} // handler method name -> has a gated registration
	var routerFile *ast.File
	for rel, f := range parsed {
		if rel == "server/http/router.go" {
			routerFile = f
		}
	}
	var gatedSels map[*ast.SelectorExpr]bool
	if routerFile != nil {
		gatedSels = gatedRouterSelectors(routerFile)
		for s := range gatedSels {
			routerGated[s.Sel.Name] = true
		}
	}
	for _, r := range refs {
		gate, ok := registry[r.file+"#"+r.fn]
		if !ok {
			gate, ok = registry[r.file+"#*"]
		}
		where := r.file + ":" + r.fn + " (" + r.sel.Sel.Name + ")"
		if !ok {
			bad = append(bad, where+": reference to a SecretACL core method from an unregistered caller; "+
				"gate it with secrets.manage (HTTP: RequireScopedSecretPermission(permSecretsManage, \"id\") on the route; "+
				"gRPC: authorizeSecretScoped(..., permSecretsManage)) and register it in secretACLCallers")
			continue
		}
		switch gate {
		case gateGRPC:
			if r.fd == nil || !grpcManageGateBefore(r.fd, r.sel.Pos()) {
				bad = append(bad, where+": registered gateGRPC but no authorizeSecretScoped(..., permSecretsManage) call precedes it")
			}
		case gateHandler:
			if r.fn != r.sel.Sel.Name {
				bad = append(bad, where+": gateHandler entries must be the handler method of the same name")
			} else if !routerGated[r.fn] {
				bad = append(bad, where+": handler is not registered in router.go behind RequireScopedSecretPermission(permSecretsManage, ...)")
			}
		case gateRouter:
			if !gatedSels[r.sel] {
				bad = append(bad, where+": registered in router.go without RequireScopedSecretPermission(permSecretsManage, ...)")
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// skipSecretACLDir names directories not scanned, each with the reason.
func skipSecretACLDir(root, path string, d fs.DirEntry) bool {
	if !d.IsDir() {
		return false
	}
	rel, _ := filepath.Rel(root, path)
	rel = filepath.ToSlash(rel)
	switch d.Name() {
	case ".git", "node_modules", ".scratch", "vendor", "web":
		return true
	}
	for _, p := range []string{
		"internal/storage",      // the storage implementations: ListSecretACLs there IS the data layer
		"internal/faultstorage", // generated storage wrapper
		"internal/core/storage", // the storage interface declaration
		"server/proto",          // generated gRPC stubs (they dispatch to the services checked here)
	} {
		if rel == p {
			return true
		}
	}
	// A nested module (cli/, scripts/...) is a different build; it has no access to core.
	if rel != "." {
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
			return true
		}
	}
	return false
}

func TestEverySecretACLCaller_SitsBehindSecretsManageGate(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	parsed := map[string]*ast.File{}
	var refs []secretACLRef
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
		f, perr := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, perr, rel)
		scanned++
		fileRefs := collectSecretACLRefs(rel, f)
		if len(fileRefs) > 0 || rel == "server/http/router.go" {
			parsed[rel] = f
		}
		refs = append(refs, fileRefs...)
		return nil
	}))
	require.Greater(t, scanned, 500, "calibration: the walk should see the whole root module, saw %d files", scanned)

	// Calibration: the three symbols x two transports, plus the router registrations, exist.
	// If this drops, the scan went blind (renamed method, moved file) rather than the code
	// getting safer.
	byFile := map[string]int{}
	for _, r := range refs {
		byFile[r.file]++
	}
	assert.GreaterOrEqual(t, byFile["server/http/handlers/secret_acl_handler.go"], 3)
	assert.GreaterOrEqual(t, byFile["server/grpc/services/secret_service.go"], 4)
	assert.GreaterOrEqual(t, byFile["server/http/router.go"], 3)
	assert.Contains(t, parsed, "server/http/router.go")

	for _, msg := range checkSecretACLCallers(refs, parsed, secretACLCallers) {
		t.Error(msg)
	}

	// Stale registry rows: every registered (file, fn) must still have a reference.
	live := map[string]bool{}
	for _, r := range refs {
		live[r.file+"#"+r.fn] = true
		live[r.file+"#*"] = true
	}
	for k := range secretACLCallers {
		assert.True(t, live[k], "stale secretACLCallers entry %q: no reference to a SecretACL core method there any more", k)
	}
}

// The gate constant the structural checks key on must still mean secrets.manage in both
// transports; otherwise "permSecretsManage" would be a name with no content.
func TestSecretACLGuard_PermSecretsManageIsSecretsManage(t *testing.T) {
	for _, file := range []string{
		filepath.Join("router.go"),
		filepath.Join("..", "grpc", "services", "constants.go"),
	} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		require.NoError(t, err)
		val := ""
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, id := range vs.Names {
				if id.Name == "permSecretsManage" && i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						val, _ = strconv.Unquote(lit.Value)
					}
				}
			}
			return true
		})
		assert.Equal(t, "secrets.manage", val, "%s: permSecretsManage must be \"secrets.manage\"", file)
	}
}

// TestSecretACLGuard_DetectorSelfTest drives checkSecretACLCallers over synthetic sources:
// green for the real shapes, red for a missing gate or an unregistered caller.
func TestSecretACLGuard_DetectorSelfTest(t *testing.T) {
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	const goodRouter = `package http
func NewRouter() {
	r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Post("/{id}/acl", secretHandler.GrantSecretACL)
}`
	const ungatedRouter = `package http
func NewRouter() {
	r.Post("/{id}/acl", secretHandler.GrantSecretACL)
}`
	const wrongPermRouter = `package http
func NewRouter() {
	r.With(customMiddleware.RequireScopedSecretPermission(permSecretsRead, "id")).Post("/{id}/acl", secretHandler.GrantSecretACL)
}`
	const handler = `package handlers
func (h *SecretHandler) GrantSecretACL() { h.coreService.GrantSecretACL(ctx) }`
	const goodGRPC = `package services
func (s *S) GrantSecretACL() {
	if err := authorizeSecretScoped(ctx, s.core, user, id, permSecretsManage); err != nil { return }
	s.core.GrantSecretACL(ctx)
}`
	const gateAfterGRPC = `package services
func (s *S) GrantSecretACL() {
	s.core.GrantSecretACL(ctx)
	_ = authorizeSecretScoped(ctx, s.core, user, id, permSecretsManage)
}`
	const wrongPermGRPC = `package services
func (s *S) GrantSecretACL() {
	_ = authorizeSecretScoped(ctx, s.core, user, id, permSecretsRead)
	s.core.GrantSecretACL(ctx)
}`
	const thirdCaller = `package handlers
func (h *Other) Sneaky() { h.coreService.ListSecretACLs(ctx, 1) }`

	registry := map[string]secretACLGate{
		"server/http/handlers/secret_acl_handler.go#GrantSecretACL": gateHandler,
		"server/http/router.go#*":                                   gateRouter,
		"server/grpc/services/secret_service.go#GrantSecretACL":     gateGRPC,
	}
	run := func(files map[string]string) []string {
		parsed := map[string]*ast.File{}
		var refs []secretACLRef
		for rel, src := range files {
			f := parse(src)
			parsed[rel] = f
			refs = append(refs, collectSecretACLRefs(rel, f)...)
		}
		return checkSecretACLCallers(refs, parsed, registry)
	}
	const (
		rRouter  = "server/http/router.go"
		rHandler = "server/http/handlers/secret_acl_handler.go"
		rGRPC    = "server/grpc/services/secret_service.go"
	)
	assert.Empty(t, run(map[string]string{rRouter: goodRouter, rHandler: handler, rGRPC: goodGRPC}), "real shapes are green")
	assert.NotEmpty(t, run(map[string]string{rRouter: ungatedRouter, rHandler: handler, rGRPC: goodGRPC}), "ungated route is red")
	assert.NotEmpty(t, run(map[string]string{rRouter: wrongPermRouter, rHandler: handler, rGRPC: goodGRPC}), "route gated on another permission is red")
	assert.NotEmpty(t, run(map[string]string{rRouter: goodRouter, rHandler: handler, rGRPC: gateAfterGRPC}), "gate after the core call is red")
	assert.NotEmpty(t, run(map[string]string{rRouter: goodRouter, rHandler: handler, rGRPC: wrongPermGRPC}), "gRPC gated on another permission is red")
	assert.NotEmpty(t, run(map[string]string{rRouter: goodRouter, rHandler: handler, rGRPC: goodGRPC,
		"server/http/handlers/zz_third.go": thirdCaller}), "a third, unregistered caller is red")
	// A handler whose route is gone from the router is red too.
	assert.NotEmpty(t, run(map[string]string{rRouter: "package http\nfunc NewRouter() {}", rHandler: handler, rGRPC: goodGRPC}))
}
