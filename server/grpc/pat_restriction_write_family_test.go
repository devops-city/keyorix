package grpc_test

// pat_restriction_write_family_test.go — PAT-GUARD-3, the gRPC half of
// server/http/pat_restriction_write_family_test.go: a restricted PAT is refused on
// every ungated write RPC unless core's restrictedPATUngatedWrites table allows it
// with a reason (ADR-042, deny-by-default).
//
// gRPC has no route-level permission gate: each handler in server/grpc/services
// authorizes itself. So "ungated" is derived from the handlers' AST. A unary RPC
// whose leading verb is a write (grpcWriteVerbs) is gated when its handler — the
// exported method <Method> on <Service>GRPCService — or a function of that package
// it calls, transitively, calls something named *authorize*/*Authorize* or
// requireAdmin*. Every other write RPC is ungated and must have a table entry, and
// every gRPC table entry must still be an ungated write. Every refused entry is then
// called by every restricted persona of #3062's fixture and must answer
// PermissionDenied with the entry's sentinel text, while the unrestricted controls
// are not refused with it. An allowed entry needs a case in grpcRestrictedPATAllowedCases.
//
// What the scan does NOT see, said plainly: authorization done inside core rather
// than in the handler (such an RPC shows up as ungated and must be declared, the
// fail-safe direction), and a handler that authorizes on only some paths (it counts
// as gated). Streaming RPCs are not enumerated (the only one, StreamAuditLogs, is a
// read).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/core"
)

// grpcRestrictedPATAllowedCases proves a restricted PAT really succeeds on an
// allowed ungated write RPC. Empty: the only ungated write RPC is refused.
var grpcRestrictedPATAllowedCases = map[string]func(t *testing.T, w *grpcPATGuardWorld){}

// grpcHandlerAuthorizes parses the services package and reports, per
// "<Receiver>.<Method>" handler, whether it reaches an authorization call.
func grpcHandlerAuthorizes(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	var handlers []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, perr := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, perr)
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				rt := fd.Recv.List[0].Type
				if s, ok := rt.(*ast.StarExpr); ok {
					rt = s.X
				}
				if id, ok := rt.(*ast.Ident); ok {
					name = id.Name + "." + name
					if strings.HasSuffix(id.Name, "GRPCService") && fd.Name.IsExported() {
						handlers = append(handlers, name)
					}
				}
			}
			funcs[name] = fd
		}
	}
	isAuthorizer := func(n string) bool {
		return strings.Contains(strings.ToLower(n), "authorize") || strings.HasPrefix(n, "requireAdmin")
	}
	var reaches func(name string, seen map[string]bool) bool
	reaches = func(name string, seen map[string]bool) bool {
		fd := funcs[name]
		if fd == nil || seen[name] {
			return false
		}
		seen[name] = true
		recv, _, _ := strings.Cut(name, ".")
		if !strings.Contains(name, ".") {
			recv = ""
		}
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident: // a package function
				found = isAuthorizer(fn.Name) || reaches(fn.Name, seen)
			case *ast.SelectorExpr: // s.helper(...), s.core.AuthorizePrincipal(...)
				found = isAuthorizer(fn.Sel.Name) || (recv != "" && reaches(recv+"."+fn.Sel.Name, seen))
			}
			return !found
		})
		return found
	}
	out := map[string]bool{}
	for _, h := range handlers {
		out[h] = reaches(h, map[string]bool{})
	}
	return out
}

// handlerName maps "keyorix.v1.BreakGlassService" + "ActivateBreakGlass" to
// "BreakGlassGRPCService.ActivateBreakGlass".
func handlerName(m grpcMethod) string {
	svc := m.serviceFull[strings.LastIndex(m.serviceFull, ".")+1:]
	return strings.TrimSuffix(svc, "Service") + "GRPCService." + m.methodName
}

// TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy is the gRPC family-wide
// guard (see the file header).
func TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy(t *testing.T) {
	w := newGRPCPATGuardWorld(t)
	methods := discoverUnaryMethods(w.srv)
	require.Greater(t, len(methods), 50, "sanity: the server should register the whole unary surface")
	authorizes := grpcHandlerAuthorizes(t, "services")
	table := core.RestrictedPATUngatedWrites()

	ungated := map[string]grpcMethod{}
	gated := 0
	for _, m := range methods {
		if !hasVerb(m.methodName, grpcWriteVerbs) {
			continue
		}
		auth, ok := authorizes[handlerName(m)]
		if !assert.True(t, ok, "%s: no handler %s found in server/grpc/services — the scan cannot judge it", m.key(), handlerName(m)) {
			continue
		}
		if auth {
			gated++
			continue
		}
		ungated[m.fullMethod()] = m
		_, declared := table[m.fullMethod()]
		assert.True(t, declared, "%s is an ungated write RPC with no restricted-PAT declaration: add it to "+
			"core.restrictedPATUngatedWrites (internal/core/pat_restriction_writes.go) as refused, or allowed with a "+
			"reason (deny-by-default, ADR-042 PAT-GUARD-3)", m.fullMethod())
	}
	assert.Greater(t, gated, 40, "sanity: most write RPCs authorize in their handler")
	require.NotEmpty(t, ungated, "sanity: ActivateBreakGlass is ungated by design")
	for key, p := range table {
		if !strings.HasPrefix(key, "/") {
			continue // an HTTP route
		}
		_, ok := ungated[key]
		assert.True(t, ok, "restricted-PAT table entry %q is not an ungated write RPC any more: remove it", key)
		if p.Allowed {
			assert.NotEmpty(t, strings.TrimSpace(p.Reason), "allowed entry %q needs a reason", key)
		}
	}

	call := func(m grpcMethod, token string, req *dynamicpb.Message) error {
		ctx, cancel := context.WithTimeout(
			metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token)), 10*time.Second)
		defer cancel()
		return w.conn.Invoke(ctx, m.fullMethod(), req, dynamicpb.NewMessage(m.output))
	}
	for key, m := range ungated {
		p, ok := table[key]
		if !ok {
			continue
		}
		if p.Allowed {
			c, ok := grpcRestrictedPATAllowedCases[key]
			if assert.True(t, ok, "allowed entry %s has no behavioural case in grpcRestrictedPATAllowedCases", key) {
				t.Run("allowed "+key, func(t *testing.T) { c(t, w) })
			}
			continue
		}
		t.Run("refused "+key, func(t *testing.T) {
			want := p.RefusalError().Error()
			req := w.requestWithIDs(m.input, w.canaryPID, true)
			for _, owner := range []string{"", "admin_"} {
				for _, persona := range []string{"pat_decoy_project", "pat_decoy_env", "pat_users_read_only", "pat_secrets_read_decoy", "pat_system_read_only"} {
					err := call(m, w.tokens[owner+persona], req)
					assert.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", owner+persona, err)
					assert.Equal(t, want, status.Convert(err).Message(), owner+persona)
				}
				err := call(m, w.tokens[owner+"pat_unrestricted"], req)
				assert.NotEqual(t, want, status.Convert(err).Message(), "control: an unrestricted PAT must not be refused as restricted")
			}
		})
	}
	for key := range grpcRestrictedPATAllowedCases {
		assert.True(t, table[key].Allowed, "grpcRestrictedPATAllowedCases has a case for %s, which is not an allowed entry", key)
	}
}
