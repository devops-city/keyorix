// auth_budget_routes_guard_test.go — no auth endpoint without a budget, and no
// budget that fails open (Andrei, 2026-10-10 18:52, AUTH-AUDIT-1 item 5).
//
// authRouteClasses classifies EVERY route router.go registers under /auth/
// (derived by parsing router.go, so a new route fails the guard until someone
// classifies it here). Two tests read it:
//
//   - TestEveryAuthRoute_IsClassifiedAndBudgeted (the guard): a public route
//     that takes a guessable input must be budgeted, and its handler must call
//     the budget's entry point, checked on the handler's AST. A route marked
//     authenticated must be mounted behind the Authentication middleware, and
//     a public one must not be; both are derived from router.go, not taken
//     from the table. An exempt route carries its reason.
//   - TestEveryAuthBudget_HoldsWithItsStorageDown (the sweep): every budgeted
//     route, with the budget's LoginAttempt storage failing on every call,
//     still refuses once the budget is spent, with byte-for-byte the 429 the
//     healthy store sends for that route.
//
// What this does NOT check: that an authenticated route's credential check
// feeds the per-account lockout. That bound lives in core (recordFailedLogin
// and loginLocked are its only writer and reader), and its fallback is proved
// there (internal/core/account_lockout_storage_fallback_test.go).
package handlers

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type authRouteKind int

const (
	routeIPBudget      authRouteKind = iota + 1 // public, per-IP budget
	routeAuthenticated                          // behind Authentication
	routeExempt                                 // public, no budget, reason given
)

type authRouteClass struct {
	kind    authRouteKind
	handler string // AuthHandler method router.go mounts
	budget  string // routeIPBudget: "login" | "password_reset" | "sso_begin"
	why     string // routeExempt: the reason
}

// budgetEntryPoints is the call each budget's handlers must make before doing
// any work: the shared limiter's check for that budget.
var budgetEntryPoints = map[string]string{
	"login":          "checkLoginRateLimit",
	"password_reset": "IsPasswordResetRateLimited",
	"sso_begin":      "IsSSOBeginRateLimited",
}

var authRouteClasses = map[string]authRouteClass{
	"POST /auth/login":                         {kind: routeIPBudget, handler: "AuthHandler.Login", budget: "login"},
	"POST /auth/refresh":                       {kind: routeIPBudget, handler: "AuthHandler.RefreshToken", budget: "login"},
	"POST /auth/mfa/verify":                    {kind: routeIPBudget, handler: "AuthHandler.VerifyMFA", budget: "login"},
	"POST /auth/webauthn/login/begin":          {kind: routeIPBudget, handler: "AuthHandler.BeginWebAuthnLogin", budget: "login"},
	"POST /auth/webauthn/login/finish":         {kind: routeIPBudget, handler: "AuthHandler.FinishWebAuthnLogin", budget: "login"},
	"POST /auth/webauthn/passwordless/begin":   {kind: routeIPBudget, handler: "AuthHandler.BeginWebAuthnPasswordlessLogin", budget: "login"},
	"POST /auth/webauthn/passwordless/finish":  {kind: routeIPBudget, handler: "AuthHandler.FinishWebAuthnPasswordlessLogin", budget: "login"},
	"POST /auth/setup/consume":                 {kind: routeIPBudget, handler: "AuthHandler.ConsumeSetup", budget: "login"},
	"POST /auth/password-reset":                {kind: routeIPBudget, handler: "AuthHandler.PasswordReset", budget: "password_reset"},
	"GET /auth/sso/{provider}/login":           {kind: routeIPBudget, handler: "AuthHandler.BeginSSO", budget: "sso_begin"},
	"GET /auth/saml/{provider}/login":          {kind: routeIPBudget, handler: "AuthHandler.BeginSAML", budget: "sso_begin"},
	"POST /auth/logout":                        {kind: routeExempt, handler: "AuthHandler.Logout", why: "revokes the presented session; CSRF-gated; no credential is checked and nothing is created"},
	"GET /auth/setup/{token}":                  {kind: routeExempt, handler: "AuthHandler.GetSetupToken", why: "describes a single-use 256-bit setup token; guessing one is infeasible, nothing is written; consume is budgeted"},
	"GET /auth/sso/providers":                  {kind: routeExempt, handler: "AuthHandler.ListSSOProviders", why: "static provider list, no input"},
	"GET /auth/sso/{provider}/callback":        {kind: routeExempt, handler: "AuthHandler.CompleteSSO", why: "consumes a single-use state minted by the budgeted begin; the IdP authenticates the user"},
	"GET /auth/saml/{provider}/metadata":       {kind: routeExempt, handler: "AuthHandler.SAMLMetadata", why: "static SP metadata, no input"},
	"POST /auth/saml/{provider}/acs":           {kind: routeExempt, handler: "AuthHandler.CompleteSAML", why: "consumes an IdP-signed assertion bound to a request minted by the budgeted begin"},
	"GET /auth/profile":                        {kind: routeAuthenticated, handler: "AuthHandler.Profile"},
	"PUT /auth/profile":                        {kind: routeAuthenticated, handler: "AuthHandler.UpdateProfile"},
	"POST /auth/change-password":               {kind: routeAuthenticated, handler: "AuthHandler.ChangePassword"},
	"POST /auth/mfa/enroll":                    {kind: routeAuthenticated, handler: "AuthHandler.EnrollMFA"},
	"POST /auth/mfa/activate":                  {kind: routeAuthenticated, handler: "AuthHandler.ActivateMFA"},
	"POST /auth/mfa/disable":                   {kind: routeAuthenticated, handler: "AuthHandler.DisableMFA"},
	"GET /auth/mfa/recovery-codes":             {kind: routeAuthenticated, handler: "AuthHandler.RecoveryCodesStatus"},
	"POST /auth/mfa/recovery-codes/regenerate": {kind: routeAuthenticated, handler: "AuthHandler.RegenerateRecoveryCodes"},
	"POST /auth/mfa/stepup":                    {kind: routeAuthenticated, handler: "AuthHandler.MFAStepUp"},
	"POST /auth/webauthn/register/begin":       {kind: routeAuthenticated, handler: "AuthHandler.BeginWebAuthnRegistration"},
	"POST /auth/webauthn/register/finish":      {kind: routeAuthenticated, handler: "AuthHandler.FinishWebAuthnRegistration"},
	"GET /auth/webauthn/credentials":           {kind: routeAuthenticated, handler: "AuthHandler.ListWebAuthnCredentials"},
	"DELETE /auth/webauthn/credentials/{id}":   {kind: routeAuthenticated, handler: "AuthHandler.DeleteWebAuthnCredential"},
	"POST /auth/webauthn/reauth/begin":         {kind: routeAuthenticated, handler: "AuthHandler.BeginWebAuthnReauth"},
	"POST /auth/webauthn/reauth/finish":        {kind: routeAuthenticated, handler: "AuthHandler.FinishWebAuthnReauth"},
	"GET /auth/sessions":                       {kind: routeAuthenticated, handler: "AuthHandler.ListSessions"},
	"DELETE /auth/sessions/{id}":               {kind: routeAuthenticated, handler: "AuthHandler.RevokeSession"},
	"GET /auth/tokens":                         {kind: routeAuthenticated, handler: "PATHandler.ListPATs"},
	"POST /auth/tokens":                        {kind: routeAuthenticated, handler: "PATHandler.CreatePAT"},
	"DELETE /auth/tokens/{id}":                 {kind: routeAuthenticated, handler: "PATHandler.RevokePAT"},
	"GET /auth/tokens/expired":                 {kind: routeAuthenticated, handler: "PATExpiryHandler.ListExpiredPATs"},
	"DELETE /auth/tokens/expired":              {kind: routeAuthenticated, handler: "PATExpiryHandler.BulkRevokeExpiredPATs"},
	"POST /auth/end-impersonation":             {kind: routeAuthenticated, handler: "ImpersonationHandler.End"},
}

type mountedRoute struct {
	method, path, handler string
	// behindAuth: registered inside a router function after that function
	// called Use(...Authentication(...)), i.e. chi runs the Authentication
	// middleware before the handler.
	behindAuth bool
}

// routerAuthRoutes parses router.go and returns every r.<Method>("/auth/...", h)
// call, with or without a r.With(...) prefix. h is the selector's method name
// when h is x.Method, else the expression's source form (which then matches no
// classification and fails the guard).
func routerAuthRoutes(t *testing.T) []mountedRoute {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join("..", "router.go"), nil, 0)
	require.NoError(t, err)
	// Every position after a Use(...Authentication(...)) call, up to the end
	// of the function literal that made it, is behind Authentication.
	type span struct{ from, to token.Pos }
	var authed []span
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		for _, st := range lit.Body.List {
			es, ok := st.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Use" {
				continue
			}
			for _, a := range call.Args {
				if inner, ok := a.(*ast.CallExpr); ok {
					if isel, ok := inner.Fun.(*ast.SelectorExpr); ok && isel.Sel.Name == "Authentication" {
						authed = append(authed, span{from: call.End(), to: lit.End()})
					}
				}
			}
		}
		return true
	})
	require.NotEmpty(t, authed, "found no Use(...Authentication(...)) in router.go: the authenticated classification would be unverifiable")
	behind := func(pos token.Pos) bool {
		for _, sp := range authed {
			if pos >= sp.from && pos <= sp.to {
				return true
			}
		}
		return false
	}

	var out []mountedRoute
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		method := strings.ToUpper(sel.Sel.Name)
		switch method {
		case "GET", "POST", "PUT", "DELETE", "PATCH":
		default:
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		path, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.HasPrefix(path, "/auth/") {
			return true
		}
		h := fmt.Sprintf("%T", call.Args[1])
		if hs, ok := call.Args[1].(*ast.SelectorExpr); ok {
			h = hs.Sel.Name
		}
		out = append(out, mountedRoute{method: method, path: path, handler: h, behindAuth: behind(call.Pos())})
		return true
	})
	return out
}

// handlerMethods parses this package's non-test files and returns every
// method declared on a pointer receiver, keyed "Type.Method".
func handlerMethods(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	out := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok {
					out[id.Name+"."+fd.Name.Name] = fd
				}
			}
		}
	}
	return out
}

// callsSelector reports whether body contains a call x.name(...) for any x.
func callsSelector(body *ast.BlockStmt, name string) bool {
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

func TestEveryAuthRoute_IsClassifiedAndBudgeted(t *testing.T) {
	routes := routerAuthRoutes(t)
	require.NotEmpty(t, routes, "parsed no /auth/ routes out of router.go: the parser no longer matches how routes are registered, so this guard would pass vacuously")
	methods := handlerMethods(t)
	require.Contains(t, methods, "AuthHandler.Login", "parsed no AuthHandler methods: this guard would pass vacuously")

	seen := map[string]bool{}
	for _, r := range routes {
		key := r.method + " " + r.path
		seen[key] = true
		cls, ok := authRouteClasses[key]
		if !assert.True(t, ok, "%s (handler %s) is a new auth route: classify it in authRouteClasses. A public route that takes a guessable input needs a budget, and every budget goes through the shared limiter, so it cannot fail open", key, r.handler) {
			continue
		}
		_, mountedMethod, _ := strings.Cut(cls.handler, ".")
		assert.Equal(t, mountedMethod, r.handler, "%s: router.go mounts a different handler than the one classified", key)
		fd, ok := methods[cls.handler]
		if !assert.True(t, ok, "%s: %s not found in this package", key, cls.handler) {
			continue
		}
		if cls.kind == routeAuthenticated {
			assert.True(t, r.behindAuth, "%s: classified authenticated, but router.go does not mount it behind the Authentication middleware", key)
		} else {
			assert.False(t, r.behindAuth, "%s: classified public, but router.go mounts it behind Authentication: reclassify it", key)
		}
		switch cls.kind {
		case routeIPBudget:
			entry, ok := budgetEntryPoints[cls.budget]
			require.True(t, ok, "%s: unknown budget %q", key, cls.budget)
			assert.True(t, callsSelector(fd.Body, entry),
				"%s: %s no longer calls %s, so this public route has no %s budget", key, cls.handler, entry, cls.budget)
		case routeAuthenticated:
			// Checked above, on the router: chi authenticates before the handler.
		case routeExempt:
			assert.NotEmpty(t, cls.why, "%s: an exempt route must say why it needs no budget", key)
		default:
			t.Errorf("%s: unclassified kind", key)
		}
	}
	var stale []string
	for key := range authRouteClasses {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale, "classified routes router.go no longer registers: remove them so this table stays a complete picture")
}

// --- the sweep ---------------------------------------------------------------

// budgetRouteRequests drives each budgeted handler with the smallest request
// that reaches its budget check (each one checks before reading the body,
// except ConsumeSetup, which needs both fields present first).
var budgetRouteRequests = map[string]func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder{
	"Login": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.Login, "/auth/login", map[string]string{"username": "alice", "password": "x"})
	},
	"RefreshToken": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.RefreshToken, "/auth/refresh", map[string]string{})
	},
	"VerifyMFA": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.VerifyMFA, "/auth/mfa/verify", map[string]string{})
	},
	"BeginWebAuthnLogin": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.BeginWebAuthnLogin, "/auth/webauthn/login/begin", map[string]string{})
	},
	"FinishWebAuthnLogin": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.FinishWebAuthnLogin, "/auth/webauthn/login/finish", map[string]string{})
	},
	"BeginWebAuthnPasswordlessLogin": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.BeginWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/begin", map[string]string{})
	},
	"FinishWebAuthnPasswordlessLogin": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish", map[string]string{})
	},
	"ConsumeSetup": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.ConsumeSetup, "/auth/setup/consume", map[string]string{"token": "no-such-token", "password": "x"})
	},
	"PasswordReset": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return postJSONTo(t, h.PasswordReset, "/auth/password-reset", map[string]string{"email": "a@b.com"})
	},
	"BeginSSO": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return getFrom(h.BeginSSO, "/auth/sso/none/login")
	},
	"BeginSAML": func(t *testing.T, h *AuthHandler) *httptest.ResponseRecorder {
		return getFrom(h.BeginSAML, "/auth/saml/none/login")
	},
}

func getFrom(fn http.HandlerFunc, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	fn(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// spendBudget uses up budget for the test client's IP through core's own
// record path, so the healthy store and the down store are filled the same way.
func spendBudget(c *core.KeyorixCore, budget string) {
	ctx := context.Background()
	switch budget {
	case "login":
		for i := 0; i < core.LoginMaxAttempts; i++ {
			c.RecordFailedLogin(ctx, lockoutOracleTestIP)
		}
	case "password_reset":
		for i := 0; i < core.PasswordResetMaxAttempts; i++ {
			c.RecordPasswordResetAttempt(ctx, lockoutOracleTestIP)
		}
	case "sso_begin":
		for i := 0; i < core.SSOBeginMaxAttempts; i++ {
			c.RecordSSOBeginAttempt(ctx, lockoutOracleTestIP)
		}
	default:
		panic("unknown budget " + budget)
	}
}

func TestEveryAuthBudget_HoldsWithItsStorageDown(t *testing.T) {
	var keys []string
	for key, cls := range authRouteClasses {
		if cls.kind == routeIPBudget {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	require.NotEmpty(t, keys)
	for i, key := range keys {
		cls := authRouteClasses[key]
		t.Run(key, func(t *testing.T) {
			_, method, _ := strings.Cut(cls.handler, ".")
			drive, ok := budgetRouteRequests[method]
			require.True(t, ok, "%s is budgeted but has no request in budgetRouteRequests: add one so the sweep covers it", key)

			cdb := openLoginBudgetDB(t, fmt.Sprintf("file:kxbudgetsweepctl%d?mode=memory&cache=shared", i))
			cc := core.NewKeyorixCore(store.NewLocalStorage(cdb))
			spendBudget(cc, cls.budget)
			control := drive(t, NewAuthHandler(cc, false))
			require.Equal(t, http.StatusTooManyRequests, control.Code, "control: the healthy %s budget must refuse once spent: %s", cls.budget, control.Body.String())

			pdb := openLoginBudgetDB(t, fmt.Sprintf("file:kxbudgetsweepprobe%d?mode=memory&cache=shared", i))
			pc := core.NewKeyorixCore(loginAttemptsDownStore{store.NewLocalStorage(pdb)})
			spendBudget(pc, cls.budget)
			probe := drive(t, NewAuthHandler(pc, false))
			require.Equal(t, http.StatusTooManyRequests, probe.Code,
				"with LoginAttempt storage down the %s budget must still refuse (no auth budget fails open): %s", cls.budget, probe.Body.String())
			requireSameResponse(t, control, probe, key+" 429 from the in-memory fallback")
		})
	}
}
