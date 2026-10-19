// machine_principal_no_5xx_test.go — AUTH-MACHINE-500-1.
//
// A machine-identity token authenticates with UserID 0 (ADR-030). Routes that act
// on "the caller's own" user record (sessions, personal access tokens) hand that 0
// to a core function which rejects it as a validation error, and the handler used
// to map any core error to 500. Nothing was disclosed, but a 500 pages operators,
// pollutes error metrics and hides real failures. A wrong-principal request is the
// caller's mistake: 403.
//
// Two tests:
//   - TestUserSelfRoutes_MachineToken_Forbidden pins the exact status and the
//     standard error body on the routes the report named.
//   - TestEveryRoute_MachineToken_NoServerError is the family guard: the route set
//     is derived (chi.Walk over NewRouter, every method), each route is called with
//     a real zero-grant machine bearer token, and no response may be 5xx.
//
// What the walk does not cover: it binds every {param} to 1 and sends an empty JSON
// object, so a route whose 5xx needs a real object id or a valid body is not reached
// past its validation. It proves "no route 5xxs on the machine path with this
// input", not "no route can ever 5xx for a machine".
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

var machineWalkParam = regexp.MustCompile(`\{[^}]*\}`)

// zeroGrantMachineRouter returns the real router and a bearer token for a machine
// identity that holds no role grant.
func zeroGrantMachineRouter(t *testing.T) (http.Handler, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := newFullSchemaTestCore(t)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)

	mi, err := c.CreateMachineIdentity(ctx, projects[0].ID, "m500-ci-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, projects[0].ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "m500-token"})
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Server.HTTP = config.ServerInstanceConfig{Enabled: true, Port: "8080"}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	return router, tok.PlainToken
}

func machineCall(router http.Handler, token, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestUserSelfRoutes_MachineToken_Forbidden: a machine principal on the caller-owned
// session/token routes gets 403 with the standard error envelope, not 500.
func TestUserSelfRoutes_MachineToken_Forbidden(t *testing.T) {
	router, token := zeroGrantMachineRouter(t)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/sessions"},
		{http.MethodGet, "/api/v1/auth/tokens"},
		{http.MethodGet, "/api/v1/auth/tokens/expired"},
		{http.MethodDelete, "/api/v1/auth/tokens/expired"},
		{http.MethodPost, "/api/v1/auth/end-impersonation"},
		{http.MethodDelete, "/api/v1/secrets/1/self-share"},
	} {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			w := machineCall(router, token, rt.method, rt.path)
			require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), "body: %s", w.Body.String())
			assert.Equal(t, "Forbidden", body["error"])
			assert.EqualValues(t, http.StatusForbidden, body["code"])
			assert.NotEmpty(t, body["message"])
			assert.NotContains(t, w.Body.String(), "user ID is required", "internal validation text must not reach the client")
		})
	}
}

// TestEveryRoute_MachineToken_NoServerError is the family guard (see file header).
func TestEveryRoute_MachineToken_NoServerError(t *testing.T) {
	router, token := zeroGrantMachineRouter(t)
	routes, ok := router.(chi.Routes)
	require.True(t, ok)

	walked := 0
	require.NoError(t, chi.Walk(routes, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		path := strings.ReplaceAll(machineWalkParam.ReplaceAllString(pattern, "1"), "/*", "/x")
		if path == "/x" || strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/static/") {
			return nil
		}
		walked++
		w := machineCall(router, token, method, path)
		// 501 is "this feature is not enabled on this server" (webauthn in this
		// fixture); it does not depend on the principal, so it is not what this
		// guard is about.
		if w.Code >= 500 && w.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: machine token got %d: %s", method, pattern, w.Code, w.Body.String())
		}
		return nil
	}))
	require.Greater(t, walked, 200, "walked only %d routes", walked)
}
