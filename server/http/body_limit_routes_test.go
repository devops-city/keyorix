package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// bodyRoute is one registered route that accepts a request body.
type bodyRoute struct{ method, pattern, path string }

var chiParam = regexp.MustCompile(`\{[^}]+\}`)

// walkBodyRoutes returns every POST/PUT/PATCH/DELETE route the real router registers
// (SCIM enabled, so /scim/v2 is included), with path parameters filled in.
func walkBodyRoutes(t *testing.T, router http.Handler) []bodyRoute {
	t.Helper()
	routes, ok := router.(chi.Routes)
	require.True(t, ok, "NewRouter must return a chi router so its routes can be walked")
	var out []bodyRoute
	err := chi.Walk(routes, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return nil
		}
		path := chiParam.ReplaceAllString(pattern, "1")
		path = strings.ReplaceAll(path, "/*", "/x")
		out = append(out, bodyRoute{method, pattern, path})
		return nil
	})
	require.NoError(t, err)
	return out
}

func newBodyLimitRouter(t *testing.T) http.Handler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg := &config.Config{}
	cfg.SCIM.Enabled = true
	cfg.SCIM.Token = strings.Repeat("s", 64)
	router, err := NewRouter(cfg, newTestCore(t))
	require.NoError(t, err)
	return router
}

// sendDeclared sends a request that declares a body of n bytes. The cap is enforced
// on the declared length before any byte is read, so the body itself can be empty.
func sendDeclared(router http.Handler, method, path string, n int64) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Body = io.NopCloser(strings.NewReader(""))
	req.ContentLength = n
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestEveryBodyRoute_RefusesOverItsClassCap is the family-wide guard: it walks every
// route the real router registers that can take a body and sends each one a body
// declared one byte over its route class's cap. Every one must answer 413 before
// any handler, authentication or CSRF check runs, so no handler can read a body
// past the cap and none can be added that escapes it.
//
// Classes: unauthenticated credential routes (/auth/*, /system/init) 64 KiB, the SAML
// ACS 1 MiB, everything else server.http.max_request_body_bytes (10 MiB default).
// Not covered: a chunked body (no declared length) is cut off by http.MaxBytesReader
// inside the handler's read instead, and the handler picks the 4xx
// (server/middleware TestMaxBodyBytes_RejectsOversize).
func TestEveryBodyRoute_RefusesOverItsClassCap(t *testing.T) {
	router := newBodyLimitRouter(t)
	global := (&config.Config{}).Server.HTTP.EffectiveMaxRequestBodyBytes()
	limitFor := requestBodyLimit(global)

	routes := walkBodyRoutes(t, router)
	require.Greater(t, len(routes), 100, "walked only %d body routes: the walk is not seeing the router", len(routes))

	var publicAuth int
	for _, rt := range routes {
		limit := limitFor(httptest.NewRequest(rt.method, rt.path, nil))
		if limit < global {
			publicAuth++
		}
		if w := sendDeclared(router, rt.method, rt.path, limit+1); w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s with a %d-byte body (cap %d): status %d, want 413", rt.method, rt.pattern, limit+1, limit, w.Code)
		}
	}
	// The public credential class must actually be populated, or the 64 KiB cap is
	// tested on nothing.
	require.GreaterOrEqual(t, publicAuth, 10, "only %d routes fell in a public-auth class", publicAuth)
}

// TestPublicAuthRoutes_TightBodyCap pins the class caps on concrete routes: a body
// just over 64 KiB is refused on login and /system/init, while the same size is still
// accepted onto the SAML ACS and onto an authenticated API route (which reach their
// handlers and fail for other reasons). Before route classes, every public route
// took up to 10 MiB.
func TestPublicAuthRoutes_TightBodyCap(t *testing.T) {
	router := newBodyLimitRouter(t)
	over := publicAuthBodyLimit + 1

	for _, path := range []string{"/auth/login", "/auth/mfa/verify", "/auth/setup/consume", "/system/init"} {
		if w := sendDeclared(router, http.MethodPost, path, over); w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("POST %s with %d bytes: status %d, want 413", path, over, w.Code)
		}
		if w := sendDeclared(router, http.MethodPost, path, publicAuthBodyLimit); w.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("POST %s at exactly the cap: 413, want it to reach the handler", path)
		}
	}
	for _, path := range []string{"/auth/saml/okta/acs", "/api/v1/secrets"} {
		if w := sendDeclared(router, http.MethodPost, path, over); w.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("POST %s with %d bytes: 413, but its class cap is larger", path, over)
		}
	}
	if w := sendDeclared(router, http.MethodPost, "/auth/saml/okta/acs", samlACSBodyLimit+1); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("SAML ACS over %d bytes: status %d, want 413", samlACSBodyLimit, w.Code)
	}
}

// TestRequestBodyLimit_ClassCapsSurviveGlobalOverride: an operator raising or
// disabling server.http.max_request_body_bytes never lifts the public-route caps;
// lowering it below a class cap lowers that class too.
func TestRequestBodyLimit_ClassCapsSurviveGlobalOverride(t *testing.T) {
	req := func(p string) *http.Request { return httptest.NewRequest(http.MethodPost, p, nil) }
	for _, global := range []int64{-1, 100 << 20} {
		f := requestBodyLimit(global)
		require.Equal(t, publicAuthBodyLimit, f(req("/auth/login")), "global %d", global)
		require.Equal(t, samlACSBodyLimit, f(req("/auth/saml/x/acs")), "global %d", global)
		require.Equal(t, global, f(req("/api/v1/secrets")), "global %d", global)
	}
	f := requestBodyLimit(1024)
	require.Equal(t, int64(1024), f(req("/auth/login")))
	require.Equal(t, int64(1024), f(req("/auth/saml/x/acs")))
}

// TestDeeplyNestedJSON_RefusedAsClientError: JSON nesting depth is bounded by
// encoding/json's own limit (10000) on top of the byte cap, so a pathologically
// nested body under the cap is a 4xx from the decoder, never a 5xx, a panic or a
// stack overflow.
func TestDeeplyNestedJSON_RefusedAsClientError(t *testing.T) {
	router := newBodyLimitRouter(t)
	body := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	require.Less(t, int64(len(body)), publicAuthBodyLimit)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("deeply nested JSON: status %d, want a 4xx", w.Code)
	}
}
