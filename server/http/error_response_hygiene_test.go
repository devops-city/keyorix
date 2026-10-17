package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

var hygieneParam = regexp.MustCompile(`\{[^}]+\}`)

// assertErrorHygiene: an error response carries the baseline security headers,
// Cache-Control: no-store, and the API's JSON error body ({"error": <string>,
// "code": <status>, ...}).
func assertErrorHygiene(t *testing.T, w *httptest.ResponseRecorder, where string) {
	t.Helper()
	assertBaselineSecurityHeaders(t, w.Result(), where)
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: %d with Cache-Control %q, want no-store", where, w.Code, cc)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("%s: %d with Content-Type %q and body %q, want the JSON error body", where, w.Code, ct, w.Body.String())
		return
	}
	var body struct {
		Error any `json:"error"`
		Code  any `json:"code"`
		// SCIM's RFC 7644 error shape carries status instead of code.
		Status any `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error == nil && body.Status == nil {
		t.Errorf("%s: %d body %q is not an error envelope", where, w.Code, w.Body.String())
	}
}

// TestEveryErrorResponse_HeadersNoStoreAndJSONBody is the response-hygiene family
// guard. It walks every route the real router registers (SCIM enabled) and sends
// each one an unauthenticated request with an empty JSON body, then sends the
// responses the router itself produces: an unknown backend path (404), a known
// path with the wrong method (405), a missing static asset (404), and /metrics with
// a wrong token (401). Every response with status >= 400 must carry the baseline
// security headers, Cache-Control: no-store and the JSON error body. Before this,
// the router's own 404/405/401 were net/http's text/plain (or empty) bodies.
func TestEveryErrorResponse_HeadersNoStoreAndJSONBody(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg := &config.Config{}
	cfg.SCIM.Enabled = true
	cfg.SCIM.Token = strings.Repeat("s", 64)
	cfg.Server.HTTP.MetricsToken = "metrics-token-abcdefghijklmnopqrstuvwxyz"
	router, err := NewRouter(cfg, newTestCore(t))
	require.NoError(t, err)

	// The route walk spends the per-client /metrics failure budget (one 401 per method),
	// so the explicit cases below come from a second client address.
	remoteAddr := ""
	send := func(method, path, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if remoteAddr != "" {
			req.RemoteAddr = remoteAddr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	routes, ok := router.(chi.Routes)
	require.True(t, ok)
	walked, errors := 0, 0
	require.NoError(t, chi.Walk(routes, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		path := strings.ReplaceAll(hygieneParam.ReplaceAllString(pattern, "1"), "/*", "/x")
		// The SPA shell, the status pages and static assets answer 200 or are covered
		// by the explicit cases below.
		if path == "/x" || strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/static/") {
			return nil
		}
		walked++
		w := send(method, path, "")
		if w.Code >= 400 {
			errors++
			assertErrorHygiene(t, w, method+" "+pattern)
		}
		return nil
	}))
	require.Greater(t, walked, 200, "walked only %d routes", walked)
	require.Greater(t, errors, 200, "only %d error responses: the walk is not reaching the auth gate", errors)

	remoteAddr = "192.0.2.77:4321"
	for _, tc := range []struct {
		method, path, auth string
		want               int
	}{
		{http.MethodGet, "/api/v2/no-such-route", "", http.StatusNotFound},
		{http.MethodGet, "/auth/no-such-route", "", http.StatusNotFound},
		{http.MethodPost, "/no-such-page", "", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/health", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/assets/no-such-file.js", "", http.StatusNotFound},
		{http.MethodGet, "/metrics", "Bearer wrong", http.StatusUnauthorized},
	} {
		w := send(tc.method, tc.path, tc.auth)
		if w.Code != tc.want {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, w.Code, tc.want)
			continue
		}
		assertErrorHygiene(t, w, tc.method+" "+tc.path)
	}
}
