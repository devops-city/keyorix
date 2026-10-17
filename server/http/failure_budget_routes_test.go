package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

func sendFrom(router http.Handler, method, path, ip, auth, body string) int {
	code, _ := sendFromBody(router, method, path, ip, auth, body)
	return code
}

func sendFromBody(router http.Handler, method, path, ip, auth, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// TestSystemInit_BootstrapTokenGuessingThrottled drives the real router on an
// uninitialised system: wrong bootstrap tokens from one IP get 403 until the
// failure budget is spent, then 429 without reaching core (no bootstrap lock
// taken); another IP holding the right token still initialises the system. On main
// every wrong guess was answered 403, without bound.
func TestSystemInit_BootstrapTokenGuessingThrottled(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := newTestCore(t)
	c.SetBootstrapToken("the-real-bootstrap-token-0123456789")
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	guess := `{"username":"testadmin","email":"testadmin@example.com","password":"TestPassword123!","bootstrap_token":"guess"}`
	for i := range bootstrapFailureBurst {
		if got := sendFrom(router, http.MethodPost, "/system/init", "198.51.100.7", "", guess); got != http.StatusForbidden {
			t.Fatalf("wrong token %d: status %d, want 403", i+1, got)
		}
	}
	if got := sendFrom(router, http.MethodPost, "/system/init", "198.51.100.7", "", guess); got != http.StatusTooManyRequests {
		t.Fatalf("wrong token past the budget: status %d, want 429", got)
	}

	ok := strings.Replace(guess, `"guess"`, `"the-real-bootstrap-token-0123456789"`, 1)
	if got, body := sendFromBody(router, http.MethodPost, "/system/init", "198.51.100.8", "", ok); got != http.StatusOK {
		t.Fatalf("right token from another IP: status %d, want 200 (%s)", got, body)
	}
	// Initialised now: the idempotent answer is a 200 and costs nothing, however often.
	for range 3 * bootstrapFailureBurst {
		if got := sendFrom(router, http.MethodPost, "/system/init", "198.51.100.8", "", ok); got != http.StatusOK {
			t.Fatalf("idempotent init: status %d, want 200 every time", got)
		}
	}
}

// TestMetrics_TokenGuessingThrottled: with server.http.metrics_token set, wrong
// tokens from one IP get 401 until the failure budget is spent, then 429; a scraper
// with the right token on another IP is unaffected, and successful scrapes never
// spend the budget.
func TestMetrics_TokenGuessingThrottled(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	cfg := &config.Config{}
	cfg.Server.HTTP.MetricsToken = "metrics-token-abcdefghijklmnopqrstuvwxyz"
	router, err := NewRouter(cfg, newTestCore(t))
	require.NoError(t, err)

	for i := range metricsFailureBurst {
		if got := sendFrom(router, http.MethodGet, "/metrics", "198.51.100.20", "Bearer wrong", ""); got != http.StatusUnauthorized {
			t.Fatalf("wrong token %d: status %d, want 401", i+1, got)
		}
	}
	if got := sendFrom(router, http.MethodGet, "/metrics", "198.51.100.20", "Bearer wrong", ""); got != http.StatusTooManyRequests {
		t.Fatalf("wrong token past the budget: status %d, want 429", got)
	}
	for range 3 * metricsFailureBurst {
		if got := sendFrom(router, http.MethodGet, "/metrics", "198.51.100.21", "Bearer "+cfg.Server.HTTP.MetricsToken, ""); got != http.StatusOK {
			t.Fatalf("right token: status %d, want 200 on every scrape", got)
		}
	}
}

// TestBearerTokenGuessingThrottledThroughRouter: guessing bearer credentials
// (session, PAT, machine token, OIDC JWT) against the API spends the per-IP
// failed-token budget the Authentication middleware keeps; past it, 429. The
// limiter's own unit test (server/middleware TestIPFailureLimiter_StillEnforcesBudget)
// cannot see whether the router's auth path feeds it.
func TestBearerTokenGuessingThrottledThroughRouter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)

	// The failed-token limiter is process-wide; an address no other test uses.
	const ip = "198.51.100.231"
	got429 := false
	for i := range 50 {
		// A distinct token every time: a repeated one is answered from the negative cache.
		code := sendFrom(router, http.MethodGet, "/api/v1/secrets", ip, "Bearer guess-"+strings.Repeat("x", i+1), "")
		if code == http.StatusTooManyRequests {
			got429 = true
			if i < 10 {
				t.Fatalf("throttled after only %d guesses", i)
			}
			break
		}
		if code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status %d, want 401 or 429", i+1, code)
		}
	}
	if !got429 {
		t.Fatal("50 wrong bearer tokens from one IP were never throttled")
	}
}
