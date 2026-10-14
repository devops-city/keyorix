package http

// login_ratelimit_realip_test.go — regression coverage for HARDENING-BACKLOG #301:
// the global RealIP-style client-IP derivation must NOT let an unauthenticated caller
// spoof its rate-limit identity via X-Forwarded-For / X-Real-IP, unless the request
// actually arrived through an operator-configured trusted reverse proxy.
//
// Login() (server/http/handlers/auth.go) keys the ADR-040 failed-login budget
// (core.LoginMaxAttempts = 10 per core.LoginWindow) on r.RemoteAddr, which by the
// time it reaches the handler has already passed through the router's client-IP
// middleware (server/http/router.go → server/middleware/client_ip.go). Before that
// middleware existed, the router installed chi's stock middleware.RealIP, which
// substitutes ANY caller-supplied forwarding header into r.RemoteAddr unconditionally
// — letting an attacker either (a) bypass the throttle entirely by incrementing a
// fake X-Forwarded-For per attempt, or (b) lock out a victim's real IP by replaying
// failed logins with their address in X-Forwarded-For.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// attemptLogin POSTs one failed login (bad credentials, unique username per call so
// the failure is on "user not found" rather than any shared state) with the given
// spoofed forwarding header value, and returns the response status code.
func attemptLoginSpoofed(t *testing.T, client *http.Client, serverURL, xff string) int {
	t.Helper()
	body := strings.NewReader(`{"username":"no-such-user","password":"wrong"}`)
	req, err := http.NewRequest(http.MethodPost, serverURL+"/auth/login", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestLoginRateLimit_DefaultConfig_IgnoresSpoofedForwardedFor proves #301 (a): with
// no trusted proxies configured (the fail-closed default), every request from this
// single real TCP connection is counted under the SAME rate-limit key regardless of
// what X-Forwarded-For claims — so an attacker incrementing a fake header per attempt
// cannot bypass the ADR-040 10-attempts/15-minute budget.
func TestLoginRateLimit_DefaultConfig_IgnoresSpoofedForwardedFor(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
			// TrustedProxies intentionally left empty: the fail-closed default.
		},
	}
	c := newTestCore(t)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	// Exhaust the budget: 10 failed attempts, each claiming a DIFFERENT spoofed
	// source IP. If the header were honored, each would land under its own
	// synthetic-IP bucket and never trip the limiter (the pre-fix bypass).
	for i := range 10 {
		status := attemptLoginSpoofed(t, client, server.URL, "10.0.0.1")
		require.NotEqual(t, http.StatusTooManyRequests, status,
			"attempt %d: budget should not be exhausted yet", i+1)
	}
	// The 11th failed attempt from the SAME real connection — regardless of the
	// (still spoofed, now yet another distinct) X-Forwarded-For value — must be
	// throttled: proof all 10 prior attempts were correctly counted together
	// under the real peer address, not fragmented across attacker-chosen headers.
	status := attemptLoginSpoofed(t, client, server.URL, "192.0.2.99")
	require.Equal(t, http.StatusTooManyRequests, status,
		"the real TCP peer must be rate-limited after 10 failures, independent of X-Forwarded-For")
}

// TestLoginRateLimit_TrustedProxy_HonorsForwardedFor proves #301 (b): when the
// operator explicitly configures a trusted proxy CIDR AND the request's real peer
// falls inside it (i.e. it genuinely came from the reverse proxy), the forwarded
// client IP IS honored for the rate-limit key — so legitimate reverse-proxy / load
// balancer deployments keep correct per-client throttling instead of everyone behind
// the proxy sharing one bucket.
func TestLoginRateLimit_TrustedProxy_HonorsForwardedFor(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "8080",
				// httptest.NewServer listens on 127.0.0.1, so the test client's real
				// peer address is inside this CIDR — simulating "the request really
				// did come through our trusted edge".
				TrustedProxies: []string{"127.0.0.1/32"},
			},
		},
	}
	c := newTestCore(t)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	// 10 failed attempts, each with a DISTINCT forwarded client IP: because the
	// peer (127.0.0.1) is a configured trusted proxy, each is correctly attributed
	// to its own distinct client and none of them should exhaust any single budget.
	for i := range 10 {
		status := attemptLoginSpoofed(t, client, server.URL, "203.0.113.50")
		require.NotEqual(t, http.StatusTooManyRequests, status,
			"attempt %d for distinct forwarded client 203.0.113.50 should not yet be limited", i+1)
	}
	// An 11th attempt for that SAME forwarded client must now be throttled — proving
	// the header value (not the shared proxy peer) is the effective rate-limit key.
	status := attemptLoginSpoofed(t, client, server.URL, "203.0.113.50")
	require.Equal(t, http.StatusTooManyRequests, status,
		"the forwarded client IP must be rate-limited after 10 failures once the proxy hop is trusted")

	// A DIFFERENT forwarded client, still via the same trusted proxy peer, has its
	// own fresh budget — proving per-client (not per-proxy) throttling still works.
	status = attemptLoginSpoofed(t, client, server.URL, "203.0.113.51")
	require.NotEqual(t, http.StatusTooManyRequests, status,
		"a different forwarded client behind the same trusted proxy must not share the exhausted budget")
}
