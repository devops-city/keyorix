package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func newRLRequest(userID uint) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/posture", nil)
	if userID != 0 {
		uc := &UserContext{UserID: userID}
		req = req.WithContext(context.WithValue(req.Context(), GetUserContextKey(), uc))
	}
	return req
}

// #163: disabled (the config zero value) is a transparent no-op — every request
// passes through regardless of volume.
func TestPrincipalRateLimit_DisabledIsNoOp(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for range 50 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRLRequest(1))
		require.Equal(t, http.StatusOK, w.Code)
	}
}

// A principal exceeding their burst gets 429; a DIFFERENT principal is unaffected —
// budgets are per-principal, not shared.
func TestPrincipalRateLimit_EnforcesPerPrincipalBudget(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 3})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// User 1 exhausts their burst of 3.
	for i := range 3 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRLRequest(1))
		require.Equal(t, http.StatusOK, w.Code, "request %d within burst must pass", i)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRLRequest(1))
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "the 4th request within the same instant must be limited")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	// User 2 has their own independent budget — unaffected by user 1's exhaustion.
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, newRLRequest(2))
	assert.Equal(t, http.StatusOK, w2.Code, "a different principal must have an independent budget")
}

// When Burst is left at its zero value (config omits it), PrincipalRateLimit
// must fall back to RequestsPerSecond as the burst size, rather than building
// a limiter with burst 0 (which would reject every request outright).
func TestPrincipalRateLimit_ZeroBurstFallsBackToRequestsPerSecond(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 3})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// Exactly RequestsPerSecond (3) requests must pass as the initial burst.
	for i := range 3 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRLRequest(9))
		require.Equal(t, http.StatusOK, w.Code, "request %d within the fallback burst must pass", i)
	}
	// The 4th immediate request must be limited — proving burst was set to 3
	// (RequestsPerSecond), not left at 0 (which would already have rejected
	// request 0 above).
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRLRequest(9))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// An unauthenticated request (no UserContext) falls back to an IP-keyed budget
// rather than panicking or bypassing the limiter entirely.
func TestPrincipalRateLimit_FallsBackToIPForUnauthenticated(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := newRLRequest(0)
	req.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "a second request from the same IP within burst=1 must be limited")
}

// TestIPFailureLimiter_SweepAmortized is #G19: ipFailureLimiter.allow used to
// call sweepLocked() on EVERY invocation (a full O(n) scan of the limiter map
// under the shared mutex), unlike its sibling principalRateLimiter.allow, which
// explicitly amortizes the identical sweep to once every
// principalLimiterSweepEvery calls. Proven deterministically here (idle entries
// must survive until the amortization boundary, not be swept on the very next
// call) rather than via a timing-based benchmark, which would be flaky in CI.
func TestIPFailureLimiter_SweepAmortized(t *testing.T) {
	l := &ipFailureLimiter{limiters: make(map[string]*principalBucket)}

	// An entry idle well past principalLimiterIdleTTL — eligible for eviction the
	// moment a sweep actually runs.
	l.limiters["203.0.113.9"] = &principalBucket{
		limiter:  rate.NewLimiter(rate.Limit(1), tokenAuthFailureBurst),
		lastSeen: time.Now().Add(-2 * principalLimiterIdleTTL),
	}

	// Fewer calls than the amortization interval: the idle entry must survive —
	// sweepLocked() must not have run yet. Each call uses a distinct IP so the
	// idle entry itself is never touched/refreshed by allow().
	for range principalLimiterSweepEvery - 1 {
		l.allow("10.0.0.1")
	}
	l.mu.Lock()
	_, stillPresent := l.limiters["203.0.113.9"]
	l.mu.Unlock()
	assert.True(t, stillPresent,
		"an idle entry must survive until the sweep amortization boundary, not be evicted on every call")

	// One more call crosses the Nth-call boundary: the sweep must now have run.
	l.allow("10.0.0.2")
	l.mu.Lock()
	_, stillPresent = l.limiters["203.0.113.9"]
	l.mu.Unlock()
	assert.False(t, stillPresent, "the idle entry must be evicted once the amortized sweep runs")
}

// TestIPFailureLimiter_StillEnforcesBudget is a basic sanity check that
// amortizing the sweep didn't change allow()'s actual rate-limiting behavior:
// a single IP still gets exactly tokenAuthFailureBurst allowances before being
// throttled.
func TestIPFailureLimiter_StillEnforcesBudget(t *testing.T) {
	l := &ipFailureLimiter{limiters: make(map[string]*principalBucket)}

	for i := range tokenAuthFailureBurst {
		require.True(t, l.allow("198.51.100.5"), "call %d within the burst must be allowed", i+1)
	}
	assert.False(t, l.allow("198.51.100.5"), "a call past the burst must be denied")
}
