package middleware

// auth_transient_error_test.go — regression coverage for the auth middleware's
// transient-vs-permanent error handling (Wave 6 low/info finding,
// findings-server/middleware-auth.json index 2).
//
// Before this fix, handleAuthRequest's slow path treated ANY error from
// validateToken identically — a genuinely bad token and a transient
// infrastructure failure (DB timeout, connection error, context deadline
// exceeded during the underlying storage lookup) both got negative-cached for
// invalidTokenTTL and counted against the per-source-IP brute-force budget
// (recordTokenAuthFailure / tokenAuthFailureBurst, PAT-003). That meant a brief
// storage blip could: (1) keep rejecting a legitimate token from the negative
// cache for up to invalidTokenTTL after the backend recovered, and (2) push a
// shared NAT/corporate-egress IP over the failure-burst threshold from
// concurrent legitimate retries, starting to 429 unrelated healthy traffic.
//
// isTransientValidationError (auth.go) now distinguishes the two by checking
// whether the request's own context was canceled or hit its deadline during
// validation — the storage layer's errors are deliberately opaque by the time
// they reach this package, so the context is the one reliable signal available
// here. These tests simulate that with an already-canceled request context,
// standing in for a DB timeout/connection error aborting the in-flight lookup.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleAuthRequest_TransientError_SkipsNegativeCacheAndRateLimit is the
// negative-behavior-change case: a transient failure (simulated via an
// already-canceled request context, standing in for a context-deadline-exceeded
// DB error) must NOT negative-cache the token and must NOT consume any of the
// per-IP brute-force budget, and must surface as a retryable 503 rather than a
// 401.
func TestHandleAuthRequest_TransientError_SkipsNegativeCacheAndRateLimit(t *testing.T) {
	// A source IP unused by any other test in this package, so this test's
	// budget assertions can't be polluted by (or pollute) the shared,
	// package-global recordTokenAuthFailure limiter.
	const remoteAddr = "203.0.113.10:5555"
	const ip = "203.0.113.10"

	handler := newTestAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := "not-a-recognized-token-transient"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = remoteAddr

	// Simulate the request's context already having been canceled/timed out by
	// the time validateToken returns — standing in for a DB timeout or
	// connection error aborting the underlying storage lookup mid-flight.
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code,
		"a transient infrastructure failure must surface as a retryable 503, not a 401")

	// Must NOT be negative-cached: a retry after the backend recovers should
	// re-attempt validation rather than being auto-rejected from a stale
	// "invalid" cache entry for up to invalidTokenTTL.
	key := tokenKey(token)
	_, found := cacheGet(key)
	assert.False(t, found, "a transient error must not populate the negative token cache")

	// Must NOT have consumed the per-IP brute-force budget: every one of
	// tokenAuthFailureBurst allowances should still be available for this IP,
	// proving the request above did not call recordTokenAuthFailure.
	for i := range tokenAuthFailureBurst {
		assert.True(t, recordTokenAuthFailure(ip),
			"budget slot %d should still be available — a transient error must not consume the per-IP failure budget", i)
	}
}

// TestHandleAuthRequest_InvalidCredential_StillNegativeCachesAndRateLimits is
// the unchanged-behavior case: a genuinely invalid credential (normal,
// non-canceled context) must still negative-cache and still count against the
// per-IP brute-force budget exactly as before, so this fix does not weaken the
// PAT-003 brute-force protection the negative-caching/rate-limiting exists for.
func TestHandleAuthRequest_InvalidCredential_StillNegativeCachesAndRateLimits(t *testing.T) {
	const remoteAddr = "203.0.113.20:5555"
	const ip = "203.0.113.20"

	handler := newTestAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := "not-a-recognized-token-permanent"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = remoteAddr
	// Deliberately NOT canceled/deadline-bound — an ordinary, live request
	// context, so isTransientValidationError must return false here.
	require.Nil(t, req.Context().Err())

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "an invalid credential must still be rejected with 401")

	// Must be negative-cached, exactly as before this fix.
	key := tokenKey(token)
	entry, found := cacheGet(key)
	require.True(t, found, "an invalid credential must still populate the negative token cache")
	assert.Nil(t, entry.userCtx, "the negative cache entry must carry a nil userCtx")

	// Must have consumed exactly one unit of the per-IP brute-force budget: only
	// tokenAuthFailureBurst-1 further allowances should remain for this IP.
	for i := range tokenAuthFailureBurst - 1 {
		assert.True(t, recordTokenAuthFailure(ip),
			"remaining budget slot %d should still be available", i)
	}
	assert.False(t, recordTokenAuthFailure(ip),
		"the budget should now be exhausted — the request above must have consumed one unit")
}

// TestIsTransientValidationError unit-tests the classifier directly, covering
// its documented signals: a canceled/deadline-exceeded context, a wrapped
// context sentinel in err, and the ordinary "neither" case.
func TestIsTransientValidationError(t *testing.T) {
	plainErr := context.DeadlineExceeded // reused below only as a distinct error value where noted

	t.Run("canceled context is transient", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.True(t, isTransientValidationError(ctx, errors.New("session not found")))
	})

	t.Run("deadline-exceeded context is transient", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		assert.True(t, isTransientValidationError(ctx, errors.New("session not found")))
	})

	t.Run("err wrapping context.DeadlineExceeded is transient even with a live context", func(t *testing.T) {
		assert.True(t, isTransientValidationError(context.Background(), plainErr))
	})

	t.Run("an ordinary invalid-credential error with a live context is not transient", func(t *testing.T) {
		assert.False(t, isTransientValidationError(context.Background(), errors.New("session not found")))
	})
}
