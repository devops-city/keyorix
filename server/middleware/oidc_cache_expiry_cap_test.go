// oidc_cache_expiry_cap_test.go — INV-MW-oidc-cache-capped-at-exp
// (OIDC-EXPIRY-CAP-1).
//
// A federated OIDC JWT's positive auth-cache entry used to live for the whole
// validTokenTTL regardless of the token's own exp, and the cache-hit path never
// re-verifies the JWT — so an expired token kept authenticating for up to ~30 s.
// The entry must now end at exp (or at validTokenTTL when exp is further away),
// and a token that is already expired, or within oidcCacheSkew of expiring, or
// whose validator reported no exp at all, must never be cached.
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const oidcCapToken = "header.valid.sig"

// oidcExpValidator is fakeValidator whose federated token reports a chosen exp
// and counts slow-path validations.
type oidcExpValidator struct {
	fakeValidator
	exp   func() time.Time
	calls *atomic.Int32
}

func (v oidcExpValidator) ValidateOIDCToken(_ context.Context, token string) (*models.MachineIdentity, []string, time.Time, error) {
	v.calls.Add(1)
	m, roles, _, err := v.fakeValidator.ValidateOIDCToken(context.Background(), token)
	return m, roles, v.exp(), err
}

func serveOIDCWithExp(t *testing.T, exp func() time.Time) (calls *atomic.Int32, do func() int) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	resetTokenCacheG18(oidcCapToken)
	t.Cleanup(func() { resetTokenCacheG18(oidcCapToken) })
	calls = &atomic.Int32{}
	h := authenticationWithValidator(oidcExpValidator{exp: exp, calls: calls}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	do = func() int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+oidcCapToken)
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	return calls, do
}

// exp beyond the TTL behaves as before: cached for validTokenTTL, second request
// is a cache hit (no second slow-path validation).
func TestOIDCCache_ExpBeyondTTL_CachedForTTL(t *testing.T) {
	calls, do := serveOIDCWithExp(t, func() time.Time { return time.Now().Add(time.Hour) })
	before := time.Now()
	require.Equal(t, http.StatusOK, do())
	e, ok := cacheGet(tokenKey(oidcCapToken))
	require.True(t, ok, "a token with a distant exp must be cached")
	require.WithinDuration(t, before.Add(validTokenTTL), e.expiresAt, 2*time.Second)
	require.Equal(t, http.StatusOK, do())
	require.EqualValues(t, 1, calls.Load(), "second request must be a cache hit")
}

// exp inside the TTL window: the entry ends at exp, not at now+validTokenTTL.
func TestOIDCCache_ExpInsideTTL_EntryEndsAtExp(t *testing.T) {
	exp := time.Now().Add(15 * time.Second)
	_, do := serveOIDCWithExp(t, func() time.Time { return exp })
	require.Equal(t, http.StatusOK, do())
	e, ok := cacheGet(tokenKey(oidcCapToken))
	require.True(t, ok)
	require.False(t, e.expiresAt.After(exp), "cache entry %s must not outlive exp %s", e.expiresAt, exp)
	require.WithinDuration(t, exp, e.expiresAt, time.Millisecond)
}

// A cached entry that has reached exp is a miss: the token is re-verified, and
// the verifier (which sees the real exp) is what refuses it.
func TestOIDCCache_AtExp_EntryIsMiss(t *testing.T) {
	exp := time.Now().Add(oidcCacheSkew + 150*time.Millisecond)
	_, do := serveOIDCWithExp(t, func() time.Time { return exp })
	require.Equal(t, http.StatusOK, do())
	_, ok := cacheGet(tokenKey(oidcCapToken))
	require.True(t, ok, "just outside the skew allowance the token is still cached")
	time.Sleep(time.Until(exp) + 20*time.Millisecond)
	_, ok = cacheGet(tokenKey(oidcCapToken))
	require.False(t, ok, "right after exp the cache entry must be gone")
}

// Clock-skew boundary and degenerate exps: never cached.
func TestOIDCCache_NearOrPastExp_NeverCached(t *testing.T) {
	cases := []struct {
		name string
		exp  func() time.Time
	}{
		{"already_expired", func() time.Time { return time.Now().Add(-time.Second) }},
		{"expires_now", func() time.Time { return time.Now() }},
		{"inside_skew", func() time.Time { return time.Now().Add(oidcCacheSkew - time.Second) }},
		{"zero_exp_from_validator", func() time.Time { return time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, do := serveOIDCWithExp(t, tc.exp)
			require.Equal(t, http.StatusOK, do(), "the slow path still decides; only caching is refused")
			_, ok := cacheGet(tokenKey(oidcCapToken))
			require.False(t, ok, "must not be cached")
			require.Equal(t, http.StatusOK, do())
			require.EqualValues(t, 2, calls.Load(), "every request must re-validate")
		})
	}
}

// Just outside the skew allowance the token is cached (the boundary's other side).
func TestOIDCCache_JustOutsideSkew_Cached(t *testing.T) {
	_, do := serveOIDCWithExp(t, func() time.Time { return time.Now().Add(oidcCacheSkew + 2*time.Second) })
	require.Equal(t, http.StatusOK, do())
	_, ok := cacheGet(tokenKey(oidcCapToken))
	require.True(t, ok)
}
