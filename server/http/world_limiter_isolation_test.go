package http

// world_limiter_isolation_test.go — WALK-LIMITER-1.
//
// Every in-process test server dials from httptest's fixed client address
// (192.0.2.1) and shares one package-level invalid-token limiter
// (middleware.globalTokenAuthFailureLimiter). A walk that spends the per-IP failure
// budget used to leave the next walk's world starting at 429 "too many invalid token
// attempts" instead of 401. newSVWorldFromConfig now empties the limiter, so each
// world starts with a full budget.
//
// This test drives that deterministically instead of relying on walk timing: it
// exhausts the budget, builds a new world, and requires the first dead-token call to
// be a 401. It is red when the reset in newSVWorldFromConfig is removed. It does not
// claim anything about production: the limiter's burst and refill are unchanged, and
// the production limiter tests are untouched.

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewWorldStartsWithAFreshInvalidTokenBudget(t *testing.T) {
	first := newSVWorld(t, "sqlite", 1)

	// A distinct token per call: a repeated dead token is negative-cached for
	// invalidTokenTTL and only its first refusal is charged to the IP.
	limited := false
	for i := range 100 {
		code, _ := awDo(first.a, http.MethodGet, fmt.Sprintf("not-a-credential-%d", i), "/api/v1/auth/profile", nil)
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
		require.Equal(t, http.StatusUnauthorized, code, "a dead token is refused until the budget runs out")
	}
	require.True(t, limited, "non-vacuity: the shared per-IP budget must actually be exhausted before the second world is built")

	second := newSVWorld(t, "sqlite", 1)
	code, body := awDo(second.a, http.MethodGet, "not-a-credential-second-world", "/api/v1/auth/profile", nil)
	require.Equal(t, http.StatusUnauthorized, code, "a new world must not inherit the previous world's spent budget: %s", body)
}
