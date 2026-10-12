// health_auth_rate_limit_test.go — /health reports whether an auth rate limit
// is running on its in-memory storage fallback (AUTH-AUDIT-1 item 5, point 4):
// "degraded" while one has fallen back within its window, "ok" otherwise. It
// stays a 200 "healthy" liveness answer either way, and names no budget, key,
// account or address.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func healthBody(t *testing.T, probe func() bool) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	HealthCheckWithAuthRateLimit(probe)(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return w.Code, body
}

func TestHealth_ReportsTheAuthRateLimitFallback(t *testing.T) {
	db := openLoginBudgetDB(t, "file:kxhealthfallback?mode=memory&cache=shared")
	healthy := core.NewKeyorixCore(store.NewLocalStorage(db))
	down := core.NewKeyorixCore(loginAttemptsDownStore{store.NewLocalStorage(db)})
	_ = healthy.IsLoginRateLimited(context.Background(), "203.0.113.60")
	code, body := healthBody(t, healthy.AuthRateLimitDegraded)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "ok", body["auth_rate_limit"], "no fallback has happened")

	_ = down.IsLoginRateLimited(context.Background(), "203.0.113.61")
	code, body = healthBody(t, down.AuthRateLimitDegraded)
	require.Equal(t, http.StatusOK, code, "a degraded limiter is not a failed liveness check")
	assert.Equal(t, "healthy", body["status"])
	assert.Equal(t, "degraded", body["auth_rate_limit"], "the login budget just used its in-memory fallback")

	keys := make([]string, 0, len(body))
	for k := range body {
		if k != "instance_nonce" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"auth_rate_limit", "status", "timestamp", "uptime"}, keys,
		"/health is unauthenticated: it may say THAT a limit is degraded, never which budget, key or address")
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "203.0.113.61")
}
