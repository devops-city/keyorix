package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/ratelimitmetrics"
)

func rejections(t *testing.T, limiter ratelimitmetrics.Limiter) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range fams {
		if mf.GetName() != "keyorix_rate_limit_rejections_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "limiter" && lp.GetValue() == string(limiter) {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("keyorix_rate_limit_rejections_total{limiter=%q} not exposed", limiter)
	return 0
}

// TestRateLimitRejectionMetric asserts the effect: a refused request moves the
// counter for its limiter and only that limiter.
func TestRateLimitRejectionMetric(t *testing.T) {
	t.Run("principal limiter", func(t *testing.T) {
		before := rejections(t, ratelimitmetrics.Principal)
		other := rejections(t, ratelimitmetrics.TokenAuthFailure)
		h := PrincipalRateLimit(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		refused := 0
		for range 3 {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.RemoteAddr = "192.0.2.77:1234"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusTooManyRequests {
				refused++
			}
		}
		require.Positive(t, refused, "burst of 1 must refuse a rapid second request")
		assert.Equal(t, before+float64(refused), rejections(t, ratelimitmetrics.Principal))
		assert.Equal(t, other, rejections(t, ratelimitmetrics.TokenAuthFailure))
	})

	t.Run("token auth failure limiter", func(t *testing.T) {
		before := rejections(t, ratelimitmetrics.TokenAuthFailure)
		refused := 0
		for range tokenAuthFailureBurst + 5 {
			if !recordTokenAuthFailure("198.51.100.99") {
				refused++
			}
		}
		require.Positive(t, refused)
		assert.Equal(t, before+float64(refused), rejections(t, ratelimitmetrics.TokenAuthFailure))
	})
}
