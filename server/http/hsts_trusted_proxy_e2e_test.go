package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestSecurityHeaders_HSTS_TrustedProxyRealRouter drives the production router over a
// real TCP connection (the peer is 127.0.0.1), so it proves ClientIP's trust decision
// reaches SecurityHeaders through router.go's actual middleware order, not just in the
// isolated chain of server/middleware/hsts_trusted_proxy_test.go.
func TestSecurityHeaders_HSTS_TrustedProxyRealRouter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	const want = "max-age=31536000; includeSubDomains"

	start := func(t *testing.T, trusted []string, directTLS bool) *httptest.Server {
		t.Helper()
		cfg := &config.Config{}
		cfg.Server.HTTP.TrustedProxies = trusted
		router, err := NewRouter(cfg, newTestCore(t))
		require.NoError(t, err)
		var srv *httptest.Server
		if directTLS {
			srv = httptest.NewTLSServer(router)
		} else {
			srv = httptest.NewServer(router)
		}
		t.Cleanup(srv.Close)
		return srv
	}
	get := func(t *testing.T, srv *httptest.Server, xfp string) []string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
		require.NoError(t, err)
		if xfp != "" {
			req.Header.Set("X-Forwarded-Proto", xfp)
		}
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.Header.Values("Strict-Transport-Security")
	}

	t.Run("direct TLS, tls.enabled unset", func(t *testing.T) {
		assert.Equal(t, []string{want}, get(t, start(t, nil, true), ""))
	})
	t.Run("trusted proxy, X-Forwarded-Proto https", func(t *testing.T) {
		assert.Equal(t, []string{want}, get(t, start(t, []string{"127.0.0.1"}, false), "https"))
	})
	t.Run("trusted proxy, X-Forwarded-Proto http", func(t *testing.T) {
		assert.Empty(t, get(t, start(t, []string{"127.0.0.1"}, false), "http"))
	})
	t.Run("untrusted peer forges X-Forwarded-Proto https", func(t *testing.T) {
		assert.Empty(t, get(t, start(t, []string{"10.0.0.0/8"}, false), "https"))
	})
	t.Run("no trusted proxies, peer forges X-Forwarded-Proto https", func(t *testing.T) {
		assert.Empty(t, get(t, start(t, nil, false), "https"))
	})
	t.Run("plain http, no header", func(t *testing.T) {
		assert.Empty(t, get(t, start(t, []string{"127.0.0.1"}, false), ""))
	})
}
