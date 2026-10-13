package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// cookieShape is everything about a Set-Cookie except its (random) value.
type cookieShape struct {
	Name     string
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
	Path     string
	Clearing bool
}

// manualJar replays cookies the way a browser on the client's side of the
// load balancer would: unlike net/http/cookiejar it also sends Secure cookies back
// over this plain-http test server, because the browser's connection to the LB IS https.
type manualJar map[string]string

func (j manualJar) absorb(cs []*http.Cookie) {
	for _, c := range cs {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j, c.Name)
			continue
		}
		j[c.Name] = c.Value
	}
}

// cookieFlows drives login, refresh, impersonation begin/end and logout through the
// production router and returns, per flow, the shape of every Set-Cookie it sent.
func cookieFlows(t *testing.T, cfg *config.Config, directTLS bool, xfp string) map[string][]cookieShape {
	t.Helper()
	testCore := newTestCore(t)
	_ = createTestToken(t, testCore) // seeds testadmin
	target, err := testCore.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "target-cookie-secure", Email: "target-cookie-secure@example.com", Password: "CorrectHorseBattery9!",
	})
	require.NoError(t, err)

	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	var srv *httptest.Server
	if directTLS {
		srv = httptest.NewTLSServer(router)
	} else {
		srv = httptest.NewServer(router)
	}
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = 5 * time.Second

	jar := manualJar{}
	out := map[string][]cookieShape{}
	do := func(flow, path string, body []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		require.NoError(t, err)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if xfp != "" {
			req.Header.Set("X-Forwarded-Proto", xfp)
		}
		for n, v := range jar {
			req.AddCookie(&http.Cookie{Name: n, Value: v})
		}
		if csrf, ok := jar[middleware.CSRFCookieName]; ok {
			req.Header.Set(middleware.CSRFHeaderName, csrf)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, flow)
		cs := resp.Cookies()
		jar.absorb(cs)
		for _, c := range cs {
			out[flow] = append(out[flow], cookieShape{
				Name: c.Name, Secure: c.Secure, HttpOnly: c.HttpOnly,
				SameSite: c.SameSite, Path: c.Path, Clearing: c.MaxAge < 0,
			})
		}
	}

	login, err := json.Marshal(map[string]string{"username": "testadmin", "password": "TestPassword123!"})
	require.NoError(t, err)
	start, err := json.Marshal(map[string]uint{"user_id": target.ID})
	require.NoError(t, err)

	do("login", "/auth/login", login)
	do("refresh", "/auth/refresh", nil)
	do("impersonation begin", "/api/v1/admin/impersonate", start)
	do("impersonation end", "/api/v1/auth/end-impersonation", nil)
	do("logout", "/auth/logout", nil)
	return out
}

// COOKIE-SECURE-1: the Secure flag of every cookie the server sets follows the same
// "request is effectively https" decision as HSTS (middleware.RequestIsHTTPS).
func TestSessionCookies_SecureBehindTrustedProxy(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	newCfg := func(trusted []string, tlsEnabled bool) *config.Config {
		cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{
			Enabled: true, Port: "8080", TrustedProxies: trusted, TLS: config.TLSConfig{Enabled: tlsEnabled},
		}}}
		return cfg
	}

	cases := []struct {
		name       string
		trusted    []string
		tlsEnabled bool
		directTLS  bool
		xfp        string
		wantSecure bool
	}{
		{"trusted proxy, https", []string{"127.0.0.1"}, false, false, "https", true},
		{"trusted proxy, http", []string{"127.0.0.1"}, false, false, "http", false},
		{"trusted proxy, no X-Forwarded-Proto", []string{"127.0.0.1"}, false, false, "", false},
		{"untrusted peer forges https", []string{"10.0.0.0/8"}, false, false, "https", false},
		{"no trusted proxies, peer forges https", nil, false, false, "https", false},
		{"plain http, nothing configured", nil, false, false, "", false},
		{"direct TLS, tls.enabled unset", nil, false, true, "", true},
		{"tls.enabled", nil, true, false, "", true},
	}
	// Per-flow cookie names every flow must produce, so a flow that silently stops
	// setting a cookie cannot make the Secure assertions below vacuous.
	wantNames := map[string][]string{
		"login":               {middleware.SessionCookieName, middleware.CSRFCookieName},
		"refresh":             {middleware.SessionCookieName, middleware.CSRFCookieName},
		"impersonation begin": {middleware.SessionCookieName, middleware.AdminSessionCookieName, middleware.CSRFCookieName},
		"impersonation end":   {middleware.AdminSessionCookieName, middleware.SessionCookieName, middleware.CSRFCookieName},
		"logout":              {middleware.SessionCookieName, middleware.CSRFCookieName},
	}

	var plainHTTP map[string][]cookieShape
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cookieFlows(t, newCfg(c.trusted, c.tlsEnabled), c.directTLS, c.xfp)
			if c.name == "plain http, nothing configured" {
				plainHTTP = got
			}
			for flow, names := range wantNames {
				var gotNames []string
				for _, sh := range got[flow] {
					gotNames = append(gotNames, sh.Name)
					assert.Equal(t, c.wantSecure, sh.Secure, "%s: %s Secure", flow, sh.Name)
				}
				assert.ElementsMatch(t, names, gotNames, "%s: cookies set", flow)
			}
		})
	}

	// A forged header from an untrusted peer must be indistinguishable from plain
	// http: same cookies, same attributes (including Secure=false), nothing else moves.
	t.Run("forged header changes nothing versus plain http", func(t *testing.T) {
		require.NotNil(t, plainHTTP, "plain-http baseline case must run first")
		forged := cookieFlows(t, newCfg([]string{"10.0.0.0/8"}, false), false, "https")
		assert.Equal(t, plainHTTP, forged)
	})
}
