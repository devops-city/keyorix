package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// hstsThroughChain drives ClientIP then SecurityHeaders, the order router.go wires
// them in, and returns the Strict-Transport-Security values the response carries.
func hstsThroughChain(t *testing.T, trusted []string, tlsEnabled bool, req *http.Request) []string {
	t.Helper()
	h := ClientIP(trusted)(SecurityHeaders(tlsEnabled, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Header().Values("Strict-Transport-Security")
}

func hstsReq(peer string, xfp ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.RemoteAddr = peer
	for _, v := range xfp {
		r.Header.Add("X-Forwarded-Proto", v)
	}
	return r
}

// HSTS-LB-1: behind a TLS-terminating load balancer the backend sends HSTS only on
// the word of a configured trusted proxy, using ClientIP's own trust decision.
func TestSecurityHeaders_HSTSBehindTrustedProxy(t *testing.T) {
	const lb = "10.0.0.5:41000"
	const attacker = "203.0.113.7:51000"
	trusted := []string{"10.0.0.0/24"}
	want := []string{"max-age=31536000; includeSubDomains"}

	cases := []struct {
		name       string
		trusted    []string
		tlsEnabled bool
		req        func() *http.Request
		want       []string
	}{
		{"direct TLS (r.TLS set), no proxy config", nil, false, func() *http.Request {
			r := hstsReq(attacker)
			r.TLS = &tls.ConnectionState{}
			return r
		}, want},
		{"direct TLS listener (tls.enabled)", nil, true, func() *http.Request { return hstsReq(attacker) }, want},
		{"trusted proxy says https", trusted, false, func() *http.Request { return hstsReq(lb, "https") }, want},
		{"trusted proxy says HTTPS (case-insensitive)", trusted, false, func() *http.Request { return hstsReq(lb, "HTTPS") }, want},
		{"trusted proxy says http", trusted, false, func() *http.Request { return hstsReq(lb, "http") }, nil},
		{"trusted proxy, no X-Forwarded-Proto", trusted, false, func() *http.Request { return hstsReq(lb) }, nil},
		{"trusted proxy, junk X-Forwarded-Proto", trusted, false, func() *http.Request { return hstsReq(lb, "https-ish") }, nil},
		{"untrusted peer forges https", trusted, false, func() *http.Request { return hstsReq(attacker, "https") }, nil},
		{"no trusted proxies configured, peer forges https", nil, false, func() *http.Request { return hstsReq(lb, "https") }, nil},
		// A proxy that appends instead of overwriting: the client's forged value comes
		// first, the trusted proxy's own value last, and the last one decides.
		{"trusted proxy appends http after client's forged https (one line)", trusted, false, func() *http.Request { return hstsReq(lb, "https, http") }, nil},
		{"trusted proxy appends http after client's forged https (two lines)", trusted, false, func() *http.Request { return hstsReq(lb, "https", "http") }, nil},
		{"trusted proxy appends https after client's http", trusted, false, func() *http.Request { return hstsReq(lb, "http", "https") }, want},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, hstsThroughChain(t, c.trusted, c.tlsEnabled, c.req()))
		})
	}
}

// Without ClientIP in front, nothing marks the request, so a forged header from any
// peer cannot turn HSTS on: the order dependency fails closed.
func TestSecurityHeaders_HSTSWithoutClientIPIgnoresForwardedProto(t *testing.T) {
	h := SecurityHeaders(false, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, hstsReq("10.0.0.5:41000", "https"))
	assert.Empty(t, rec.Header().Values("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTSPreloadOptIn(t *testing.T) {
	h := SecurityHeaders(true, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, "max-age=31536000; includeSubDomains; preload", rec.Header().Get("Strict-Transport-Security"))
}
