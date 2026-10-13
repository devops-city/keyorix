package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func serve(t *testing.T, tlsEnabled bool) http.Header {
	t.Helper()
	h := SecurityHeaders(tlsEnabled, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Header()
}

func TestSecurityHeaders_AlwaysSet(t *testing.T) {
	hdr := serve(t, false)
	assert.Equal(t, "nosniff", hdr.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", hdr.Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", hdr.Get("Referrer-Policy"))
	assert.Equal(t, "none", hdr.Get("X-Permitted-Cross-Domain-Policies"))
	// HSTS is NOT sent over plain HTTP (TLS terminated elsewhere or not at all).
	assert.Empty(t, hdr.Get("Strict-Transport-Security"))
}

// #112: CSP must be sent in the single-binary/embedded-SPA serving mode too — it
// previously had none at all (only the separate Helm nginx frontend sent one).
func TestSecurityHeaders_CSPAlwaysSet(t *testing.T) {
	hdr := serve(t, false)
	csp := hdr.Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self'", "no unsafe-inline/unsafe-eval on scripts — the primary XSS vector")
	assert.NotContains(t, csp, "script-src 'self' 'unsafe-inline'")
	// DAST #1211: directives that don't fall back to default-src must be explicit.
	assert.Contains(t, csp, "form-action 'self'")
	assert.Contains(t, csp, "base-uri 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Contains(t, csp, "object-src 'none'")
	// DAST #1212: no https: scheme wildcard in img-src.
	assert.NotContains(t, csp, "img-src 'self' data: https:")
	assert.Contains(t, csp, "img-src 'self' data:")
}

func TestSecurityHeaders_HSTSOnlyWithTLS(t *testing.T) {
	hdr := serve(t, true)
	// No preload unless the operator opts in (TestSecurityHeaders_HSTSPreloadOptIn).
	assert.Equal(t, "max-age=31536000; includeSubDomains", hdr.Get("Strict-Transport-Security"))
}

// DAST #1209 (ZAP/90004): Cross-Origin-Resource-Policy must be set on every response
// to counter Spectre-style cross-origin side-channel attacks.
func TestSecurityHeaders_CORPAlwaysSet(t *testing.T) {
	hdr := serve(t, false)
	assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Resource-Policy"))
}

// DAST #1209 / #1214 / #1215: all three Cross-Origin-* headers must be present.
func TestSecurityHeaders_CrossOriginHeadersAlwaysSet(t *testing.T) {
	hdr := serve(t, false)
	assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Resource-Policy"))
	assert.Equal(t, "require-corp", hdr.Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Opener-Policy"))
}
