package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecovery_DoesNotLeakInternals is the security invariant: a panic returns an opaque
// 500 and the response body never carries the panic value, a stack trace, or other
// internals to the client (this is a secrets manager — operators read the logs instead).
func TestRecovery_DoesNotLeakInternals(t *testing.T) {
	const sensitive = "super-secret-token-do-not-leak"
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: " + sensitive)
	})

	rec := httptest.NewRecorder()
	Recovery()(panicking).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	body := rec.Body.String()
	assert.NotContains(t, body, sensitive, "the panic value must never reach the client")
	for _, leak := range []string{"stack", "goroutine", "runtime.", ".go:", "boom"} {
		assert.NotContains(t, body, leak, "response must not leak internals (%q)", leak)
	}

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "InternalServerError", resp["error"])
	assert.NotContains(t, resp, "details", "no details field is ever returned")
}

// TestRecovery_PassesThroughNonPanic confirms the middleware is transparent on the happy
// path.
func TestRecovery_PassesThroughNonPanic(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rec := httptest.NewRecorder()
	Recovery()(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", strings.TrimSpace(rec.Body.String()))
}

// TestRecovery_RedactsSetupTokenInPanicContextLog is #G29 (high + low): the
// PANIC CONTEXT log line used to write r.URL.Path raw, bypassing logger.go's
// redaction entirely — a panic mid-request to GET /auth/setup/{token} would
// write that single-use bearer credential straight to the panic log.
func TestRecovery_RedactsSetupTokenInPanicContextLog(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const token = "panicPathMustNotLeakThisSetupToken456"
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	Recovery()(panicking).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/setup/"+token, nil))

	logged := buf.String()
	assert.NotContains(t, logged, token, "the setup token must never reach the panic-context log")
	assert.Contains(t, logged, "[REDACTED]")
}

// brokenResponseWriter is an http.ResponseWriter whose Write always fails,
// simulating a client that disconnects (or a broken transport) right as the
// panic-recovery response is being written.
type brokenResponseWriter struct {
	header http.Header
}

func (b *brokenResponseWriter) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}

func (b *brokenResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func (b *brokenResponseWriter) WriteHeader(int) {}

// TestRecovery_LogsWhenResponseEncodingFails covers the fallback branch taken
// when json.Encode of the panic response itself fails to write (e.g. the
// client already disconnected): Recovery must not panic itself, and must log
// the encode failure rather than silently dropping it.
func TestRecovery_LogsWhenResponseEncodingFails(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	w := &brokenResponseWriter{}

	require.NotPanics(t, func() {
		Recovery()(panicking).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil))
	})

	assert.Contains(t, buf.String(), "Failed to encode panic response")
}

// TestRecovery_RedactsSSOCallbackQueryInPanicContextLog covers the same gap
// for the OAuth/OIDC SSO callback's authorization code.
func TestRecovery_RedactsSSOCallbackQueryInPanicContextLog(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const code = "panicPathMustNotLeakThisOAuthCode789"
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/okta/callback?code="+code+"&state=xyz", nil)
	Recovery()(panicking).ServeHTTP(rec, req)

	logged := buf.String()
	assert.NotContains(t, logged, code, "the OAuth authorization code must never reach the panic-context log")
	assert.Contains(t, logged, "[redacted]")
}
