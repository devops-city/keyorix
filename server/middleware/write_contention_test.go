package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serve runs WriteContention around a handler and returns the recorded response.
func serveWriteContention(path string, h http.HandlerFunc) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	WriteContention(h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	return rec
}

// internalError mimics a handler's generic failure (sendError shape).
func internalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "999")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":"InternalError","message":"Failed to create group"}`))
}

func TestWriteContention_RewritesInternalErrorAfterGateTimeout(t *testing.T) {
	rec := serveWriteContention("/api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		corestorage.NoteWriteContention(r.Context())
		internalError(w)
	})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "5", rec.Header().Get("Retry-After"))
	assert.Empty(t, rec.Header().Get("Content-Length"), "the 500's Content-Length must not survive")
	assert.JSONEq(t, `{"success":false,"error":"ServiceUnavailable","message":"The service is temporarily busy. Please retry shortly.","code":503}`, rec.Body.String())
	assert.NotContains(t, strings.ToLower(rec.Body.String()), "failed to create group", "the handler's own body must be replaced")
}

func TestWriteContention_LeavesEverythingElseAlone(t *testing.T) {
	t.Run("500 with no gate timeout", func(t *testing.T) {
		rec := serveWriteContention("/api/v1/groups", func(w http.ResponseWriter, r *http.Request) { internalError(w) })
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Empty(t, rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Body.String(), "Failed to create group")
	})
	for _, code := range []int{http.StatusOK, http.StatusNotFound, http.StatusConflict, http.StatusBadGateway} {
		t.Run(http.StatusText(code)+" after a swallowed gate timeout", func(t *testing.T) {
			rec := serveWriteContention("/api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
				corestorage.NoteWriteContention(r.Context())
				w.WriteHeader(code)
				_, _ = w.Write([]byte("handler body"))
			})
			assert.Equal(t, code, rec.Code, "only a plain 500 is converted")
			assert.Empty(t, rec.Header().Get("Retry-After"))
			assert.Equal(t, "handler body", rec.Body.String())
		})
	}
	t.Run("implicit 200 via Write", func(t *testing.T) {
		rec := serveWriteContention("/api/v1/x", func(w http.ResponseWriter, r *http.Request) {
			corestorage.NoteWriteContention(r.Context())
			_, _ = w.Write([]byte("ok"))
		})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
	})
}

// The credential surface is exempt: a storage failure after a credential matched
// must keep looking like a wrong credential (#2740 option C / #2888), never a
// distinguishable 503.
func TestWriteContention_CredentialSurfaceIsExempt(t *testing.T) {
	for _, path := range []string{"/auth/login", "/auth/mfa/verify", "/auth/webauthn/login/finish", "/auth/setup/consume", "/auth/password-reset"} {
		rec := serveWriteContention(path, func(w http.ResponseWriter, r *http.Request) {
			assert.Nil(t, corestorage.ContentionSignalFrom(r.Context()), "no signal is installed on the credential surface")
			corestorage.NoteWriteContention(r.Context()) // no-op without a signal
			internalError(w)
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code, path)
		assert.Empty(t, rec.Header().Get("Retry-After"), path)
	}
}

func TestWriteContention_PassesFlushThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteContention(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		require.True(t, ok, "wrapped writer must still be a Flusher")
		_, _ = w.Write([]byte("chunk"))
		f.Flush()
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil))
	assert.True(t, rec.Flushed)
}
