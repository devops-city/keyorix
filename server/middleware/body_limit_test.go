package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readBody runs a request with the given body through MaxBodyBytes(limit) and reports
// what the handler read and whether the read errored. The body's length is not
// declared (ContentLength -1, as for a chunked upload), so this exercises the
// MaxBytesReader layer; a declared oversize length is refused before the handler
// (TestMaxBodyBytes_DeclaredOversizeRefusedBeforeHandler).
func readBody(t *testing.T, limit int64, body string) (string, error) {
	t.Helper()
	var got []byte
	var readErr error
	h := MaxBodyBytes(limit)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, readErr = io.ReadAll(r.Body)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.ContentLength = -1
	h.ServeHTTP(httptest.NewRecorder(), req)
	return string(got), readErr
}

func TestMaxBodyBytes_RejectsOversize(t *testing.T) {
	_, err := readBody(t, 10, strings.Repeat("x", 50)) // 50 bytes, cap 10
	require.Error(t, err, "reading past the cap fails")
	assert.Contains(t, err.Error(), "too large")
}

func TestMaxBodyBytes_AllowsUnderLimit(t *testing.T) {
	got, err := readBody(t, 100, "small payload")
	require.NoError(t, err)
	assert.Equal(t, "small payload", got)
}

func TestMaxBodyBytes_AtLimitOK(t *testing.T) {
	got, err := readBody(t, 5, "12345") // exactly at the cap
	require.NoError(t, err)
	assert.Equal(t, "12345", got)
}

func TestMaxBodyBytes_DisabledWhenNonPositive(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		got, err := readBody(t, limit, strings.Repeat("y", 1000))
		require.NoError(t, err, "limit %d disables the cap", limit)
		assert.Len(t, got, 1000)
	}
}

// TestMaxBodyBytes_DeclaredOversizeRefusedBeforeHandler: a Content-Length over the
// cap is answered 413 with the JSON error body and the connection marked for close,
// and the handler never runs. Before, the handler ran and its decode error became
// whatever that handler reports (mostly a generic 400).
func TestMaxBodyBytes_DeclaredOversizeRefusedBeforeHandler(t *testing.T) {
	ran := false
	h := MaxBodyBytes(10)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 11))))

	assert.False(t, ran, "handler must not run for a declared-oversize body")
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "close", w.Header().Get("Connection"))
	assert.JSONEq(t, `{"success":false,"error":"PayloadTooLarge","message":"request body too large","code":413}`, w.Body.String())

	// At the cap is served.
	ran = false
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 10))))
	assert.True(t, ran)
}

// TestMaxBodyBytesFor_PerRequestCap: the cap is chosen per request.
func TestMaxBodyBytesFor_PerRequestCap(t *testing.T) {
	h := MaxBodyBytesFor(func(r *http.Request) int64 {
		if r.URL.Path == "/small" {
			return 4
		}
		return 100
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for path, want := range map[string]int{"/small": http.StatusRequestEntityTooLarge, "/big": http.StatusNoContent} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader("12345")))
		assert.Equal(t, want, w.Code, path)
	}
}
