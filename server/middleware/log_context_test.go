package middleware

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/logging"
)

func TestLogContext_UsesCleanedCallerIDOrMintsOne(t *testing.T) {
	var seen logging.Fields
	var headerSeenByNext string
	h := LogContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = logging.FromContext(r.Context())
		headerSeenByNext = r.Header.Get(RequestIDHeader)
	}))

	t.Run("caller id kept and echoed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set(RequestIDHeader, "client-abc-123")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, "client-abc-123", seen.RequestID)
		assert.Equal(t, "client-abc-123", rec.Header().Get(RequestIDHeader))
		assert.Equal(t, "client-abc-123", headerSeenByNext, "downstream (chi RequestID) must adopt the same id")
		assert.Equal(t, logging.PrincipalAnonymous, seen.PrincipalType)
	})

	t.Run("hostile id cleaned", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set(RequestIDHeader, "a\x1b[31mb"+strings.Repeat("z", 400))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.NotContains(t, seen.RequestID, "\x1b")
		assert.LessOrEqual(t, len(seen.RequestID), 128)
	})

	t.Run("missing id minted", func(t *testing.T) {
		rec1, rec2 := httptest.NewRecorder(), httptest.NewRecorder()
		h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/x", nil))
		first := seen.RequestID
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/x", nil))
		assert.Len(t, first, 24)
		assert.NotEqual(t, first, seen.RequestID, "ids are unique per request")
	})
}

// TestBuildRequestContext_SetsPrincipalType: the shared holder learns who authenticated.
func TestBuildRequestContext_SetsPrincipalType(t *testing.T) {
	mid := uint(7)
	for _, tc := range []struct {
		name string
		uc   *UserContext
		want string
	}{
		{"nil user", nil, logging.PrincipalAnonymous},
		{"human", &UserContext{UserID: 1}, logging.PrincipalUser},
		{"machine", &UserContext{MachineIdentityID: &mid}, logging.PrincipalMachine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, h := logging.WithHolder(t.Context())
			h.SetPrincipalType(logging.PrincipalAnonymous)
			_ = buildRequestContext(ctx, tc.uc, nil)
			assert.Equal(t, tc.want, h.Snapshot().PrincipalType)
		})
	}
}

// TestJSONAccessLog_CarriesRequestFields drives Logger() in JSON mode through a chi
// router: one JSON object per request with the chi route pattern (not the raw path),
// the request id, the principal type set later in the chain, and a redacted URI.
func TestJSONAccessLog_CarriesRequestFields(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
		require.NoError(t, logging.Setup(logging.FormatText, &buf))
	})
	require.NoError(t, logging.Setup(logging.FormatJSON, &buf))

	r := chi.NewRouter()
	r.Use(LogContext)
	r.Use(Logger())
	r.Get("/api/v1/secrets/{id}", func(w http.ResponseWriter, req *http.Request) {
		if h := logging.HolderFrom(req.Context()); h != nil {
			h.SetPrincipalType(logging.PrincipalMachine) // what buildRequestContext does after auth
		}
		w.WriteHeader(http.StatusTeapot)
	})
	r.Get("/auth/setup/{token}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/42?x=1", nil)
	req.Header.Set(RequestIDHeader, "rid-777")
	r.ServeHTTP(httptest.NewRecorder(), req)
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/setup/SETUPTOKENSHOULDNOTLEAK", nil))
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nope", nil))

	var recs []map[string]any
	for l := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &m), l)
		recs = append(recs, m)
	}
	require.Len(t, recs, 3)

	got := recs[0]
	assert.Equal(t, "http request", got["msg"])
	assert.Equal(t, "rid-777", got["request_id"])
	assert.Equal(t, "machine_identity", got["principal_type"])
	assert.Equal(t, "/api/v1/secrets/{id}", got["route"], "route is the pattern, not /api/v1/secrets/42")
	assert.EqualValues(t, http.StatusTeapot, got["status"])
	assert.Equal(t, "GET", got["method"])
	assert.NotNil(t, got["duration_ms"])

	assert.NotContains(t, buf.String(), "SETUPTOKENSHOULDNOTLEAK", "the redaction the text log has also applies here")
	assert.Equal(t, "unmatched", recs[2]["route"])
	assert.Equal(t, "anonymous", recs[2]["principal_type"])
}
