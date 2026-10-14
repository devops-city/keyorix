package k8ssync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHealth_LivenessAlwaysOK(t *testing.T) {
	h := NewStatus().Handler()
	rec := get(t, h, "/healthz")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHealth_ReadinessGatesOnFirstSync(t *testing.T) {
	s := NewStatus()
	h := s.Handler()

	// Before any reconcile: not ready.
	assert.Equal(t, http.StatusServiceUnavailable, get(t, h, "/readyz").Code)

	// After a pass completes: ready.
	s.Record(Result{Created: 2})
	assert.Equal(t, http.StatusOK, get(t, h, "/readyz").Code)
}

func TestHealth_MetricsExposition(t *testing.T) {
	s := NewStatus()
	h := s.Handler()

	// Two passes accumulate into the counters; the gauge reflects the last pass.
	s.Record(Result{Created: 1, Updated: 0, Unchanged: 2, Failed: 0})
	s.Record(Result{Created: 0, Updated: 3, Unchanged: 2, Failed: 1})

	body := get(t, h, "/metrics").Body.String()
	assert.Contains(t, body, "keyorix_k8s_sync_reconcile_passes_total 2")
	assert.Contains(t, body, `keyorix_k8s_sync_secrets_total{outcome="created"} 1`)
	assert.Contains(t, body, `keyorix_k8s_sync_secrets_total{outcome="updated"} 3`)
	assert.Contains(t, body, `keyorix_k8s_sync_secrets_total{outcome="unchanged"} 4`)
	assert.Contains(t, body, `keyorix_k8s_sync_secrets_total{outcome="failed"} 1`)
	assert.Contains(t, body, "keyorix_k8s_sync_last_failed 1")
	// Well-formed exposition: every metric has a HELP and TYPE line.
	assert.Contains(t, body, "# TYPE keyorix_k8s_sync_reconcile_passes_total counter")
}

func TestHealth_MetricsBeforeFirstRun(t *testing.T) {
	body := get(t, NewStatus().Handler(), "/metrics").Body.String()
	assert.Contains(t, body, "keyorix_k8s_sync_reconcile_passes_total 0")
	assert.Contains(t, body, "keyorix_k8s_sync_last_run_timestamp_seconds 0")
}

// ---- HandlerWithToken: /metrics bearer-token gate ----

func getWithAuth(t *testing.T, h http.Handler, path, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerWithToken_EmptyTokenLeavesMetricsUnauthenticated(t *testing.T) {
	h := NewStatus().HandlerWithToken("")
	assert.Equal(t, http.StatusOK, get(t, h, "/metrics").Code)
}

func TestHandlerWithToken_MetricsRejectsMissingHeader(t *testing.T) {
	h := NewStatus().HandlerWithToken("s3cr3t")
	assert.Equal(t, http.StatusUnauthorized, get(t, h, "/metrics").Code)
}

func TestHandlerWithToken_MetricsRejectsWrongToken(t *testing.T) {
	h := NewStatus().HandlerWithToken("s3cr3t")
	rec := getWithAuth(t, h, "/metrics", "Bearer wrong")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandlerWithToken_MetricsAcceptsMatchingToken(t *testing.T) {
	s := NewStatus()
	s.Record(Result{Created: 1})
	h := s.HandlerWithToken("s3cr3t")
	rec := getWithAuth(t, h, "/metrics", "Bearer s3cr3t")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "keyorix_k8s_sync_reconcile_passes_total 1")
}

// The probe endpoints must stay reachable without any Authorization header even when
// a metrics token is configured -- kubelet has no way to supply one, and none of these
// three expose secret values (only counts, a timestamp, and an error count).
func TestHandlerWithToken_ProbeEndpointsStayUnauthenticated(t *testing.T) {
	s := NewStatus()
	s.Record(Result{Created: 1})
	h := s.HandlerWithToken("s3cr3t")

	assert.Equal(t, http.StatusOK, get(t, h, "/healthz").Code)
	assert.Equal(t, http.StatusOK, get(t, h, "/readyz").Code)
	assert.Equal(t, http.StatusOK, get(t, h, "/status").Code)
}

func TestHealth_StatusReportsCounts(t *testing.T) {
	s := NewStatus()
	h := s.Handler()

	// Before a run.
	var before map[string]any
	require.NoError(t, json.Unmarshal(get(t, h, "/status").Body.Bytes(), &before))
	assert.Equal(t, false, before["ran"])
	_, hasLastRun := before["last_run"]
	assert.False(t, hasLastRun, "no last_run before the first pass")

	// After a run with mixed outcomes.
	s.Record(Result{Created: 1, Updated: 2, Unchanged: 3, Failed: 1, Errors: []string{"app/x: boom"}})
	var after map[string]any
	require.NoError(t, json.Unmarshal(get(t, h, "/status").Body.Bytes(), &after))
	assert.Equal(t, true, after["ran"])
	assert.EqualValues(t, 1, after["created"])
	assert.EqualValues(t, 2, after["updated"])
	assert.EqualValues(t, 3, after["unchanged"])
	assert.EqualValues(t, 1, after["failed"])
	assert.EqualValues(t, 1, after["errors"], "error count, not the messages")
	assert.Contains(t, after, "last_run")
}
