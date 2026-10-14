package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestHealthCheck(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	HealthCheck(w, req)

	// Before any assertion below consumes w.Body via a Decoder.
	contracttest.AssertOpenAPIResponse(t, req, w)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))

	// Liveness signal + the keys the probe/consumers rely on.
	assert.Equal(t, "healthy", body["status"])
	assert.Contains(t, body, "timestamp")
	assert.Contains(t, body, "uptime")
	// version/commit are deliberately NOT disclosed on the unauthenticated /health
	// (CVE-targeting); they live on the system.read-gated /api/v1/system/info.
	assert.NotContains(t, body, "version")
	assert.NotContains(t, body, "commit")

	// The old handler fabricated dependency health (always "healthy" db/storage/
	// encryption) — that lie is gone. Liveness must not claim DB health (see /readyz).
	assert.NotContains(t, body, "checks")
	assert.NotContains(t, w.Body.String(), "free_space")
}
