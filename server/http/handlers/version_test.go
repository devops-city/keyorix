package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestVersionHandler_ExposesOnlySkewFields(t *testing.T) {
	cfg := &config.Config{MinimumCLIVersion: "1.2.0"}
	handler := MakeVersionHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	// Before any assertion below consumes w.Body via a Decoder.
	contracttest.AssertOpenAPIResponse(t, req, w)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))

	assert.Equal(t, float64(1), body["api_version"])
	assert.Equal(t, "1.2.0", body["minimum_cli_version"])

	// This is the whole point of a dedicated endpoint (see VersionInfo's doc comment):
	// never disclose the build version or commit here, same rationale as /health.
	assert.NotContains(t, body, "version")
	assert.NotContains(t, body, "commit")
	assert.NotContains(t, body, "build_time")
	assert.NotContains(t, body, "git_commit")

	// Exactly the two documented fields -- nothing extra leaked in.
	assert.Len(t, body, 2)
}

func TestVersionHandler_EmptyMinimumMeansNoFloor(t *testing.T) {
	cfg := &config.Config{}
	handler := MakeVersionHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "", body["minimum_cli_version"])
}
