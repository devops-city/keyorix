package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /system/info carries security.audit_reads_skipped (ADR-112 Amendment 4),
// false by default, so an auditor and the web UI banner can see it over the API.
func TestMakeSystemInfoHandler_ReportsAuditReadsSkipped(t *testing.T) {
	for _, on := range []bool{false, true} {
		cfg := &config.Config{}
		cfg.Storage.Type = "local"
		cfg.Storage.Database.InsecureAuditSkipReads = on

		rr := httptest.NewRecorder()
		MakeSystemInfoHandler(cfg, freshCoreS12(t))(rr,
			userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)))
		require.Equal(t, http.StatusOK, rr.Code)

		var resp map[string]any
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
		security := resp["data"].(map[string]any)["security"].(map[string]any)
		got, present := security["audit_reads_skipped"]
		require.True(t, present, "audit_reads_skipped must always be present, also when false")
		assert.Equal(t, on, got)
	}
}

// security.audit_owed (SUSPEND-AUDIT-LOUD) is for system.write callers only, like
// recovery_key: a caller without it never gets the field.
func TestMakeSystemInfoHandler_AuditOwedOnlyForSystemWrite(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg, freshCoreS12(t))(rr,
		userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)))
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	security := resp["data"].(map[string]any)["security"].(map[string]any)
	_, present := security["audit_owed"]
	assert.False(t, present, "audit_owed must be absent for a caller without system.write")
}
