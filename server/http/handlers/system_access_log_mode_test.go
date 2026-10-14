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

// GET /system/info carries the effective server.access_log.on_sink_stall and the
// dropped-line counter, so a drop is never silent: default "block", "drop" when
// configured, and the counter always present.
func TestMakeSystemInfoHandler_AccessLogStallModeReflectsConfig(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"", "block"},
		{"block", "block"},
		{"drop", "drop"},
	} {
		cfg := &config.Config{}
		cfg.Server.AccessLog.OnSinkStall = tc.configured
		rr := httptest.NewRecorder()
		MakeSystemInfoHandler(cfg, freshCoreS12(t))(rr,
			userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)))
		require.Equal(t, http.StatusOK, rr.Code)

		var resp map[string]interface{}
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
		security := resp["data"].(map[string]interface{})["security"].(map[string]interface{})
		assert.Equal(t, tc.want, security["access_log_on_sink_stall"], "configured %q", tc.configured)
		dropped, present := security["access_log_dropped"]
		require.True(t, present, "access_log_dropped must always be present")
		assert.IsType(t, float64(0), dropped)
	}
}
