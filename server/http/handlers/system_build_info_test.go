package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /system/info must report the stamped build identity: the CLI's `system info` and the web
// footer read version, git_commit and build_time from here (#3143). build_time used to be a
// hard-coded "unknown" even for a stamped image.
func TestMakeSystemInfoHandler_ReportsStampedBuildIdentity(t *testing.T) {
	oldV, oldC, oldB := version.Version, version.Commit, version.BuildDate
	t.Cleanup(func() { version.Version, version.Commit, version.BuildDate = oldV, oldC, oldB })
	version.Version, version.Commit, version.BuildDate = "v9.9.9", "abc1234", "2026-10-13T01:02:03Z"

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(&config.Config{}, freshCoreS12(t))(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "v9.9.9", resp.Data["version"])
	assert.Equal(t, "abc1234", resp.Data["git_commit"])
	assert.Equal(t, "2026-10-13T01:02:03Z", resp.Data["build_time"])
}
