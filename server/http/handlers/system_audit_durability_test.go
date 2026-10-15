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

// TestMakeSystemInfoHandler_ReportsEffectiveAuditDurability: GET
// /system/info carries the EFFECTIVE storage.database.audit_durability
// (ADR-112 Amendment 3) -- the backend default when nothing is written
// (standard on PostgreSQL, strict on SQLite), the explicit level or the
// deprecated alias's mapping otherwise -- so an auditor can read it without
// host access. The old audit_durable_sync_skipped boolean is gone.
func TestMakeSystemInfoHandler_ReportsEffectiveAuditDurability(t *testing.T) {
	strictVal, trueVal := "strict", true
	cases := []struct {
		name        string
		storageType string
		level       *string
		alias       *bool
		want        string
	}{
		{"postgres default", "postgres", nil, nil, "standard"},
		{"postgres strict", "postgres", &strictVal, nil, "strict"},
		{"postgres deprecated alias true", "postgres", nil, &trueVal, "standard"},
		{"sqlite default", "local", nil, nil, "strict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Storage.Type = tc.storageType
			if tc.level != nil {
				cfg.Storage.Database.AuditDurability = *tc.level
			}
			cfg.Storage.Database.InsecureAuditSkipDurableSync = tc.alias

			rr := httptest.NewRecorder()
			MakeSystemInfoHandler(cfg, freshCoreS12(t))(rr,
				userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)))
			require.Equal(t, http.StatusOK, rr.Code)

			var resp map[string]any
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
			security := resp["data"].(map[string]any)["security"].(map[string]any)
			assert.Equal(t, tc.want, security["audit_durability"])
			_, old := security["audit_durable_sync_skipped"]
			assert.False(t, old, "the Amendment 1 boolean is replaced by audit_durability")
		})
	}
}
