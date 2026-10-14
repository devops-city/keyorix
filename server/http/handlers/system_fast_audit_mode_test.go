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

// TestMakeSystemInfoHandler_AuditDurableSyncSkippedReflectsConfig exercises
// ADR-112 Amendment 1's API-visibility requirement (FASTAUDIT-1,
// docs/specs/fast-audit-mode.md): the fast audit mode must be readable from
// GET /system/info, so "is this install still committing audit durably before
// disclosing a secret?" is answerable by a buyer's auditor WITHOUT host
// access -- and it must default to false, never a silent true.
//
// Same shape as TestMakeSystemInfoHandler_KeylessRecoveryModeReflectsConfig
// (system_test.go) deliberately: this is the same category of setting with
// the same four flagging requirements, so it gets the same guard.
func TestMakeSystemInfoHandler_AuditDurableSyncSkippedReflectsConfig(t *testing.T) {
	cfg := &config.Config{}
	// Postgres: the ONE backend where the mode is in effect (Andrei's
	// decision, 2026-10-05 -- SQLite refuses to start, remote reports it
	// ignored). Setting the bool without the backend would assert a state no
	// deployment can reach.
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.InsecureAuditSkipDurableSync = true

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg, freshCoreS12(t))(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	security := resp["data"].(map[string]any)["security"].(map[string]any)
	val, present := security["audit_durable_sync_skipped"]
	require.True(t, present,
		"GET /system/info's security block must carry audit_durable_sync_skipped -- it is the one place "+
			"ADR-112 Amendment 1 requires the deviation to be visible without host access")
	assert.True(t, val.(bool),
		"audit_durable_sync_skipped must be true on Postgres with the setting on: this field reports IN "+
			"EFFECT, i.e. \"is my audit durability weakened right now\"")
	_, reasonPresent := security["audit_durable_sync_skip_not_in_effect_reason"]
	assert.False(t, reasonPresent,
		"an IN EFFECT setting must carry NO not-in-effect reason (the field is omitempty), or a consumer "+
			"cannot use a non-empty reason as the unambiguous signal of the ignored state")

	// Zero-value config: the field must be present and false. Present AND
	// false matters, not just false: a missing key would read as "this server
	// is too old to know about the setting", which is a different (and, to an
	// auditor, far less useful) statement than "this server is durable".
	rr2 := httptest.NewRecorder()
	MakeSystemInfoHandler(&config.Config{}, freshCoreS12(t))(rr2,
		userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)))
	var resp2 map[string]any
	require.NoError(t, json.NewDecoder(rr2.Body).Decode(&resp2))
	security2 := resp2["data"].(map[string]any)["security"].(map[string]any)
	val2, present2 := security2["audit_durable_sync_skipped"]
	require.True(t, present2, "audit_durable_sync_skipped must always be present, not omitted when false")
	assert.False(t, val2.(bool), "audit_durable_sync_skipped must default to false")
}
