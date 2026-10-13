// break_glass_settings_test.go — GET /api/v1/projects/{id}/break-glass also reports the
// server's break-glass limits (settings), so the web picker offers only lifetimes the
// server honours. Same audience as the list itself (a project member, or roles.read);
// a non-member gets the old 403 and none of it.
package http

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

type bgSettingsResponse struct {
	Data struct {
		Settings *struct {
			Enabled           bool   `json:"enabled"`
			EmergencyRole     string `json:"emergency_role"`
			DefaultTTLSeconds int64  `json:"default_ttl_seconds"`
			MaxTTLSeconds     int64  `json:"max_ttl_seconds"`
		} `json:"settings"`
	} `json:"data"`
}

func (f *bgOwnFixture) settings(t *testing.T, tok string, projectID uint) bgSettingsResponse {
	t.Helper()
	code, _, raw := f.list(t, tok, projectID)
	require.Equal(t, http.StatusOK, code, raw)
	var out bgSettingsResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	require.NotNil(t, out.Data.Settings, "list answer must carry settings: %s", raw)
	return out
}

func TestBreakGlassSettings_MemberAndReaderSeeEffectiveLimits(t *testing.T) {
	f := newBGOwnFixture(t)
	f.d.c.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: 90 * time.Minute, MaxTTL: 6 * time.Hour,
	})
	for name, tok := range map[string]string{"member": f.aliceTok, "roles.read": f.d.adminTok} {
		s := f.settings(t, tok, f.d.projectID).Data.Settings
		assert.True(t, s.Enabled, name)
		assert.Equal(t, "project_developer", s.EmergencyRole, name)
		assert.Equal(t, int64(90*60), s.DefaultTTLSeconds, name)
		assert.Equal(t, int64(6*3600), s.MaxTTLSeconds, name)
	}
}

// The reported ceiling is what activation really enforces: an unset max falls back to the
// default, and a default above the max is reported capped.
func TestBreakGlassSettings_ReportTheCeilingActivationEnforces(t *testing.T) {
	f := newBGOwnFixture(t)
	f.d.c.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: true, EmergencyRole: "project_developer"})
	s := f.settings(t, f.aliceTok, f.d.projectID).Data.Settings
	assert.Equal(t, int64(4*3600), s.DefaultTTLSeconds, "unset default is 4h")
	assert.Equal(t, int64(4*3600), s.MaxTTLSeconds, "unset max falls back to the default")

	f.d.c.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: 8 * time.Hour, MaxTTL: 2 * time.Hour,
	})
	s = f.settings(t, f.aliceTok, f.d.projectID).Data.Settings
	assert.Equal(t, int64(2*3600), s.DefaultTTLSeconds)
	assert.Equal(t, int64(2*3600), s.MaxTTLSeconds)
}

func TestBreakGlassSettings_DisabledIsReportedToMembers(t *testing.T) {
	f := newBGOwnFixture(t)
	f.d.c.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: false})
	s := f.settings(t, f.aliceTok, f.d.projectID).Data.Settings
	assert.False(t, s.Enabled)
}

// An outsider is refused exactly as before and learns nothing of the policy.
func TestBreakGlassSettings_NotForOutsiders(t *testing.T) {
	f := newBGOwnFixture(t)
	code, _, raw := f.list(t, f.oscarTok, f.d.projectID)
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.NotContains(t, raw, "settings")
	assert.NotContains(t, raw, "emergency_role")
	assert.NotContains(t, raw, "project_developer")
	assert.NotContains(t, raw, "max_ttl_seconds")
}
