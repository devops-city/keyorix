package startup

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drop mode is a posture deviation; the default (block) records nothing.
func TestAppendAccessLogPosture(t *testing.T) {
	for _, mode := range []string{"", "block"} {
		cfg := &config.Config{}
		cfg.Server.AccessLog.OnSinkStall = mode
		res := &ValidationResult{}
		appendAccessLogPosture(cfg, res)
		assert.Empty(t, res.Warnings, "mode %q", mode)
		assert.Empty(t, res.InsecureSettings, "mode %q", mode)
	}

	cfg := &config.Config{}
	cfg.Server.AccessLog.OnSinkStall = "drop"
	res := &ValidationResult{}
	appendAccessLogPosture(cfg, res)
	assert.Equal(t, []string{AccessLogDropModeWarning}, res.Warnings)
	require.Len(t, res.InsecureSettings, 1)
	assert.Equal(t, AccessLogOnSinkStallSettingName, res.InsecureSettings[0].Name)
	assert.True(t, res.InsecureSettings[0].InEffect)
}
