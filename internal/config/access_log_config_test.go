package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// server.access_log.on_sink_stall accepts only "", "block" or "drop"; a typo must
// fail closed at startup, not silently pick a mode.
func TestValidate_AccessLogOnSinkStall(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		wantErr bool
	}{
		{"", false},
		{"block", false},
		{"drop", false},
		{"Drop", true},
		{"discard", true},
		{"true", true},
	} {
		cfg := &Config{}
		cfg.Server.HTTP.Port = "8080"
		cfg.Server.GRPC.Port = "9090"
		cfg.Storage.Type = "local"
		cfg.Storage.Database.Path = "./test.db"
		cfg.Server.AccessLog.OnSinkStall = tc.mode
		err := cfg.Validate()
		if tc.wantErr {
			require.Error(t, err, "mode %q", tc.mode)
			assert.Contains(t, err.Error(), "server.access_log.on_sink_stall")
		} else {
			assert.NoError(t, err, "mode %q", tc.mode)
		}
	}
}

// The default is block: an unset value, and a config with no access_log section.
func TestAccessLogOnSinkStall_DefaultIsBlock(t *testing.T) {
	assert.Equal(t, AccessLogOnSinkStallBlock, AccessLogConfig{}.EffectiveOnSinkStall())
	assert.Equal(t, AccessLogOnSinkStallDrop, AccessLogConfig{OnSinkStall: "drop"}.EffectiveOnSinkStall())

	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte("server:\n  http:\n    port: \"8080\"\n"), &cfg))
	assert.Equal(t, AccessLogOnSinkStallBlock, cfg.Server.AccessLog.EffectiveOnSinkStall())

	require.NoError(t, yaml.Unmarshal([]byte("server:\n  access_log:\n    on_sink_stall: drop\n"), &cfg))
	assert.Equal(t, AccessLogOnSinkStallDrop, cfg.Server.AccessLog.EffectiveOnSinkStall())
}
