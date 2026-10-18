package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// server.log.format accepts only "", "text" or "json"; a typo must fail closed at
// startup rather than silently fall back to text logs an operator's parser cannot read.
func TestValidate_LogFormat(t *testing.T) {
	for _, tc := range []struct {
		format  string
		wantErr bool
	}{
		{"", false},
		{"text", false},
		{"json", false},
		{"JSON", true},
		{"logfmt", true},
		{"yaml", true},
	} {
		cfg := &Config{}
		cfg.Server.HTTP.Port = "8080"
		cfg.Server.GRPC.Port = "9090"
		cfg.Storage.Type = "local"
		cfg.Storage.Database.Path = "./test.db"
		cfg.Server.Log.Format = tc.format
		err := cfg.Validate()
		if tc.wantErr {
			require.Error(t, err, "format %q", tc.format)
			assert.Contains(t, err.Error(), "server.log.format")
		} else {
			assert.NoError(t, err, "format %q", tc.format)
		}
	}
}

func TestLogFormat_DefaultIsText(t *testing.T) {
	assert.Equal(t, LogFormatText, LogConfig{}.EffectiveFormat())

	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte("server:\n  log:\n    format: json\n"), &cfg))
	assert.Equal(t, LogFormatJSON, cfg.Server.Log.EffectiveFormat())
}
