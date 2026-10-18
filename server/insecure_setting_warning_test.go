package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// BOOT-REFUSALS-1 "Misleading messages" item 3: the cleartext warning named
// security.insecure_allow_cleartext_transport, a key the loader rejects, and read
// as if the operator had set it although it is the default for an absent
// security.require_transport_tls.
func registryEntry(t *testing.T, name string) config.InsecureSetting {
	t.Helper()
	for _, s := range config.InsecureSettingsRegistry {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no registry entry %s", name)
	return config.InsecureSetting{}
}

func TestInsecureSettingWarning_CleartextNamesTheKeyToWrite(t *testing.T) {
	cfg := &config.Config{}
	line := insecureSettingWarning(registryEntry(t, "security.insecure_allow_cleartext_transport"), cfg)
	assert.Contains(t, line, "security.insecure_allow_cleartext_transport is in effect", "the stable identifier stays greppable")
	assert.Contains(t, line, "not a config key")
	assert.Contains(t, line, "security.require_transport_tls is false or not set")
	assert.Contains(t, line, "set security.require_transport_tls: true")
	assert.NotContains(t, line, "config: security.require_transport_tls", "the old shape that read as if the operator set the key")
}

// Every entry whose Name is not a YAML key says so; every other entry keeps the
// "config: <keys>" shape.
func TestInsecureSettingWarning_EveryEntry(t *testing.T) {
	cfg := &config.Config{}
	for _, s := range config.InsecureSettingsRegistry {
		line := insecureSettingWarning(s, cfg)
		require.True(t, strings.HasPrefix(line, "WARNING: "+s.Name+" is in effect ("), line)
		settable := false
		for _, p := range s.SourcePaths {
			settable = settable || p == s.Name
		}
		if settable {
			assert.Contains(t, line, "; config: "+strings.Join(s.SourcePaths, ", ")+")", s.Name)
			assert.NotContains(t, line, "not a config key", s.Name)
		} else {
			assert.Contains(t, line, "not a config key", s.Name)
		}
	}
}
