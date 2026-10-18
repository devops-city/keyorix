package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BOOT-REFUSALS-1 "Misleading messages" item 5: an unknown key was reported with
// the Go type of its section ("field webauthn not found in type
// config.SecurityConfig"); the operator writes YAML, so name the section.
func loadYAML(t *testing.T, body string) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	_, err := Load(p)
	return err
}

func TestLoad_UnknownKeyNamesTheYAMLSection(t *testing.T) {
	cases := []struct{ body, want string }{
		{"security:\n  webauthn: {}\n", `unknown key "webauthn" under security`},
		{"encryption:\n  enabled: true\n", `unknown key "encryption" at the top level`},
		{"server:\n  http:\n    tls:\n      ciphers: []\n", `unknown key "ciphers" under server.grpc.tls or server.http.tls`},
		{"storage:\n  encryption:\n    key_provider:\n      typo: x\n", `unknown key "typo" under storage.encryption.key_provider`},
	}
	for _, tc := range cases {
		err := loadYAML(t, tc.body)
		require.Error(t, err, tc.body)
		msg := err.Error()
		assert.Contains(t, msg, "failed to unmarshal config", "the page's Match text stays")
		assert.Contains(t, msg, tc.want)
		assert.Contains(t, msg, "line ", "the line number stays")
		assert.NotContains(t, msg, "not found in type", "no Go type names")
	}
}

// Every struct the config reaches has a YAML path, so no unknown-key error falls
// back to a Go type name.
func TestYAMLSections_CoversEverySection(t *testing.T) {
	s := yamlSections()
	assert.Equal(t, []string{""}, s["config.Config"])
	assert.Equal(t, []string{"security"}, s["config.SecurityConfig"])
	for typ, paths := range s {
		require.NotEmpty(t, paths, typ)
		for _, p := range paths {
			assert.False(t, strings.Contains(p, ".."), "%s: %q", typ, p)
		}
	}
}
