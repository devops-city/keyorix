package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configs/dev.yaml used to declare its `encryption:` block at the top level instead
// of nesting it under `storage:` (the Config struct has no top-level `encryption`
// field at all — only StorageConfig.Encryption). Because Load() used a plain,
// non-strict yaml.Unmarshal, the misplaced block was silently discarded: a developer
// running `make run` believed local Postgres storage was encrypted when
// storage.encryption.enabled actually stayed at its Go zero value (false), and every
// secret value was written to the dev database in plaintext. This test locks in both
// halves of the fix: the misplaced key is now correctly nested, and Load() itself
// would refuse to silently swallow a similar mistake in the future.
func TestLoadDevYAML_EncryptionEnabled(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	require.NoError(t, err)
	p := filepath.Join(repoRoot, "configs", "dev.yaml")
	if _, statErr := os.Stat(p); statErr != nil {
		t.Skipf("configs/dev.yaml not found at %s: %v", p, statErr)
	}

	cfg, err := Load(p)
	require.NoError(t, err, "configs/dev.yaml must load cleanly")
	assert.True(t, cfg.Storage.Encryption.Enabled,
		"storage.encryption.enabled must be true — configs/dev.yaml intends to encrypt the local dev Postgres database")
}

// Regression guard for the class of bug behind configs/dev.yaml's misplaced
// top-level `encryption:` block: Load() must now use a strict/KnownFields YAML
// decoder, so any unrecognized key — whether a genuine typo or a correctly-spelled
// field nested under the wrong parent — fails loudly at startup instead of being
// silently dropped.
func TestLoadRejectsUnknownTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keyorix.yaml")
	// Mirrors the exact real-world mistake: `encryption:` belongs under `storage:`,
	// not at the document root.
	require.NoError(t, os.WriteFile(p, []byte(
		"storage:\n  type: postgres\nencryption:\n  enabled: true\n",
	), 0o600))

	_, err := Load(p)
	require.Error(t, err, "an unrecognized top-level key must fail Load(), not be silently dropped")
	assert.Contains(t, err.Error(), "encryption")
}

// Companion to TestLoadRejectsUnknownTopLevelKey: an unrecognized key nested inside a
// known block (not just at the document root) must be rejected too.
func TestLoadRejectsUnknownNestedKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"storage:\n  type: postgres\n  encryption:\n    enabled: true\n    made_up_field: true\n",
	), 0o600))

	_, err := Load(p)
	require.Error(t, err, "an unrecognized nested key must fail Load(), not be silently dropped")
	assert.Contains(t, err.Error(), "made_up_field")
}

// Strict-mode hardening must not regress the historical behavior for a config file
// that is empty, whitespace-only, or comments-only: Load() should still succeed and
// return the all-defaults zero-value Config, matching the old yaml.Unmarshal
// behavior (which silently no-ops on an empty document) rather than surfacing the
// yaml.Decoder's io.EOF as a load error.
func TestLoadEmptyFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"empty":        "",
		"whitespace":   "   \n\n   \n",
		"comment-only": "# nothing but a comment\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name+".yaml")
			require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

			cfg, err := Load(p)
			require.NoError(t, err)
			assert.False(t, cfg.Storage.Encryption.Enabled, "zero-value default")
		})
	}
}

// A well-formed config with only known fields (across nested blocks) must still
// load cleanly under the strict decoder — a hardening change that's too aggressive
// is as dangerous as one that's too permissive.
func TestLoadAcceptsWellFormedConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"environment: development\n"+
			"server:\n  http:\n    enabled: true\n    port: \"8080\"\n"+
			"storage:\n  type: postgres\n  database:\n    host: localhost\n    port: \"5432\"\n"+
			"  encryption:\n    enabled: true\n",
	), 0o600))

	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "development", cfg.Environment)
	assert.True(t, cfg.Storage.Encryption.Enabled)
}
