package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A config file using ONLY the deprecated old keys must decode exactly as if
// it had used the current insecure_ names — the whole point of "deprecated
// alias, warns when used" is that behavior is unchanged, only visibility
// changes. Exercises one setting from each of the four YAML shapes this
// mechanism has to handle: top-level security.*, security.login_lockout.*
// (nested struct), audit_checkpoints.* (its own top-level block), and
// sso.providers[].* (inside a YAML sequence).
func TestLoad_DeprecatedAliases_OldKeysStillWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
security:
  allow_unsafe_file_permissions: true
  login_lockout:
    disabled: true
audit_checkpoints:
  disabled: true
sso:
  providers:
    - name: okta
      type: saml
      trust_asserted_email: true
      saml:
        allow_idp_initiated: false
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.Security.AllowUnsafeFilePermissions)
	assert.True(t, cfg.Security.LoginLockout.Disabled)
	assert.True(t, cfg.AuditCheckpoints.Disabled)
	require.Len(t, cfg.SSO.Providers, 1)
	assert.True(t, cfg.SSO.Providers[0].TrustAssertedEmail)
	require.NotNil(t, cfg.SSO.Providers[0].SAML)
	assert.False(t, cfg.SSO.Providers[0].SAML.AllowIDPInitiated)

	// 5, not 4: the test body sets saml.allow_idp_initiated explicitly (to
	// false) as well as the other 4 old keys above it -- "present" triggers
	// the warning regardless of the value, same as every other alias here.
	assert.Len(t, cfg.DeprecatedSettingWarnings, 5, "one warning per deprecated key found: %v", cfg.DeprecatedSettingWarnings)
	for _, w := range cfg.DeprecatedSettingWarnings {
		assert.Contains(t, w, "deprecated")
	}
}

// The current insecure_ names work exactly as before (no behavior change for
// an operator who already migrated), and produce zero deprecation warnings.
func TestLoad_DeprecatedAliases_NewKeysProduceNoWarnings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
security:
  insecure_allow_unsafe_file_permissions: true
  login_lockout:
    insecure_disable_login_lockout: true
audit_checkpoints:
  insecure_disable_audit_checkpoints: true
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.Security.AllowUnsafeFilePermissions)
	assert.True(t, cfg.Security.LoginLockout.Disabled)
	assert.True(t, cfg.AuditCheckpoints.Disabled)
	assert.Empty(t, cfg.DeprecatedSettingWarnings)
}

// When BOTH the deprecated old key and its replacement are set, the new key
// wins (not an arbitrary last-one-wins from map iteration order) and a
// specific "both set" warning fires — silently ignoring one of two
// conflicting values would be exactly the kind of silent weakening ADR-112
// exists to prevent.
func TestLoad_DeprecatedAliases_BothSetNewKeyWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
security:
  allow_unsafe_file_permissions: true
  insecure_allow_unsafe_file_permissions: false
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.False(t, cfg.Security.AllowUnsafeFilePermissions, "the explicit insecure_ key must win over the deprecated alias")
	require.Len(t, cfg.DeprecatedSettingWarnings, 1)
	assert.Contains(t, cfg.DeprecatedSettingWarnings[0], "both")
}

// A config file that mentions neither the old nor the new key for any
// registered alias produces zero warnings and leaves every renamed field at
// its ordinary zero-value default — resolveDeprecatedAliases must be a
// strict no-op on a document it has nothing to do with, not just "no error."
func TestLoad_DeprecatedAliases_NoneUsedIsANoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte("locale:\n  language: en\n"), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Empty(t, cfg.DeprecatedSettingWarnings)
	assert.False(t, cfg.Security.AllowUnsafeFilePermissions)
}

// RED-proof target for resolveDeprecatedAliases itself: an old key that
// Load's strict KnownFields(true) decoder would otherwise reject outright as
// an unrecognized field (since the struct field's yaml tag was renamed) must
// never reach that decoder un-rewritten. Calling resolveDeprecatedAliases
// directly isolates this from Load's other behavior.
func TestResolveDeprecatedAliases_RewritesOldKeyToNewName(t *testing.T) {
	data := []byte("security:\n  allow_unsafe_file_permissions: true\n")
	rewritten, warnings := resolveDeprecatedAliases(data)
	require.Len(t, warnings, 1)

	var raw struct {
		Security map[string]interface{} `yaml:"security"`
	}
	require.NoError(t, yaml.Unmarshal(rewritten, &raw))
	_, oldStillPresent := raw.Security["allow_unsafe_file_permissions"]
	assert.False(t, oldStillPresent, "the old key must not survive the rewrite")
	newVal, newPresent := raw.Security["insecure_allow_unsafe_file_permissions"]
	require.True(t, newPresent, "the new key must be present after the rewrite")
	assert.Equal(t, true, newVal)
}

// TestLoad_DeprecatedAliases_FallbackChainOldKeysStillWork covers the gap the
// coordinator's review of #2454 found: the two KeyProviderConfig settings live
// on the FALLBACK entries too (`fallbacks:` is []KeyProviderConfig), so a
// config file setting an old key under a fallback had it left untranslated —
// and then Load's dec.KnownFields(true) rejected it as an unrecognized field.
// A HARD BOOT FAILURE where the whole mechanism promises a deprecation
// warning, which is worse than the rename not existing at all: the deployment
// most likely to use a fallback chain is the one least able to take an
// unexplained refusal to start.
//
// RED without the two `fallbacks[]` rows in deprecatedSettingAliases:
//
//	Load() -> "yaml: unmarshal errors: line 11: field allow_weaker_fallback
//	not found in type config.KeyProviderConfig"
func TestLoad_DeprecatedAliases_FallbackChainOldKeysStillWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
storage:
  encryption:
    enabled: true
    key_provider:
      type: kms
      kms_allow_context_fallback: true
      fallbacks:
        - type: kms
          kms_allow_context_fallback: true
          allow_weaker_fallback: true
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err, "an old key under a fallback entry must still DECODE, not hard-fail KnownFields(true)")

	kp := cfg.Storage.Encryption.KeyProvider
	assert.True(t, kp.KMSAllowContextFallback, "the primary provider's old key must still take effect")
	require.Len(t, kp.Fallbacks, 1)
	assert.True(t, kp.Fallbacks[0].KMSAllowContextFallback, "the fallback's own old key must still take effect")
	assert.True(t, kp.Fallbacks[0].AllowWeakerFallback, "the fallback's own old key must still take effect")

	// And it must warn, not pass silently — the point of a deprecated alias.
	assert.NotEmpty(t, cfg.DeprecatedSettingWarnings)
}

// TestInsecureSettingsInEffect_SeesAFallbackChainOptOut is the half that
// matters for ADR-112 rather than for decoding: a weakening set ONLY on a
// fallback entry must still register as in effect, so it is warned about,
// audited in the settings diff and reported as a posture deviation. A
// decode-only fix would leave the setting working and invisible.
func TestInsecureSettingsInEffect_SeesAFallbackChainOptOut(t *testing.T) {
	cfg := &Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.KeyProvider.Type = "kms"
	cfg.Storage.Encryption.KeyProvider.Fallbacks = []KeyProviderConfig{
		{Type: "kms", AllowWeakerFallback: true},
	}

	var found bool
	for _, e := range InsecureSettingsRegistry {
		if e.Name == "storage.encryption.key_provider.insecure_allow_weaker_kek_fallback" {
			found = true
			assert.True(t, e.InEffect(cfg), "a weakening set only on a FALLBACK entry must still count as in effect")
			assert.Equal(t, "true", e.Value(cfg))
		}
	}
	require.True(t, found, "registry entry not found — renamed?")
}

// yamlForPath renders a minimal document that sets dotted path to value. A
// segment ending in "[]" becomes a one-element sequence, matching the alias
// table's spelling.
func yamlForPath(path, value string) string {
	var b strings.Builder
	indent := ""
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		name := strings.TrimSuffix(seg, "[]")
		if i == len(segs)-1 {
			fmt.Fprintf(&b, "%s%s: %s\n", indent, name, value)
			break
		}
		fmt.Fprintf(&b, "%s%s:\n", indent, name)
		indent += "  "
		if strings.HasSuffix(seg, "[]") {
			b.WriteString(indent + "- ")
			// The sequence element's first key shares the "- " line.
			rest := yamlForPath(strings.Join(segs[i+1:], "."), value)
			lines := strings.Split(strings.TrimRight(rest, "\n"), "\n")
			b.WriteString(lines[0] + "\n")
			for _, l := range lines[1:] {
				b.WriteString(indent + "  " + l + "\n")
			}
			return b.String()
		}
	}
	return b.String()
}

// boolAtPath walks cfg by yaml tags along dotted path ("[]" segments take
// element 0) and returns the bool there.
func boolAtPath(cfg *Config, path string) (bool, error) {
	v := reflect.ValueOf(cfg).Elem()
	for _, seg := range strings.Split(path, ".") {
		name := strings.TrimSuffix(seg, "[]")
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return false, fmt.Errorf("%s: nil pointer before %q", path, name)
			}
			v = v.Elem()
		}
		found := false
		for i := 0; i < v.NumField(); i++ {
			if strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0] == name {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("no field tagged %q on the way to %s", name, path)
		}
		if strings.HasSuffix(seg, "[]") {
			if v.Kind() != reflect.Slice || v.Len() == 0 {
				return false, fmt.Errorf("%s: expected a non-empty sequence at %q", path, name)
			}
			v = v.Index(0)
		}
	}
	for v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() != reflect.Bool {
		return false, fmt.Errorf("%s is a %s, not a bool", path, v.Kind())
	}
	return v.Bool(), nil
}

// releasedOldPaths are the pre-rename keys exactly as released (the yaml tags
// on main before #2899), spelled INDEPENDENTLY of deprecatedSettingAliases.
// The independence is the point: YAML generated from the alias table's own
// OldPath would rewrite a misspelled row's own misspelling and pass, while
// every real deployment using the released key failed to boot.
var releasedOldPaths = []string{
	"security.allow_unsafe_file_permissions",
	"security.login_lockout.disabled",
	"security.recover_admin.keyless_mode",
	"audit.siem.allow_private_network_target",
	"audit.siem.allow_insecure_transport",
	"evidence_delivery.webhook.allow_private_network_target",
	"evidence_delivery.webhook.allow_insecure_transport",
	"notifications.webhook.allow_private_network_target",
	"notifications.webhook.allow_insecure_transport",
	"dynamic_secrets.allow_private_network_targets",
	"dynamic_secrets.allow_insecure_transport",
	"storage.encryption.key_provider.kms_allow_context_fallback",
	"storage.encryption.key_provider.allow_weaker_fallback",
	"storage.encryption.key_provider.fallbacks[].kms_allow_context_fallback",
	"storage.encryption.key_provider.fallbacks[].allow_weaker_fallback",
	"sso.providers[].trust_asserted_email",
	"sso.providers[].saml.allow_idp_initiated",
	"audit_checkpoints.disabled",
}

// aliasRoundTrip loads a config that sets ONLY the released key oldPath to
// true, through the real Load, against the given alias table, and checks the
// value arrives at that row's NewPath with exactly one deprecation warning
// naming the old key.
func aliasRoundTrip(t *testing.T, table []deprecatedSettingAlias, oldPath string) error {
	t.Helper()
	var alias *deprecatedSettingAlias
	for i := range table {
		if table[i].OldPath == oldPath {
			alias = &table[i]
		}
	}
	if alias == nil {
		return fmt.Errorf("released key %s has no alias row (misspelled OldPath?) -- a deployment still using it fails to boot", oldPath)
	}
	saved := deprecatedSettingAliases
	deprecatedSettingAliases = table
	defer func() { deprecatedSettingAliases = saved }()

	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	if err := os.WriteFile(path, []byte(yamlForPath(oldPath, "true")), 0600); err != nil {
		return err
	}
	cfg, err := Load(path)
	if err != nil {
		return fmt.Errorf("released key %s no longer loads (an existing deployment would fail to boot): %w", oldPath, err)
	}
	got, err := boolAtPath(cfg, alias.NewPath)
	if err != nil {
		return err
	}
	if !got {
		return fmt.Errorf("released key %s=true did not arrive at %s", oldPath, alias.NewPath)
	}
	if len(cfg.DeprecatedSettingWarnings) != 1 || !strings.Contains(cfg.DeprecatedSettingWarnings[0], oldPath) {
		return fmt.Errorf("want exactly one deprecation warning naming %s, got %v", oldPath, cfg.DeprecatedSettingWarnings)
	}
	return nil
}

// TestLoad_DeprecatedAliases_EveryReleasedKeyRoundTripsThroughLoad drives
// EVERY released pre-rename key through Load (coordinator review of #2899:
// 7 of 16 were covered, so a typo in an untested OldPath would ship and
// hard-fail the boot of the first deployment still using the old name).
func TestLoad_DeprecatedAliases_EveryReleasedKeyRoundTripsThroughLoad(t *testing.T) {
	if len(releasedOldPaths) != len(deprecatedSettingAliases) {
		t.Errorf("alias table has %d rows but %d released keys are listed -- every row must be a released key "+
			"and every released key must have a row", len(deprecatedSettingAliases), len(releasedOldPaths))
	}
	for _, old := range releasedOldPaths {
		t.Run(old, func(t *testing.T) {
			if err := aliasRoundTrip(t, deprecatedSettingAliases, old); err != nil {
				t.Error(err)
			}
		})
	}

	// Calibration: the table with ONE row misspelled must fail for that key.
	typo := make([]deprecatedSettingAlias, len(deprecatedSettingAliases))
	copy(typo, deprecatedSettingAliases)
	for i := range typo {
		if typo[i].OldPath == "security.recover_admin.keyless_mode" {
			typo[i].OldPath = "security.recover_admin.keyles_mode"
		}
	}
	if err := aliasRoundTrip(t, typo, "security.recover_admin.keyless_mode"); err == nil {
		t.Error("calibration: a misspelled OldPath row must fail the round trip for the released key")
	}
}

// TestDocs_ConfigurationListsEveryDeprecatedAlias keeps the operator-facing
// rename table in docs/CONFIGURATION.md in step with deprecatedSettingAliases
// (coordinator review of #2899, item 3: the docs showed 3 of 16).
func TestDocs_ConfigurationListsEveryDeprecatedAlias(t *testing.T) {
	raw, err := os.ReadFile("../../docs/CONFIGURATION.md")
	require.NoError(t, err)
	doc := string(raw)
	for _, a := range deprecatedSettingAliases {
		row := fmt.Sprintf("| `%s` | `%s` |", a.OldPath, a.NewPath)
		assert.Contains(t, doc, row, "docs/CONFIGURATION.md's rename table is missing %s -> %s", a.OldPath, a.NewPath)
	}
}
