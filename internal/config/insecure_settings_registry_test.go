package config

import (
	"strings"
	"testing"
)

// TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook is
// the ADR-112 structural CI test: every registry entry must carry the
// insecure_ prefix (so it can't be enabled by accident or misread in
// review), a non-nil InEffect (the start-up warning's hook -- see
// server/main.go's warnInsecureSettingsInEffect, which loops this registry
// unconditionally), and a non-nil Value (the settings-diff audit's hook --
// see server/main.go's securityPostureSnapshot, which also loops this
// registry unconditionally). Because both consumers iterate the WHOLE
// registry with no per-entry opt-out, any entry satisfying this test is
// mechanically guaranteed warned-about and audited; this test is what makes
// that guarantee hold for every entry added in the future, not just the ones
// present today.
func TestInsecureSettingsRegistry_EveryEntryHasThePrefixWarningAndAuditHook(t *testing.T) {
	if len(InsecureSettingsRegistry) == 0 {
		t.Fatal("registry must not be empty")
	}
	seenNames := make(map[string]bool, len(InsecureSettingsRegistry))
	for _, e := range InsecureSettingsRegistry {
		t.Run(e.Name, func(t *testing.T) {
			if e.Name == "" {
				t.Fatal("entry has no Name")
			}
			leaf := e.Name
			if i := strings.LastIndex(leaf, "."); i >= 0 {
				leaf = leaf[i+1:]
			}
			if !strings.HasPrefix(leaf, "insecure_") {
				t.Errorf("Name %q's leaf segment %q must start with insecure_", e.Name, leaf)
			}
			if e.Describe == "" {
				t.Error("entry has no Describe")
			}
			if e.InEffect == nil {
				t.Error("entry has no InEffect -- the start-up warning loop can't evaluate it")
			}
			if e.Value == nil {
				t.Error("entry has no Value -- the settings-diff audit loop can't snapshot it")
			}
			if seenNames[e.Name] {
				t.Errorf("Name %q is registered more than once", e.Name)
			}
			seenNames[e.Name] = true
		})
	}
}

// Every renamed setting's DeprecatedAlias (when non-empty) must actually
// appear in deprecatedSettingAliases with a matching NewPath whose leaf
// equals the registry entry's own leaf -- i.e. the registry and the alias
// table must agree on what each setting is called today. A registry entry
// claiming a rename that the alias table doesn't know about would mean the
// OLD key silently stopped working with no deprecation warning at all,
// exactly the silent-weakening failure mode ADR-112 exists to prevent.
func TestInsecureSettingsRegistry_DeprecatedAliasesMatchAliasTable(t *testing.T) {
	aliasByOld := make(map[string]string, len(deprecatedSettingAliases))
	for _, a := range deprecatedSettingAliases {
		aliasByOld[a.OldPath] = a.NewPath
	}
	for _, e := range InsecureSettingsRegistry {
		if e.DeprecatedAlias == "" {
			continue
		}
		t.Run(e.Name, func(t *testing.T) {
			newPath, ok := aliasByOld[e.DeprecatedAlias]
			if !ok {
				t.Fatalf("registry entry %q claims DeprecatedAlias %q, but no such entry exists in deprecatedSettingAliases", e.Name, e.DeprecatedAlias)
			}
			registryLeaf := e.Name[strings.LastIndex(e.Name, ".")+1:]
			aliasLeaf := newPath[strings.LastIndex(newPath, ".")+1:]
			if registryLeaf != aliasLeaf {
				t.Errorf("registry entry %q's leaf %q does not match deprecatedSettingAliases' NewPath leaf %q (from %q)",
					e.Name, registryLeaf, aliasLeaf, newPath)
			}
		})
	}
}

// Once a setting is renamed, its SourcePaths must name the CURRENT key, not
// the old one -- SourcePaths is what insecure_settings_sweep_test.go sweeps
// Config's surface against, and a renamed entry still pointing at its old
// path would stop covering the setting (and would be caught, loudly, by
// TestConfigSurface_RegistrySourcePathsAllExist -- this test says the same
// thing at the registry's own level, where the fix belongs).
func TestInsecureSettingsRegistry_RenamedEntriesSourceTheirCurrentKey(t *testing.T) {
	for _, e := range InsecureSettingsRegistry {
		if e.DeprecatedAlias == "" {
			continue
		}
		t.Run(e.Name, func(t *testing.T) {
			for _, p := range e.SourcePaths {
				if p == e.DeprecatedAlias {
					t.Errorf("SourcePaths still names the DEPRECATED path %q; after the rename it must name the current key (%q)", p, e.Name)
				}
			}
		})
	}
}

// Calling every entry's InEffect/Value against a zero-value *Config must
// never panic -- the start-up warning loop and the settings-diff snapshot
// both run this unconditionally on every boot, including the very first one
// before any encryption/SSO/etc. config exists. A nil-pointer-dereference
// here (e.g. a provider's *SAMLProviderConfig) would crash every server
// start, not just degrade a posture check.
func TestInsecureSettingsRegistry_ZeroValueConfigNeverPanics(t *testing.T) {
	cfg := &Config{}
	for _, e := range InsecureSettingsRegistry {
		t.Run(e.Name, func(t *testing.T) {
			_ = e.InEffect(cfg)
			_ = e.Value(cfg)
		})
	}
}

// issue2895TrackedKeys is #2895's table: the fourteen security-weakening
// settings tracked there, by the config key(s) they read TODAY. Rows 1-13
// are the known exceptions (a polarity inversion or a shape change each);
// row 14, sso.providers[].trust_asserted_email (renamed by #2899 to
// insecure_trust_saml_asserted_email, old key kept as an alias), is mechanically renameable
// and sits with the other renameable entries, listed in #2895 only because
// its name gives a lexical sweep nothing to see.
var issue2895TrackedKeys = [][]string{
	{"security.require_transport_tls"},
	{"security.enable_file_permission_check"},
	{"storage.encryption.enabled"},
	{"storage.encryption.key_provider.shamir_commitment"},
	{"membership.validation_mode"},
	{"sso.providers.auto_provision"},
	{"sso.providers.group_sync"},
	{"server.http.metrics_token", "server.grpc.metrics_token"},
	{"server.http.max_request_body_bytes", "server.grpc.max_request_body_bytes"},
	{"storage.database.ssl_mode"},
	{"server.http.ratelimit.enabled", "server.grpc.ratelimit.enabled"},
	{"credential_delivery.mode"},
	{"credential_delivery.smtp.tls", "notifications.email.tls"},
	{"sso.providers.insecure_trust_saml_asserted_email"}, // renamed from trust_asserted_email (#2899)
}

// untrackedIssue2895Keys returns every #2895 key no entry of registry covers.
func untrackedIssue2895Keys(registry []InsecureSetting) []string {
	covered := map[string]bool{}
	for _, e := range registry {
		for _, p := range e.SourcePaths {
			covered[p] = true
		}
	}
	var missing []string
	for _, row := range issue2895TrackedKeys {
		for _, k := range row {
			if !covered[k] {
				missing = append(missing, k)
			}
		}
	}
	return missing
}

// TestInsecureSettingsRegistry_EveryIssue2895RowIsRegistered turns "all
// fourteen are fully covered by the registry under their current names"
// (#2895, and this package's doc) from a sentence into a check. A row dropped
// from the registry -- in a split, a rebase, a rename that forgets its
// SourcePaths -- is exactly the non-lexical kind of weakening the sweep's
// net 1 cannot see, so it must fail here by name.
func TestInsecureSettingsRegistry_EveryIssue2895RowIsRegistered(t *testing.T) {
	if len(issue2895TrackedKeys) != 14 {
		t.Fatalf("#2895 tracks 14 settings; this table has %d -- keep it in step with the issue", len(issue2895TrackedKeys))
	}
	if missing := untrackedIssue2895Keys(InsecureSettingsRegistry); len(missing) > 0 {
		t.Errorf("#2895 settings with no InsecureSettingsRegistry entry covering them: %v -- each "+
			"is in effect SILENTLY (no start-up warning, no settings-diff audit, no posture deviation)", missing)
	}

	// Calibration: the guard must fire on the shape the coordinator asked
	// about -- the fourteenth row dropped in the split.
	var without []InsecureSetting
	for _, e := range InsecureSettingsRegistry {
		if !strings.Contains(strings.Join(e.SourcePaths, ","), "asserted_email") {
			without = append(without, e)
		}
	}
	if got := untrackedIssue2895Keys(without); len(got) != 1 || got[0] != "sso.providers.insecure_trust_saml_asserted_email" {
		t.Errorf("calibration: dropping the trust_asserted_email entry must be reported; got %v", got)
	}
}

// Review point 3 (MERGE-MASTER, #2899): a setting that lives on KeyProviderConfig
// can be set on a fallbacks[] entry as well as on the primary, and the alias table
// carries a row for each. The registry entry's SourcePaths must name EVERY current
// spelling the alias table can produce (flattened, as explicitlySetPathsIn spells
// it), or the posture report labels a fallback-only weakening "shipped default"
// although the operator wrote it.
func TestInsecureSettingsRegistry_SourcePathsCoverEveryAliasRowNewPath(t *testing.T) {
	byAlias := map[string]InsecureSetting{}
	for _, e := range InsecureSettingsRegistry {
		if e.DeprecatedAlias != "" {
			byAlias[e.DeprecatedAlias] = e
		}
	}
	for _, a := range deprecatedSettingAliases {
		// A fallbacks[] row has the same setting as the primary's row.
		e, ok := byAlias[strings.Replace(a.OldPath, "fallbacks[].", "", 1)]
		if !ok {
			continue // not a registry-backed setting (nothing to label)
		}
		want := flattenSequencePath(a.NewPath)
		found := false
		for _, p := range e.SourcePaths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("registry entry %q: SourcePaths %v omit %q, the current spelling of alias row %q", e.Name, e.SourcePaths, want, a.OldPath)
		}
	}
}
