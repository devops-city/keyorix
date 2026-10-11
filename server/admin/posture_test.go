package admin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// writeSecureBaselineConfig writes a self-contained, secure-compliant config
// file into dir and chdirs the test there (so config.ResolvedPath("") -- used
// internally by collectFilePermissionPosture -- resolves to it), then loads
// and returns it exactly the way runAdminValidate does. Modeled on
// configs/test.yaml's minimal shape, with every security-relevant field
// flipped to its compliant value instead of that fixture's deliberate
// everything-disabled posture.
func writeSecureBaselineConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	yaml := `
locale:
  language: en
  fallback_language: en

storage:
  type: local
  database:
    path: "posture.db"
  encryption:
    enabled: false

security:
  enable_file_permission_check: true
  allow_unsafe_file_permissions: false
  require_transport_tls: false
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))
	cfg, err := config.Load("")
	require.NoError(t, err)
	// loadConfig (admin.go) always does this before any admin command touches
	// storage -- this helper bypasses loadConfig to control the YAML directly,
	// so it must replicate that one side effect, or a storage call that
	// localizes an error message panics with "i18n not initialized".
	require.NoError(t, i18n.Initialize(cfg))
	// Simulate a server that has booted at least once (the realistic target
	// of a posture check -- an operator does not run this against a config
	// whose database has never been created): without this, the database
	// file genuinely does not exist yet, and collectFilePermissionPosture's
	// ValidateStartup call would report a false permission deviation for a
	// file that simply hasn't been created, not one with a real problem.
	require.NoError(t, withUsableStorage(cfg, func(corestorage.Storage) error { return nil }))
	return cfg
}

// TestShippedProductionTemplates_ReportOnlyKnownDeviations runs the
// config-only collectors over the REAL shipped templates
// (server/config/production.yaml and web-enabled.yaml), not a synthetic
// fixture built to match.
//
// The templates genuinely do not match the secure baseline -- they ship TLS
// terminated by a fronting reverse proxy and no metrics token -- and the
// report must say so rather than exclude those settings (the #2478 blocker).
// What is asserted is the exact set of deviations each template produces, BY
// ORIGIN, with origin derived from what the file literally writes
// (config.ExplicitlySetPaths):
//
//   - production.yaml WRITES `require_transport_tls: false` (its comment
//     explains the proxy-fronted shape), so that one is EXPLICIT. An earlier
//     version of this test asserted "no template ever explicitly asks for a
//     weakening" and passed only because origin was keyed on Describe text,
//     which labelled this line a shipped default (coordinator review #4).
//     That claim is withdrawn: this template does ask, deliberately.
//   - web-enabled.yaml is silent on it, so there it is a shipped default.
//
// A new deviation appearing means a template was weakened (or a new registry
// entry covers something they leave open); one disappearing means a default
// got hardened. Either fails here until the table is updated on purpose.
//
// Scoped to the config-only collectors (insecure-settings registry, TLS): the
// others need disk-resident key material these templates reference by
// absolute host paths that do not exist on this machine, or a live database.
func TestShippedProductionTemplates_ReportOnlyKnownDeviations(t *testing.T) {
	known := map[string]map[string]deviationOrigin{
		"../config/production.yaml": {
			"security.insecure_allow_cleartext_transport":   originExplicit,
			"server.insecure_allow_unauthenticated_metrics": originShippedDefault,
		},
		"../config/web-enabled.yaml": {
			"security.insecure_allow_cleartext_transport":   originShippedDefault,
			"server.insecure_allow_unauthenticated_metrics": originShippedDefault,
		},
	}
	for path, want := range known {
		t.Run(path, func(t *testing.T) {
			// config.Load's traversal guard rejects a ".." path outright (it
			// reads rooted at the application directory) -- copy the real
			// template into a temp dir and chdir there so Load("") resolves
			// to the genuine, unmodified file content under its own name.
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			dir := t.TempDir()
			t.Chdir(dir)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), raw, 0600))
			cfg, err := config.Load("")
			require.NoError(t, err)
			explicit, err := config.ExplicitlySetPaths("")
			require.NoError(t, err)

			report := &postureReport{}
			collectInsecureSettingsPosture(cfg, explicit, report)
			collectTLSPosture(cfg, report)

			got := map[string]deviationOrigin{}
			for _, d := range report.deviations {
				name := strings.SplitN(d.detail, " ", 2)[0]
				got[name] = d.origin
			}
			assert.Equal(t, want, got,
				"%s's deviations changed. A new one means a template was weakened; a missing one means a default "+
					"was hardened (the goal -- update this table) or stopped being reported (the #2478 blocker "+
					"coming back). Full report: %+v", path, report.deviations)
		})
	}
}

// TestRunAdminValidatePosture_BaselineFixtureReportsOnlyKnownShippedDefaults
// is the end-to-end counterpart of the templates test above, and its assertion
// changed with this PR's blocker fix for the same reason.
//
// It used to require ZERO deviations from writeSecureBaselineConfig's fixture.
// That fixture is not actually hardened -- it disables encryption at rest
// deliberately (so the test needs no on-disk key material) and leaves
// require_transport_tls, the metrics token and API rate limiting at their
// shipped defaults. It only read as "zero" because the excluded class hid
// exactly those four. Asserting zero again would mean re-adding the exclusion.
//
// So: the deviations must be exactly the four the fixture knowingly accepts,
// each with the origin the file's own text gives it.
// TestCollectInsecureSettingsPosture_FullyHardenedConfigReportsZero below is
// what proves zero is still reachable at all.
func TestRunAdminValidatePosture_BaselineFixtureReportsOnlyKnownShippedDefaults(t *testing.T) {
	cfg := writeSecureBaselineConfig(t)
	explicit, err := config.ExplicitlySetPaths("")
	require.NoError(t, err)

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, explicit, report)

	// Origin is what the fixture file literally writes: it WRITES
	// require_transport_tls: false and storage.encryption.enabled: false, and
	// is silent on the metrics token and rate limiting.
	accepted := map[string]deviationOrigin{
		"security.insecure_allow_cleartext_transport":            originExplicit,
		"storage.encryption.insecure_disable_encryption_at_rest": originExplicit,
		"server.insecure_allow_unauthenticated_metrics":          originShippedDefault,
		"server.insecure_disable_api_ratelimit":                  originShippedDefault,
	}
	got := map[string]deviationOrigin{}
	for _, d := range report.deviations {
		got[strings.SplitN(d.detail, " ", 2)[0]] = d.origin
	}
	assert.Equal(t, accepted, got,
		"a deviation the fixture knowingly accepts stopped being reported (the #2478 blocker returning), or a new "+
			"one appeared. Got: %+v", report.deviations)
}

// TestCollectInsecureSettingsPosture_FullyHardenedConfigReportsZero is the
// calibration that stops "count everything" degenerating into "always report
// something". If the report can never come back clean, an operator has no way
// to tell a hardened install from an unhardened one and the exit code stops
// meaning anything.
//
// Built by hardening every setting the registry reads, then asserting the
// registry itself sees nothing in effect -- derived from the registry rather
// than a hand-listed set, so a new entry whose secure state this config does
// not reach fails here and has to be considered.
func TestCollectInsecureSettingsPosture_FullyHardenedConfigReportsZero(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.RequireTransportTLS = true
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Security.RequireMFA = true // #2986: security.require_mfa is a registry entry now
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Database.SSLMode = "require"
	cfg.Membership.ValidationMode = "allowlist"
	cfg.Server.HTTP.MetricsToken = "set"
	cfg.Server.GRPC.MetricsToken = "set"
	cfg.Server.HTTP.MaxRequestBodyBytes = 1 << 20
	cfg.Server.GRPC.MaxRequestBodyBytes = 1 << 20
	cfg.Server.HTTP.RateLimit.Enabled = true
	cfg.Server.GRPC.RateLimit.Enabled = true
	cfg.CredentialDelivery.Mode = "smtp"
	cfg.CredentialDelivery.SMTP.TLS = "starttls"
	cfg.Notifications.Email.TLS = "starttls"

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, nil, report)

	assert.Empty(t, report.deviations,
		"a fully hardened config must report zero — otherwise the exit code can never distinguish a hardened "+
			"install from an unhardened one. Still in effect: %+v", report.deviations)
}

func TestRunAdminValidatePosture_AdminWithoutMFAIsADeviationAndNonZeroExit(t *testing.T) {
	cfg := writeSecureBaselineConfig(t)

	err := withUsableStorage(cfg, func(store corestorage.Storage) error {
		ctx := context.Background()
		user, err := store.CreateUser(ctx, &models.User{
			Username: "root", UsernameFolded: "root", Email: "root@x.io", EmailFolded: "root@x.io",
			IsActive: true, AccountState: core.AccountActive,
		})
		if err != nil {
			return err
		}
		roleName, err := identity.NewFoldedName("admin")
		if err != nil {
			return err
		}
		role, err := store.CreateRole(ctx, roleName, "install administrator")
		if err != nil {
			return err
		}
		return store.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{})
	})
	require.NoError(t, err)

	err = runAdminValidatePosture(cfg, "")
	require.Error(t, err, "an admin-tier holder with no MFA must be a counted deviation")
}

// The explicit-path set comes from config.ExplicitlySetPaths over a real file,
// for the current insecure_ key AND its pre-#2899 deprecated alias: a file still
// writing the old name asked for the weakening just as explicitly, and must not
// be reported as a shipped default because the registry's SourcePaths now name
// the renamed key.
func TestCollectInsecureSettingsPosture_InEffectSettingIsADeviation(t *testing.T) {
	for _, key := range []string{"insecure_allow_unsafe_file_permissions", "allow_unsafe_file_permissions"} {
		t.Run(key, func(t *testing.T) {
			testInEffectSettingIsADeviation(t, key)
		})
	}
}

func testInEffectSettingIsADeviation(t *testing.T, key string) {
	cfg := &config.Config{}
	cfg.Security.AllowUnsafeFilePermissions = true
	cfg.Security.EnableFilePermissionCheck = true

	cfgPath := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("security:\n  "+key+": true\n"), 0o600))
	explicit, err := config.ExplicitlySetPaths(cfgPath)
	require.NoError(t, err)

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, explicit, report)

	// Asserts PRESENCE, not that this is the only deviation. A zero-value
	// Config has several other weakenings in effect (encryption off, TLS not
	// required, rate limiting off, ...) and since this PR's fix every one of
	// them counts -- so a Len(deviations, 1) assertion here would be asserting
	// the very exclusion the blocker fix removed.
	var found *postureDeviation
	for i := range report.deviations {
		if strings.Contains(report.deviations[i].detail, "security.insecure_allow_unsafe_file_permissions") {
			found = &report.deviations[i]
		}
	}
	require.NotNil(t, found, "expected the in-effect setting among the deviations, got: %v", report.deviations)
	assert.Equal(t, "insecure-setting", found.category)
	assert.Equal(t, originExplicit, found.origin, "the config file asked for this one, so it is not a shipped default")
}

// TestCollectInsecureSettingsPosture_EncryptionAtRestDisabledIsACountedDeviation
// is the red/green for this PR's blocker. It replaces
// TestCollectInsecureSettingsPosture_NeedsAndreiEntryIsInformationalNotADeviation,
// which asserted the OPPOSITE and is the test that locked the false all-clear
// in: it required that an entry whose Describe contains "NEEDS ANDREI" never
// counts toward the exit code.
//
// Encryption at rest is the starkest member of that excluded set. With it off,
// every secret value is stored in plaintext -- and nothing else in the report
// catches it, because collectKeyFileSetPosture early-returns when encryption
// is disabled (correctly: there is then no key material to check). So the old
// shape printed "No deviations found." and exited 0 for an install storing
// every secret in the clear.
//
// RED on the pre-fix body (`if strings.Contains(s.Describe, needsAndreiMarker)
// { report.info(...); continue }`): zero deviations, one informational line.
func TestCollectInsecureSettingsPosture_EncryptionAtRestDisabledIsACountedDeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Storage.Encryption.Enabled = false // secrets stored unencrypted at rest

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, nil, report)

	var found *postureDeviation
	for i := range report.deviations {
		if strings.Contains(report.deviations[i].detail, "insecure_disable_encryption_at_rest") {
			found = &report.deviations[i]
		}
	}
	require.NotNil(t, found,
		"encryption-at-rest disabled must be a COUNTED deviation, not informational: nothing else in the "+
			"report catches it (collectKeyFileSetPosture early-returns when encryption is off), so excluding "+
			"it means an install storing every secret in plaintext prints \"No deviations found.\" and exits 0. "+
			"Got deviations=%v informational=%v", report.deviations, report.informational)
	assert.Equal(t, "insecure-setting", found.category)

	for _, line := range report.informational {
		assert.NotContains(t, line, "insecure_disable_encryption_at_rest",
			"it must not ALSO be reported as informational — that is how the old shape read as covered")
	}
}

// TestCollectInsecureSettingsPosture_EveryPreviouslyExcludedEntryNowCounts is
// the family-wide half: the old marker match covered thirteen entries, so
// fixing only the one above would leave twelve. This drives a config in which
// each of the previously-excluded settings is in effect and asserts that each
// one lands in deviations rather than informational, keyed off the registry
// itself so a future entry cannot quietly rejoin the excluded set.
//
// RED on the pre-fix body: every one of them is informational and
// report.deviations is empty.
func TestCollectInsecureSettingsPosture_EveryPreviouslyExcludedEntryNowCounts(t *testing.T) {
	// The exact shape the old marker match excluded: a zero-value config, where
	// every polarity-inverted and sentinel-valued weakening is in its weak
	// state (encryption off, TLS not required, ssl_mode unset, no metrics
	// token, rate limiting off, ...).
	cfg := &config.Config{}

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, nil, report)

	// The set is pinned by NAME, not found by matching "NEEDS ANDREI" in Describe:
	// that marker is prose, and once the naming decisions were settled (#2984)
	// the Describe strings lost it, the old selection came back empty, and this
	// test's premise check fired on an unchanged collector. Keying a security
	// test on description text is the same unsound mechanism the collector's own
	// doc comment rejects.
	previouslyExcluded := map[string]bool{
		"security.insecure_allow_cleartext_transport":                           true,
		"security.insecure_skip_startup_validation":                             true,
		"storage.encryption.key_provider.insecure_omit_shamir_commitment_check": true,
		"storage.encryption.insecure_disable_encryption_at_rest":                true,
		"membership.insecure_skip_membership_review":                            true,
		"sso.providers.insecure_auto_provision_sso_users":                       true,
		"sso.providers.insecure_auto_sync_sso_groups":                           true,
		"server.insecure_allow_unauthenticated_metrics":                         true,
		"server.insecure_disable_max_request_body_cap":                          true,
		"storage.database.insecure_disable_database_tls":                        true,
		"server.insecure_disable_api_ratelimit":                                 true,
		"credential_delivery.insecure_allow_log_delivery":                       true,
		"credential_delivery.insecure_allow_plaintext_smtp":                     true,
	}
	inRegistry := make(map[string]bool, len(config.InsecureSettingsRegistry))
	var expected []string
	var expectedPreviouslyExcluded int
	for _, s := range config.InsecureSettingsRegistry {
		inRegistry[s.Name] = true
		// Every in-effect entry must count, not just the previously-excluded
		// ones: that is what stops a future entry quietly joining an excluded set.
		if s.InEffect(cfg) {
			expected = append(expected, s.Name)
			if previouslyExcluded[s.Name] {
				expectedPreviouslyExcluded++
			}
		}
	}
	for name := range previouslyExcluded {
		require.True(t, inRegistry[name],
			"test premise broken: previously-excluded entry %s is no longer in InsecureSettingsRegistry (renamed? update this list)", name)
	}
	require.NotZero(t, expectedPreviouslyExcluded,
		"test premise broken: expected the zero-value config to put several previously-excluded settings in effect, got in-effect=%v", expected)

	counted := make(map[string]bool, len(report.deviations))
	for _, d := range report.deviations {
		for _, name := range expected {
			if strings.Contains(d.detail, name) {
				counted[name] = true
			}
		}
	}
	for _, name := range expected {
		assert.True(t, counted[name],
			"%s is in effect and must be a COUNTED deviation — an unsettled insecure_ NAME is not a reason "+
				"to stop reporting what the setting DOES (#2478 blocker)", name)
	}
	assert.Empty(t, report.informational,
		"no in-effect weakening may be downgraded to informational, got: %v", report.informational)
}

// A weakening that is merely the current shipped default is still counted, and
// says so. This is the companion that stops the blocker fix being undone by a
// different route: an exclusion re-added as "origin shipped-default means do
// not count" would pass every test above and reopen the same hole.
func TestCollectInsecureSettingsPosture_ShippedDefaultIsLabelledButStillCounted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Security.RequireTransportTLS = false // production.yaml's deliberate proxy-fronted shape

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, nil, report)

	var found *postureDeviation
	for i := range report.deviations {
		if strings.Contains(report.deviations[i].detail, "insecure_allow_cleartext_transport") {
			found = &report.deviations[i]
		}
	}
	require.NotNil(t, found, "a cleartext-transport opt-out must still be counted, got: %v", report.deviations)
	assert.Equal(t, originShippedDefault, found.origin,
		"it must be LABELLED as a shipped default so an operator can tell it from a deliberate change")
}

func TestCollectFilePermissionPosture_ExplicitlyDisabledIsADeviation(t *testing.T) {
	yaml := strings.Replace(postureFixtureYAML, "enable_file_permission_check: true", "enable_file_permission_check: false", 1)
	cfgPath, cfg := writePostureFixture(t, yaml, 0600)

	report := &postureReport{}
	collectFilePermissionPosture(cfg, cfgPath, report)

	require.Len(t, report.deviations, 1, "got %+v", report.deviations)
	assert.Equal(t, "file-permissions", report.deviations[0].category)
	assert.Contains(t, report.deviations[0].detail, "enable_file_permission_check is disabled")
}

func TestCollectTLSPosture_CleartextWithoutRequireIsInformationalOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.TLS.Enabled = false
	cfg.Security.RequireTransportTLS = false

	report := &postureReport{}
	collectTLSPosture(cfg, report)

	assert.Empty(t, report.deviations, "production.yaml ships cleartext-by-design (reverse-proxy TLS termination); this must not be a deviation")
	assert.NotEmpty(t, report.informational)
}

func TestCollectTLSPosture_CleartextWithRequireTLSIsADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.TLS.Enabled = false
	cfg.Security.RequireTransportTLS = true

	report := &postureReport{}
	collectTLSPosture(cfg, report)

	require.Len(t, report.deviations, 1)
	assert.Equal(t, "tls", report.deviations[0].category)
}

func TestCollectTLSPosture_TLSEnabledDisabledListenerSkipped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = false
	cfg.Server.GRPC.Enabled = true
	cfg.Server.GRPC.TLS.Enabled = true

	report := &postureReport{}
	collectTLSPosture(cfg, report)

	assert.Empty(t, report.deviations)
	// Nothing at all: a disabled listener contributes nothing, and an enabled
	// listener WITH TLS has nothing to report either. (The tls_mode
	// informational line this used to expect is behind a TODO(FIX-4) in
	// collectTLSPosture -- the field is not in this PR's base chain. Restore
	// the Len(informational, 1) assertion with it.)
	assert.Empty(t, report.informational, "an enabled+TLS listener and a disabled listener both contribute nothing")
}
