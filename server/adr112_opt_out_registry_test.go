// adr112_opt_out_registry_test.go -- ADR-112 (secure-by-default baseline,
// item 2): the opt-out rule's server-side wiring. The registry itself and
// its structural guarantees live in internal/config
// (insecure_settings_registry.go / insecure_settings_registry_test.go);
// these tests cover the three loops server/main.go runs over it.
package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/configs"
	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
)

// Flipping ONE setting's InEffect from false to true adds exactly one new
// warning line naming it, without disturbing whatever else a baseline
// config legitimately warns about (a bare zero-value *config.Config is NOT
// itself "clean" -- e.g. an empty metrics_token, or rate limiting defaulting
// disabled, are both genuinely in-effect weak states on the Go zero value by
// construction; this test isolates the one setting under test rather than
// asserting a raw zero-value config logs nothing at all).
func TestWarnInsecureSettingsInEffect_WarnsOnlyWhenInEffect(t *testing.T) {
	baseline := &config.Config{}
	before := captureLogs(func() { warnInsecureSettingsInEffect(baseline) })
	if strings.Contains(before, "security.insecure_allow_unsafe_file_permissions") {
		t.Fatal("test premise broken: the baseline must not already warn about this specific setting")
	}

	weak := &config.Config{}
	weak.Security.AllowUnsafeFilePermissions = true
	after := captureLogs(func() { warnInsecureSettingsInEffect(weak) })
	if !strings.Contains(after, "security.insecure_allow_unsafe_file_permissions") {
		t.Errorf("expected a warning naming the in-effect setting, got: %q", after)
	}
}

// Every DeprecatedSettingWarnings entry config.Load produced gets its own
// logged line — this is the ONLY place those warnings are surfaced, since
// config.Load itself is side-effect-free (see its own doc comment).
func TestWarnDeprecatedSettingAliases_LogsEachWarning(t *testing.T) {
	cfg := &config.Config{DeprecatedSettingWarnings: []string{"alpha is deprecated", "beta is deprecated"}}
	logged := captureLogs(func() { warnDeprecatedSettingAliases(cfg) })
	for _, want := range cfg.DeprecatedSettingWarnings {
		if !strings.Contains(logged, want) {
			t.Errorf("expected logged output to contain %q, got: %q", want, logged)
		}
	}

	none := &config.Config{}
	logged = captureLogs(func() { warnDeprecatedSettingAliases(none) })
	if logged != "" {
		t.Errorf("no deprecated warnings must log nothing, got: %q", logged)
	}
}

// securityPostureSnapshot must cover every registry entry exactly once --
// the settings-diff audit depends on this to see the whole picture every
// boot, not just whichever entries happen to be in effect right now (an
// entry flipping from in-effect back to not-in-effect is itself a change
// that must be diffable, which requires it being in BOTH snapshots).
func TestSecurityPostureSnapshot_CoversEveryRegistryEntryExactlyOnce(t *testing.T) {
	cfg := &config.Config{}
	snapshot := securityPostureSnapshot(cfg)
	if len(snapshot) != len(config.InsecureSettingsRegistry) {
		t.Fatalf("snapshot has %d entries, registry has %d", len(snapshot), len(config.InsecureSettingsRegistry))
	}
	for _, s := range config.InsecureSettingsRegistry {
		val, ok := snapshot[s.Name]
		if !ok {
			t.Errorf("snapshot missing entry %q", s.Name)
			continue
		}
		if want := s.Value(cfg); val != want {
			t.Errorf("snapshot[%q] = %q, want %q", s.Name, val, want)
		}
	}
}

// internalMarker matches text that is meant for the maintainers' working
// notes, not for an operator reading the boot log (#2979: "NEEDS ANDREI",
// "item 1", "polarity-inverted rename", "not a boolean today", issue numbers).
var internalMarker = regexp.MustCompile(`(?i)needs andrei|andrei|polarity|\bitem [0-9]|not a boolean today|known exception|#[0-9]{3,}`)

// Every start-up warning the registry loop can print must read as operator
// text. The zero-value config has several entries in effect (empty
// metrics_token, rate limiting off, TLS off, ...), so its boot log is the
// worst case for the "WARNING: ... is in effect" lines the demo showed.
func TestWarnInsecureSettingsInEffect_NoInternalMarkersInBootLog(t *testing.T) {
	out := captureLogs(func() { warnInsecureSettingsInEffect(&config.Config{}) })
	if !strings.Contains(out, "is in effect") {
		t.Fatalf("test premise broken: the zero-value config should have warnings in effect, got %q", out)
	}
	if m := internalMarker.FindString(out); m != "" {
		t.Errorf("boot log leaks an internal marker %q:\n%s", m, out)
	}
}

// The same check for every registry entry's description, in effect or not,
// so a setting nobody has in effect today cannot reintroduce a marker.
func TestInsecureSettingsRegistry_DescribeIsOperatorText(t *testing.T) {
	for _, s := range config.InsecureSettingsRegistry {
		if m := internalMarker.FindString(s.Describe); m != "" {
			t.Errorf("%s: Describe leaks an internal marker %q: %q", s.Name, m, s.Describe)
		}
	}
}

// The config `keyorix-server admin init` writes is what every new install
// boots with, so its boot log is the first thing an operator reads (#2979).
// Assert it is free of internal notes and of the "protocol_versions is set but
// NOT honored" warning the template itself used to trigger on every boot.
// The real security warnings (cleartext listener, insecure settings in effect)
// must still be there: this is about wording and noise, not about hiding state.
//
// Since the template became the secure baseline (ADR-112 §4), the relaxed
// config that still produces those warnings is the one `admin init --dev`
// writes, so this test runs against it; the secure template is covered by
// TestDefaultConfigTemplate_SecureBootLogIsOperatorText below.
func TestDefaultConfigTemplate_BootLogIsOperatorText(t *testing.T) {
	devTemplate, err := configs.DevConfigTemplate()
	if err != nil {
		t.Fatalf("dev config template: %v", err)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(devTemplate, &cfg); err != nil {
		t.Fatalf("dev config template does not parse: %v", err)
	}
	out := captureLogs(func() {
		warnInsecureSettingsInEffect(&cfg)
		_ = checkTransportTLSPosture(&cfg)
	})
	if m := internalMarker.FindString(out); m != "" {
		t.Errorf("default-config boot log leaks an internal marker %q:\n%s", m, out)
	}
	if strings.Contains(out, "NOT honored") {
		t.Errorf("the shipped template sets a field the server warns it ignores on every boot:\n%s", out)
	}
	for _, want := range []string{"is in effect", "CLEARTEXT"} {
		if !strings.Contains(out, want) {
			t.Errorf("real security warning %q went missing from the default-config boot log:\n%s", want, out)
		}
	}
}

// The secure template is the config every new install boots with: its boot log
// must be free of internal notes and the "NOT honored" noise, and it must not
// carry the cleartext-listener warning (TLS is on, require_transport_tls is set).
func TestDefaultConfigTemplate_SecureBootLogIsOperatorText(t *testing.T) {
	var cfg config.Config
	if err := yaml.Unmarshal(configs.DefaultConfigTemplate, &cfg); err != nil {
		t.Fatalf("default config template does not parse: %v", err)
	}
	out := captureLogs(func() {
		warnInsecureSettingsInEffect(&cfg)
		_ = checkTransportTLSPosture(&cfg)
	})
	if m := internalMarker.FindString(out); m != "" {
		t.Errorf("default-config boot log leaks an internal marker %q:\n%s", m, out)
	}
	if strings.Contains(out, "NOT honored") {
		t.Errorf("the shipped template sets a field the server warns it ignores on every boot:\n%s", out)
	}
	if strings.Contains(out, "CLEARTEXT") {
		t.Errorf("the secure default config boots with a cleartext listener warning:\n%s", out)
	}
}

// TestResolveADR112BootPosture_GracePeriodWarnsAndIsDiffed is #2908 at the
// boot path: an upgraded deployment (users, no enforcement marker) that never
// set security.enable_file_permission_check only WARNS on a failed startup
// check, so the opt-out warning must name insecure_skip_startup_validation and
// the settings-diff snapshot must record grace-warn-only. Once the marker
// ratchets it to enforced, neither appears and the snapshot value changes --
// which is what makes leaving the grace period an audited transition.
// RED if resolveADR112BootPosture warns before applying the grace decision.
func TestResolveADR112BootPosture_GracePeriodWarnsAndIsDiffed(t *testing.T) {
	const name = "security.insecure_skip_startup_validation"
	for _, tc := range []struct {
		label     string
		marker    bool
		wantWarn  bool
		wantValue config.StartupValidationState
	}{
		{"upgrade in grace period", false, true, config.StartupValidationGraceWarnOnly},
		{"upgrade past grace period", true, false, config.StartupValidationEnforcingImplicit},
	} {
		t.Run(tc.label, func(t *testing.T) {
			adr112GraceSoftened.Store(false)
			cfg := adr112GraceConfig(t)
			migrateADR112DB(t, cfg, 2)
			if tc.marker {
				db, err := appstorage.OpenGormDB(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := recordADR112Enforced(db, adr112FilePermEnforcedKey, time.Now()); err != nil {
					t.Fatal(err)
				}
				closeGormDB(db)
			}
			logs := captureLogs(func() { resolveADR112BootPosture(cfg) })
			if got := strings.Contains(logs, "WARNING: "+name+" is in effect"); got != tc.wantWarn {
				t.Errorf("opt-out warning for %s: got %v, want %v; logs:\n%s", name, got, tc.wantWarn, logs)
			}
			if got := securityPostureSnapshot(cfg)[name]; got != string(tc.wantValue) {
				t.Errorf("settings-diff value = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

// TestResolveADR112BootPosture_RequireMFAOptOutWarnsAndIsDiffed is #2986: an
// explicit security.require_mfa: false is an ADR-112 opt-out like any other, so
// the boot must warn naming the registry entry and the settings-diff snapshot
// must record it. Before the entry existed neither happened (the posture report
// counted it, the boot path and the audit trail did not). The grace-period
// state gets the same treatment as insecure_skip_startup_validation's (#2908):
// an upgraded deployment that never set the key does NOT enforce MFA yet.
// RED while security.require_mfa has no registry entry.
func TestResolveADR112BootPosture_RequireMFAOptOutWarnsAndIsDiffed(t *testing.T) {
	const name = "security.insecure_disable_mfa_requirement"
	for _, tc := range []struct {
		label     string
		explicit  *bool // non-nil: the config file writes require_mfa
		users     int
		marker    bool
		wantWarn  bool
		wantValue string
	}{
		{"explicit false", boolPtr(false), 0, false, true, "off"},
		{"explicit true", boolPtr(true), 0, false, false, "enforcing-explicit"},
		{"implicit, fresh install", nil, 0, false, false, "enforcing-implicit"},
		{"implicit, upgrade in grace period", nil, 2, false, true, "grace-not-enforced"},
		{"implicit, upgrade past grace period", nil, 2, true, false, "enforcing-implicit"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			adr112GraceSoftened.Store(false)
			cfg := adr112GraceConfig(t)
			if tc.explicit != nil {
				cfg.Security.RequireMFA = *tc.explicit
			} else {
				cfg.Security.RequireMFA = true
				cfg.Security.RequireMFAImplicitDefault = true
			}
			if tc.users > 0 {
				migrateADR112DB(t, cfg, tc.users)
			}
			if tc.marker {
				db, err := appstorage.OpenGormDB(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := recordADR112Enforced(db, adr112RequireMFAEnforcedKey, time.Now()); err != nil {
					t.Fatal(err)
				}
				closeGormDB(db)
			}
			logs := captureLogs(func() { resolveADR112BootPosture(cfg) })
			if got := strings.Contains(logs, "WARNING: "+name+" is in effect"); got != tc.wantWarn {
				t.Errorf("opt-out warning for %s: got %v, want %v; logs:\n%s", name, got, tc.wantWarn, logs)
			}
			if got := securityPostureSnapshot(cfg)[name]; got != tc.wantValue {
				t.Errorf("settings-diff value = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }
