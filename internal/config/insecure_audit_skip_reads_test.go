package config

// insecure_audit_skip_reads_test.go -- ADR-112 Amendment 4
// (storage.database.insecure_audit_skip_reads): default off, a registry entry
// with the full opt-out treatment, config file only, and refused by a
// compliance profile.
//
// The reachability tests reuse audit_durability_reachability_test.go's walker
// and comment stripping, and have the same stated limits: they recognise the
// literal selector `.InsecureAuditSkipReads` and KEYORIX_* environment names
// only, not a copy of the field under another name.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// insecureAuditSkipReadsRawFieldAllowedFiles is every non-test file outside
// internal/config allowed to read the raw field, with the reason. Each one
// only READS it; TestInsecureAuditSkipReads_NoWriteAssignment forbids writes.
var insecureAuditSkipReadsRawFieldAllowedFiles = map[string]string{
	"server/main.go": "wires the setting into core (SetInsecureAuditSkipReads) and writes the per-start " +
		"admin.audit_reads_skipped_at_startup event",
	"server/http/handlers/system.go": "reports security.audit_reads_skipped in GET /system/info",
	"internal/startup/validation.go": "reports the deviation in `admin validate`",
}

var insecureAuditSkipReadsSelectorRe = regexp.MustCompile(`\.InsecureAuditSkipReads\b`)

func writeSkipReadsConfig(t *testing.T, extraDatabaseLines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n" + extraDatabaseLines
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func skipReadsRegistryEntry(t *testing.T) InsecureSetting {
	t.Helper()
	for _, s := range InsecureSettingsRegistry {
		if s.Name == InsecureAuditSkipReadsSettingName {
			return s
		}
	}
	t.Fatalf("%s has no InsecureSettingsRegistry entry, so it gets no start-up WARNING, no settings-diff "+
		"audit and no posture deviation", InsecureAuditSkipReadsSettingName)
	return InsecureSetting{}
}

// Default false: a config file that does not name the key leaves reads audited,
// and the registry entry is not in effect.
func TestInsecureAuditSkipReads_DefaultFalse(t *testing.T) {
	cfg, err := Load(writeSkipReadsConfig(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.Database.InsecureAuditSkipReads {
		t.Fatal("insecure_audit_skip_reads must default to false")
	}
	e := skipReadsRegistryEntry(t)
	if e.InEffect(cfg) || e.Value(cfg) != "false" {
		t.Fatalf("default config: InEffect=%v Value=%q, want false/\"false\"", e.InEffect(cfg), e.Value(cfg))
	}

	cfg, err = Load(writeSkipReadsConfig(t, "    insecure_audit_skip_reads: true\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Storage.Database.InsecureAuditSkipReads || !e.InEffect(cfg) || e.Value(cfg) != "true" {
		t.Fatalf("the config file key must set it: field=%v InEffect=%v Value=%q",
			cfg.Storage.Database.InsecureAuditSkipReads, e.InEffect(cfg), e.Value(cfg))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("with no compliance profile, the setting must be accepted: %v", err)
	}
}

// Registry structural test: the entry has the insecure_ prefix, sources its
// own key, and its Describe says plainly that reads are not audited (that text
// is the start-up WARNING and the posture deviation).
func TestInsecureAuditSkipReads_RegistryEntry(t *testing.T) {
	e := skipReadsRegistryEntry(t)
	if leaf := e.Name[strings.LastIndex(e.Name, ".")+1:]; !strings.HasPrefix(leaf, "insecure_") {
		t.Errorf("leaf %q lacks the insecure_ prefix", leaf)
	}
	if len(e.SourcePaths) != 1 || e.SourcePaths[0] != InsecureAuditSkipReadsSettingName {
		t.Errorf("SourcePaths = %v, want [%s]", e.SourcePaths, InsecureAuditSkipReadsSettingName)
	}
	if !strings.Contains(e.Describe, "secret reads are NOT audited") {
		t.Errorf("Describe must say \"secret reads are NOT audited\": %q", e.Describe)
	}
	if e.DeprecatedAlias != "" {
		t.Errorf("a new setting has no deprecated alias, got %q", e.DeprecatedAlias)
	}
}

// Every non-test file outside internal/config that references the raw field is
// allowlisted with a reason, and every allowlist entry is still live.
func TestInsecureAuditSkipReads_ReferencesAreAllowlisted(t *testing.T) {
	root := repoRootForFastAuditScan()
	actual := map[string]bool{}
	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if !strings.HasPrefix(rel, "internal/config/") && insecureAuditSkipReadsSelectorRe.Match(stripGoComments(data)) {
			actual[rel] = true
		}
	})
	for path := range actual {
		if _, ok := insecureAuditSkipReadsRawFieldAllowedFiles[path]; !ok {
			t.Errorf("%s references DatabaseConfig.InsecureAuditSkipReads but is not in "+
				"insecureAuditSkipReadsRawFieldAllowedFiles; add it with the reason", path)
		}
	}
	for path := range insecureAuditSkipReadsRawFieldAllowedFiles {
		if !actual[path] {
			t.Errorf("allowlist entry %s no longer references the field; remove it", path)
		}
	}
}

// Config file only: no Go code outside internal/config/config.go assigns the
// field, so no HTTP handler, gRPC RPC or CLI flag can turn read auditing off.
func TestInsecureAuditSkipReads_NoWriteAssignment(t *testing.T) {
	writeRe := regexp.MustCompile(`\.InsecureAuditSkipReads\s*=[^=]|SetInsecureAuditSkipReads\(\s*true`)
	walkMainModuleGoFiles(t, repoRootForFastAuditScan(), func(rel string, data []byte) {
		if m := writeRe.Find(stripGoComments(data)); m != nil {
			t.Errorf("%s: %q looks like a write to insecure_audit_skip_reads outside the config file. ADR-112 "+
				"Amendment 4 makes it settable from the config FILE ONLY; a remotely reachable way to stop "+
				"auditing reads must not ship.", rel, m)
		}
	})
}

// Config file only, the environment half: no KEYORIX_* variable names it.
func TestInsecureAuditSkipReads_NotSettableFromTheEnvironment(t *testing.T) {
	envRe := regexp.MustCompile(`(?i)KEYORIX_[A-Z0-9_]*SKIP_READS[A-Z0-9_]*`)
	walkMainModuleGoFiles(t, repoRootForFastAuditScan(), func(rel string, data []byte) {
		if m := envRe.FindString(string(data)); m != "" {
			t.Errorf("%s introduces an environment variable %q for insecure_audit_skip_reads; it is config "+
				"file only", rel, m)
		}
	})
	t.Setenv("KEYORIX_STORAGE_DATABASE_INSECURE_AUDIT_SKIP_READS", "true")
	cfg, err := Load(writeSkipReadsConfig(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.Database.InsecureAuditSkipReads {
		t.Fatal("an environment variable turned insecure_audit_skip_reads on")
	}
}

// The refusal hook: an active compliance profile refuses the setting at
// Validate, naming both; an inactive profile, or the setting off, passes.
func TestInsecureAuditSkipReads_RefusedByAnActiveComplianceProfile(t *testing.T) {
	active := true
	gates := []ComplianceProfileGate{{Name: "security.compliance_profile", Active: func(*Config) bool { return active }}}
	cfg := &Config{}
	cfg.Storage.Database.InsecureAuditSkipReads = true

	err := refuseSkipReadsUnderProfiles(cfg, gates)
	if err == nil {
		t.Fatal("an active compliance profile must refuse insecure_audit_skip_reads")
	}
	for _, want := range []string{InsecureAuditSkipReadsSettingName, "security.compliance_profile"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %s", err, want)
		}
	}
	active = false
	if err := refuseSkipReadsUnderProfiles(cfg, gates); err != nil {
		t.Errorf("an inactive profile must not refuse: %v", err)
	}
	active = true
	cfg.Storage.Database.InsecureAuditSkipReads = false
	if err := refuseSkipReadsUnderProfiles(cfg, gates); err != nil {
		t.Errorf("a profile must not refuse a config that leaves reads audited: %v", err)
	}
}

// The tripwire for "when one is added": a compliance-profile-looking key in
// Config's YAML surface must be registered in complianceProfileGates, so the
// refusal cannot be forgotten. Green today because no such key exists.
func TestInsecureAuditSkipReads_ComplianceProfileKeyIsGated(t *testing.T) {
	profileRe := regexp.MustCompile(`(?i)(^|[._])(compliance[._a-z]*profile|profile[._a-z]*compliance|compliance_mode)($|[._])`)
	gated := map[string]bool{}
	for _, g := range complianceProfileGates {
		gated[g.Name] = true
	}
	for _, path := range liveConfigSurfacePaths() {
		if profileRe.MatchString(path) && !gated[path] {
			t.Errorf("config key %s looks like a compliance profile setting but is not in complianceProfileGates: "+
				"ADR-112 Amendment 4 requires a compliance profile to refuse %s", path, InsecureAuditSkipReadsSettingName)
		}
	}
	// Calibration: the pattern does match the shapes it is meant to catch.
	for _, p := range []string{"security.compliance_profile", "compliance.profile", "compliance_mode"} {
		if !profileRe.MatchString(p) {
			t.Errorf("tripwire pattern misses %q", p)
		}
	}
	if profileRe.MatchString("compliance_digest.enabled") {
		t.Error("tripwire pattern must not match the unrelated compliance_digest settings")
	}
}
