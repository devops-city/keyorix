// audit_durability_test.go — ADR-112 Amendment 3 (Andrei, 2026-10-15):
// storage.database.audit_durability = strict | standard, standard by default
// on PostgreSQL, strict only on SQLite, with the old
// insecure_audit_skip_durable_sync boolean as a deprecated alias.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeAuditDurabilityConfig writes a minimal, otherwise-valid config for
// storageType with extra lines appended to its storage.database block, so the
// arms of every case below differ only in those lines.
func writeAuditDurabilityConfig(t *testing.T, storageType string, dbLines ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("storage:\n  type: " + storageType + "\n  database:\n")
	switch storageType {
	case "local", "sqlite":
		b.WriteString("    path: ./secrets.db\n")
	case "postgres", "postgresql":
		b.WriteString("    host: db\n    name: keyorix\n    user: keyorix\n")
	}
	for _, l := range dbLines {
		b.WriteString("    " + l + "\n")
	}
	b.WriteString("  encryption:\n    enabled: false\n")
	b.WriteString("server:\n  http:\n    enabled: false\n  grpc:\n    enabled: false\n")
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

func loadAndValidate(t *testing.T, path string) (*Config, error) {
	t.Helper()
	cfg, err := Load(path)
	require.NoError(t, err, "Load itself must succeed -- every refusal here belongs to Validate")
	return cfg, cfg.Validate()
}

// TestEffectiveAuditDurability_DefaultPerBackend: a config that sets neither
// key gets standard on PostgreSQL and strict everywhere else.
func TestEffectiveAuditDurability_DefaultPerBackend(t *testing.T) {
	for storageType, want := range map[string]AuditDurabilityLevel{
		"postgres":   AuditDurabilityStandard,
		"postgresql": AuditDurabilityStandard,
		"local":      AuditDurabilityStrict,
		"sqlite":     AuditDurabilityStrict,
		"remote":     AuditDurabilityStrict,
		"":           AuditDurabilityStrict,
		"postgress":  AuditDurabilityStrict, // allowlist: an unknown backend never claims standard
	} {
		st := (&DatabaseConfig{}).EffectiveAuditDurability(storageType)
		require.Equal(t, want, st.Level, "storage.type %q", storageType)
		require.False(t, st.Explicit, "storage.type %q: nothing was written, so this is the backend default", storageType)
	}

	// Through Load, so the default is what a real config file gets.
	for _, storageType := range []string{"postgres", "postgresql"} {
		cfg, err := loadAndValidate(t, writeAuditDurabilityConfig(t, storageType))
		require.NoError(t, err)
		require.Equal(t, AuditDurabilityStandard, cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).Level)
	}
	cfg, err := loadAndValidate(t, writeAuditDurabilityConfig(t, "local"))
	require.NoError(t, err)
	require.Equal(t, AuditDurabilityStrict, cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).Level)
}

// TestEffectiveAuditDurability_ExplicitLevelsAndAlias covers the explicit
// setting and the deprecated alias's mapping: true -> standard, explicit
// false -> strict.
func TestEffectiveAuditDurability_ExplicitLevelsAndAlias(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  AuditDurabilityLevel
	}{
		{"audit_durability: strict", []string{"audit_durability: strict"}, AuditDurabilityStrict},
		{"audit_durability: standard", []string{"audit_durability: standard"}, AuditDurabilityStandard},
		{"alias true -> standard", []string{"insecure_audit_skip_durable_sync: true"}, AuditDurabilityStandard},
		{"alias explicit false -> strict", []string{"insecure_audit_skip_durable_sync: false"}, AuditDurabilityStrict},
		{"both, agreeing (standard)", []string{"audit_durability: standard", "insecure_audit_skip_durable_sync: true"}, AuditDurabilityStandard},
		{"both, agreeing (strict)", []string{"audit_durability: strict", "insecure_audit_skip_durable_sync: false"}, AuditDurabilityStrict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadAndValidate(t, writeAuditDurabilityConfig(t, "postgres", tc.lines...))
			require.NoError(t, err)
			st := cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type)
			require.Equal(t, tc.want, st.Level)
			require.True(t, st.Explicit)
		})
	}
}

// TestConfigValidate_RejectsStandardAuditDurabilityOnSQLite: SQLite runs
// strict only; standard (by name or through the alias) refuses to start with
// the named error. Both directions: strict, an explicit false alias and no
// setting at all still validate on SQLite.
func TestConfigValidate_RejectsStandardAuditDurabilityOnSQLite(t *testing.T) {
	for _, storageType := range []string{"local", "sqlite"} {
		for _, line := range []string{"audit_durability: standard", "insecure_audit_skip_durable_sync: true"} {
			t.Run(storageType+"/"+line, func(t *testing.T) {
				_, err := loadAndValidate(t, writeAuditDurabilityConfig(t, storageType, line))
				require.Error(t, err, "standard on SQLite must refuse to start, never be ignored")
				require.Equal(t, auditDurabilityStandardSQLiteUnsupportedError, err.Error())
				require.Contains(t, err.Error(), "only supported with PostgreSQL")
			})
		}
		for _, lines := range [][]string{nil, {"audit_durability: strict"}, {"insecure_audit_skip_durable_sync: false"}} {
			t.Run(storageType+"/allowed "+strings.Join(lines, ","), func(t *testing.T) {
				_, err := loadAndValidate(t, writeAuditDurabilityConfig(t, storageType, lines...))
				require.NoError(t, err, "SQLite with strict (or nothing) must validate -- otherwise the check rejects every SQLite install")
			})
		}
	}
}

// TestConfigValidate_AllowsBothAuditDurabilityLevelsOnPostgres keeps the
// SQLite refusal from hiding a check that rejects standard everywhere.
func TestConfigValidate_AllowsBothAuditDurabilityLevelsOnPostgres(t *testing.T) {
	for _, storageType := range []string{"postgres", "postgresql"} {
		for _, level := range []string{"strict", "standard"} {
			_, err := loadAndValidate(t, writeAuditDurabilityConfig(t, storageType, "audit_durability: "+level))
			require.NoError(t, err, "storage.type %q, audit_durability %q", storageType, level)
		}
	}
}

// TestConfigValidate_RefusesConflictingAuditDurabilityAlias: both keys set
// with conflicting levels refuses to start; neither may silently win.
func TestConfigValidate_RefusesConflictingAuditDurabilityAlias(t *testing.T) {
	for _, lines := range [][]string{
		{"audit_durability: strict", "insecure_audit_skip_durable_sync: true"},
		{"audit_durability: standard", "insecure_audit_skip_durable_sync: false"},
	} {
		t.Run(strings.Join(lines, ","), func(t *testing.T) {
			cfg, err := loadAndValidate(t, writeAuditDurabilityConfig(t, "postgres", lines...))
			require.Error(t, err)
			require.Contains(t, err.Error(), "remove the deprecated key")
			require.Contains(t, err.Error(), "insecure_audit_skip_durable_sync")
			// A config that skipped Validate still reports what it really does
			// rather than either key's claim.
			require.Equal(t, AuditDurabilityStrict, cfg.Storage.Database.EffectiveAuditDurability("postgres").Level)
		})
	}
}

func TestConfigValidate_RejectsUnknownAuditDurability(t *testing.T) {
	_, err := loadAndValidate(t, writeAuditDurabilityConfig(t, "postgres", "audit_durability: fast"))
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown value "fast"`)
}

// TestLoad_DeprecatedAuditDurabilityAliasAddsDeprecationLine: the old key
// works, but never silently -- Load records one deprecation line naming the
// replacement, which server/main.go logs at start-up.
func TestLoad_DeprecatedAuditDurabilityAliasAddsDeprecationLine(t *testing.T) {
	for alias, level := range map[string]string{"true": "standard", "false": "strict"} {
		cfg, err := loadAndValidate(t, writeAuditDurabilityConfig(t, "postgres", "insecure_audit_skip_durable_sync: "+alias))
		require.NoError(t, err)
		require.Len(t, cfg.DeprecatedSettingWarnings, 1)
		w := cfg.DeprecatedSettingWarnings[0]
		require.Contains(t, w, "insecure_audit_skip_durable_sync")
		require.Contains(t, w, "deprecated")
		require.Contains(t, w, "storage.database.audit_durability: "+level)
	}
	cfg, err := loadAndValidate(t, writeAuditDurabilityConfig(t, "postgres", "audit_durability: strict"))
	require.NoError(t, err)
	require.Empty(t, cfg.DeprecatedSettingWarnings, "the current key must not log a deprecation line")
}

// TestAuditDurabilityStatus_StartupLine pins the INFO line every start logs.
func TestAuditDurabilityStatus_StartupLine(t *testing.T) {
	std := AuditDurabilityStatus{Level: AuditDurabilityStandard}.StartupLine()
	require.Equal(t, "audit durability: standard (PostgreSQL default; committed before every disclosure; "+
		"up to ~600 ms of entries can be lost to an OS crash or power loss; set audit_durability: strict to "+
		"wait for the disk sync)", std)

	explicitStd := AuditDurabilityStatus{Level: AuditDurabilityStandard, Explicit: true}.StartupLine()
	require.NotContains(t, explicitStd, "PostgreSQL default", "an explicitly chosen level is not the default")
	require.True(t, strings.HasPrefix(explicitStd, "audit durability: standard (committed before every disclosure;"))

	strict := AuditDurabilityStatus{Level: AuditDurabilityStrict}.StartupLine()
	require.Equal(t, "audit durability: strict (committed and synced to disk before every disclosure; no audit "+
		"entry is lost to any crash or power loss)", strict)
	for _, line := range []string{std, explicitStd, strict} {
		require.NotContains(t, strings.ToUpper(line), "WARNING", "both levels are baseline; the line is INFO")
	}
}
