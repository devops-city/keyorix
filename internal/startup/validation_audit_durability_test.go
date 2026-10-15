package startup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditDurabilityConfigYAML is a minimal, otherwise-valid config for the
// given storage type, with extra storage.database lines, so the arms of each
// case below differ only in those lines.
func auditDurabilityConfigYAML(storageType, absDBPath string, dbLines ...string) string {
	var dbBlock string
	switch storageType {
	case "local", "sqlite":
		dbBlock = fmt.Sprintf("    path: %q\n", absDBPath)
	case "postgres":
		dbBlock = "    host: db\n    name: keyorix\n    user: keyorix\n"
	}
	for _, l := range dbLines {
		dbBlock += "    " + l + "\n"
	}
	return fmt.Sprintf(`
storage:
  type: %s
  database:
%s  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`, storageType, dbBlock)
}

// TestValidateStartup_ReportsAuditDurabilityLevelNotADeviation: admin validate
// (which prints this result) reports the effective level, and neither level is
// a Warning or an InsecureSettings entry -- standard is the PostgreSQL
// baseline (ADR-112 Amendment 3), not a posture deviation. Includes the
// deprecated alias set to true, which main reported as a deviation.
func TestValidateStartup_ReportsAuditDurabilityLevelNotADeviation(t *testing.T) {
	cases := []struct {
		name        string
		storageType string
		lines       []string
		want        config.AuditDurabilityLevel
		explicit    bool
	}{
		{"sqlite default", "local", nil, config.AuditDurabilityStrict, false},
		{"postgres default", "postgres", nil, config.AuditDurabilityStandard, false},
		{"postgres strict", "postgres", []string{"audit_durability: strict"}, config.AuditDurabilityStrict, true},
		{"postgres deprecated alias true", "postgres", []string{"insecure_audit_skip_durable_sync: true"}, config.AuditDurabilityStandard, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "keyorix.yaml")
			writeConfig(t, configPath, auditDurabilityConfigYAML(tc.storageType, filepath.Join(dir, "secrets.db"), tc.lines...))

			result, err := ValidateStartup(configPath, false)
			require.NoError(t, err)
			assert.Equal(t, tc.want, result.EffectiveAuditDurability.Level)
			assert.Equal(t, tc.explicit, result.EffectiveAuditDurability.Explicit)
			assert.Empty(t, result.InsecureSettings, "audit durability is never a structured posture deviation")
			for _, w := range result.Warnings {
				assert.NotContains(t, w, "audit", "audit durability is never a posture warning, got %q", w)
			}
		})
	}
}

// TestPrintValidationResult_ShowsAuditDurability: the printed admin validate
// output carries the level name plus its one line of meaning.
func TestPrintValidationResult_ShowsAuditDurability(t *testing.T) {
	out := captureStdout(t, func() {
		PrintValidationResult(&ValidationResult{
			ConfigValid: true, PermissionsOK: true, EncryptionOK: true, DatabaseOK: true,
			EffectiveAuditDurability: config.AuditDurabilityStatus{Level: config.AuditDurabilityStrict},
		})
	})
	assert.Contains(t, out, "Audit durability: strict (committed and synced to disk before every disclosure")
	assert.NotContains(t, out, "Warnings")
}

// TestValidateStartup_RemoteConfigIsRejectedBeforePostureReporting pins that
// a remote config never reaches posture reporting (ADR-083), instead of
// leaving it as a comment that can silently stop being true (CLAUDE.md: "when
// a verdict depends on a condition, guard the condition, not the conclusion").
func TestValidateStartup_RemoteConfigIsRejectedBeforePostureReporting(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keyorix.yaml")
	writeConfig(t, configPath, `
storage:
  type: remote
  database:
    path: ""
  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`)

	result, err := ValidateStartup(configPath, false)
	require.Error(t, err,
		"storage.type: remote must be rejected for a server config (ADR-083). If this now SUCCEEDS, remote "+
			"has become server-reachable and its audit durability needs a posture arm -- "+
			"config.EffectiveAuditDurability reports strict for it, since remote implements no relaxation.")
	assert.Contains(t, err.Error(), "remote storage is a CLI/client mode only",
		"the rejection must still be ADR-083's, not some other error that happens to fail for a different "+
			"reason -- otherwise this test would pass while the reachability claim became false")
	require.NotNil(t, result)
	assert.Empty(t, result.InsecureSettings,
		"a config that never validated must not have had posture entries computed for it")
}

// captureStdout returns what fn printed to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}
