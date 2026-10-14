package admin

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var updatePostureGolden = flag.Bool("update-posture-golden", false, "rewrite server/admin/testdata/posture_*.golden")

// postureImplicitFilePermYAML never sets security.enable_file_permission_check,
// so config.Load resolves it to its ADR-112 implicit default. require_mfa is
// set explicitly so its own grace period stays out of these reports.
const postureImplicitFilePermYAML = `
locale:
  language: en
  fallback_language: en
storage:
  type: local
  database:
    path: "{{DIR}}/posture.db"
  encryption:
    enabled: false
security:
  allow_unsafe_file_permissions: false
  require_transport_tls: true
  require_mfa: true
`

// seedPostureDeployment makes the fixture's database look like a deployment
// that has run before (one non-admin user), optionally past the
// file-permission-check grace period (marker written).
func seedPostureDeployment(t *testing.T, cfg *config.Config, users int, marker bool) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, withUsableStorage(cfg, func(store corestorage.Storage) error {
		for i := range users {
			name := "user" + string(rune('a'+i))
			if _, err := store.CreateUser(ctx, &models.User{
				Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io",
				IsActive: true, AccountState: core.AccountActive,
			}); err != nil {
				return err
			}
		}
		if marker {
			return store.SetSystemMetadata(ctx, config.ADR112FilePermEnforcedMarker, "2026-10-10T00:00:00Z")
		}
		return nil
	}))
}

// TestRunAdminValidatePosture_StartupValidationGracePeriodIsADeviation is
// #2908's end-to-end red test: an upgraded deployment (users, no
// adr112.file_permission_check.enforced marker) that never set
// security.enable_file_permission_check is inside the ADR-112 grace period,
// where the server only WARNS about a failed startup check. The posture
// report must count that as a deviation; on main it printed it as an
// informational line and the deployment's posture read clean.
func TestRunAdminValidatePosture_StartupValidationGracePeriodIsADeviation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		users         int
		marker        bool
		wantDeviation bool
	}{
		{"upgrade in grace period", 1, false, true},
		{"upgrade past grace period (marker)", 1, true, false},
		{"fresh install (no users)", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, cfg := writePostureFixture(t, postureImplicitFilePermYAML, 0600)
			require.True(t, cfg.Security.EnableFilePermissionCheckImplicitDefault, "premise: the key is absent")
			seedPostureDeployment(t, cfg, tc.users, tc.marker)

			out, _ := captureStdout(t, func() error { return runAdminValidatePosture(cfg, cfgPath) })
			counted := deviationLines(out)
			hasSkip := strings.Contains(counted, "security.insecure_skip_startup_validation")
			assert.Equal(t, tc.wantDeviation, hasSkip,
				"security.insecure_skip_startup_validation counted as a deviation: got %v, want %v\n%s", hasSkip, tc.wantDeviation, out)
		})
	}
}

// deviationLines returns only the counted part of a printed posture report
// (the informational section is cut off).
func deviationLines(out string) string {
	if before, _, ok := strings.Cut(out, "Informational (not counted"); ok {
		return before
	}
	return out
}

// TestRunAdminValidatePosture_StartupValidationGolden pins the full printed
// report for each security.enable_file_permission_check state, so a change in
// how any of them reads is a reviewed diff of testdata/posture_*.golden.
// Regenerate with: go test ./server/admin -run StartupValidationGolden -update-posture-golden
func TestRunAdminValidatePosture_StartupValidationGolden(t *testing.T) {
	wd, err := os.Getwd() // writePostureFixture chdirs away; resolve testdata first
	require.NoError(t, err)
	for _, tc := range []struct {
		golden string
		key    string // "" leaves the key absent
		users  int
		marker bool
	}{
		{"posture_startup_validation_off.golden", "false", 1, false},
		{"posture_startup_validation_grace.golden", "", 1, false},
		{"posture_startup_validation_implicit.golden", "", 1, true},
		{"posture_startup_validation_explicit.golden", "true", 1, false},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			yaml := postureImplicitFilePermYAML
			if tc.key != "" {
				yaml = strings.Replace(yaml, "security:\n", "security:\n  enable_file_permission_check: "+tc.key+"\n", 1)
			}
			cfgPath, cfg := writePostureFixture(t, yaml, 0600)
			seedPostureDeployment(t, cfg, tc.users, tc.marker)

			out, _ := captureStdout(t, func() error { return runAdminValidatePosture(cfg, cfgPath) })
			out = strings.ReplaceAll(out, filepath.Dir(cfgPath), "{{DIR}}")

			path := filepath.Join(wd, "testdata", tc.golden)
			if *updatePostureGolden {
				require.NoError(t, os.WriteFile(path, []byte(out), 0o644))
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "missing golden; regenerate with -update-posture-golden")
			assert.Equal(t, string(want), out)
		})
	}
}
