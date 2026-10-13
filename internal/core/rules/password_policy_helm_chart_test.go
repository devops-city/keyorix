// password_policy_helm_chart_test.go -- SESSION U guard U3: the Helm chart
// and the server disagreeing on a validation rule (admin password length,
// #2271) broke CI jobs once already. deploy/helm/keyorix/templates/secret.yaml
// hardcodes a 16-character minimum for auth.adminPassword in its own `fail`
// check -- this test asserts that hardcoded number never drifts from the
// server's real bootstrap policy by reading the minimum from
// DefaultPasswordPolicy().MinLength (this file's own source of truth, not a
// second hand-copied constant) and rendering the chart at MinLength-1 (must
// fail with the chart's own message) and MinLength (must render).
//
// Skips cleanly if helm is not installed, so `go test ./...` still passes
// with no helm on PATH. CI DOES have helm on PATH for the "helm-chart" job
// (.github/workflows/ci.yml installs it via azure/setup-helm), so this check
// actually runs there.
package rules

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// repoRootForHelmChartTest locates the repository root relative to this
// file's own location on disk, so the test works regardless of the test
// runner's working directory (matches the repoRootG1619/repoRootU1 pattern
// used by this campaign's other AST/external-tool guard tests).
func repoRootForHelmChartTest() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

// renderKeyorixChart runs `helm template` against deploy/helm/keyorix with
// the given admin password, returning combined stdout+stderr and the
// resulting error (non-nil on a template `fail`). --set-string forces the
// value to be treated as a string even when it looks like a plain number
// (a bare `--set` would otherwise coerce e.g. "1234567890123456" to an
// int64, which the chart's own `len` check cannot operate on).
func renderKeyorixChart(adminPassword string) (string, error) {
	chartPath := filepath.Join(repoRootForHelmChartTest(), "deploy", "helm", "keyorix")
	cmd := exec.Command("helm", "template", "kx", chartPath, //nolint:gosec // fixed binary name, fixed chart path derived from this file's own location, not external input
		"--set", "auth.masterPassword=x",
		"--set", "postgresql.auth.password=x",
		"--set-string", "auth.adminPassword="+adminPassword,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestHelmChart_AdminPasswordMinLength_MatchesServerPolicy(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart-vs-server admin-password-length conformance check")
	}

	minLen := DefaultPasswordPolicy().MinLength

	t.Run("one below the server minimum fails with the chart's own message", func(t *testing.T) {
		out, err := renderKeyorixChart(strings.Repeat("a", minLen-1))
		if err == nil {
			t.Fatalf("expected `helm template` to refuse a %d-character auth.adminPassword (server minimum is %d), but it rendered successfully -- "+
				"the chart's own length check (deploy/helm/keyorix/templates/secret.yaml) has drifted from rules.DefaultPasswordPolicy().MinLength:\n%s",
				minLen-1, minLen, out)
		}
		if !strings.Contains(out, "auth.adminPassword must be at least") {
			t.Fatalf("`helm template` failed as expected for a too-short auth.adminPassword, but not with the chart's own length-check message -- "+
				"got:\n%s", out)
		}
	})

	t.Run("exactly the server minimum renders successfully", func(t *testing.T) {
		out, err := renderKeyorixChart(strings.Repeat("a", minLen))
		if err != nil {
			t.Fatalf("expected `helm template` to accept a %d-character auth.adminPassword (the server's own minimum), but it failed: %v\n%s",
				minLen, err, out)
		}
		if !strings.Contains(out, "KEYORIX_ADMIN_PASSWORD:") {
			t.Fatalf("`helm template` succeeded but the rendered Secret has no KEYORIX_ADMIN_PASSWORD key:\n%s", out)
		}
	})
}

// renderKeyorixChartAdmin renders the chart with an admin identity as well as a
// password (#3201).
func renderKeyorixChartAdmin(adminPassword, username, email string) (string, error) {
	chartPath := filepath.Join(repoRootForHelmChartTest(), "deploy", "helm", "keyorix")
	cmd := exec.Command("helm", "template", "kx", chartPath, //nolint:gosec // fixed binary name, fixed chart path derived from this file's own location, not external input
		"--set", "auth.masterPassword=x",
		"--set", "postgresql.auth.password=x",
		"--set-string", "auth.adminPassword="+adminPassword,
		"--set-string", "auth.adminUsername="+username,
		"--set-string", "auth.adminEmail="+email,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// #3201: a first-admin password that embeds the admin's identity is refused by
// the server at first boot (crash-looping pod). The chart must refuse it at
// render time, and the chart's verdict must agree with the server's policy for
// every case, so the two cannot drift: each case is checked against
// DefaultPasswordPolicy().Validate (the personal-info rule) as well as the chart.
func TestHelmChart_AdminPasswordContainingIdentity_MatchesServerPolicy(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart-vs-server admin-password identity conformance check")
	}
	policy := DefaultPasswordPolicy()
	cases := []struct {
		name, password, username, email string
		wantRefused                     bool
	}{
		{"issue repro: contains the default username", "Dw5-Admin-Passphrase#2026", "admin", "admin@keyorix.local", true},
		{"case-insensitive", "Dw5-ADMIN-Passphrase#2026", "admin", "admin@keyorix.local", true},
		{"contains a custom username", "Correct-Horse-Boss-2026", "boss", "b@keyorix.local", true},
		{"contains the email local part", "Correct-Horse-ops.team-2026", "root", "ops.team@keyorix.local", true},
		{"contains the display name", "Dw5-Administrator-Pass#2026", "root", "r@keyorix.local", true},
		{"valid password still renders", "Correct-Horse-Battery-2026", "admin", "admin@keyorix.local", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverErr := policy.Validate(tc.password, &models.User{Username: tc.username, Email: tc.email, DisplayName: "Administrator"})
			serverRefuses := serverErr != nil && strings.Contains(serverErr.Error(), "username, email, or display name")
			if serverRefuses != tc.wantRefused {
				t.Fatalf("test case disagrees with the server policy: server refusal=%v (err=%v), case wants %v", serverRefuses, serverErr, tc.wantRefused)
			}
			out, err := renderKeyorixChartAdmin(tc.password, tc.username, tc.email)
			if tc.wantRefused {
				if err == nil {
					t.Fatalf("chart rendered a password the server refuses:\n%s", out)
				}
				if !strings.Contains(out, "auth.adminPassword must not contain") {
					t.Fatalf("chart failed, but not with the identity message:\n%s", out)
				}
				if strings.Contains(out, tc.password) {
					t.Fatalf("the chart error echoes the password:\n%s", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("chart refused a password the server accepts: %v\n%s", err, out)
			}
		})
	}
}
