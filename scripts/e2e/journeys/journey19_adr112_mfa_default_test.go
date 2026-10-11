//go:build e2e

package journeys

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_ADR112FreshInstallRequiresMFAEnrolment drives ADR-112 item 1 on a fresh
// install with the shipped config (admin init's template, security.require_mfa: true,
// enable_file_permission_check: true) the way an operator does with the CLI:
//
//  1. the server boots (the startup checks pass on a fresh install's own files);
//  2. the first admin login succeeds, but the session is confined to MFA enrolment:
//     `keyorix project list` and GET /api/v1/projects are refused with
//     MFAEnrollmentRequired, while the profile stays reachable;
//  3. `keyorix mfa enroll` + `keyorix mfa activate` enrol a TOTP factor;
//  4. `keyorix login --mfa-code` completes the two-step login, and the same commands
//     now work.
//
// Red before #2446's CLI enrolment port: `keyorix mfa enroll` does not exist on main.
func TestJourney_ADR112FreshInstallRequiresMFAEnrolment(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const adminUser = "smoketestadmin"
	adminPw := harness.BootstrapAdminPassword
	env := s.CLIEnv()

	// ── 1-2. first login works, everything but enrolment is refused ───────────
	out := runCLI(t, cliBin, env, "login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw)
	if !strings.Contains(out, "Logged in to") {
		t.Fatalf("expected the first (pre-MFA) login to succeed, got:\n%s", out)
	}
	out = runCLIExpectErr(t, cliBin, env, "project", "list")
	if !strings.Contains(out, "multi-factor") && !strings.Contains(out, "403") {
		t.Fatalf("expected project list to be refused until MFA is enrolled, got:\n%s", out)
	}

	token := adminLogin(t, s, adminUser, adminPw)
	denied := restCall(t, s, token, http.MethodGet, "/api/v1/projects", nil)
	if denied.StatusCode != http.StatusForbidden || !strings.Contains(string(denied.Raw), "MFAEnrollmentRequired") {
		t.Fatalf("GET /api/v1/projects before enrolment: want 403 MFAEnrollmentRequired, got %d: %s", denied.StatusCode, denied.Raw)
	}
	restExpect(t, s, token, http.MethodGet, "/api/v1/auth/profile", nil, http.StatusOK)

	// ── 3. enrol through the CLI ───────────────────────────────────────────────
	out = runCLI(t, cliBin, env, "mfa", "enroll")
	m := regexp.MustCompile(`(?m)^  ([A-Z2-7]{16,})$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find the base32 secret in `mfa enroll` output:\n%s", out)
	}
	secret := m[1]
	now := time.Now().UTC()
	code, burned := totpCodeAt(t, secret, now), totpStep(now)
	out = runCLI(t, cliBin, env, "mfa", "activate", "--code", code, "--password", adminPw)
	if !strings.Contains(out, "MFA enabled") || !strings.Contains(out, "recovery codes") {
		t.Fatalf("expected activation with recovery codes, got:\n%s", out)
	}

	// ── 4. two-step login, then the refused commands work ──────────────────────
	out = runCLI(t, cliBin, env, "login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw,
		"--mfa-code", totpCodeAfterStep(t, secret, burned))
	if !strings.Contains(out, "Logged in to") {
		t.Fatalf("expected the MFA login to succeed, got:\n%s", out)
	}
	runCLI(t, cliBin, env, "project", "list")

	// The fresh install was enforced, not graced: no ADR-112 grace-period warning.
	logBytes, err := os.ReadFile(s.LogPath)
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	if strings.Contains(string(logBytes), "ADR-112 grace period") {
		t.Fatalf("a fresh install must not be in the ADR-112 grace period; server log:\n%s", logBytes)
	}
}
