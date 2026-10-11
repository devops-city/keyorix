//go:build e2e

// Package journeys, journey 16: the DEMO-1 golden path (docs/demo/GOLDEN-PATH.md) —
// the exact admin-day-one narrative a brand-new customer is walked through: org
// structure, a least-privilege user whose grant is honored at the exact boundary it
// claims (not merely "a role exists"), a full secret lifecycle (create, reveal,
// rotate, soft-delete, restore — exact value preserved throughout), a CI-style
// machine identity reading that secret over the real HTTP API, and — the one piece
// no other journey in this directory covers end to end — `admin recover-admin`'s
// break-glass account recovery, driven through the real server/CLI binaries.
//
// Deliberately narrow about what it reuses vs. owns:
//   - Audit tamper-detection (modified/deleted row -> VALID/BROKEN) is journey3's
//     job; this journey only confirms the admin's reveal and the machine's read
//     are findable and that the untampered chain reports VALID — not a second
//     tamper-detection assertion.
//   - Backup/restore/encryption-rotation disaster recovery is journey6's job.
//     `admin recover-admin` (a locked-out ADMIN ACCOUNT, not a lost database) is a
//     different recovery story with no existing e2e coverage anywhere in this
//     repo (confirmed: `grep -rl recover-admin scripts/e2e` found nothing before
//     this file) — that gap is this journey's actual reason to exist.
//   - Does not exercise MFA enrollment or a live-server admin backup/recovery-key
//     command: both are open DEMO-1 findings (#2552, #2540/#2602) that fail by
//     design today; this journey guards what currently works, not what's already
//     tracked as broken. Extend it once those land.
package journeys

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	n16ProjectName    = "n16-backend-api"
	n16EnvName        = "development"
	n16SecretName     = "n16-stripe-api-key"
	n16SecretValueV1  = "n16-sk-test-v1-8a2f"
	n16SecretValueV2  = "n16-sk-test-v2-rotated-c71e"
	n16LeastPrivUser  = "n16-alice"
	n16LeastPrivEmail = "n16-alice@example.invalid"
	n16LeastPrivPass  = "Harbor-Nettle-24-Fjord!"
	n16MachineName    = "n16-ci-app"
	// harness.StartServer always bootstraps this exact username/email/password.
	n16AdminUser  = "smoketestadmin"
	n16AdminEmail = "smoketestadmin@example.invalid"
)

func TestJourney_GoldenPath(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite-goldenpath"})
	// Close is safe to call again even after this test's own mid-run s.Close()
	// below (it only Kills a still-live process; a second call on an already-
	// exited one is a no-op), so one unconditional Cleanup covers both.
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, n16AdminUser, harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── Org structure ───────────────────────────────────────────────────────────
	runCLI(t, cliBin, aEnv, "project", "create", "--name", n16ProjectName)
	projID := projectID(t, s, adminToken, n16ProjectName)
	envID := environmentID(t, s, adminToken, projID, n16EnvName)

	// ── Least-privilege user: grant honored at the exact scope claimed ──────────
	runCLI(t, cliBin, aEnv, "user", "create", "--username", n16LeastPrivUser,
		"--email", n16LeastPrivEmail, "--password", n16LeastPrivPass)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", n16LeastPrivEmail,
		"--role", "project_viewer", "--project", n16ProjectName)

	aliceToken := mfaPersonaLogin(t, s, n16LeastPrivUser, n16LeastPrivPass)
	// She can read the ONE project she was granted...
	restExpect(t, s, aliceToken, http.MethodGet, "/api/v1/projects/"+strconv.Itoa(projID), nil, http.StatusOK)
	// ...and since #2780 the all-projects list is least-privilege rather than
	// admin-only: it answers 200 with exactly the projects this persona can
	// already read one-by-one, instead of the 403 that used to empty the web
	// project switcher for them. The boundary DEMO-1 (#2562) found is still the
	// thing under test, it just moved from the status code into the filter — so
	// assert the SET: her one granted project is served, and nothing else is.
	scopedEnv := restCall(t, s, aliceToken, http.MethodGet, "/api/v1/projects", nil)
	if scopedEnv.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/projects as a project-scoped viewer: want 200, got %d: %s",
			scopedEnv.StatusCode, scopedEnv.Raw)
	}
	if got := listedProjectNames(t, scopedEnv); len(got) != 1 || got[0] != n16ProjectName {
		t.Fatalf("GET /api/v1/projects as a project-scoped viewer: want exactly [%s], got %v: %s",
			n16ProjectName, got, scopedEnv.Raw)
	}

	// ── Secret lifecycle: create, reveal, rotate, soft-delete, restore ──────────
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n16SecretName,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID),
		"--value", n16SecretValueV1)
	secID := secretID(t, s, adminToken, projID, envID, n16SecretName)

	getOut := runCLI(t, cliBin, aEnv, "secret", "get", "--id", strconv.Itoa(secID), "--show-value")
	if got := parseDecryptedValue(t, getOut); got != n16SecretValueV1 {
		t.Fatalf("secret get after create: want %q, got %q", n16SecretValueV1, got)
	}

	runCLI(t, cliBin, aEnv, "secret", "rotate", "--id", strconv.Itoa(secID), "--value", n16SecretValueV2)
	getOut = runCLI(t, cliBin, aEnv, "secret", "get", "--id", strconv.Itoa(secID), "--show-value")
	if got := parseDecryptedValue(t, getOut); got != n16SecretValueV2 {
		t.Fatalf("secret get after rotate: want %q, got %q", n16SecretValueV2, got)
	}
	versionsOut := runCLI(t, cliBin, aEnv, "secret", "versions", "--id", strconv.Itoa(secID))
	if !strings.Contains(versionsOut, "Total Versions: 2") {
		t.Fatalf("secret versions after one rotate: want 2 total versions, got:\n%s", versionsOut)
	}

	runCLI(t, cliBin, aEnv, "secret", "delete", "--id", strconv.Itoa(secID), "--force")
	trashOut := runCLI(t, cliBin, aEnv, "secret", "trash", "--project", strconv.Itoa(projID))
	if !strings.Contains(trashOut, n16SecretName) {
		t.Fatalf("secret trash after delete: want %q listed, got:\n%s", n16SecretName, trashOut)
	}
	runCLI(t, cliBin, aEnv, "secret", "restore", "--id", strconv.Itoa(secID))
	getOut = runCLI(t, cliBin, aEnv, "secret", "get", "--id", strconv.Itoa(secID), "--show-value")
	if got := parseDecryptedValue(t, getOut); got != n16SecretValueV2 {
		t.Fatalf("secret get after restore: want the exact pre-delete value %q, got %q", n16SecretValueV2, got)
	}

	// ── A CI-style machine identity reads the secret over the real HTTP API ─────
	runCLI(t, cliBin, aEnv, "machine", "create", "--name", n16MachineName,
		"--project", n16ProjectName, "--type", "ci")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", n16MachineName,
		"--project", n16ProjectName, "--role", "project_viewer")
	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", n16MachineName,
		"--name", "n16-ci-token", "--project", n16ProjectName)
	machineToken, _ := parseIssuedToken(t, issueOut)

	machEnv := restExpect(t, s, machineToken, http.MethodGet, "/api/v1/secrets/"+strconv.Itoa(secID), nil, http.StatusOK)
	var machSecret struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(machEnv.Data, &machSecret); err != nil {
		t.Fatalf("decode machine identity's GET /api/v1/secrets/%d: %v\nraw: %s", secID, err, machEnv.Data)
	}
	if machSecret.Name != n16SecretName {
		t.Fatalf("machine identity read the wrong secret: want %q, got %q", n16SecretName, machSecret.Name)
	}

	// ── Audit: find the reveal and the machine read; confirm the chain is VALID ──
	// (Tamper-detection itself is journey3's job — this is a find+verify check.)
	logsOut := runCLI(t, cliBin, aEnv, "audit", "logs", "--limit", "50")
	if !strings.Contains(logsOut, "secret.read") {
		t.Fatalf("audit logs: expected to find a secret.read event, got:\n%s", logsOut)
	}
	if _, err := runCLIRaw(cliBin, aEnv, "audit", "verify"); err != nil {
		t.Fatalf("audit verify on an untampered chain: want success, got: %v", err)
	}

	// ── admin recover-admin: the break-glass account-recovery story ─────────────
	// No existing journey drives this end to end; it's this journey's reason to
	// exist. Needs the server stopped first (the same exclusive-DB-lock guard
	// every `admin` subcommand takes -- DEMO-1 #2540/#2602 found this also
	// blocks running several of these commands against a LIVE server, which is
	// a separate, already-filed finding; this journey follows the documented
	// workaround of stopping the server first, same as a real runbook would).
	s.Close()

	keyOut, err := harness.RunAdminCmd(serverBin, s.Dir, s.Env, "recovery-key", "rotate", "--config", s.ConfigPath)
	if err != nil {
		t.Fatalf("admin recovery-key rotate: %v\n%s", err, keyOut)
	}
	recoveryKey := parseRecoveryKey(t, keyOut)

	recoverOut, err := runAdminRecoverAdmin(serverBin, s.Dir, s.Env, s.ConfigPath, n16AdminEmail, recoveryKey)
	if err != nil {
		t.Fatalf("admin recover-admin: %v\n%s", err, recoverOut)
	}
	oneTimePassword := parseOneTimePassword(t, recoverOut)

	// restartServer (defined in journey8) brings s back up in place, same
	// dir/config/port -- this journey's own t.Cleanup(s.Close) above already
	// covers the restarted process too.
	restartServer(t, s)

	recoveredToken := adminLogin(t, s, n16AdminUser, oneTimePassword)
	// The one-time password forces a real reset before anything else works --
	// confirmed, not assumed: an ordinary authenticated call must still be
	// refused until the password is actually changed.
	gatedEnv := restCall(t, s, recoveredToken, http.MethodGet, "/api/v1/projects", nil)
	if gatedEnv.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /api/v1/projects with a password-reset-required session: want 403, got %d: %s",
			gatedEnv.StatusCode, gatedEnv.Raw)
	}
}

var (
	recoveryKeyRe     = regexp.MustCompile(`(?m)^\s*([A-Z0-9]{3,}(?:-[A-Z0-9]{2,}){4,})\s*$`)
	oneTimePasswordRe = regexp.MustCompile(`(?s)One-time password[^\n]*\n\s*(\S+)\n`)
)

// parseRecoveryKey extracts the dash-grouped recovery key from `admin
// recovery-key rotate`'s stdout -- shown exactly once, same shape as a
// machine token (ADR text, "shown once and cannot be recovered later").
func parseRecoveryKey(t *testing.T, out string) string {
	t.Helper()
	m := recoveryKeyRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find a dash-grouped recovery key in `admin recovery-key rotate` output:\n%s", out)
	}
	return m[1]
}

// parseOneTimePassword extracts the one-time password from `admin
// recover-admin`'s stdout.
func parseOneTimePassword(t *testing.T, out string) string {
	t.Helper()
	m := oneTimePasswordRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find a one-time password in `admin recover-admin` output:\n%s", out)
	}
	return m[1]
}

// runAdminRecoverAdmin runs `admin recover-admin`, piping the recovery key on
// stdin as the command requires ("--recovery-key must be exactly '-'") --
// harness.RunAdminCmd has no stdin support, so this journey owns its own
// exec.Command for this one case rather than widening the shared harness for
// a single caller.
func runAdminRecoverAdmin(binary, dir string, env []string, configPath, user, recoveryKey string) (string, error) {
	cmd := exec.Command(binary, "admin", "recover-admin", //nolint:gosec // fixed harness-built binary, fixed args, no external input
		"--user", user, "--recovery-key", "-", "--config", configPath)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = strings.NewReader(recoveryKey + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
