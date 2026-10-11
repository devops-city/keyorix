//go:build e2e

// Package journeys, journey 9: break-glass emergency access (R4 spec #3,
// SESSION-R's reports/SESSION-R.md "R4" section). Fast tier (no containers):
// activate (with a written justification) -> the activating user can now
// read a secret they genuinely could not read a moment before -> an
// audit event was written (reusing journey3's audit-search path, not a
// parallel assertion) -> the project's admins were notified (the real
// notification subsystem, not a stand-in) -> `break-glass list` shows the
// activation -> `break-glass revoke` -> access really reverts (re-attempted,
// not inferred from the CLI's exit code -- the "assert the effect, not the
// return value" lesson).
package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	n9ProjectName   = "n9-break-glass"
	n9EnvName       = "development" // admin init's own default seed
	n9SecretName    = "incident-db-password"
	n9SecretValue   = "n9-secret-value-7f3a21"
	n9OncallUser    = "n9-oncall"
	n9OncallEmail   = "n9-oncall@example.invalid"
	n9UserPass      = "Harbor-Quartz-19-Delta!"
	n9NoAccessRole  = "n9-no-secret-access"
	n9Justification = "sev1 incident: need read access to rotate the leaked DB credential"
)

func TestJourney_BreakGlass(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := startServerWithBreakGlass(t, serverBin)
	t.Cleanup(s.Close)

	// This journey boots with the shipped config, so security.require_mfa is on
	// (ADR-112). Prove that premise first -- an un-enrolled admin session is
	// confined to enrolment -- then enrol TOTP through the real API and work from
	// the MFA-backed session, the way a real operator on a fresh install must.
	requireMFAEnrolmentPremise(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	adminToken := enrolTOTPAndLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── Admin: project, secret, a role deliberately WITHOUT secrets.read ───
	//
	// Every built-in project_* role (project_viewer/developer/admin/auditor)
	// grants secrets.read (ADR-021's defaultRoles), so none of them can play
	// "a project member who cannot read this secret yet" -- the role this
	// journey needs to demonstrate break-glass's escalation does not exist
	// as a product default and has to be created via REST POST /api/v1/roles
	// (CLI/REST per this journey's own mandate; there is no `role create`
	// CLI subcommand to port this to).
	runCLI(t, cliBin, aEnv, "project", "create", "--name", n9ProjectName)
	projID := projectID(t, s, adminToken, n9ProjectName)
	envID := environmentID(t, s, adminToken, projID, n9EnvName)

	runCLI(t, cliBin, aEnv, "secret", "create",
		"--name", n9SecretName, "--project", strconv.Itoa(projID),
		"--environment", strconv.Itoa(envID), "--value", n9SecretValue)
	secID := secretID(t, s, adminToken, projID, envID, n9SecretName)

	createNoAccessRole(t, s, adminToken)

	runCLI(t, cliBin, aEnv, "user", "create", "--username", n9OncallUser,
		"--email", n9OncallEmail, "--password", n9UserPass)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", n9OncallEmail,
		"--role", n9NoAccessRole, "--project", n9ProjectName)

	// Admin becomes a project member with an approver role (project_admin) --
	// without this, notifyBreakGlassAdmins has nobody to notify: an install-
	// wide system_admin who is NOT also a project member is not in
	// ListProjectMembers for this project and would never receive the alert
	// (internal/core/break_glass.go's own notifyBreakGlassAdmins, gated on
	// isApproverRole + project membership, not the global admin bypass).
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", "smoketestadmin@example.invalid",
		"--role", "project_admin", "--project", n9ProjectName)

	// require_mfa covers every interactive user, not just admins: the oncall
	// engineer enrols too before break-glass is reachable at all.
	oncallToken := enrolTOTPAndLogin(t, s, n9OncallUser, n9UserPass)

	// ── Before: the oncall user genuinely cannot read the secret ───────────
	assertSecretReadDenied(t, s, oncallToken, secID)

	// ── Activate: self-grant, with a written justification ─────────────────
	actOut := runCLI(t, cliBin, tokenEnv(s, oncallToken), "break-glass", "activate",
		"--project-id", strconv.Itoa(projID), "--justification", n9Justification)
	activationID := parseActivationID(t, actOut)

	// ── After: the SAME user can now read the SAME secret ──────────────────
	assertSecretReadValue(t, s, oncallToken, secID, n9SecretValue)

	// ── An audit event was written -- reusing journey3's audit-search path ──
	waitForAuditEventsToSettle(t, s, adminToken)
	evtEnv := restExpect(t, s, adminToken, http.MethodGet,
		"/api/v1/audit/search?action=break_glass.activated", nil, http.StatusOK)
	var evtData struct {
		Events []struct {
			ID     int    `json:"id"`
			Action string `json:"event_type"`
		} `json:"events"`
	}
	if err := json.Unmarshal(evtEnv.Data, &evtData); err != nil {
		t.Fatalf("decode audit search for break_glass.activated: %v\nraw: %s", err, evtEnv.Data)
	}
	if len(evtData.Events) != 1 {
		t.Fatalf("expected exactly 1 break_glass.activated audit event, found %d", len(evtData.Events))
	}

	// ── The project's admin was genuinely notified (the real notification
	// subsystem -- read back the admin's OWN notifications, not a stand-in
	// assertion). ────────────────────────────────────────────────────────
	assertAdminNotifiedOfBreakGlass(t, s, adminToken, projID)

	// ── `break-glass list` shows the activation ─────────────────────────────
	listOut := runCLI(t, cliBin, aEnv, "break-glass", "list", "--project-id", strconv.Itoa(projID))
	if !strings.Contains(listOut, strconv.Itoa(activationID)) {
		t.Fatalf("`break-glass list` does not show activation %d:\n%s", activationID, listOut)
	}
	if !strings.Contains(listOut, "active") {
		t.Fatalf("`break-glass list` does not show the activation as active:\n%s", listOut)
	}

	// ── Revoke (by the admin, who holds roles.assign at project scope --
	// the emergency role itself deliberately cannot revoke its own grant). ──
	runCLI(t, cliBin, aEnv, "break-glass", "revoke",
		"--project-id", strconv.Itoa(projID), "--activation-id", strconv.Itoa(activationID))

	// ── Access really reverts: re-attempt the read, don't trust the CLI's
	// exit code alone (the "assert the effect, not the return value" lesson:
	// a revoke call that silently no-ops would still exit 0 here). ─────────
	assertSecretReadDenied(t, s, oncallToken, secID)
}

// startServerWithBreakGlass is harness.StartServer's own sequence, with one
// extra step: appending a `break_glass:` block to the generated config
// before boot (mirrors journey5's startServerWithSSO -- not a harness.go
// change, since break-glass config injection is this journey's own need).
// The emergency role is project_developer: powerful-but-contained (read/
// write/delete secrets, no role administration), matching
// internal/core/break_glass.go's own documented constraint that the
// configured role must not carry roles.assign.
func startServerWithBreakGlass(t *testing.T, binary string) *harness.Server {
	t.Helper()
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir),
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-breakglass")
	configPath := "./keyorix.yaml"

	run := func(args ...string) {
		t.Helper()
		out, err := harness.RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--config", configPath)

	bgBlock := "\nbreak_glass:\n  enabled: true\n  emergency_role: project_developer\n  default_ttl: 4h\n  max_ttl: 24h\n"
	cfgFile := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgFile) // #nosec G304 -- cfgFile is this test's own t.TempDir()-derived path
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if err := os.WriteFile(cfgFile, append(raw, []byte(bgBlock)...), 0o600); err != nil {
		t.Fatalf("append break_glass: block to config: %v", err)
	}

	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)

	port := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, port)

	const bootstrapToken = "e2e-smoke-bootstrap-token-bg-0123456789"
	s := harness.BootAndBootstrap(t, binary, dir, env, configPath, port, bootstrapToken,
		"smoketestadmin", "smoketestadmin@example.invalid", harness.BootstrapAdminPassword)
	s.Backend = harness.DBBackend{Name: "sqlite-breakglass"}
	return s
}

// createNoAccessRole creates a custom role with ONLY users.read -- no
// secrets.read -- via REST POST /api/v1/roles (no CLI subcommand exists to
// create a role, confirmed by searching cli/cmd for one).
func createNoAccessRole(t *testing.T, s *harness.Server, adminToken string) {
	t.Helper()
	body := map[string]interface{}{
		"name":        n9NoAccessRole,
		"description": "project member with no secret access (journey9 fixture)",
		"permissions": []string{"users.read"},
	}
	env := restExpect(t, s, adminToken, http.MethodPost, "/api/v1/roles", body, http.StatusCreated)
	var data struct {
		Role struct {
			Name string `json:"name"`
		} `json:"role"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode create-role response: %v\nraw: %s", err, env.Data)
	}
	if data.Role.Name == "" {
		t.Fatalf("create-role response has no role name: %s", env.Data)
	}
}

// assertSecretReadDenied asserts token cannot read secID's value.
func assertSecretReadDenied(t *testing.T, s *harness.Server, token string, secID int) {
	t.Helper()
	env := restCall(t, s, token, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil)
	if env.StatusCode != http.StatusForbidden && env.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected the read to be denied (403/401), got HTTP %d: %s", env.StatusCode, string(env.Raw))
	}
}

// assertSecretReadValue asserts token CAN read secID's value, and that it
// matches want.
func assertSecretReadValue(t *testing.T, s *harness.Server, token string, secID int, want string) {
	t.Helper()
	env := restExpect(t, s, token, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var data struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode secret readback: %v\nraw: %s", err, env.Data)
	}
	if data.Value != want {
		t.Fatalf("secret readback: want %q, got %q", want, data.Value)
	}
}

// assertAdminNotifiedOfBreakGlass polls GET /api/v1/notifications (the
// admin's own, self-scoped notification list) for a break_glass.activated
// entry referencing projID -- the real notification subsystem
// (internal/core/notifications.go's notify()), not a stand-in assertion.
func assertAdminNotifiedOfBreakGlass(t *testing.T, s *harness.Server, adminToken string, projID int) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/notifications", nil, http.StatusOK)
	var data struct {
		Notifications []struct {
			Type      string `json:"type"`
			ProjectID int    `json:"project_id"`
		} `json:"notifications"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/notifications: %v\nraw: %s", err, env.Data)
	}
	for _, n := range data.Notifications {
		if n.Type == "break_glass.activated" && n.ProjectID == projID {
			return
		}
	}
	t.Fatalf("admin was not notified of the break-glass activation on project %d: %+v", projID, data.Notifications)
}

var activationIDRe = regexp.MustCompile(`\(id=(\d+)\)`)

// parseActivationID extracts the activation ID from `break-glass activate`'s
// stdout ("Emergency access activated (id=%d): role %q until %s.").
func parseActivationID(t *testing.T, out string) int {
	t.Helper()
	m := activationIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find activation id in `break-glass activate` output:\n%s", out)
	}
	id, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse activation id %q: %v", m[1], err)
	}
	return id
}
