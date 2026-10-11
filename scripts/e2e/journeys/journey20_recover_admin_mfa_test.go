//go:build e2e

package journeys

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_RecoverAdminUnderRequireMFA is #3024: the documented lost-admin
// runbook (docs/operator/j5-lost-admin.md) on the shipped config, where
// security.require_mfa is on, driven the way an operator drives it.
//
// Before the fix the runbook ended in a permanent lockout: recover-admin clears
// the admin's MFA and sets a one-time password (password_reset_required), then
// `keyorix change-password` was refused with MFAEnrollmentRequired and
// `keyorix mfa enroll` with PasswordChangeRequired. Red on main at step 3.
//
//  1. a fresh install's admin enrols TOTP and logs in with it (ADR-112);
//  2. the admin is "lost": stop the server, recovery-key rotate, recover-admin;
//  3. CLI, MFA first: log in with the one-time password, everything else is
//     refused (403 naming both pending steps), `mfa enroll` + `mfa activate`
//     work, `change-password` works and ends the setup session;
//  4. the next login needs a code; with it the admin has full access again,
//     and the audit trail shows the recovery (with the host user who ran it)
//     and the end of the setup session.
//
// TestJourney_AccountSetupPasswordFirstUnderRequireMFA covers the other order
// and a one-time-password user, on its own server: every login attempt spends
// one of the 10-per-15-minutes per-IP login slots (core.LoginMaxAttempts).
func TestJourney_RecoverAdminUnderRequireMFA(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite-recover-mfa", KeepMFADefault: true})
	t.Cleanup(s.Close)

	const (
		adminUser  = "smoketestadmin"
		adminEmail = "smoketestadmin@example.invalid"
		newPwA     = "Lantern-Quarry-58-Basalt!"
	)

	// ── 1. the admin has MFA, as require_mfa demands ────────────────────────────
	adminToken := enrolTOTPAndLogin(t, s, adminUser, harness.BootstrapAdminPassword)
	restExpect(t, s, adminToken, http.MethodGet, "/api/v1/projects", nil, http.StatusOK)

	// ── 2. lost admin: recover-admin with the server stopped ────────────────────
	s.Close()
	keyOut, err := harness.RunAdminCmd(serverBin, s.Dir, s.Env, "recovery-key", "rotate", "--config", s.ConfigPath)
	if err != nil {
		t.Fatalf("admin recovery-key rotate: %v\n%s", err, keyOut)
	}
	recoveryKey := parseRecoveryKey(t, keyOut)
	recoverOut, err := runAdminRecoverAdmin(serverBin, s.Dir, s.Env, s.ConfigPath, adminEmail, recoveryKey)
	if err != nil {
		t.Fatalf("admin recover-admin: %v\n%s", err, recoverOut)
	}
	otp := parseOneTimePassword(t, recoverOut)
	restartServer(t, s)

	// ── 3. CLI, MFA first ───────────────────────────────────────────────────────
	env := s.CLIEnv()
	out := runCLI(t, cliBin, env, "login", "--server", s.BaseURL, "--username", adminUser, "--password", otp)
	if !strings.Contains(out, "Logged in to") {
		t.Fatalf("login with the one-time password: want success, got:\n%s", out)
	}
	out = runCLIExpectErr(t, cliBin, env, "project", "list")
	if !strings.Contains(out, "403") {
		t.Fatalf("project list in the setup session: want a 403, got:\n%s", out)
	}
	// The #3024 deadlock: on main this was refused with PasswordChangeRequired.
	out = runCLI(t, cliBin, env, "mfa", "enroll")
	m := regexp.MustCompile(`(?m)^  ([A-Z2-7]{16,})$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find the base32 secret in `mfa enroll` output:\n%s", out)
	}
	secret := m[1]
	// A second setup session of the same account, over the API: refused with
	// both pending steps named, and revoked with the CLI's once setup completes.
	setupToken := adminLogin(t, s, adminUser, otp)
	assertPendingSteps(t, restCall(t, s, setupToken, http.MethodGet, "/api/v1/projects", nil), "change_password", "enroll_mfa")
	now := time.Now().UTC()
	code, burned := totpCodeAt(t, secret, now), totpStep(now)
	out = runCLI(t, cliBin, env, "mfa", "activate", "--code", code, "--password", otp)
	if !strings.Contains(out, "MFA enabled") || strings.Contains(out, "session has ended") {
		t.Fatalf("mfa activate with the password still owed: want MFA enabled and the session kept, got:\n%s", out)
	}
	out = runCLIExpectErr(t, cliBin, env, "project", "list")
	if !strings.Contains(out, "403") {
		t.Fatalf("project list with the password change still owed: want a 403, got:\n%s", out)
	}
	out = runCLI(t, cliBin, env, "change-password", "--current-password", otp, "--new-password", newPwA)
	if !strings.Contains(out, "session has ended") || !strings.Contains(out, "keyorix login") {
		t.Fatalf("change-password as the last setup step: want the session-ended instruction, got:\n%s", out)
	}
	out = runCLIExpectErr(t, cliBin, env, "project", "list")
	if !strings.Contains(out, "401") {
		t.Fatalf("project list after setup completed: the setup session must be gone (401), got:\n%s", out)
	}
	if gone := restCall(t, s, setupToken, http.MethodGet, "/api/v1/auth/profile", nil); gone.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the account's other setup session must be revoked too: want 401, got %d: %s", gone.StatusCode, gone.Raw)
	}

	// ── 4. a normal MFA login, full access, audited ─────────────────────────────
	out = runCLIExpectErr(t, cliBin, env, "login", "--server", s.BaseURL, "--username", adminUser, "--password", newPwA)
	if !strings.Contains(out, "--mfa-code") {
		t.Fatalf("login with only the new password must ask for the second factor, got:\n%s", out)
	}
	out = runCLI(t, cliBin, env, "login", "--server", s.BaseURL, "--username", adminUser, "--password", newPwA,
		"--mfa-code", totpCodeAfterStep(t, secret, burned))
	if !strings.Contains(out, "Logged in to") {
		t.Fatalf("MFA login after recovery: want success, got:\n%s", out)
	}
	runCLI(t, cliBin, env, "project", "list")
	logs := runCLI(t, cliBin, env, "audit", "logs", "--limit", "100")
	for _, want := range []string{"admin.recover_admin", "auth.account_setup_completed", "run by host user"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("audit logs: want %q, got:\n%s", want, logs)
		}
	}
	// And recover-admin told the operator what this journey just did.
	if !strings.Contains(recoverOut, "keyorix mfa enroll") || !strings.Contains(recoverOut, "change-password") {
		t.Fatalf("recover-admin must tell the operator both setup steps under require_mfa, got:\n%s", recoverOut)
	}
}

// TestJourney_AccountSetupPasswordFirstUnderRequireMFA: the same setup in the
// other order, over the public API, for a recovered admin and then for a
// one-time-password user (password_reset_required) created by that admin.
func TestJourney_AccountSetupPasswordFirstUnderRequireMFA(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite-setup-pwfirst", KeepMFADefault: true})
	t.Cleanup(s.Close)

	const (
		adminUser  = "smoketestadmin"
		adminEmail = "smoketestadmin@example.invalid"
		newPw      = "Orchid-Granite-31-Meadow!"
		otpUser    = "j20-otp-user"
		otpEmail   = "j20-otp-user@example.invalid"
		otpUserPw  = "Copper-Willow-47-Summit!"
	)
	enrolTOTPAndLogin(t, s, adminUser, harness.BootstrapAdminPassword)

	s.Close()
	keyOut, err := harness.RunAdminCmd(serverBin, s.Dir, s.Env, "recovery-key", "rotate", "--config", s.ConfigPath)
	if err != nil {
		t.Fatalf("admin recovery-key rotate: %v\n%s", err, keyOut)
	}
	recoverOut, err := runAdminRecoverAdmin(serverBin, s.Dir, s.Env, s.ConfigPath, adminEmail, parseRecoveryKey(t, keyOut))
	if err != nil {
		t.Fatalf("admin recover-admin: %v\n%s", err, recoverOut)
	}
	restartServer(t, s)
	adminToken := passwordFirstSetup(t, s, adminUser, parseOneTimePassword(t, recoverOut), newPw)

	uOut := runCLI(t, cliBin, adminEnv(s, adminToken), "user", "create", "--username", otpUser,
		"--email", otpEmail, "--one-time-password")
	userOTP := regexp.MustCompile(`One-time password for [^\n]*\n\s+(\S+)`).FindStringSubmatch(uOut)
	if userOTP == nil {
		t.Fatalf("could not find the one-time password in `user create --one-time-password` output:\n%s", uOut)
	}
	passwordFirstSetup(t, s, otpUser, userOTP[1], otpUserPw)
}

// passwordFirstSetup drives the setup session over the public API in the other
// order: change the password first (the session continues, now owing only
// enrolment), then enrol TOTP, which ends the session; then a normal MFA login
// (with a recovery code) must give full access. Returns that MFA session's token.
func passwordFirstSetup(t *testing.T, s *harness.Server, username, otp, newPassword string) string {
	t.Helper()
	token := adminLogin(t, s, username, otp)
	if denied := restCall(t, s, token, http.MethodGet, "/api/v1/projects", nil); denied.StatusCode != http.StatusForbidden {
		t.Fatalf("%s: the setup session must be confined: want 403, got %d: %s", username, denied.StatusCode, denied.Raw)
	}

	// The #3024 deadlock: on main this was refused with MFAEnrollmentRequired.
	cp := restExpect(t, s, token, http.MethodPost, "/api/v1/auth/change-password",
		map[string]string{"current_password": otp, "new_password": newPassword}, http.StatusOK)
	if reauthRequired(t, cp) {
		t.Fatalf("%s: change-password with enrolment still owed must keep the session: %s", username, cp.Raw)
	}
	assertPendingSteps(t, restCall(t, s, token, http.MethodGet, "/api/v1/projects", nil), "enroll_mfa")

	secret := beginMFAEnrollment(t, s, token)
	code := totpCodeAt(t, secret, time.Now().UTC())
	act := restExpect(t, s, token, http.MethodPost, "/api/v1/auth/mfa/activate",
		map[string]string{"code": code, "password": newPassword}, http.StatusOK)
	if !reauthRequired(t, act) {
		t.Fatalf("%s: enrolment as the last setup step must end the session: %s", username, act.Raw)
	}
	var data struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(act.Data, &data); err != nil || len(data.RecoveryCodes) == 0 {
		t.Fatalf("%s: activation returned no recovery codes (err %v): %s", username, err, act.Data)
	}
	if gone := restCall(t, s, token, http.MethodGet, "/api/v1/auth/profile", nil); gone.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%s: the setup session must be revoked after the last step: want 401, got %d: %s", username, gone.StatusCode, gone.Raw)
	}
	full := mfaLoginWithRecoveryCode(t, s, username, newPassword, data.RecoveryCodes[0])
	restExpect(t, s, full, http.MethodGet, "/api/v1/notifications", nil, http.StatusOK)
	return full
}

// mfaLoginWithRecoveryCode completes /auth/login -> /auth/mfa/verify with a
// recovery code and returns the session token. It fails if the password alone
// produced a session: after setup, every login must be a two-step MFA login.
func mfaLoginWithRecoveryCode(t *testing.T, s *harness.Server, username, password, recoveryCode string) string {
	t.Helper()
	env := restExpect(t, s, "", http.MethodPost, "/auth/login",
		map[string]string{"username": username, "password": password}, http.StatusOK)
	var challenge struct {
		Token        string `json:"token"`
		MFARequired  bool   `json:"mfa_required"`
		MFAChallenge string `json:"mfa_challenge"`
	}
	if err := json.Unmarshal(env.Data, &challenge); err != nil {
		t.Fatalf("decode /auth/login for %s: %v: %s", username, err, env.Data)
	}
	if challenge.Token != "" || !challenge.MFARequired || challenge.MFAChallenge == "" {
		t.Fatalf("%s: login after setup must require the second factor, got: %s", username, env.Data)
	}
	v := restExpect(t, s, "", http.MethodPost, "/auth/mfa/verify",
		map[string]string{"mfa_challenge": challenge.MFAChallenge, "code": recoveryCode}, http.StatusOK)
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(v.Data, &session); err != nil || session.Token == "" {
		t.Fatalf("%s: /auth/mfa/verify returned no token (err %v): %s", username, err, v.Data)
	}
	return session.Token
}

func reauthRequired(t *testing.T, env restEnvelope) bool {
	t.Helper()
	var d struct {
		ReauthenticationRequired bool `json:"reauthentication_required"`
	}
	_ = json.Unmarshal(env.Data, &d)
	return d.ReauthenticationRequired
}

// assertPendingSteps checks a setup-gate refusal: 403 naming exactly want.
func assertPendingSteps(t *testing.T, env restEnvelope, want ...string) {
	t.Helper()
	var body struct {
		PendingSteps []string `json:"pending_steps"`
	}
	_ = json.Unmarshal(env.Raw, &body)
	if env.StatusCode != http.StatusForbidden || strings.Join(body.PendingSteps, ",") != strings.Join(want, ",") {
		t.Fatalf("want 403 with pending_steps %v, got %d: %s", want, env.StatusCode, env.Raw)
	}
}
