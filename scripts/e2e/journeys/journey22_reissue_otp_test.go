//go:build e2e

package journeys

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

var reissuedOTPRe = regexp.MustCompile(`One-time password for [^\n]*\n\s+(\S+)`)

// TestJourney_AdminReissuesOneTimePassword is REISSUE-1, driven the way an admin
// drives it, against a real server: an existing user (a normal session, a chosen
// password) is handed a NEW one-time password by an administrator, and
//
//  1. the CLI prints the password once with its expiry;
//  2. the user's existing session ends at once and the old password is dead;
//  3. the new password logs in only into the restricted state (change-password owed);
//  4. the user finishes by choosing a real password and is a normal user again;
//  5. the same action is refused over REST for a non-admin (403), for the admin's
//     own account (CLI error pointing at recover-admin), and for an unknown user.
func TestJourney_AdminReissuesOneTimePassword(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite-reissue-otp"})
	t.Cleanup(s.Close)

	const (
		adminUser  = "smoketestadmin"
		adminEmail = "smoketestadmin@example.invalid"
		user       = "j22-colleague"
		userEmail  = "j22-colleague@example.invalid"
		chosenPw   = "Copper-Willow-47-Summit!"
		finalPw    = "Heron-Basalt-58-Lantern!"
	)
	// The harness runs under the shipped security.require_mfa default: the admin
	// enrols a TOTP factor first. (Journey budget: 10 password logins per IP per 15 min.)
	requireMFAEnrolmentPremise(t, s, adminUser, harness.BootstrapAdminPassword)
	adminToken, adminFactor := enrolTOTPFactor(t, s, adminUser, harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// A colleague with an ordinary, chosen password, an enrolled second factor and a
	// live session: first login with the admin-created one-time password, choose a
	// password, enrol (the setup session of #3024/#3041), then log in normally.
	created := runCLI(t, cliBin, aEnv, "user", "create", "--username", user, "--email", userEmail, "--one-time-password")
	first := reissuedOTPRe.FindStringSubmatch(created)
	if first == nil {
		t.Fatalf("no one-time password in `user create --one-time-password` output:\n%s", created)
	}
	firstToken := adminLogin(t, s, user, first[1])
	restExpect(t, s, firstToken, http.MethodPost, "/api/v1/auth/change-password",
		map[string]string{"current_password": first[1], "new_password": chosenPw}, http.StatusOK)
	userFactor := enrolTOTPOnSession(t, s, firstToken, chosenPw)
	liveToken := loginWithTOTP(t, s, user, chosenPw, userFactor)
	restExpect(t, s, liveToken, http.MethodGet, "/api/v1/auth/profile", nil, http.StatusOK)

	// ── 1. the admin reissues; the password and expiry are printed ────────────────
	out := runCLI(t, cliBin, aEnv, "user", "reissue-one-time-password", userEmail)
	m := reissuedOTPRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no one-time password in `user reissue-one-time-password` output:\n%s", out)
	}
	newOTP := m[1]
	if newOTP == first[1] || newOTP == chosenPw {
		t.Fatalf("the reissued password must be new")
	}
	exp := parseOTPExpiry(t, out)
	if exp.IsZero() {
		t.Fatalf("no expiry printed:\n%s", out)
	}

	// ── 2. the old session and the old password are dead ──────────────────────────
	if gone := restCall(t, s, liveToken, http.MethodGet, "/api/v1/auth/profile", nil); gone.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the user's existing session must end: want 401, got %d: %s", gone.StatusCode, gone.Raw)
	}
	if old := restCall(t, s, "", http.MethodPost, "/auth/login", map[string]string{"username": user, "password": chosenPw}); old.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the previous password must stop working: want 401, got %d: %s", old.StatusCode, old.Raw)
	}

	// ── 3. the new password logs in, confined to the password change ──────────────
	// The enrolled second factor is kept (a reissue must not strip MFA): the login
	// still asks for the code.
	restricted := loginWithTOTP(t, s, user, newOTP, userFactor)
	if denied := restCall(t, s, restricted, http.MethodGet, "/api/v1/projects", nil); denied.StatusCode != http.StatusForbidden {
		t.Fatalf("a reissued-OTP session must be confined: want 403, got %d: %s", denied.StatusCode, denied.Raw)
	}

	// ── 4. the user chooses a real password and is a normal user again ────────────
	restExpect(t, s, restricted, http.MethodPost, "/api/v1/auth/change-password",
		map[string]string{"current_password": newOTP, "new_password": finalPw}, http.StatusOK)
	normal := loginWithTOTP(t, s, user, finalPw, userFactor)
	restExpect(t, s, normal, http.MethodGet, "/api/v1/auth/profile", nil, http.StatusOK)

	// ── 5. refusals ───────────────────────────────────────────────────────────────
	// A non-admin may not reissue anyone's password.
	if forbidden := restCall(t, s, normal, http.MethodPost, "/api/v1/users/1/reissue-one-time-password", nil); forbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("a non-admin reissue: want 403, got %d: %s", forbidden.StatusCode, forbidden.Raw)
	}
	// The admin's own account: use recover-admin.
	self := runCLIExpectErr(t, cliBin, aEnv, "user", "reissue-one-time-password", adminEmail)
	if !strings.Contains(self, "recover-admin") {
		t.Fatalf("reissuing your own account must point at recover-admin:\n%s", self)
	}
	if reissuedOTPRe.MatchString(self) {
		t.Fatalf("a refused reissue must print no password:\n%s", self)
	}
	// The admin's own password is untouched.
	loginWithTOTP(t, s, adminUser, harness.BootstrapAdminPassword, adminFactor)
	// An unknown user.
	runCLIExpectErr(t, cliBin, aEnv, "user", "reissue-one-time-password", "99999")

	// The audit trail records the reissue, with the actor, and never the password.
	logs := runCLI(t, cliBin, aEnv, "audit", "logs", "--limit", "100")
	if !strings.Contains(logs, "user.one_time_password_reissued") {
		t.Fatalf("audit logs: want user.one_time_password_reissued, got:\n%s", logs)
	}
	if strings.Contains(logs, newOTP) {
		t.Fatalf("the audit log must never contain the one-time password")
	}
}
