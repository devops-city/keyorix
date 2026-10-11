//go:build e2e

package journeys

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

var otpExpiresRe = regexp.MustCompile(`Expires: (\S+) \(UTC\)`)

// parseOTPExpiry returns the UTC instant printed on the "Expires:" line of a
// command's output.
func parseOTPExpiry(t *testing.T, out string) time.Time {
	t.Helper()
	m := otpExpiresRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no \"Expires: <time> (UTC)\" line in the output:\n%s", out)
	}
	exp, err := time.Parse(time.RFC3339, m[1])
	if err != nil {
		t.Fatalf("Expires: %q is not RFC 3339: %v", m[1], err)
	}
	return exp
}

// TestJourney_RecoverAdminOneTimePasswordExpires is OTP-EXPIRY-1 on the shipped
// config (require_mfa on), driven the way the lost-admin runbook is driven, with
// security.recovery_one_time_password_ttl shortened to 30s so the expiry can be
// crossed for real:
//
//  1. recover-admin prints the one-time password AND when it expires (UTC),
//     honouring the configured TTL (not the 24h default);
//  2. before the expiry the password logs in (a setup session);
//  3. after it, the very same correct password is refused with the SAME status
//     and body as a wrong password, and no session is issued;
//  4. running recover-admin again re-issues a working password; the admin
//     finishes setup, and the audit trail shows auth.one_time_password_expired
//     (server-side only: the client never saw a difference);
//  5. `user create --one-time-password` tells the admin when that password
//     expires (72h default) and a password the user chose never expires.
//
// Red on the previous behaviour: step 1 has no Expires line and step 3 logs in.
func TestJourney_RecoverAdminOneTimePasswordExpires(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite-otp-expiry"})
	t.Cleanup(s.Close)

	const (
		adminUser  = "smoketestadmin"
		adminEmail = "smoketestadmin@example.invalid"
		newPw      = "Orchid-Granite-31-Meadow!"
		otpUser    = "j21-otp-user"
		otpEmail   = "j21-otp-user@example.invalid"
		otpUserPw  = "Copper-Willow-47-Summit!"
		ttl        = 30 * time.Second
	)

	// ── 1. recover-admin, with a short configured TTL ───────────────────────────
	s.Close()
	cfgPath := s.ConfigPath
	if !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(s.Dir, cfgPath) // the harness hands out a path relative to the server dir
	}
	cfg, err := os.ReadFile(cfgPath) // #nosec G304 -- the harness's own config file
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	const anchor = "\n  require_mfa: true\n"
	if !strings.Contains(string(cfg), anchor) {
		t.Fatalf("config has no %q to anchor the TTL key on:\n%s", anchor, cfg)
	}
	patched := strings.Replace(string(cfg), anchor, anchor+"  recovery_one_time_password_ttl: 30s\n", 1)
	if err := os.WriteFile(cfgPath, []byte(patched), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	keyOut, err := harness.RunAdminCmd(serverBin, s.Dir, s.Env, "recovery-key", "rotate", "--config", s.ConfigPath)
	if err != nil {
		t.Fatalf("admin recovery-key rotate: %v\n%s", err, keyOut)
	}
	recoveryKey := parseRecoveryKey(t, keyOut)

	ranAt := time.Now()
	recoverOut, err := runAdminRecoverAdmin(serverBin, s.Dir, s.Env, s.ConfigPath, adminEmail, recoveryKey)
	if err != nil {
		t.Fatalf("admin recover-admin: %v\n%s", err, recoverOut)
	}
	otp1 := parseOneTimePassword(t, recoverOut)
	exp1 := parseOTPExpiry(t, recoverOut)
	if d := exp1.Sub(ranAt); d < ttl-5*time.Second || d > ttl+5*time.Second {
		t.Fatalf("recover-admin printed an expiry %s after the run, want ~%s (security.recovery_one_time_password_ttl):\n%s", d, ttl, recoverOut)
	}
	restartServer(t, s)

	// ── 2. before the expiry it logs in ─────────────────────────────────────────
	setup := adminLogin(t, s, adminUser, otp1)
	assertPendingSteps(t, restCall(t, s, setup, http.MethodGet, "/api/v1/projects", nil), "change_password", "enroll_mfa")

	// ── 3. after the expiry: refused exactly like a wrong password ──────────────
	time.Sleep(time.Until(exp1) + 2*time.Second)
	expired := restCall(t, s, "", http.MethodPost, "/auth/login", map[string]string{"username": adminUser, "password": otp1})
	wrong := restCall(t, s, "", http.MethodPost, "/auth/login", map[string]string{"username": adminUser, "password": "Not-the-password-1!"})
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong password: want 401, got %d: %s", wrong.StatusCode, wrong.Raw)
	}
	if expired.StatusCode != wrong.StatusCode || string(expired.Raw) != string(wrong.Raw) {
		t.Fatalf("an expired one-time password must get the wrong-password response.\nexpired: %d %s\nwrong:   %d %s",
			expired.StatusCode, expired.Raw, wrong.StatusCode, wrong.Raw)
	}
	if strings.Contains(strings.ToLower(string(expired.Raw)), "expire") {
		t.Fatalf("the response must not reveal that the password merely expired: %s", expired.Raw)
	}

	// ── 4. recover-admin again; finish setup; the audit trail has the refusal ───
	s.Close()
	recoverOut2, err := runAdminRecoverAdmin(serverBin, s.Dir, s.Env, s.ConfigPath, adminEmail, recoveryKey)
	if err != nil {
		// recover-admin leaves the recovery key usable; a rotated one would be printed anew.
		t.Fatalf("second admin recover-admin: %v\n%s", err, recoverOut2)
	}
	otp2 := parseOneTimePassword(t, recoverOut2)
	if otp2 == otp1 {
		t.Fatalf("recover-admin re-issued the same one-time password")
	}
	if exp2 := parseOTPExpiry(t, recoverOut2); !exp2.After(exp1) {
		t.Fatalf("the re-issued password must carry a fresh expiry: %s is not after %s", exp2, exp1)
	}
	restartServer(t, s)
	adminToken := passwordFirstSetup(t, s, adminUser, otp2, newPw)

	logs := runCLI(t, cliBin, adminEnv(s, adminToken), "audit", "logs", "--limit", "100")
	if !strings.Contains(logs, "auth.one_time_password_expired") {
		t.Fatalf("audit logs: want auth.one_time_password_expired, got:\n%s", logs)
	}

	// ── 5. an admin-created one-time password reports its expiry too ────────────
	before := time.Now()
	uOut := runCLI(t, cliBin, adminEnv(s, adminToken), "user", "create", "--username", otpUser,
		"--email", otpEmail, "--one-time-password")
	uExp := parseOTPExpiry(t, uOut)
	if d := uExp.Sub(before); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("user create --one-time-password printed an expiry %s away, want ~72h (the default):\n%s", d, uOut)
	}
	userOTP := regexp.MustCompile(`One-time password for [^\n]*\n\s+(\S+)`).FindStringSubmatch(uOut)
	if userOTP == nil {
		t.Fatalf("could not find the one-time password in `user create --one-time-password` output:\n%s", uOut)
	}
	// It works now, and the password the user then chooses is not subject to it.
	passwordFirstSetup(t, s, otpUser, userOTP[1], otpUserPw)
	cpLogin := restCall(t, s, "", http.MethodPost, "/auth/login", map[string]string{"username": otpUser, "password": otpUserPw})
	if cpLogin.StatusCode != http.StatusOK {
		t.Fatalf("the user's chosen password must log in: %d %s", cpLogin.StatusCode, cpLogin.Raw)
	}
}
