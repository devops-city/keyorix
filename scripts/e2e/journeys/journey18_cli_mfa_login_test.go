//go:build e2e

package journeys

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_CLILoginWithMFA is #2737 (DEMO-2 golden path, step 3): once TOTP MFA is
// enabled on the account an operator uses for CLI work, `keyorix login` must still work.
//
// Before the fix, cli/cmd/login.go accepted exactly one /auth/login 200 shape -- the one
// carrying `data.token` -- and reported "login failed: HTTP %d" for anything else. An
// MFA-enabled account gets the OTHER documented 200 shape (`mfa_required` +
// `mfa_challenge`, see openapi.yaml's authLogin oneOf), so the CLI printed
// "Error: login failed: HTTP 200": the success status code of a call that succeeded,
// reported as the failure, with no indication a second factor was wanted. Every later
// golden-path step uses the CLI under that same admin account, so the demo died there.
//
// This journey drives the real CLI binary against a real server, the way an operator
// does: enrol MFA through the same API the web UI calls, then log in from the CLI with a
// TOTP code, with a recovery code, with a wrong code, and with no code at all.
//
// Red on main, green after: steps 1 and 5 below both produce "login failed: HTTP 200"
// before the fix (confirmed by running this file against main -- see the PR body).
func TestJourney_CLILoginWithMFA(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const adminUser = "smoketestadmin"
	adminPw := harness.BootstrapAdminPassword

	adminToken := adminLogin(t, s, adminUser, adminPw)

	// ── Enrol + activate TOTP exactly the way the web UI does ────────────────
	secret := beginMFAEnrollment(t, s, adminToken)
	// Activation consumes the TOTP step it was proved with (MarkTOTPStepUsed), so every
	// later code must come from a LATER step. activateMFA returns the step it burned.
	recoveryCodes, burnedStep := activateMFA(t, s, adminToken, secret, adminPw)
	if len(recoveryCodes) == 0 {
		t.Fatal("MFA activation returned no recovery codes")
	}

	// `login` takes --server on the command line and has no token yet, so its env is the
	// bare isolated HOME/PATH -- deliberately NOT tokenEnv, which would hand the CLI a
	// session it is supposed to be obtaining here.
	loginEnv := s.CLIEnv()

	t.Run("1. no --mfa-code and no terminal names the flag, never \"HTTP 200\"", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, loginEnv,
			"login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw)
		// The #2737 symptom, verbatim.
		if strings.Contains(out, "HTTP 200") {
			t.Fatalf("regression: the login POST's success status is being reported as the failure:\n%s", out)
		}
		if !strings.Contains(out, "--mfa-code") {
			t.Fatalf("expected the error to name --mfa-code (there is no terminal to prompt on here):\n%s", out)
		}
	})

	t.Run("2. --mfa-code with a TOTP code logs in and stores a working session", func(t *testing.T) {
		code := totpCodeAfterStep(t, secret, burnedStep)
		out := runCLI(t, cliBin, loginEnv,
			"login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw,
			"--mfa-code", code)
		if !strings.Contains(out, "Logged in to") {
			t.Fatalf("expected a successful login, got:\n%s", out)
		}
		if strings.Contains(out, code) {
			t.Fatalf("the second-factor code was echoed back:\n%s", out)
		}

		// The stored credential is a real session: a later command with no
		// KEYORIX_TOKEN in its environment must work off the credential file alone.
		out = runCLI(t, cliBin, loginEnv, "project", "list")
		if strings.Contains(out, "no server configured") || strings.Contains(out, "401") {
			t.Fatalf("the session login stored is not usable:\n%s", out)
		}

		// The code must not be persisted anywhere -- only the session token is.
		assertCredentialFileHasNoCode(t, s.Dir, code)
	})

	t.Run("3. --mfa-code accepts a recovery code", func(t *testing.T) {
		// The server accepts either a TOTP code or an unused recovery code on
		// /auth/mfa/verify (internal/core.VerifyMFACredentials), and the CLI must not
		// pre-judge which one it was handed.
		out := runCLI(t, cliBin, loginEnv,
			"login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw,
			"--mfa-code", recoveryCodes[0])
		if !strings.Contains(out, "Logged in to") {
			t.Fatalf("expected a recovery code to complete the login, got:\n%s", out)
		}
		if strings.Contains(out, recoveryCodes[0]) {
			t.Fatalf("the recovery code was echoed back:\n%s", out)
		}
		assertCredentialFileHasNoCode(t, s.Dir, recoveryCodes[0])
	})

	t.Run("4. a used recovery code is refused, with the server's own reason", func(t *testing.T) {
		// Single-use is the server's property (ConsumeMFARecoveryCode), not the CLI's --
		// asserted here because the CLI is now the thing presenting it, and a CLI that
		// reported this as success would be worse than the original bug.
		out := runCLIExpectErr(t, cliBin, loginEnv,
			"login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw,
			"--mfa-code", recoveryCodes[0])
		if strings.Contains(out, "HTTP 200") {
			t.Fatalf("a refused second factor must not be reported as the login POST's 200:\n%s", out)
		}
		if !strings.Contains(out, "401") {
			t.Fatalf("expected the verify endpoint's real status (401) to be surfaced:\n%s", out)
		}
	})

	t.Run("5. a wrong code reports what the server said, not \"HTTP 200\"", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, loginEnv,
			"login", "--server", s.BaseURL, "--username", adminUser, "--password", adminPw,
			"--mfa-code", "000000")
		if strings.Contains(out, "HTTP 200") {
			t.Fatalf("regression: a wrong code is being reported as the login POST's success status:\n%s", out)
		}
		if !strings.Contains(out, "Invalid or expired code") {
			t.Fatalf("expected the server's own rejection reason in the output:\n%s", out)
		}
	})
}

// ── MFA enrolment through the public API (what the web UI calls) ───────────

// beginMFAEnrollment calls POST /api/v1/auth/mfa/enroll and returns the base32 TOTP
// secret the server generated.
func beginMFAEnrollment(t *testing.T, s *harness.Server, token string) string {
	t.Helper()
	env := restExpect(t, s, token, http.MethodPost, "/api/v1/auth/mfa/enroll", nil, http.StatusOK)
	var data struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode POST /api/v1/auth/mfa/enroll: %v\nraw: %s", err, env.Data)
	}
	if data.Secret == "" {
		t.Fatalf("POST /api/v1/auth/mfa/enroll returned no secret: %s", env.Data)
	}
	return data.Secret
}

// activateMFA completes enrolment with a current TOTP code plus the account password
// (requireReauth accepts the password here precisely because no second factor is active
// yet) and returns the one-time recovery codes together with the TOTP step the
// activation consumed -- the server marks that step used, so no later login may reuse
// it.
func activateMFA(t *testing.T, s *harness.Server, token, secret, password string) (codes []string, burnedStep int64) {
	t.Helper()
	now := time.Now().UTC()
	code := totpCodeAt(t, secret, now)
	env := restExpect(t, s, token, http.MethodPost, "/api/v1/auth/mfa/activate",
		map[string]string{"code": code, "password": password}, http.StatusOK)
	var data struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode POST /api/v1/auth/mfa/activate: %v\nraw: %s", err, env.Data)
	}
	return data.RecoveryCodes, totpStep(now)
}

// enrolTOTPAndLogin takes an interactive user through what security.require_mfa
// (ADR-112, on in the shipped config) demands before anything else works: log in with
// the password, enrol + activate a TOTP factor through the public API, then complete a
// real two-step login (/auth/login's mfa_challenge -> /auth/mfa/verify). It returns the
// session token that login issued -- a fresh MFA-backed session, not the pre-enrolment
// one, so nothing here depends on the server refreshing an older session's MFA state.
func enrolTOTPAndLogin(t *testing.T, s *harness.Server, username, password string) string {
	t.Helper()
	token, _ := enrolTOTPFactor(t, s, username, password)
	return token
}

// mfaFactor is an enrolled TOTP factor: its secret plus the last TOTP step the server
// has marked used (single-use), so a later login can pick a strictly newer step.
type mfaFactor struct {
	Secret     string
	BurnedStep int64
}

// enrolTOTPFactor is enrolTOTPAndLogin that also returns the factor, for journeys that
// log in again later (e.g. against a restored server) with the same TOTP secret.
func enrolTOTPFactor(t *testing.T, s *harness.Server, username, password string) (string, *mfaFactor) {
	t.Helper()
	preToken := adminLogin(t, s, username, password)
	f := enrolTOTPOnSession(t, s, preToken, password)
	return loginWithTOTP(t, s, username, password, f), f
}

// enrolTOTPOnSession enrols + activates a TOTP factor on an existing (pre-enrolment)
// session, exactly as the web UI does, and returns the factor.
func enrolTOTPOnSession(t *testing.T, s *harness.Server, token, password string) *mfaFactor {
	t.Helper()
	secret := beginMFAEnrollment(t, s, token)
	_, burned := activateMFA(t, s, token, secret, password)
	return &mfaFactor{Secret: secret, BurnedStep: burned}
}

// loginWithTOTP completes a real two-step login for a user who already has an active
// TOTP factor, and records the step it consumed in f.
func loginWithTOTP(t *testing.T, s *harness.Server, username, password string, f *mfaFactor) string {
	t.Helper()
	env := restExpect(t, s, "", http.MethodPost, "/auth/login",
		map[string]string{"username": username, "password": password}, http.StatusOK)
	var challenge struct {
		MFARequired  bool   `json:"mfa_required"`
		MFAChallenge string `json:"mfa_challenge"`
	}
	if err := json.Unmarshal(env.Data, &challenge); err != nil {
		t.Fatalf("decode POST /auth/login for %s: %v\nraw: %s", username, err, env.Data)
	}
	if !challenge.MFARequired || challenge.MFAChallenge == "" {
		t.Fatalf("POST /auth/login for MFA-enrolled %s: expected an mfa_challenge, got: %s", username, env.Data)
	}
	code, step := totpCodeAfterStepN(t, f.Secret, f.BurnedStep)
	env = restExpect(t, s, "", http.MethodPost, "/auth/mfa/verify",
		map[string]string{"mfa_challenge": challenge.MFAChallenge, "code": code}, http.StatusOK)
	f.BurnedStep = step
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(env.Data, &session); err != nil || session.Token == "" {
		t.Fatalf("POST /auth/mfa/verify for %s returned no session token (err %v): %s", username, err, env.Data)
	}
	return session.Token
}

// requireMFAEnrolmentPremise proves a journey really runs under the shipped
// security.require_mfa default (ADR-112): a freshly logged-in, not-yet-enrolled session
// is confined to enrolment and every other route answers 403 MFAEnrollmentRequired.
// Call it before enrolTOTPAndLogin so a config that quietly stopped requiring MFA turns
// the journey red instead of letting it pass vacuously.
func requireMFAEnrolmentPremise(t *testing.T, s *harness.Server, username, password string) {
	t.Helper()
	pre := adminLogin(t, s, username, password)
	if denied := restCall(t, s, pre, http.MethodGet, "/api/v1/projects", nil); denied.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(denied.Raw), "MFAEnrollmentRequired") {
		t.Fatalf("premise: the shipped config should require MFA enrolment first; GET /api/v1/projects got %d: %s",
			denied.StatusCode, denied.Raw)
	}
}

// mfaLogin is how a journey logs an interactive user in under the shipped
// security.require_mfa default: assert the enrolment premise, then enrol a TOTP
// factor and complete a real two-step login. Journeys use it where they used a
// plain password login before the harness default became require_mfa on.
func mfaLogin(t *testing.T, s *harness.Server, username, password string) string {
	t.Helper()
	requireMFAEnrolmentPremise(t, s, username, password)
	return enrolTOTPAndLogin(t, s, username, password)
}

// mfaPersonaLogin is mfaLogin for a secondary persona (an editor, a viewer...) whose
// journey is about what the persona may DO, not about the login. It enrols a TOTP
// factor on the persona's first session and keeps using that session, which the
// server stops confining once MFA is active -- the web UI's own enrol-and-continue
// path. It spends 1 slot of the server's per-IP login budget (core.LoginMaxAttempts,
// 10 per 15 min) where mfaLogin spends 3, so a journey with several personas stays
// under it. The first user of a server goes through mfaLogin (premise + two-step login).
func mfaPersonaLogin(t *testing.T, s *harness.Server, username, password string) string {
	t.Helper()
	token := adminLogin(t, s, username, password)
	enrolTOTPOnSession(t, s, token, password)
	return token
}

// totpPeriod mirrors internal/core's own step length (mfa.go's totpPeriod).
const totpPeriod = 30 * time.Second

func totpStep(at time.Time) int64 { return at.Unix() / int64(totpPeriod.Seconds()) }

// totpCodeAt generates the code for the step containing at, with the same parameters
// internal/core.validateTOTPStep checks against.
func totpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period: uint(totpPeriod.Seconds()), Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	return code
}

// totpCodeAfterStep returns a code from the first step strictly after burned, which is
// what the server's single-use rule requires. The server accepts the current step ±1, so
// one step past a just-burned current step is both fresh and inside that window -- and
// stays inside it if the wall clock rolls over to that step while the request is in
// flight.
func totpCodeAfterStep(t *testing.T, secret string, burned int64) string {
	t.Helper()
	code, _ := totpCodeAfterStepN(t, secret, burned)
	return code
}

// totpCodeAfterStepN is totpCodeAfterStep that also returns the step the code is for.
func totpCodeAfterStepN(t *testing.T, secret string, burned int64) (string, int64) {
	t.Helper()
	for {
		now := time.Now().UTC()
		step := max(totpStep(now), burned) + 1
		at := time.Unix(step*int64(totpPeriod.Seconds()), 0).UTC()
		if step > totpStep(now)+1 {
			// Would fall outside the server's +1 skew window: wait until that step is
			// the clock's next one (re-deriving the step afterwards, not advancing past
			// it) rather than submitting a code that cannot be accepted.
			time.Sleep(time.Until(at.Add(-totpPeriod)) + time.Second)
			continue
		}
		return totpCodeAt(t, secret, at), step
	}
}

// assertCredentialFileHasNoCode fails if the second-factor code reached the credential
// file. Only the session token is persisted: the code is used for one /auth/mfa/verify
// request and then dropped.
//
// Located by walking the isolated HOME rather than by rebuilding credstore.DefaultPath()
// here -- that path is os.UserConfigDir()-relative, so it differs between the CI runner
// and a developer's Mac, and a hard-coded guess that silently finds nothing would make
// this assertion vacuous.
func assertCredentialFileHasNoCode(t *testing.T, home, code string) {
	t.Helper()
	var found []string
	if err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: not this assertion's business
		}
		if !d.IsDir() && d.Name() == "credentials.yaml" {
			found = append(found, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", home, err)
	}
	if len(found) == 0 {
		t.Fatalf("no credentials.yaml found under %s after a successful login -- the CLI stored nothing, or this assertion is looking in the wrong place", home)
	}
	for _, path := range found {
		raw, err := os.ReadFile(path) // #nosec G304 -- path came from walking this test's own isolated HOME
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(raw), code) {
			t.Fatalf("the second-factor code was written to %s", path)
		}
	}
}
