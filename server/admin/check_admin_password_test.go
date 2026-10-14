package admin

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/rules"
)

// runCheckAdminPasswordCaptured runs `admin check-admin-password` with pw on
// stdin. Every flag is passed explicitly: cobra flag values persist between runs.
func runCheckAdminPasswordCaptured(t *testing.T, pw, username, email string) (string, int) {
	t.Helper()
	return runCheckAdminPasswordWithConfig(t, "", pw, username, email)
}

// runCheckAdminPasswordWithConfig is runCheckAdminPasswordCaptured with a
// keyorix.yaml (cfgYAML, "" = none, so the default policy applies) in the
// working directory, which is where config.Load("") finds it.
func runCheckAdminPasswordWithConfig(t *testing.T, cfgYAML, pw, username, email string) (string, int) {
	t.Helper()
	dir := t.TempDir()
	if cfgYAML != "" {
		if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfgYAML), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	t.Chdir(dir)
	rootCmd.SetIn(strings.NewReader(pw))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := Execute([]string{"check-admin-password", "--username", username, "--email", email, "--display-name", "Administrator"})
	os.Stdout, os.Stderr = origOut, origErr
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), code
}

// #3201: the password from the issue ("Dw5-Admin-Passphrase#2026" contains the
// username "admin") must be refused with the policy's real reason, and the
// password itself must never be echoed.
func TestCheckAdminPassword_ContainingUsernameIsRefusedWithTheReason(t *testing.T) {
	const pw = "Dw5-Admin-Passphrase#2026"
	out, code := runCheckAdminPasswordCaptured(t, pw+"\n", "admin", "admin@keyorix.local")
	if code == 0 {
		t.Fatalf("a password containing the username was accepted:\n%s", out)
	}
	if !strings.Contains(out, "admin password rejected: password must") ||
		!strings.Contains(out, "not contain your username, email, or display name") {
		t.Fatalf("output does not state the real refusal reason:\n%s", out)
	}
	if strings.Contains(out, pw) {
		t.Fatalf("the password was printed:\n%s", out)
	}
}

func TestCheckAdminPassword_ContainingDisplayNameIsRefused(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "Dw5-Administrator-Pass#2026", "root", "root@keyorix.local")
	if code == 0 || !strings.Contains(out, "not contain your username, email, or display name") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestCheckAdminPassword_CustomUsernameIsChecked(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "Correct-Horse-Alice-2026", "alice", "a@keyorix.local")
	if code == 0 || !strings.Contains(out, "not contain your username") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestCheckAdminPassword_ValidPasswordIsAccepted(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "Correct-Horse-Battery-2026\r\n", "admin", "admin@keyorix.local")
	if code != 0 || !strings.Contains(out, "accepted") {
		t.Fatalf("a valid password was refused (code=%d):\n%s", code, out)
	}
}

// The other rules still apply: the pre-check is the server's policy, not a
// username-only filter.
func TestCheckAdminPassword_OtherPolicyRulesStillRefuse(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "short1!A", "admin", "admin@keyorix.local")
	if code == 0 || !strings.Contains(out, "at least 16 characters") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestCheckAdminPassword_EmptyStdinIsRefused(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "\n", "admin", "admin@keyorix.local")
	if code == 0 || !strings.Contains(out, "admin password rejected") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

// The configured password_policy (non-default) is what the check applies, not
// the built-in default: a password the default accepts is refused under
// min_length: 40, and the refusal names the configured length.
func TestCheckAdminPassword_HonoursConfiguredPasswordPolicy(t *testing.T) {
	const pw = "Correct-Horse-Battery-2026" // 26 chars: fine under the default
	if out, code := runCheckAdminPasswordCaptured(t, pw, "admin", "admin@keyorix.local"); code != 0 {
		t.Fatalf("precondition: default policy must accept the password (code=%d):\n%s", code, out)
	}
	out, code := runCheckAdminPasswordWithConfig(t, "password_policy:\n  min_length: 40\n", pw, "admin", "admin@keyorix.local")
	if code != adminPasswordRejectedExitCode || !strings.Contains(out, "at least 40 characters") {
		t.Fatalf("configured min_length 40 not applied (code=%d):\n%s", code, out)
	}
}

// ResolvePasswordPolicy applies a configured value over the default and leaves
// every rule the operator did not set at its default.
func TestResolvePasswordPolicy_ConfiguredValueOverridesOnlyThatRule(t *testing.T) {
	n := 40
	got := ResolvePasswordPolicy(config.PasswordPolicyConfig{MinLength: &n})
	want := rules.DefaultPasswordPolicy()
	want.MinLength = 40
	if got != want {
		t.Fatalf("ResolvePasswordPolicy(min_length 40) = %+v, want %+v", got, want)
	}
}

// Exit codes: a policy refusal is 2 (a verdict the entrypoint acts on); a
// failure to produce a verdict (stdin read error) is the generic 1.
func TestCheckAdminPassword_ExitCodes(t *testing.T) {
	if _, code := runCheckAdminPasswordCaptured(t, "Dw5-Admin-Passphrase#2026\n", "admin", "admin@keyorix.local"); code != 2 {
		t.Fatalf("policy refusal exit code = %d, want 2", code)
	}
	if _, code := runCheckAdminPasswordCaptured(t, "\n", "admin", "admin@keyorix.local"); code != 2 {
		t.Fatalf("empty password exit code = %d, want 2", code)
	}
	if _, code := runCheckAdminPasswordCaptured(t, "Correct-Horse-Battery-2026", "admin", "admin@keyorix.local"); code != 0 {
		t.Fatalf("accepted password exit code = %d, want 0", code)
	}

	// A stdin that cannot be read is not a verdict: exit 1, not 2.
	t.Chdir(t.TempDir())
	rootCmd.SetIn(errReader{})
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	if code := Execute([]string{"check-admin-password", "--username", "admin", "--email", "admin@keyorix.local", "--display-name", "Administrator"}); code != 1 {
		t.Fatalf("stdin read error exit code = %d, want 1", code)
	}
	// A flag error is not a verdict either.
	rootCmd.SetIn(strings.NewReader("x"))
	if code := Execute([]string{"check-admin-password", "--no-such-flag"}); code != 1 {
		t.Fatalf("flag error exit code = %d, want 1", code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// ResolvePasswordPolicy with no password_policy block is exactly the built-in
// default (#G37), so a partial config can never zero a rule.
func TestResolvePasswordPolicy_EmptyBlockIsTheDefault(t *testing.T) {
	if got, want := ResolvePasswordPolicy(config.PasswordPolicyConfig{}), rules.DefaultPasswordPolicy(); got != want {
		t.Fatalf("ResolvePasswordPolicy(empty) = %+v, want %+v", got, want)
	}
}

// A generated admin password must never embed the admin's username, whatever
// KEYORIX_ADMIN_USERNAME says (#3201).
func TestGenerateSecrets_AdminPasswordAvoidsConfiguredUsername(t *testing.T) {
	// A 3-letter username shows up in about 1 of 800 random 43-character tokens,
	// so 5000 draws exercise the regenerate path several times.
	t.Setenv("KEYORIX_ADMIN_USERNAME", "abc")
	policy := rules.DefaultPasswordPolicy()
	for range 5000 {
		pw, err := randomAdminPassword()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(pw), "abc") {
			t.Fatalf("generated password embeds the username: %q", pw)
		}
		if err := policy.Validate(pw, nil); err != nil {
			t.Fatal(err)
		}
	}
}
