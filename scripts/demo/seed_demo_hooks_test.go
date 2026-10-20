package demo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// seed-demo.sh's hosted-kit hooks (KEYORIX_DEMO_ADMIN_PASSWORD_FILE, skip `system init` when the
// admin exists, generated alice/security-officer passwords). The runs below are the REAL script
// stopped at its first checks (no server, no build); the full native run against a server is
// deploy/demo-hosted/native-reset-check.sh.

func seedScript(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("seed-demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runSeed(t *testing.T, state string, env ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	cmd := exec.Command("bash", seedScript(t), state) // #nosec G204 -- fixed script path, test-controlled args
	cmd.Env = append(os.Environ(), "KEYORIX_DEMO_PORT=1")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestSeedDemo_AdminPasswordFileIsValidatedBeforeAnythingElse(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "admin_password")
	if err := os.WriteFile(good, []byte("Fixture-Value-NotARealPassword-1!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "world-readable")
	if err := os.WriteFile(open, []byte("Fixture-Value-NotARealPassword-2!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ file, want string }{
		"missing":        {filepath.Join(dir, "nope"), "not a readable file"},
		"empty":          {empty, "is empty"},
		"world readable": {open, "must not be accessible to other users"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := runSeed(t, filepath.Join(dir, "state-"+strings.ReplaceAll(name, " ", "-")), "KEYORIX_DEMO_ADMIN_PASSWORD_FILE="+c.file)
			if err == nil {
				t.Fatalf("accepted a bad password file:\n%s", out)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("want %q in:\n%s", c.want, out)
			}
			if strings.Contains(out, "NotARealPassword") {
				t.Errorf("the message leaked the file content:\n%s", out)
			}
		})
	}
	// A good file passes validation and the script moves on to the next check (a server that is not there);
	// the value is never printed.
	out, err := runSeed(t, filepath.Join(dir, "state-good"), "KEYORIX_DEMO_ADMIN_PASSWORD_FILE="+good)
	if err == nil || !strings.Contains(out, "server not reachable") && !strings.Contains(out, "go is not installed") {
		t.Errorf("a good password file should get past validation (err=%v):\n%s", err, out)
	}
	if strings.Contains(out, "NotARealPassword") {
		t.Errorf("the password value was printed:\n%s", out)
	}
}

// The default (no env) path must keep working exactly as before: the fixed demo passwords are still
// what the script uses, and nothing new is required of the environment.
func TestSeedDemo_DefaultPathKeepsTheFixedDemoPasswords(t *testing.T) {
	b, err := os.ReadFile("seed-demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`ADMIN_PASSWORD="Correct-Horse-Battery-2026"`,
		`ALICE_PASSWORD="Nebula-Quartz-Flagstone-2026"`,
		`SECOFFICER_PASSWORD="Granite-Meadow-Lantern-2026"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("seed-demo.sh lost %s: the default behaviour must not change", want)
		}
	}
	// Every new behaviour is behind an env var / file the hosted kit sets.
	if !strings.Contains(s, `{ [ "${KEYORIX_DEMO_GENERATE_PASSWORDS:-0}" = 1 ] || [ -n "$ADMIN_PASSWORD_FILE" ]; } && GENERATE_PASSWORDS=1`) {
		t.Error("password generation must be opt-in (KEYORIX_DEMO_GENERATE_PASSWORDS=1 or the admin password file)")
	}
	if !strings.Contains(s, `if [ -n "$ADMIN_PASSWORD_FILE" ]; then`) || !strings.Contains(s, `[ -n "$ADMIN_PASSWORD_FILE" ] || ensure_bootstrap_token`) {
		t.Error("the default path must still create the bootstrap token up front")
	}
}

// No secret value reaches stdout, stderr or argv: every line that mentions a secret variable either
// writes it to a 0600 file (inside a umask-077 subshell), passes it through the environment of one
// command, or is the fixed-demo-password default declaration.
func TestSeedDemo_NoSecretIsPrintedOrPutOnArgv(t *testing.T) {
	b, err := os.ReadFile("seed-demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	secret := regexp.MustCompile(`\$\{?(ADMIN_PASSWORD|ALICE_PASSWORD|SECOFFICER_PASSWORD|ADMIN_TOTP|DEMO_MFA_SECRET|DEMO_MFA_URI|DEMO_RECOVERY_CODES|ALICE_MFA_SECRET|SECOFFICER_MFA_SECRET|MACHINE_TOKEN|DEMO_TOKEN)\b`)
	printing := regexp.MustCompile(`^\s*(echo|info|ok|step|printf "%s\\n"|cat\b)`)
	inFileWrite := false
	for i, line := range strings.Split(string(b), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "umask 077") {
			inFileWrite = true
		}
		if secret.MatchString(code) && printing.MatchString(code) && !inFileWrite {
			t.Errorf("seed-demo.sh:%d prints or echoes a secret variable: %s", i+1, code)
		}
		if strings.HasPrefix(code, ")") || strings.Contains(code, "} > \"$") {
			inFileWrite = false
		}
	}
}
