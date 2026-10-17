//go:build e2e

package journeys

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_CLIErrorsAndExitCodes drives the failures a user actually meets with the
// real CLI against a real server (CLI-UX-1 item 2): every one must say what is wrong in
// plain words with the next step, exit with the documented code, and never show a Go
// error chain, a stack trace or a raw HTTP body.
//
// The codes are documented in `keyorix --help`: 0 ok, 1 refused/failed, 2 usage,
// 3 not logged in / session rejected, 4 permission denied, 5 not found, 6 server
// unreachable or TLS refused.
func TestJourney_CLIErrorsAndExitCodes(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	with := func(extra ...string) []string { return append(append([]string{}, s.CLIEnv()...), extra...) }

	// A PAT with only secrets.read: logged in, but not allowed to manage users.
	patOut := runCLI(t, cliBin, aEnv, "pat", "create", "--name", "ro", "--scope", "secrets.read")
	patToken := regexp.MustCompile(`kx_pat_\S+`).FindString(patOut)
	if patToken == "" {
		t.Fatalf("no PAT in `pat create` output:\n%s", patOut)
	}
	roEnv := tokenEnv(s, patToken)

	exitCode := func(err error) int {
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("not an exit error: %v", err)
		return -1
	}

	cases := []struct {
		name string
		env  []string
		args []string
		code int
		want []string // each must appear in the output
	}{
		{"never logged in", s.CLIEnv(), []string{"project", "list"}, 3,
			[]string{"not logged in", "keyorix login"}},
		{"session rejected", with("KEYORIX_SERVER="+s.BaseURL, "KEYORIX_TOKEN=bogus"), []string{"project", "list"}, 3,
			[]string{"(HTTP 401)", "keyorix login"}},
		{"server not running", with("KEYORIX_SERVER=http://127.0.0.1:1", "KEYORIX_TOKEN=x"), []string{"project", "list"}, 6,
			[]string{"cannot reach the Keyorix server at http://127.0.0.1:1", "connection refused", "Next step"}},
		{"unknown host", with("KEYORIX_SERVER=http://nonexistent.invalid", "KEYORIX_TOKEN=x"), []string{"project", "list"}, 6,
			[]string{"cannot resolve the host name", "Next step"}},
		{"https against a plain-http server", with("KEYORIX_SERVER=https://"+strings.TrimPrefix(s.BaseURL, "http://"), "KEYORIX_TOKEN=x"),
			[]string{"project", "list"}, 6, []string{"plain HTTP", "http:// URL"}},
		{"status with the server down", with("KEYORIX_SERVER=http://127.0.0.1:1", "KEYORIX_TOKEN=x"), []string{"status"}, 6,
			[]string{"cannot reach the Keyorix server"}},
		{"permission denied", roEnv, []string{"user", "list"}, 4,
			[]string{"(HTTP 403)", "Next step"}},
		{"not found", aEnv, []string{"secret", "get", "--id", "99999"}, 5,
			[]string{"(HTTP 404)"}},
		{"unknown command", aEnv, []string{"nosuchcmd"}, 2, []string{"unknown command"}},
		{"typo in a group", aEnv, []string{"secret", "lst"}, 2,
			[]string{`unknown command "lst" for "keyorix secret"`, "list"}},
		{"unknown flag", aEnv, []string{"secret", "get", "--bogus"}, 2, []string{"unknown flag: --bogus"}},
		{"missing required flag", aEnv, []string{"billing", "report"}, 2, []string{"required flag"}},
		{"missing value flag", aEnv, []string{"secret", "create"}, 2, []string{"--name"}},
		{"stray positional argument", aEnv, []string{"secret", "get", "42"}, 2, []string{"unexpected argument"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := runCLIRaw(cliBin, c.env, c.args...)
			if got := exitCode(err); got != c.code {
				t.Fatalf("keyorix %s: exit code %d, want %d\n%s", strings.Join(c.args, " "), got, c.code, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, bad := range []string{"goroutine ", "panic:", "dial tcp", "version-skew check", "lstat ", "&{"} {
				if strings.Contains(out, bad) {
					t.Errorf("output leaks internals (%q):\n%s", bad, out)
				}
			}
		})
	}

	t.Run("a conflict is a plain failure", func(t *testing.T) {
		runCLI(t, cliBin, aEnv, "project", "create", "--name", "err-dupe")
		out, err := runCLIRaw(cliBin, aEnv, "project", "create", "--name", "err-dupe")
		if got := exitCode(err); got != 1 {
			t.Fatalf("exit code %d, want 1\n%s", got, out)
		}
		if !strings.Contains(out, "already exists (HTTP 409)") {
			t.Errorf("want the server's reason and status:\n%s", out)
		}
	})

	t.Run("success and group help still exit 0", func(t *testing.T) {
		runCLI(t, cliBin, aEnv, "version")
		out := runCLI(t, cliBin, aEnv, "secret")
		if !strings.Contains(out, "Available Commands") {
			t.Errorf("`keyorix secret` should list its subcommands:\n%s", out)
		}
	})

	t.Run("--help documents the exit codes", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "--help")
		for _, w := range []string{"Exit codes:", "usage error", "permission denied (HTTP 403)", "not logged in"} {
			if !strings.Contains(out, w) {
				t.Errorf("--help lacks %q:\n%s", w, out)
			}
		}
	})
}
