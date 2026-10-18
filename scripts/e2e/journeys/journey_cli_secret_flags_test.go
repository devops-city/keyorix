//go:build e2e

package journeys

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// runCLIStdin runs the CLI with data on stdin and returns combined stdout+stderr.
func runCLIStdin(cliBin string, env []string, stdin string, args ...string) (string, error) {
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- the journey's own built binary and fixed arguments
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestJourney_CLISecretsNeverOnTheCommandLine drives CLI-UX-1 item 5 against a real
// server: a secret given as a flag is refused with the safe alternative, the safe
// alternatives work end to end (value piped on stdin, hidden prompt fed from stdin), and
// the value never reaches the server through argv.
//
// The environment is built here, without the KEYORIX_ALLOW_INSECURE_SECRET_FLAGS opt-in
// the harness's CLIEnv carries for the journeys not yet moved off --value.
func TestJourney_CLISecretsNeverOnTheCommandLine(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	strict := []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + s.BaseURL, "KEYORIX_TOKEN=" + adminToken}

	const proj = "j-secret-flags"
	runCLI(t, cliBin, adminEnv(s, adminToken), "project", "create", "--name", proj)
	pid := projectID(t, s, adminToken, proj)
	eid := environmentID(t, s, adminToken, pid, "development")
	pidArg, eidArg := strconv.Itoa(pid), strconv.Itoa(eid)

	secretValue := func(t *testing.T, id string) string {
		t.Helper()
		out := runCLI(t, cliBin, strict, "secret", "get", "--id", id, "--show-value")
		return out
	}
	listed := func(t *testing.T, name string) bool {
		t.Helper()
		return strings.Contains(runCLI(t, cliBin, strict, "secret", "list", "--project", proj), name)
	}

	t.Run("--value is refused, names the alternatives, and nothing is created", func(t *testing.T) {
		const canary = "flag-canary-9d3b"
		out, err := runCLIStdin(cliBin, strict, "", "secret", "create", "--name", "via-flag", "--project", pidArg, "--environment", eidArg, "--value", canary)
		if err == nil {
			t.Fatalf("a secret on the command line must be refused:\n%s", out)
		}
		for _, want := range []string{"--value is not accepted", "--from-file", "stdin"} {
			if !strings.Contains(out, want) {
				t.Errorf("refusal lacks %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, canary) {
			t.Errorf("the refusal echoed the secret:\n%s", out)
		}
		if listed(t, "via-flag") {
			t.Error("the refused command still created the secret")
		}
	})

	t.Run("the value piped on stdin creates, updates and rotates a secret", func(t *testing.T) {
		out, err := runCLIStdin(cliBin, strict, "stdin-value-one\n", "secret", "create", "--name", "via-stdin", "--project", pidArg, "--environment", eidArg, "--from-file", "-")
		if err != nil {
			t.Fatalf("create from stdin: %v\n%s", err, out)
		}
		id := secretID(t, s, adminToken, pid, eid, "via-stdin")
		idArg := strconv.Itoa(id)
		if got := secretValue(t, idArg); !strings.Contains(got, "stdin-value-one") || strings.Contains(got, "stdin-value-one\n\n") {
			t.Fatalf("stored value wrong (a trailing newline must be dropped):\n%q", got)
		}

		if out, err := runCLIStdin(cliBin, strict, "stdin-value-two", "secret", "update", "--id", idArg, "--from-file", "-"); err != nil {
			t.Fatalf("update from stdin: %v\n%s", err, out)
		}
		if got := secretValue(t, idArg); !strings.Contains(got, "stdin-value-two") {
			t.Fatalf("update did not take the piped value:\n%s", got)
		}

		// rotate has no value flag worth using: its hidden prompt reads a pipe too.
		if out, err := runCLIStdin(cliBin, strict, "stdin-value-three\n", "secret", "rotate", "--id", idArg); err != nil {
			t.Fatalf("rotate from stdin: %v\n%s", err, out)
		}
		if got := secretValue(t, idArg); !strings.Contains(got, "stdin-value-three") {
			t.Fatalf("rotate did not take the piped value:\n%s", got)
		}
	})

	t.Run("empty stdin is an error, not an empty secret", func(t *testing.T) {
		out, err := runCLIStdin(cliBin, strict, "", "secret", "create", "--name", "empty-one", "--project", pidArg, "--environment", eidArg, "--from-file", "-")
		if err == nil || !strings.Contains(out, "nothing on stdin") {
			t.Fatalf("want an 'nothing on stdin' error, got err=%v\n%s", err, out)
		}
		if listed(t, "empty-one") {
			t.Error("an empty secret was created")
		}
	})

	t.Run("login --password and --mfa-code are refused", func(t *testing.T) {
		for _, flag := range []string{"--password", "--mfa-code"} {
			out, err := runCLIStdin(cliBin, []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH")}, "",
				"login", "--server", s.BaseURL, "--username", "smoketestadmin", flag, "not-a-real-value")
			if err == nil || !strings.Contains(out, flag+" is not accepted") || !strings.Contains(out, "KEYORIX_") {
				t.Errorf("login %s: want a refusal naming the KEYORIX_ variable, got err=%v\n%s", flag, err, out)
			}
			if strings.Contains(out, "not-a-real-value") {
				t.Errorf("login %s echoed the value:\n%s", flag, out)
			}
		}
	})

	t.Run("the flag is gone from --help", func(t *testing.T) {
		out := runCLI(t, cliBin, strict, "secret", "create", "--help")
		if strings.Contains(out, "--value") {
			t.Errorf("--value should not be advertised:\n%s", out)
		}
		if !strings.Contains(out, "--from-file") || !strings.Contains(out, "stdin") {
			t.Errorf("--help should teach --from-file and stdin:\n%s", out)
		}
	})

	t.Run("the migration escape hatch still works, with the old warning", func(t *testing.T) {
		env := append(append([]string{}, strict...), "KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1")
		out, err := runCLIStdin(cliBin, env, "", "secret", "create", "--name", "via-hatch", "--project", pidArg, "--environment", eidArg, "--value", "hatch-value")
		if err != nil {
			t.Fatalf("with the escape hatch the old flag must work: %v\n%s", err, out)
		}
		if !strings.Contains(out, "insecure") {
			t.Errorf("the old warning should still be printed:\n%s", out)
		}
		if !listed(t, "via-hatch") {
			t.Error("the secret was not created")
		}
	})
}
