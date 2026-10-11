//go:build e2e

package journeys

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_RunEnvInjection is J5: `keyorix run --var NAME=ref -- <cmd>`
// injects a secret into the CHILD process's environment only -- the parent
// invocation's own env/args never carry the value -- and a --var mapping the
// caller's token cannot read fails the whole command closed: non-zero exit,
// and the child process never starts at all (no partial environment, no
// partial execution).
func TestJourney_RunEnvInjection(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName      = "j14-run-injection"
		otherProjName = "j14-run-injection-other"
		envName       = "development"
		readableName  = "readable-secret"
		readableValue = "run-secret-xyz789-do-not-leak"
		forbiddenName = "forbidden-secret"
		forbiddenVal  = "should-never-appear-anywhere"
		machineName   = "j14-runner"
	)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── Setup: a project with a readable secret, a SECOND project holding a
	// secret the runner's token has no grant on at all, and a project-scoped
	// machine token for the first project only ─────────────────────────────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	projID := projectID(t, s, adminToken, projName)
	envID := environmentID(t, s, adminToken, projID, envName)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", readableName,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", readableValue)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", otherProjName)
	otherProjID := projectID(t, s, adminToken, otherProjName)
	otherEnvID := environmentID(t, s, adminToken, otherProjID, envName)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", forbiddenName,
		"--project", strconv.Itoa(otherProjID), "--environment", strconv.Itoa(otherEnvID), "--value", forbiddenVal)

	runCLI(t, cliBin, aEnv, "machine", "create", "--project", projName, "--name", machineName, "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", machineName, "--project", projName, "--role", "project_viewer")
	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", machineName, "--project", projName, "--name", "j14-runner-token")
	machToken, _ := parseIssuedToken(t, issueOut)
	runnerEnv := machineEnv(s, machToken)

	// ── Happy path: the child process sees the value; the invocation's own
	// env/args never carry it ────────────────────────────────────────────────

	runArgs := []string{
		"run", "--project-id", strconv.Itoa(projID), "--env", envName,
		"--var", "APP_SECRET=" + readableName,
		"--", "sh", "-c", `printf %s "$APP_SECRET"`,
	}
	childOut := runCLI(t, cliBin, runnerEnv, runArgs...)
	if childOut != readableValue {
		t.Fatalf("child process env: want %q, got %q", readableValue, childOut)
	}

	for _, arg := range runArgs {
		if strings.Contains(arg, readableValue) {
			t.Fatalf("the secret VALUE leaked into the keyorix invocation's own argv: %q", arg)
		}
	}
	for _, kv := range runnerEnv {
		if strings.Contains(kv, readableValue) {
			t.Fatalf("the secret VALUE leaked into the parent process's own env: %q", kv)
		}
	}

	// ── Fail-closed: a --var referencing a secret this token cannot read
	// (forbidden-secret lives in a DIFFERENT project the token has zero grant
	// on -- it never even appears in this scope's secret list) aborts the
	// WHOLE command before the child ever starts: non-zero exit, no partial
	// env, and -- the stronger assertion -- the child process never runs at
	// all, proven by a sentinel file that would exist if it had. ──────────

	sentinel := filepath.Join(t.TempDir(), "run-should-not-execute")
	failArgs := []string{
		"run", "--project-id", strconv.Itoa(projID), "--env", envName,
		"--var", "APP_SECRET=" + readableName,
		"--var", "LEAK=" + forbiddenName,
		"--", "sh", "-c", "echo ran > '" + sentinel + "'",
	}
	errOut := runCLIExpectErr(t, cliBin, runnerEnv, failArgs...)
	if !strings.Contains(errOut, forbiddenName) {
		t.Fatalf("expected the failure to name the unreadable secret %q, got:\n%s", forbiddenName, errOut)
	}
	if strings.Contains(errOut, forbiddenVal) {
		t.Fatalf("the forbidden secret's VALUE leaked into the CLI's own error output: %q", errOut)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("child process ran despite the --var resolution failure (sentinel file exists): stat err=%v", err)
	}
}
