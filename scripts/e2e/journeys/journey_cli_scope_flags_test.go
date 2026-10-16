//go:build e2e

package journeys

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_CLIScopeFlagSpellings drives, against a real server, the flag-name
// unification of CLI-UX-1: `--project` and `--env` are accepted on every command that
// names a project or an environment, whichever spelling the command defines
// (`--project-id`, `--environment`, `--environment-id`), and the old spellings still work.
func TestJourney_CLIScopeFlagSpellings(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		proj = "j-scope-flags"
		name = "scope-secret"
	)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", proj)
	pid := projectID(t, s, adminToken, proj)
	eid := environmentID(t, s, adminToken, pid, "development")
	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/secrets", map[string]interface{}{
		"name": name, "value": "scope-value", "project_id": pid, "environment_id": eid, "type": "generic",
	}, http.StatusCreated)
	pidArg, eidArg := strconv.Itoa(pid), strconv.Itoa(eid)

	t.Run("--env works where the command defines --environment", func(t *testing.T) {
		for _, flag := range []string{"--env", "--environment"} {
			out := runCLI(t, cliBin, aEnv, "secret", "list", "--project", proj, flag, eidArg)
			if !strings.Contains(out, name) {
				t.Fatalf("secret list %s %s: secret missing:\n%s", flag, eidArg, out)
			}
		}
		// An environment with no secrets proves the filter really applied.
		out := runCLI(t, cliBin, aEnv, "secret", "list", "--project", proj, "--env", strconv.Itoa(eid+1000))
		if strings.Contains(out, name) {
			t.Fatalf("--env was accepted but ignored; the other environment still lists the secret:\n%s", out)
		}
	})

	t.Run("--project works where the command defines --project-id", func(t *testing.T) {
		for _, flag := range []string{"--project", "--project-id"} {
			out := runCLI(t, cliBin, aEnv, "rotation", "status", flag, pidArg)
			if strings.Contains(out, "unknown flag") {
				t.Fatalf("rotation status %s %s: %s", flag, pidArg, out)
			}
		}
	})

	t.Run("a command with both spellings keeps their different meanings", func(t *testing.T) {
		// run: --project is a name, --project-id the numeric ID.
		out := runCLIExpectErr(t, cliBin, aEnv, "run", "--project", "no-such-project-"+proj, "--env", "development", "--", "true")
		if strings.Contains(out, "unknown flag") {
			t.Fatalf("run lost a flag:\n%s", out)
		}
	})
}
