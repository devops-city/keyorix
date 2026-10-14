//go:build e2e

package journeys

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_ProjectSuspendClearSyncedCopiesCLI is the breach responder's freeze:
// `keyorix project suspend-secrets --clear-synced-copies` against a real server. Every
// secret in the project is suspended with the choice (a workload reading by reference,
// as the operator and k8s-sync do, sees 409 SecretSuspended with
// details.clear_synced_copies), one project event records the choice and the count, a
// plain freeze carries nothing, a caller without secrets.write is refused and changes
// nothing, and resume-secrets removes the choice.
func TestJourney_ProjectSuspendClearSyncedCopiesCLI(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j-freeze-purge"
		envName     = "development"
		machineName = "j-freeze-purge-reader"
	)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	pid := projectID(t, s, adminToken, projName)
	eid := environmentID(t, s, adminToken, pid, envName)

	runCLI(t, cliBin, aEnv, "machine", "create", "--project", projName, "--name", machineName, "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", machineName, "--project", projName, "--role", "project_viewer")
	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", machineName, "--project", projName, "--name", "j-token")
	machToken, _ := parseIssuedToken(t, issueOut)
	mEnv := adminEnv(s, machToken) // a read-only caller: no secrets.write

	newSecret := func(name string) (ref string) {
		runCLI(t, cliBin, aEnv, "secret", "create", "--name", name,
			"--project", strconv.Itoa(pid), "--environment", strconv.Itoa(eid), "--value", "j-value-"+name)
		return projName + "/" + envName + "/" + name
	}
	refusal := func(ref string) (status int, code string, clear bool) {
		t.Helper()
		env := restCall(t, s, machToken, http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
		var body struct {
			Error   string `json:"error"`
			Details *struct {
				ClearSyncedCopies bool `json:"clear_synced_copies"`
			} `json:"details"`
		}
		if err := json.Unmarshal(env.Raw, &body); err != nil {
			t.Fatalf("decode refusal: %v\n%s", err, env.Raw)
		}
		return env.StatusCode, body.Error, body.Details != nil && body.Details.ClearSyncedCopies
	}
	projectAudit := func() string {
		env := restExpect(t, s, adminToken, http.MethodGet,
			"/api/v1/audit/search?action=secret.bulk_suspend_attempted&limit=50", nil, http.StatusOK)
		return string(env.Raw)
	}

	refA, refB := newSecret("j-freeze-a"), newSecret("j-freeze-b")
	pidArg := strconv.Itoa(pid)

	t.Run("a caller without secrets.write is refused and nothing changes", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, mEnv, "project", "suspend-secrets", "--id", pidArg, "--clear-synced-copies")
		if strings.Contains(out, "suspended -- value reads are now blocked") {
			t.Fatalf("a refused freeze must not claim success:\n%s", out)
		}
		for _, ref := range []string{refA, refB} {
			if status, _, _ := refusal(ref); status != http.StatusOK {
				t.Fatalf("%s must still be readable after a refused freeze, got HTTP %d", ref, status)
			}
		}
	})

	t.Run("flag: every secret frozen with the choice, announced, audited once, seen by the reader", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "project", "suspend-secrets", "--id", pidArg,
			"--reason", "leaked in CI logs", "--clear-synced-copies")
		for _, want := range []string{"2 secret(s) suspended", "cleared on their next sync", "secret rotate"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output does not contain %q:\n%s", want, out)
			}
		}
		for _, ref := range []string{refA, refB} {
			status, code, clear := refusal(ref)
			if status != http.StatusConflict || code != "SecretSuspended" || !clear {
				t.Fatalf("%s: reader sees status=%d code=%q clear=%v; want 409 SecretSuspended clear=true", ref, status, code, clear)
			}
		}
		audit := projectAudit()
		if n := strings.Count(audit, "bulk-suspend attempted: 2 secret(s) targeted"); n != 1 {
			t.Fatalf("want exactly one project event with the count, found %d:\n%s", n, audit)
		}
		if !strings.Contains(audit, "(clear_synced_copies=true)") {
			t.Fatalf("the audit trail must record the choice:\n%s", audit)
		}
	})

	t.Run("resume-secrets removes the choice and the reads work again", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "project", "resume-secrets", "--id", pidArg)
		if !strings.Contains(out, "2 secret(s) resumed") {
			t.Fatalf("unexpected output:\n%s", out)
		}
		for _, ref := range []string{refA, refB} {
			if status, _, _ := refusal(ref); status != http.StatusOK {
				t.Fatalf("after resume %s must be readable, got HTTP %d", ref, status)
			}
		}
	})

	t.Run("a plain freeze carries no choice and does not mention one", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "project", "suspend-secrets", "--id", pidArg)
		if strings.Contains(out, "synced") {
			t.Fatalf("a plain freeze must not talk about synced copies:\n%s", out)
		}
		status, code, clear := refusal(refA)
		if status != http.StatusConflict || code != "SecretSuspended" || clear {
			t.Fatalf("reader sees status=%d code=%q clear=%v; want 409 SecretSuspended clear=false", status, code, clear)
		}
	})

	t.Run("flag on an already-frozen project adds the choice", func(t *testing.T) {
		runCLI(t, cliBin, aEnv, "project", "suspend-secrets", "--id", pidArg, "--clear-synced-copies")
		for _, ref := range []string{refA, refB} {
			if _, _, clear := refusal(ref); !clear {
				t.Fatalf("%s: freezing again with the flag must add the choice", ref)
			}
		}
	})
}
