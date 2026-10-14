//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_SecretSuspendClearSyncedCopiesCLI is SUSPEND-PURGE-1 as the person
// responding to a compromise meets it: `keyorix secret suspend --clear-synced-copies`
// against a real server. The choice is stored with the suspension and audited, the
// output tells them to rotate, a workload reading by reference (what the operator and
// k8s-sync do) sees the 409 SecretSuspended refusal carrying details.clear_synced_copies,
// a plain suspension carries nothing, and resume removes the choice.
func TestJourney_SecretSuspendClearSyncedCopiesCLI(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j-suspend-purge"
		envName     = "development"
		machineName = "j-suspend-purge-reader"
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

	newSecret := func(name string) (id int, ref string) {
		runCLI(t, cliBin, aEnv, "secret", "create", "--name", name,
			"--project", strconv.Itoa(pid), "--environment", strconv.Itoa(eid), "--value", "j-value-"+name)
		return secretID(t, s, adminToken, pid, eid, name), projName + "/" + envName + "/" + name
	}
	// refusal reads the secret by reference as the machine identity would.
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
	storedChoice := func(id int) bool {
		env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", id), nil, http.StatusOK)
		var d struct {
			Status            string `json:"status"`
			ClearSyncedCopies bool   `json:"clear_synced_copies"`
		}
		if err := json.Unmarshal(env.Data, &d); err != nil {
			t.Fatalf("decode secret: %v\n%s", err, env.Data)
		}
		return d.ClearSyncedCopies
	}

	t.Run("flag: stored, announced, rotation prompt, seen by the reader, audited", func(t *testing.T) {
		id, ref := newSecret("j-flagged")
		out := runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id),
			"--reason", "leaked in CI logs", "--clear-synced-copies")
		for _, want := range []string{"suspended", "cleared on their next sync", "secret rotate"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output does not contain %q:\n%s", want, out)
			}
		}
		if !storedChoice(id) {
			t.Fatal("the secret must report clear_synced_copies=true while suspended")
		}
		status, code, clear := refusal(ref)
		if status != http.StatusConflict || code != "SecretSuspended" || !clear {
			t.Fatalf("reader sees status=%d code=%q clear=%v; want 409 SecretSuspended clear=true", status, code, clear)
		}
		audit := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/audit", id), nil, http.StatusOK)
		if !strings.Contains(string(audit.Raw), "clear_synced_copies=true") {
			t.Fatalf("the audit trail must record the choice:\n%s", audit.Raw)
		}

		runCLI(t, cliBin, aEnv, "secret", "resume", "--id", strconv.Itoa(id))
		if storedChoice(id) {
			t.Fatal("resume must remove the choice")
		}
		if status, _, _ := refusal(ref); status != http.StatusOK {
			t.Fatalf("after resume the reader must get the value, got HTTP %d", status)
		}
	})

	t.Run("plain suspend carries no choice, and does not mention one", func(t *testing.T) {
		id, ref := newSecret("j-plain")
		out := runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id))
		if strings.Contains(out, "synced") {
			t.Fatalf("a plain suspend must not talk about synced copies:\n%s", out)
		}
		status, code, clear := refusal(ref)
		if status != http.StatusConflict || code != "SecretSuspended" || clear {
			t.Fatalf("reader sees status=%d code=%q clear=%v; want 409 SecretSuspended clear=false", status, code, clear)
		}
	})

	t.Run("flag on an already-suspended secret adds the choice", func(t *testing.T) {
		id, ref := newSecret("j-upgrade")
		runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id))
		if _, _, clear := refusal(ref); clear {
			t.Fatal("precondition: a plain suspension carries no choice")
		}
		runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id), "--clear-synced-copies")
		if _, _, clear := refusal(ref); !clear {
			t.Fatal("suspending again with the flag must add the choice")
		}
	})
}
