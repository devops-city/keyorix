//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_SecretSuspendAuditRefusedHintCLI is SUSPEND-HINT-1 as the person responding
// to a compromise meets it against a real server: while the audit log refuses
// secret.suspended rows (a trigger in the live server's own SQLite file),
// `keyorix secret suspend --clear-synced-copies` is refused (fail closed: nothing changes,
// the reader is NOT cut off) with the stable code SuspendAuditUnavailable, and both the
// REST body and the CLI output say what to do now. Following that advice (the same
// command without the flag) cuts the reader off at once.
func TestJourney_SecretSuspendAuditRefusedHintCLI(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j-suspend-hint"
		envName     = "development"
		machineName = "j-suspend-hint-reader"
		secretName  = "j-hint"
	)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	pid := projectID(t, s, adminToken, projName)
	eid := environmentID(t, s, adminToken, pid, envName)
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", projName, "--name", machineName, "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", machineName, "--project", projName, "--role", "project_viewer")
	machToken, _ := parseIssuedToken(t, runCLI(t, cliBin, aEnv, "machine", "token", "issue", machineName, "--project", projName, "--name", "j-token"))
	runCLISecret(t, cliBin, aEnv, "j-hint-value", "secret", "create", "--name", secretName,
		"--project", strconv.Itoa(pid), "--environment", strconv.Itoa(eid))
	id := secretID(t, s, adminToken, pid, eid, secretName)
	ref := projName + "/" + envName + "/" + secretName
	suspendPath := fmt.Sprintf("/api/v1/secrets/%d/suspend", id)

	dbPath := filepath.Join(s.Dir, "keyorix.db")
	sqlite := func(stmt string) {
		t.Helper()
		out, err := exec.Command("sqlite3", dbPath, stmt).CombinedOutput() // #nosec G204 -- this test's own tempdir DB path and a fixed statement
		if err != nil {
			t.Fatalf("sqlite3 %q: %v\n%s", stmt, err, out)
		}
	}
	readerStatus := func() int {
		t.Helper()
		return restCall(t, s, machToken, http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil).StatusCode
	}

	sqlite(`CREATE TRIGGER j_refuse_suspend_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = 'secret.suspended' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;`)
	t.Cleanup(func() { sqlite(`DROP TRIGGER IF EXISTS j_refuse_suspend_audit;`) })

	t.Run("REST: stable code and fixed message, no raw error text", func(t *testing.T) {
		env := restCall(t, s, adminToken, http.MethodPost, suspendPath, map[string]any{"clear_synced_copies": true})
		if env.StatusCode != http.StatusInternalServerError {
			t.Fatalf("want HTTP 500, got %d\n%s", env.StatusCode, env.Raw)
		}
		var body struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(env.Raw, &body); err != nil {
			t.Fatalf("decode refusal: %v\n%s", err, env.Raw)
		}
		if body.Error != "SuspendAuditUnavailable" {
			t.Fatalf("want the stable code SuspendAuditUnavailable, got %q\n%s", body.Error, env.Raw)
		}
		if !strings.Contains(body.Message, "suspend without clearing synced copies to cut access immediately") ||
			!strings.Contains(body.Message, "clearing needs the audit log back") {
			t.Fatalf("the message must say what to do now:\n%s", env.Raw)
		}
		if strings.Contains(string(env.Raw), "audit unavailable") {
			t.Fatalf("the storage error text must not reach the client:\n%s", env.Raw)
		}
	})

	t.Run("CLI: prints the reason and the command that cuts access now; nothing changed", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id),
			"--reason", "leaked in CI logs", "--clear-synced-copies")
		for _, want := range []string{
			"suspend without clearing synced copies to cut access immediately",
			"(HTTP 500)",
			"Next step:",
			"without `--clear-synced-copies`",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("CLI output does not contain %q:\n%s", want, out)
			}
		}
		if st := readerStatus(); st != http.StatusOK {
			t.Fatalf("a refused suspend must change nothing: the reader should still read the secret, got HTTP %d", st)
		}
	})

	t.Run("the advised plain suspend cuts access now, with the audit log still down", func(t *testing.T) {
		runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id), "--reason", "leaked in CI logs")
		if st := readerStatus(); st != http.StatusConflict {
			t.Fatalf("the plain suspend must cut the reader off at once, got HTTP %d", st)
		}
	})
}
