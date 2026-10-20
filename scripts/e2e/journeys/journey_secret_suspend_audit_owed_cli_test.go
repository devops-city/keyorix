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
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_SecretSuspendAuditOwedCLI is SUSPEND-AUDIT-LOUD as an operator meets it
// against a real server: while the audit log refuses secret.suspended rows (a trigger
// in the live server's own SQLite file), `keyorix secret suspend` still succeeds and
// the reader is cut off at once; GET /api/v1/system/info shows the owed row to the
// administrator; once the audit log accepts writes again the server's own
// audit_owed_backfill job writes the row and the warning clears.
func TestJourney_SecretSuspendAuditOwedCLI(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j-suspend-owed"
		envName     = "development"
		machineName = "j-suspend-owed-reader"
		secretName  = "j-owed"
	)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	pid := projectID(t, s, adminToken, projName)
	eid := environmentID(t, s, adminToken, pid, envName)
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", projName, "--name", machineName, "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", machineName, "--project", projName, "--role", "project_viewer")
	machToken, _ := parseIssuedToken(t, runCLI(t, cliBin, aEnv, "machine", "token", "issue", machineName, "--project", projName, "--name", "j-token"))
	runCLISecret(t, cliBin, aEnv, "j-owed-value", "secret", "create", "--name", secretName,
		"--project", strconv.Itoa(pid), "--environment", strconv.Itoa(eid))
	id := secretID(t, s, adminToken, pid, eid, secretName)
	ref := projName + "/" + envName + "/" + secretName

	owedPending := func() int64 {
		t.Helper()
		env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/system/info", nil, http.StatusOK)
		var d struct {
			Security struct {
				AuditOwed *struct {
					Pending int64 `json:"pending"`
				} `json:"audit_owed"`
			} `json:"security"`
		}
		if err := json.Unmarshal(env.Data, &d); err != nil {
			t.Fatalf("decode system info: %v\n%s", err, env.Data)
		}
		if d.Security.AuditOwed == nil {
			t.Fatalf("the administrator must see security.audit_owed:\n%s", env.Data)
		}
		return d.Security.AuditOwed.Pending
	}
	suspendRows := func() string {
		t.Helper()
		return string(restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/audit", id), nil, http.StatusOK).Raw)
	}
	dbPath := filepath.Join(s.Dir, "keyorix.db")
	sqlite := func(stmt string) {
		t.Helper()
		out, err := exec.Command("sqlite3", dbPath, stmt).CombinedOutput() // #nosec G204 -- this test's own tempdir DB path and a fixed statement
		if err != nil {
			t.Fatalf("sqlite3 %q: %v\n%s", stmt, err, out)
		}
	}

	if got := owedPending(); got != 0 {
		t.Fatalf("precondition: nothing owed, got %d", got)
	}
	sqlite(`CREATE TRIGGER j_refuse_suspend_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = 'secret.suspended' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;`)
	recovered := false
	t.Cleanup(func() {
		if !recovered {
			sqlite(`DROP TRIGGER IF EXISTS j_refuse_suspend_audit;`)
		}
	})

	runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id), "--reason", "j-owed-breach")
	if st := restCall(t, s, machToken, http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil).StatusCode; st != http.StatusConflict {
		t.Fatalf("the suspension must cut the reader off at once, got HTTP %d", st)
	}
	if got := owedPending(); got != 1 {
		t.Fatalf("the administrator must see one owed audit row, got %d", got)
	}
	if strings.Contains(suspendRows(), "j-owed-breach") {
		t.Fatal("precondition: the refused row must not be in the audit log yet")
	}

	sqlite(`DROP TRIGGER j_refuse_suspend_audit;`)
	recovered = true
	// The server's audit_owed_backfill job runs every minute.
	deadline := time.Now().Add(90 * time.Second)
	for owedPending() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the backfill job did not write the owed row within 90 s of the audit log recovering")
		}
		time.Sleep(2 * time.Second)
	}
	rows := suspendRows()
	if strings.Count(rows, "j-owed-breach") != 1 || !strings.Contains(rows, "recorded late") {
		t.Fatalf("the owed secret.suspended row must be in the audit log exactly once, marked late:\n%s", rows)
	}
}
