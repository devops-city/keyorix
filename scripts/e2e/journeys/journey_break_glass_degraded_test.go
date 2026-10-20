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

// TestJourney_BreakGlassDegradedWhileAuditDown is BREAKGLASS-OWED-1 as an on-call
// engineer and an operator meet it against a real server: while the audit log
// refuses the activation's rows (a trigger in the live server's own SQLite file),
// `keyorix break-glass activate` still works; the activation is degraded and cut to
// 15 minutes; the administrator is notified and sees it in GET /api/v1/system/info;
// with the owed-audit table refusing writes too, the next activation is refused with
// 503 naming recover-admin; once the audit log recovers, the server's own
// audit_owed_backfill job writes the rows into the audit trail and settles it.
func TestJourney_BreakGlassDegradedWhileAuditDown(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := startServerWithBreakGlass(t, serverBin)
	t.Cleanup(s.Close)

	const (
		projName = "j-bg-degraded"
		oncall   = "j-bgd-oncall"
		peer     = "j-bgd-peer"
		pass     = "Harbor-Quartz-19-Delta!"
		why      = "sev1: audit storage full, need access to rotate the leaked credential"
	)
	adminToken := enrolTOTPAndLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	pid := projectID(t, s, adminToken, projName)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", "smoketestadmin@example.invalid", "--role", "project_admin", "--project", projName)
	for _, u := range []string{oncall, peer} {
		runCLI(t, cliBin, aEnv, "user", "create", "--username", u, "--email", u+"@example.invalid", "--password", pass)
		runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", u+"@example.invalid", "--role", "project_viewer", "--project", projName)
	}
	oncallToken := enrolTOTPAndLogin(t, s, oncall, pass)
	peerToken := enrolTOTPAndLogin(t, s, peer, pass)

	type degraded struct {
		Unsettled     int64 `json:"unsettled"`
		Unreviewed    int64 `json:"unreviewed"`
		ActivationIDs []int `json:"activation_ids"`
	}
	status := func() degraded {
		t.Helper()
		env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/system/info", nil, http.StatusOK)
		var d struct {
			Security struct {
				BreakGlassDegraded *degraded `json:"break_glass_degraded"`
			} `json:"security"`
		}
		if err := json.Unmarshal(env.Data, &d); err != nil {
			t.Fatalf("decode system info: %v\n%s", err, env.Data)
		}
		if d.Security.BreakGlassDegraded == nil {
			t.Fatalf("the administrator must see security.break_glass_degraded:\n%s", env.Data)
		}
		return *d.Security.BreakGlassDegraded
	}
	dbPath := filepath.Join(s.Dir, "keyorix.db")
	sqlite := func(stmt string) {
		t.Helper()
		out, err := exec.Command("sqlite3", dbPath, stmt).CombinedOutput() // #nosec G204 -- this test's own tempdir DB path and a fixed statement
		if err != nil {
			t.Fatalf("sqlite3 %q: %v\n%s", stmt, err, out)
		}
	}
	if st := status(); st.Unsettled != 0 {
		t.Fatalf("precondition: nothing degraded, got %+v", st)
	}

	// The audit log refuses the activation's rows (only those, so logins and the
	// rest of the server keep auditing).
	sqlite(`CREATE TRIGGER j_bgd_refuse_audit BEFORE INSERT ON audit_events WHEN NEW.event_type IN ('role.assigned', 'break_glass.activated') BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;`)
	recovered := false
	t.Cleanup(func() {
		if !recovered {
			sqlite(`DROP TRIGGER IF EXISTS j_bgd_refuse_audit; DROP TRIGGER IF EXISTS j_bgd_refuse_owed;`)
		}
	})

	out := runCLI(t, cliBin, tokenEnv(s, oncallToken), "break-glass", "activate",
		"--project-id", strconv.Itoa(pid), "--justification", why, "--ttl", "4h")
	aid := parseActivationID(t, out)

	// The member's own list says degraded, with the 15-minute lifetime.
	env := restExpect(t, s, oncallToken, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/break-glass", pid), nil, http.StatusOK)
	var list struct {
		Activations []struct {
			ID        int       `json:"id"`
			Degraded  bool      `json:"degraded"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"activations"`
	}
	if err := json.Unmarshal(env.Data, &list); err != nil || len(list.Activations) != 1 || list.Activations[0].ID != aid {
		t.Fatalf("own list must show activation %d (err %v):\n%s", aid, err, env.Data)
	}
	a := list.Activations[0]
	if !a.Degraded {
		t.Fatalf("activation %d must be degraded while the audit log refuses its rows:\n%s", aid, env.Data)
	}
	if life := a.ExpiresAt.Sub(a.CreatedAt); life > 15*time.Minute+time.Second {
		t.Fatalf("a 4h request must be cut to 15 minutes while degraded, got %s", life)
	}

	st := status()
	if st.Unsettled != 1 || st.Unreviewed != 1 || len(st.ActivationIDs) != 1 || st.ActivationIDs[0] != aid {
		t.Fatalf("the administrator must see activation %d unsettled and unreviewed, got %+v", aid, st)
	}
	notes := string(restExpect(t, s, adminToken, http.MethodGet, "/api/v1/notifications", nil, http.StatusOK).Raw)
	if !strings.Contains(notes, "DEGRADED") {
		t.Fatalf("the project's admin must be notified of a degraded activation:\n%s", notes)
	}

	// The owed-audit table refuses too: nothing can be recorded, nothing is granted.
	sqlite(`CREATE TRIGGER j_bgd_refuse_owed BEFORE INSERT ON pending_audit_events BEGIN SELECT RAISE(ABORT, 'owed table unavailable'); END;`)
	res := restCall(t, s, peerToken, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/break-glass", pid),
		map[string]string{"justification": why})
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(res.Raw), "BreakGlassUnrecordable") ||
		!strings.Contains(string(res.Raw), "recover-admin") || strings.Contains(string(res.Raw), "owed table unavailable") {
		t.Fatalf("unrecordable activation must be 503 BreakGlassUnrecordable naming recover-admin, without driver text; got HTTP %d:\n%s",
			res.StatusCode, res.Raw)
	}

	sqlite(`DROP TRIGGER j_bgd_refuse_owed; DROP TRIGGER j_bgd_refuse_audit;`)
	recovered = true
	// The server's audit_owed_backfill job runs every minute.
	deadline := time.Now().Add(90 * time.Second)
	for status().Unsettled != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the backfill job did not settle the degraded activation within 90 s of the audit log recovering")
		}
		time.Sleep(2 * time.Second)
	}
	waitForAuditEventsToSettle(t, s, adminToken)
	evt := string(restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?action=break_glass.activated", nil, http.StatusOK).Raw)
	if strings.Count(evt, "recorded late") != 1 || !strings.Contains(evt, fmt.Sprintf("activation %d", aid)) {
		t.Fatalf("the owed break_glass.activated row must be in the audit trail exactly once, marked late:\n%s", evt)
	}
	if st := status(); st.Unreviewed != 1 {
		t.Fatalf("the mandatory review is still owed after settling, got %+v", st)
	}
}
