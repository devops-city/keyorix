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

// TestJourney_ShareElevation is the demo's share step (docs/demo/GOLDEN-PATH.md 3b)
// against a real server and the real CLI: #2976 (the owner who holds only the global
// admin role got a bare 403) and #2941 (a share may elevate a project member's access
// on that one secret). Steps, each asserted:
//  1. The global-only admin owns a secret in a project it is not a member of; sharing
//     is refused WITH the reason.
//  2. After `rbac assign-role ... project_admin` (what scripts/demo/up.sh now seeds),
//     `share create --permission write` to a project_viewer succeeds.
//  3. The viewer updates the secret with the CLI (the share elevates her) — and
//     nothing else: suspend, resume, move or re-share are refused with the reason
//     (#3001 allowlist: update value, update metadata, rotate).
//  4. `share revoke`; the viewer's update is refused again, her role's read stays.
//  5. The audit trail names the share id on create, elevated update and revoke.
//  6. Sharing with a non-member is refused with the reason.
func TestJourney_ShareElevation(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	shareElevation(t, s, cliBin, "smoketestadmin", "smoketestadmin@example.invalid", harness.BootstrapAdminPassword)
}

const (
	n20Project   = "n20-backend-api"
	n20EnvName   = "development"
	n20Secret    = "n20-db-password"
	n20Value     = "n20-value-v1"
	n20UserPass  = "Cinder-Falcon-88-Marsh!"
	n20Viewer    = "n20-alice"
	n20ViewerEml = "n20-alice@example.invalid"
	n20Outsider  = "n20-bob"
	n20OutEml    = "n20-bob@example.invalid"
)

func shareElevation(t *testing.T, s *harness.Server, cliBin, adminUser, adminEmail, adminPass string) {
	t.Helper()
	adminToken := adminLogin(t, s, adminUser, adminPass)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n20Project)
	proj := projectID(t, s, adminToken, n20Project)
	env := environmentID(t, s, adminToken, proj, n20EnvName)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n20Secret,
		"--project", strconv.Itoa(proj), "--environment", strconv.Itoa(env), "--value", n20Value)
	sid := secretID(t, s, adminToken, proj, env, n20Secret)

	runCLI(t, cliBin, aEnv, "user", "create", "--username", n20Viewer, "--email", n20ViewerEml, "--password", n20UserPass)
	runCLI(t, cliBin, aEnv, "user", "create", "--username", n20Outsider, "--email", n20OutEml, "--password", n20UserPass)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", n20ViewerEml, "--role", "project_viewer", "--project", n20Project)
	aliceID := n20UserID(t, s, adminToken, n20Viewer)
	bobID := n20UserID(t, s, adminToken, n20Outsider)
	aliceToken := adminLogin(t, s, n20Viewer, n20UserPass)
	aliceEnv := tokenEnv(s, aliceToken)
	sharePath := fmt.Sprintf("/api/v1/secrets/%d/share", sid)

	t.Run("owner who is not a project member is told why (#2976)", func(t *testing.T) {
		e := restCall(t, s, adminToken, http.MethodPost, sharePath,
			map[string]interface{}{"recipient_id": aliceID, "is_group": false, "permission": "write"})
		if e.StatusCode != http.StatusForbidden || !strings.Contains(e.Message, "not a member of this secret's project") {
			t.Fatalf("want 403 naming the membership reason, got %d: %s", e.StatusCode, e.Raw)
		}
		runCLIExpectErr(t, cliBin, aEnv, "share", "create", "--secret-id", strconv.Itoa(sid),
			"--recipient-id", strconv.Itoa(aliceID), "--permission", "write")
	})

	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", adminEmail, "--role", "project_admin", "--project", n20Project)

	t.Run("sharing with a non-member is refused with the reason", func(t *testing.T) {
		e := restCall(t, s, adminToken, http.MethodPost, sharePath,
			map[string]interface{}{"recipient_id": bobID, "is_group": false, "permission": "read"})
		if e.StatusCode != http.StatusForbidden || !strings.Contains(e.Message, "recipient is not a member") {
			t.Fatalf("want 403 naming the recipient reason, got %d: %s", e.StatusCode, e.Raw)
		}
	})

	// Before the share: the viewer reads but cannot update.
	runCLIExpectErr(t, cliBin, aliceEnv, "secret", "update", "--id", strconv.Itoa(sid), "--value", "before-share")
	assertSecretUnchanged(t, s, adminToken, sid, n20Value)

	runCLI(t, cliBin, aEnv, "share", "create", "--secret-id", strconv.Itoa(sid),
		"--recipient-id", strconv.Itoa(aliceID), "--permission", "write")
	shareID := onlyShareID(t, s, adminToken, sid)

	t.Run("a write share elevates the viewer on this secret (#2941)", func(t *testing.T) {
		runCLI(t, cliBin, aliceEnv, "secret", "update", "--id", strconv.Itoa(sid), "--value", "updated-by-alice")
		assertSecretUnchanged(t, s, adminToken, sid, "updated-by-alice")
		// Never delete, never re-share.
		runCLIExpectErr(t, cliBin, aliceEnv, "secret", "delete", "--id", strconv.Itoa(sid), "--force")
		if e := restCall(t, s, aliceToken, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", sid), nil); e.StatusCode != http.StatusForbidden {
			t.Errorf("write share must not grant delete: got %d: %s", e.StatusCode, e.Raw)
		}
		if e := restCall(t, s, aliceToken, http.MethodPost, sharePath,
			map[string]interface{}{"recipient_id": bobID, "is_group": false, "permission": "read"}); e.StatusCode != http.StatusForbidden {
			t.Errorf("write share must not grant re-sharing: got %d: %s", e.StatusCode, e.Raw)
		}
	})

	t.Run("a write share elevates only update, metadata and rotate (#3001)", func(t *testing.T) {
		runCLI(t, cliBin, aliceEnv, "secret", "rotate", "--id", strconv.Itoa(sid), "--value", "rotated-by-alice")
		assertSecretUnchanged(t, s, adminToken, sid, "rotated-by-alice")
		runCLI(t, cliBin, aliceEnv, "secret", "update", "--id", strconv.Itoa(sid), "--value", "updated-by-alice")
		// An incident freeze she could undo, or a denial of service: refused, with the reason.
		runCLIExpectErr(t, cliBin, aliceEnv, "secret", "suspend", "--id", strconv.Itoa(sid))
		for _, p := range []string{"suspend", "resume", "move", "rollback", "transfer-ownership"} {
			e := restCall(t, s, aliceToken, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/%s", sid, p), map[string]interface{}{})
			if e.StatusCode != http.StatusForbidden || !strings.Contains(e.Message, "only lets you update its value and metadata or rotate it") {
				t.Errorf("POST .../%s: want 403 with the share reason, got %d: %s", p, e.StatusCode, e.Raw)
			}
		}
	})

	runCLI(t, cliBin, aEnv, "share", "revoke", "--share-id", strconv.Itoa(shareID))

	t.Run("revoke removes exactly the elevation", func(t *testing.T) {
		runCLIExpectErr(t, cliBin, aliceEnv, "secret", "update", "--id", strconv.Itoa(sid), "--value", "after-revoke")
		if e := restCall(t, s, aliceToken, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", sid),
			map[string]string{"value": "after-revoke-rest"}); e.StatusCode != http.StatusForbidden {
			t.Errorf("after revoke the update must be refused: got %d: %s", e.StatusCode, e.Raw)
		}
		assertSecretUnchanged(t, s, adminToken, sid, "updated-by-alice")
		out := runCLI(t, cliBin, aliceEnv, "secret", "get", "--id", strconv.Itoa(sid), "--show-value")
		if !strings.Contains(out, "updated-by-alice") {
			t.Errorf("the viewer's role read must survive the revoke, got:\n%s", out)
		}
	})

	t.Run("audit names the share id", func(t *testing.T) {
		waitForAuditEventsToSettle(t, s, adminToken)
		marker := fmt.Sprintf("share %d", shareID)
		for _, action := range []string{"share_created", "share_access_elevated", "share_revoked"} {
			e := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?action="+action, nil, http.StatusOK)
			var data struct {
				Events []struct {
					Description string `json:"description"`
				} `json:"events"`
			}
			if err := json.Unmarshal(e.Data, &data); err != nil {
				t.Fatalf("decode audit search %s: %v\nraw: %s", action, err, e.Data)
			}
			found := false
			for _, ev := range data.Events {
				found = found || strings.Contains(ev.Description, marker)
			}
			if !found {
				t.Errorf("no %s audit event names %q: %s", action, marker, e.Data)
			}
		}
	})
}

// onlyShareID returns the single share on secret sid (GET /api/v1/secrets/{id}/shares).
func onlyShareID(t *testing.T, s *harness.Server, adminToken string, sid int) int {
	t.Helper()
	e := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/shares", sid), nil, http.StatusOK)
	var shares []struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(e.Data, &shares); err != nil {
		var wrapped struct {
			Shares []struct {
				ID int `json:"id"`
			} `json:"shares"`
		}
		if werr := json.Unmarshal(e.Data, &wrapped); werr != nil {
			t.Fatalf("decode shares of secret %d: %v / %v\nraw: %s", sid, err, werr, e.Data)
		}
		for _, sh := range wrapped.Shares {
			shares = append(shares, struct {
				ID int `json:"id"`
			}{sh.ID})
		}
	}
	if len(shares) != 1 {
		t.Fatalf("want exactly one share on secret %d, got %d: %s", sid, len(shares), e.Data)
	}
	return shares[0].ID
}

// n20UserID resolves a username to its user ID (?username= is an exact match).
func n20UserID(t *testing.T, s *harness.Server, adminToken, username string) int {
	t.Helper()
	e := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/users?username="+username, nil, http.StatusOK)
	var data struct {
		Users []struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/users?username=%s: %v\nraw: %s", username, err, e.Data)
	}
	for _, u := range data.Users {
		if u.Username == username {
			return u.ID
		}
	}
	t.Fatalf("user %q not found: %s", username, e.Data)
	return 0
}
