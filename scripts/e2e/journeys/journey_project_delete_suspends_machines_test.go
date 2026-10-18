//go:build e2e

package journeys

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_ProjectDeleteSuspendsMachineTokens (#3433) is the operator who deletes a
// project and expects its CI token to stop working: against a real server, a machine
// token of the deleted project is refused 401 (as an unknown token is), a token of
// another project keeps working, the audit log carries one machine_identity.suspended
// event naming the project soft-delete, and restoring the project brings the token
// back with a machine_identity.activated event naming the restore.
func TestJourney_ProjectDeleteSuspendsMachineTokens(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	machineToken := func(project, machine string) string {
		t.Helper()
		runCLI(t, cliBin, aEnv, "machine", "create", "--project", project, "--name", machine, "--type", "ci")
		runCLI(t, cliBin, aEnv, "machine", "grant-role", machine, "--project", project, "--role", "project_viewer")
		out := runCLI(t, cliBin, aEnv, "machine", "token", "issue", machine, "--project", project, "--name", machine+"-token")
		tok, _ := parseIssuedToken(t, out)
		return tok
	}
	authenticates := func(tok string) bool {
		t.Helper()
		return restCall(t, s, tok, http.MethodGet, "/api/v1/auth/profile", nil).StatusCode != http.StatusUnauthorized
	}
	auditFor := func(action string) string {
		t.Helper()
		return string(restExpect(t, s, adminToken, http.MethodGet,
			"/api/v1/audit/search?action="+action+"&limit=50", nil, http.StatusOK).Raw)
	}

	runCLI(t, cliBin, aEnv, "project", "create", "--name", "j-doomed")
	runCLI(t, cliBin, aEnv, "project", "create", "--name", "j-keeper")
	doomedID := strconv.Itoa(projectID(t, s, adminToken, "j-doomed"))
	doomedTok := machineToken("j-doomed", "j-doomed-ci")
	keeperTok := machineToken("j-keeper", "j-keeper-ci")

	if !authenticates(doomedTok) || !authenticates(keeperTok) {
		t.Fatal("both machine tokens must authenticate before the delete")
	}

	restExpect(t, s, adminToken, http.MethodDelete, "/api/v1/projects/"+doomedID+"?force=true", nil, http.StatusOK)

	t.Run("the deleted project's token is refused like an unknown token", func(t *testing.T) {
		env := restCall(t, s, doomedTok, http.MethodGet, "/api/v1/auth/profile", nil)
		if env.StatusCode != http.StatusUnauthorized {
			t.Fatalf("machine token of a deleted project: HTTP %d, want 401: %s", env.StatusCode, env.Raw)
		}
		unknown := restCall(t, s, "kx_machine_notarealtoken", http.MethodGet, "/api/v1/auth/profile", nil)
		if unknown.StatusCode != env.StatusCode {
			t.Fatalf("dead token %d vs unknown token %d: must be indistinguishable", env.StatusCode, unknown.StatusCode)
		}
	})
	t.Run("another project's token keeps working", func(t *testing.T) {
		if !authenticates(keeperTok) {
			t.Fatal("a machine identity of a live project must not be suspended")
		}
	})
	t.Run("the suspension is audited with the project soft-delete as the reason", func(t *testing.T) {
		raw := auditFor("machine_identity.suspended")
		if !strings.Contains(raw, "j-doomed-ci") || !strings.Contains(raw, "project soft-delete (project "+doomedID+")") {
			t.Fatalf("no machine_identity.suspended event naming j-doomed-ci and the project soft-delete:\n%s", raw)
		}
		if strings.Contains(raw, "j-keeper-ci") {
			t.Fatalf("the live project's identity must not be suspended:\n%s", raw)
		}
	})

	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/projects/"+doomedID+"/restore", nil, http.StatusOK)

	t.Run("restore brings the token back, audited", func(t *testing.T) {
		raw := auditFor("machine_identity.activated")
		if !strings.Contains(raw, "j-doomed-ci") || !strings.Contains(raw, "project restore (project "+doomedID+")") {
			t.Fatalf("no machine_identity.activated event naming j-doomed-ci and the project restore:\n%s", raw)
		}
		if env := restCall(t, s, doomedTok, http.MethodGet, "/api/v1/auth/profile", nil); env.StatusCode == http.StatusUnauthorized {
			t.Fatalf("the restored project's machine token must authenticate again: %s", env.Raw)
		}
	})
}
