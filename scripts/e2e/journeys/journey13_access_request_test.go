//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_AccessRequest is J26: a zero-grant user requests access to a
// project, an admin approves it and the requester can then read a secret
// they couldn't before; a second requester is denied and keeps no access; a
// third request is withdrawn by its own requester before anyone reviews it;
// and a requester who later holds review rights (via the first approval)
// cannot approve their own, separate, later request -- the maker-!=-checker
// guard (internal/core/invitations.go: "a requester cannot approve their own
// access request").
//
// `--project-id` is used throughout for the zero-grant requester and for the
// project-scoped (not deployment-wide) reviewer (#2360, closed): the
// project-NAME resolution these subcommands otherwise use
// (resolveRequestProjectID -> GET /api/v1/projects) is gated on a GLOBAL
// permission neither caller ever holds (confirmed live by journey2's own N2
// finding). #2360's body names `request access`/`list`/`withdraw`/`review` as
// all affected; all four now carry the flag, and this journey is the real-server
// proof for each of them: the self-approval attempt and the withdraw path below
// are driven through the CLI, not over REST as they had to be before.
func TestJourney_AccessRequest(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j13-access-request"
		envName     = "development"
		secretName  = "prod-db-password"
		secretValue = "j13-secret-value-4f8a"
		userPass    = "Ferrous-Quartz-29-Dell!"
		requesterU  = "j13-requester"
		requesterEm = "j13-requester@example.invalid"
		deniedU     = "j13-denied"
		deniedEm    = "j13-denied@example.invalid"
	)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── Setup: a project with a secret, and two zero-grant human users ──────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	projID := projectID(t, s, adminToken, projName)
	envID := environmentID(t, s, adminToken, projID, envName)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", secretName,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", secretValue)

	runCLI(t, cliBin, aEnv, "user", "create", "--username", requesterU, "--email", requesterEm, "--password", userPass)
	runCLI(t, cliBin, aEnv, "user", "create", "--username", deniedU, "--email", deniedEm, "--password", userPass)

	requesterToken := mfaPersonaLogin(t, s, requesterU, userPass)
	requesterEnvCLI := tokenEnv(s, requesterToken)
	deniedToken := mfaPersonaLogin(t, s, deniedU, userPass)
	deniedEnvCLI := tokenEnv(s, deniedToken)

	ref := fmt.Sprintf("%s/%s/%s", projName, envName, secretName)

	// Before any request: neither user can read the secret.
	runCLIExpectErr(t, cliBin, requesterEnvCLI, "secret", "get", "--ref", ref)
	runCLIExpectErr(t, cliBin, deniedEnvCLI, "secret", "get", "--ref", ref)

	// ── Approve path: request -> approve -> requester can now read ──────────

	reqOut := runCLI(t, cliBin, requesterEnvCLI, "request", "access",
		"--project-id", strconv.Itoa(projID), "--role", "project_admin", "--reason", "need prod access")
	req1ID := parseAccessRequestID(t, reqOut)

	approveOut := runCLI(t, cliBin, aEnv, "request", "review",
		"--id", strconv.Itoa(req1ID), "--action", "approve", "--project", projName, "--role", "project_admin")
	if !strings.Contains(approveOut, "approved") {
		t.Fatalf("expected `request review --action approve` to confirm approval, got:\n%s", approveOut)
	}

	// The real outcome, not just the command's own exit status: the requester
	// could not read before, and can now.
	readOut := runCLI(t, cliBin, requesterEnvCLI, "secret", "get", "--ref", ref)
	if v := parseDecryptedValue(t, readOut); v != secretValue {
		t.Fatalf("approved requester's read: want %q, got %q", secretValue, v)
	}

	assertAccessRequestAudit(t, s, adminToken, projID, "access_request.approved", fmt.Sprintf("access request %d", req1ID))

	// ── Self-approval is refused ─────────────────────────────────────────────
	// The requester now holds project_admin on projID (the grant just made),
	// so they hold roles.assign at that scope -- enough to pass the review
	// route's RequireScopedPermission gate -- and files a SEPARATE, later
	// request to reach the maker-!=-checker guard itself, not a permission
	// denial. Driven through the CLI with --project-id (#2360): a
	// project-scoped reviewer is still denied GET /api/v1/projects, so
	// `request review --project <name>` cannot resolve a name for them.

	selfReqOut := runCLI(t, cliBin, requesterEnvCLI, "request", "access",
		"--project-id", strconv.Itoa(projID), "--role", "project_viewer",
		"--reason", "second request, for the self-approval check")
	req2ID := parseAccessRequestID(t, selfReqOut)

	selfApproveErr := runCLIExpectErr(t, cliBin, requesterEnvCLI, "request", "review",
		"--id", strconv.Itoa(req2ID), "--action", "approve", "--project-id", strconv.Itoa(projID))
	if !strings.Contains(selfApproveErr, "cannot approve their own") {
		t.Fatalf("self-approval: want the maker-!=-checker refusal message, got:\n%s", selfApproveErr)
	}

	// ── Deny path: a second requester is rejected and keeps no access ───────

	deniedReqOut := runCLI(t, cliBin, deniedEnvCLI, "request", "access",
		"--project-id", strconv.Itoa(projID), "--reason", "also need access")
	req3ID := parseAccessRequestID(t, deniedReqOut)

	rejectOut := runCLI(t, cliBin, aEnv, "request", "review",
		"--id", strconv.Itoa(req3ID), "--action", "reject", "--project", projName, "--reason", "not justified")
	if !strings.Contains(rejectOut, "rejected") {
		t.Fatalf("expected `request review --action reject` to confirm rejection, got:\n%s", rejectOut)
	}

	runCLIExpectErr(t, cliBin, deniedEnvCLI, "secret", "get", "--ref", ref)
	assertAccessRequestAudit(t, s, adminToken, projID, "access_request.rejected", fmt.Sprintf("access request %d", req3ID))

	// ── Withdraw path: the denied user requests again, then withdraws it
	// themselves before anyone reviews it ────────────────────────────────────

	// Both steps through the CLI with --project-id (#2360): the withdrawer is a
	// zero-grant caller, so project-NAME resolution is unavailable to them.
	withdrawReqOut := runCLI(t, cliBin, deniedEnvCLI, "request", "access",
		"--project-id", strconv.Itoa(projID), "--reason", "trying again")
	req4ID := parseAccessRequestID(t, withdrawReqOut)

	withdrawOut := runCLI(t, cliBin, deniedEnvCLI, "request", "withdraw",
		"--id", strconv.Itoa(req4ID), "--project-id", strconv.Itoa(projID))
	if !strings.Contains(withdrawOut, fmt.Sprintf("Access request %d withdrawn.", req4ID)) {
		t.Fatalf("expected `request withdraw` to confirm the withdrawal, got:\n%s", withdrawOut)
	}

	// `request list --project-id` is the admin's read-back of the resulting state
	// (the same flag, exercised on the fourth subcommand #2360 names).
	listOut := runCLI(t, cliBin, aEnv, "request", "list", "--project-id", strconv.Itoa(projID))
	if !regexp.MustCompile(fmt.Sprintf(`(?m)^%d\s.*\bwithdrawn\b`, req4ID)).MatchString(listOut) {
		t.Fatalf("withdrawn request %d not listed as \"withdrawn\" by `request list --project-id %d`:\n%s",
			req4ID, projID, listOut)
	}
	// The withdrawer still has no access (withdrawing your own request must
	// not itself grant anything).
	runCLIExpectErr(t, cliBin, deniedEnvCLI, "secret", "get", "--ref", ref)
	assertAccessRequestAudit(t, s, adminToken, projID, "access_request.withdrawn", fmt.Sprintf("request %d", req4ID))
}

// accessRequestIDRe is anchored to the "Access requested: id=N" line
// specifically -- with --project-id, runRequestAccess ALSO prints "Requesting
// access to project id=<projectID>..." earlier in the same output, and a bare
// `id=(\d+)` regex matches that project-ID echo first (it comes first in the
// combined stdout), silently returning the wrong number.
var accessRequestIDRe = regexp.MustCompile(`Access requested: id=(\d+)`)

// parseAccessRequestID extracts the numeric request ID from `request
// access`'s stdout ("Access requested: id=%d project=...").
func parseAccessRequestID(t *testing.T, cliOutput string) int {
	t.Helper()
	m := accessRequestIDRe.FindStringSubmatch(cliOutput)
	if m == nil {
		t.Fatalf("could not find \"id=<N>\" in `request access` output:\n%s", cliOutput)
	}
	id, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse access request ID %q: %v", m[1], err)
	}
	return id
}

// assertAccessRequestAudit confirms an audit event of the given action type,
// scoped to projID, whose description contains descSubstr, was recorded --
// the "assert the effect, not the return value" check for every access-
// request state transition above.
func assertAccessRequestAudit(t *testing.T, s *harness.Server, adminToken string, projID int, action, descSubstr string) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/audit/search?project_id=%d&action=%s&limit=50", projID, action), nil, http.StatusOK)
	var data struct {
		Events []struct {
			Description string `json:"description"`
		} `json:"events"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode audit search for action %q: %v\nraw: %s", action, err, env.Data)
	}
	for _, e := range data.Events {
		if strings.Contains(e.Description, descSubstr) {
			return
		}
	}
	t.Fatalf("no audit event with action %q and description containing %q found for project %d", action, descSubstr, projID)
}
