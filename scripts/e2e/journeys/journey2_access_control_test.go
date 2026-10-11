//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_AccessControl is N2: two projects, four principals (admin,
// project-A editor, project-A viewer, an outsider with no project
// membership). Asserts, with both CLI and REST: the viewer can read but not
// write in A; the editor can write in A but not B; the outsider sees
// neither project (GET /api/v1/projects itself requires GLOBAL secrets.read
// -- CONFIRMED empirically, not assumed: system_viewer, the universal
// auto-granted baseline every account holds, does NOT carry secrets.read
// (internal/core/auth_bootstrap.go's defaultRoles), so a zero-grant or
// project-scoped-only caller is denied 403 at the route gate itself, before
// any project name could ever reach the response body -- "not even names in
// lists" holds structurally, not via any filtering this journey needed to
// add); removing the editor's role takes effect immediately, no stale
// cache/re-login required; an access request -> approval -> time-bound grant
// works and access ends after expiry. Every denial leaves state unchanged.
func TestJourney_AccessControl(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	accessControl(t, s, cliBin, mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword))
}

const (
	n2ProjectA  = "n2-access-control-a"
	n2ProjectB  = "n2-access-control-b"
	n2EnvName   = "development"
	n2SecretA   = "shared-config-a"
	n2SecretB   = "shared-config-b"
	n2ValueA    = "value-in-project-a"
	n2ValueB    = "value-in-project-b"
	n2UserPass  = "Cinder-Falcon-88-Marsh!"
	n2EditorU   = "n2-editor"
	n2ViewerU   = "n2-viewer"
	n2Outsider  = "n2-outsider"
	n2EditorEml = "n2-editor@example.invalid"
	n2ViewerEml = "n2-viewer@example.invalid"
	n2OutEml    = "n2-outsider@example.invalid"
)

func accessControl(t *testing.T, s *harness.Server, cliBin, adminToken string) {
	t.Helper()
	aEnv := adminEnv(s, adminToken)

	// ── Setup: two projects, one secret each, three human users ────────────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n2ProjectA)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", n2ProjectB)
	projA := projectID(t, s, adminToken, n2ProjectA)
	projB := projectID(t, s, adminToken, n2ProjectB)
	envA := environmentID(t, s, adminToken, projA, n2EnvName)
	envB := environmentID(t, s, adminToken, projB, n2EnvName)

	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n2SecretA,
		"--project", strconv.Itoa(projA), "--environment", strconv.Itoa(envA), "--value", n2ValueA)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", n2SecretB,
		"--project", strconv.Itoa(projB), "--environment", strconv.Itoa(envB), "--value", n2ValueB)
	secretAID := secretID(t, s, adminToken, projA, envA, n2SecretA)

	runCLI(t, cliBin, aEnv, "user", "create", "--username", n2EditorU, "--email", n2EditorEml, "--password", n2UserPass)
	runCLI(t, cliBin, aEnv, "user", "create", "--username", n2ViewerU, "--email", n2ViewerEml, "--password", n2UserPass)
	runCLI(t, cliBin, aEnv, "user", "create", "--username", n2Outsider, "--email", n2OutEml, "--password", n2UserPass)

	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", n2EditorEml, "--role", "project_developer", "--project", n2ProjectA)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", n2ViewerEml, "--role", "project_viewer", "--project", n2ProjectA)
	// n2Outsider gets no grant anywhere.

	editorToken := mfaPersonaLogin(t, s, n2EditorU, n2UserPass)
	viewerToken := mfaPersonaLogin(t, s, n2ViewerU, n2UserPass)
	outsiderToken := mfaPersonaLogin(t, s, n2Outsider, n2UserPass)
	editorEnv := tokenEnv(s, editorToken)
	viewerEnv := tokenEnv(s, viewerToken)
	outsiderEnv := tokenEnv(s, outsiderToken)

	refA := fmt.Sprintf("%s/%s/%s", n2ProjectA, n2EnvName, n2SecretA)

	// ── Viewer: read succeeds, every write denied and leaves state unchanged ──

	t.Run("viewer can read but not write in A", func(t *testing.T) {
		restEnv := restExpect(t, s, viewerToken, http.MethodGet,
			"/api/v1/secrets/value?ref="+url.QueryEscape(refA), nil, http.StatusOK)
		var got struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(restEnv.Data, &got); err != nil {
			t.Fatalf("decode viewer REST read: %v", err)
		}
		if got.Value != n2ValueA {
			t.Fatalf("viewer REST read: want %q, got %q", n2ValueA, got.Value)
		}
		cliOut := runCLI(t, cliBin, viewerEnv, "secret", "get", "--ref", refA)
		if v := parseDecryptedValue(t, cliOut); v != n2ValueA {
			t.Fatalf("viewer CLI read: want %q, got %q", n2ValueA, v)
		}

		// Write denials (CLI -- REST is exercised directly below for the update case,
		// since create/delete's denial path is identical in shape).
		runCLIExpectErr(t, cliBin, viewerEnv, "secret", "create", "--name", "viewer-should-not-exist",
			"--project", strconv.Itoa(projA), "--environment", strconv.Itoa(envA), "--value", "nope")
		runCLIExpectErr(t, cliBin, viewerEnv, "secret", "update", "--id", strconv.Itoa(secretAID), "--value", "nope")
		runCLIExpectErr(t, cliBin, viewerEnv, "secret", "delete", "--id", strconv.Itoa(secretAID), "--force")

		restEnv2 := restCall(t, s, viewerToken, http.MethodPut,
			fmt.Sprintf("/api/v1/secrets/%d", secretAID), map[string]string{"value": "nope-rest"})
		if restEnv2.StatusCode != http.StatusForbidden {
			t.Errorf("viewer REST update: want HTTP %d, got %d: %s", http.StatusForbidden, restEnv2.StatusCode, string(restEnv2.Raw))
		}
		assertDenialLeaksNothing(t, restEnv2, n2ValueA, n2ValueB, n2ProjectB)

		assertSecretUnchanged(t, s, adminToken, secretAID, n2ValueA)
		assertNoSecretNamed(t, s, adminToken, projA, envA, "viewer-should-not-exist")
	})

	// ── Editor: writes succeed in A, denied in B, state unchanged in B ──────

	t.Run("editor can write in A but not B", func(t *testing.T) {
		runCLI(t, cliBin, editorEnv, "secret", "create", "--name", "editor-created-in-a",
			"--project", strconv.Itoa(projA), "--environment", strconv.Itoa(envA), "--value", "editor-value")
		createdID := secretID(t, s, adminToken, projA, envA, "editor-created-in-a")
		assertSecretUnchanged(t, s, adminToken, createdID, "editor-value")

		runCLIExpectErr(t, cliBin, editorEnv, "secret", "create", "--name", "editor-should-not-exist-in-b",
			"--project", strconv.Itoa(projB), "--environment", strconv.Itoa(envB), "--value", "nope")
		assertNoSecretNamed(t, s, adminToken, projB, envB, "editor-should-not-exist-in-b")

		// REST, exact status -- runCLIExpectErr alone passes on ANY non-zero
		// exit (a renamed flag, a usage error) and proves nothing about what
		// the SERVER actually did with the request; this is the assertion
		// that actually pins the denial.
		createEnv := restCall(t, s, editorToken, http.MethodPost, "/api/v1/secrets", map[string]interface{}{
			"name": "editor-should-not-exist-in-b-rest", "project_id": projB, "environment_id": envB, "value": "nope", "type": "generic",
		})
		if createEnv.StatusCode != http.StatusForbidden {
			t.Errorf("editor REST create in B: want HTTP %d, got %d: %s", http.StatusForbidden, createEnv.StatusCode, string(createEnv.Raw))
		}
		assertDenialLeaksNothing(t, createEnv, n2ValueA, n2ValueB, n2ProjectB)
		assertNoSecretNamed(t, s, adminToken, projB, envB, "editor-should-not-exist-in-b-rest")

		secretBID := secretID(t, s, adminToken, projB, envB, n2SecretB)
		runCLIExpectErr(t, cliBin, editorEnv, "secret", "update", "--id", strconv.Itoa(secretBID), "--value", "nope")
		assertSecretUnchanged(t, s, adminToken, secretBID, n2ValueB)

		updateEnv := restCall(t, s, editorToken, http.MethodPut,
			fmt.Sprintf("/api/v1/secrets/%d", secretBID), map[string]string{"value": "nope-rest"})
		if updateEnv.StatusCode != http.StatusForbidden {
			t.Errorf("editor REST update in B: want HTTP %d, got %d: %s", http.StatusForbidden, updateEnv.StatusCode, string(updateEnv.Raw))
		}
		assertDenialLeaksNothing(t, updateEnv, n2ValueA, n2ValueB, n2ProjectB)
		assertSecretUnchanged(t, s, adminToken, secretBID, n2ValueB)
	})

	// ── Outsider: project list names neither project; direct access to a known
	// secret ID in A denied too.
	//
	// Since #2780 the listing is least-privilege rather than admin-only: it
	// answers 200 with only the caller's visible projects instead of 403 for
	// anyone short of a global admin. For an outsider that set is EMPTY, so the
	// secrecy property this journey guards is unchanged -- neither project is
	// named -- and only the shape of the refusal moved. Asserting the empty set
	// rather than the status code is also the stronger assertion: a regression
	// that started serving projects to a non-member would now fail here, where
	// before #2780 the 403 said nothing about what the filter does. ───────────

	t.Run("outsider sees neither project, denied direct access too", func(t *testing.T) {
		restEnv := restCall(t, s, outsiderToken, http.MethodGet, "/api/v1/projects", nil)
		if restEnv.StatusCode != http.StatusOK {
			t.Errorf("outsider GET /api/v1/projects: want HTTP %d, got %d: %s", http.StatusOK, restEnv.StatusCode, string(restEnv.Raw))
		}
		if names := listedProjectNames(t, restEnv); len(names) != 0 {
			t.Errorf("outsider GET /api/v1/projects: want an empty listing, got %v: %s", names, string(restEnv.Raw))
		}
		assertRawLeaksNothing(t, restEnv, n2ProjectA, n2ProjectB)
		// The CLI follows the server: it now exits 0 with an empty list instead
		// of erroring. It must still name neither project.
		listOut := runCLI(t, cliBin, outsiderEnv, "project", "list")
		for _, name := range []string{n2ProjectA, n2ProjectB} {
			if strings.Contains(listOut, name) {
				t.Errorf("keyorix project list leaked %q to an outsider:\n%s", name, listOut)
			}
		}

		restEnv2 := restCall(t, s, outsiderToken, http.MethodGet,
			"/api/v1/secrets/value?ref="+url.QueryEscape(refA), nil)
		if restEnv2.StatusCode != http.StatusForbidden {
			t.Errorf("outsider direct secret access: want HTTP %d, got %d: %s", http.StatusForbidden, restEnv2.StatusCode, string(restEnv2.Raw))
		}
		assertDenialLeaksNothing(t, restEnv2, n2ValueA, n2ValueB, n2ProjectB)
		runCLIExpectErr(t, cliBin, outsiderEnv, "secret", "get", "--ref", refA)
	})

	// ── Immediate role-removal: no re-login, no stale grant ─────────────────

	t.Run("removing editor's role denies the very next call", func(t *testing.T) {
		// No re-login, same editorEnv/session token throughout. internal/core/
		// rbac_management.go's removeUserRoleUnguarded makes this immediate via TWO
		// independent mechanisms (red-proofed together -- disabling either ALONE left
		// the other still enforcing immediate denial, just via a different HTTP status:
		// storage.RemoveRole's row deletion alone still denies via a freshly-queried
		// 403 since AuthorizePrincipal always re-reads user_roles live, never a cached
		// permission set; evictUserSessionCache's cache-tombstone alone still denies
		// via a 401, invalidating the whole session rather than one permission).
		runCLI(t, cliBin, aEnv, "rbac", "remove-role", "--user", n2EditorEml, "--role", "project_developer", "--project", n2ProjectA)
		runCLIExpectErr(t, cliBin, editorEnv, "secret", "create", "--name", "editor-post-revoke",
			"--project", strconv.Itoa(projA), "--environment", strconv.Itoa(envA), "--value", "nope")
		assertNoSecretNamed(t, s, adminToken, projA, envA, "editor-post-revoke")

		// REST, exact status -- since #2423, removeUserRoleUnguarded's
		// evictUserSessionCache CLEARS the editor's cached auth entry instead of
		// writing a negative tombstone (a role removal does not invalidate the
		// session itself; a tombstone answered 401 "unauthenticated" for a
		// session that was still valid). The very next call is therefore
		// re-authorized live against user_roles and denied with 403
		// (authenticated, but no longer permitted) -- still immediate, with no
		// stale grant. Before #2423 this asserted 401.
		postRevokeEnv := restCall(t, s, editorToken, http.MethodPost, "/api/v1/secrets", map[string]interface{}{
			"name": "editor-post-revoke-rest", "project_id": projA, "environment_id": envA, "value": "nope", "type": "generic",
		})
		if postRevokeEnv.StatusCode != http.StatusForbidden {
			t.Errorf("editor REST create after role removal: want HTTP %d, got %d: %s", http.StatusForbidden, postRevokeEnv.StatusCode, string(postRevokeEnv.Raw))
		}
		assertDenialLeaksNothing(t, postRevokeEnv, n2ValueA, n2ValueB, n2ProjectB)
		assertNoSecretNamed(t, s, adminToken, projA, envA, "editor-post-revoke-rest")
	})

	// ── Access request -> approval -> time-bound grant -> expiry ────────────

	t.Run("access request approve with a TTL, access ends after expiry", func(t *testing.T) {
		// REST, not CLI, for this one step -- a REAL, CONFIRMED CLI gap found here:
		// `keyorix request access --project <name>` resolves the name to an ID via
		// resolveRequestProjectID (cli/cmd/request.go), which calls GET
		// /api/v1/projects -- the SAME globally-gated route N2's own "outsider sees
		// neither project" case above proves an outsider cannot call (403). So the
		// CLI's self-service `request access` is unusable by exactly the persona the
		// feature exists for: a caller with no visibility into the project they want
		// access to. The SERVER route itself has no such restriction --
		// POST /api/v1/projects/{id}/access-requests (server/http/router.go:516) carries
		// no permission middleware at all, by design (confirmed: any authenticated
		// caller may request access to any project BY ID). Only the CLI's
		// name-only `--project` flag (no `--project-id` escape hatch exists) is the
		// blocker. Not a security bug (over-restrictive, not under-restrictive) --
		// filed as a CLI usability gap in the report, worked around here via REST with
		// the project ID this test already resolved as admin, rather than patched.
		reqEnv := restExpect(t, s, outsiderToken, http.MethodPost,
			fmt.Sprintf("/api/v1/projects/%d/access-requests", projA),
			map[string]string{"suggested_role": "project_viewer"}, http.StatusCreated)
		var reqData struct {
			AccessRequest struct {
				ID int `json:"ID"` // internal/storage/models.AccessRequest carries no json tags -- default Go field casing
			} `json:"access_request"`
		}
		if err := json.Unmarshal(reqEnv.Data, &reqData); err != nil {
			t.Fatalf("decode POST access-requests response: %v\nraw: %s", err, reqEnv.Data)
		}
		reqID := reqData.AccessRequest.ID

		runCLI(t, cliBin, aEnv, "request", "review", "--id", strconv.Itoa(reqID), "--action", "approve",
			"--project", n2ProjectA, "--role", "project_viewer", "--ttl", "3s")

		// Immediate: same outsider session, no re-login, can now read in A.
		restEnv := restExpect(t, s, outsiderToken, http.MethodGet,
			"/api/v1/secrets/value?ref="+url.QueryEscape(refA), nil, http.StatusOK)
		var got struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(restEnv.Data, &got); err != nil {
			t.Fatalf("decode post-approval read: %v", err)
		}
		if got.Value != n2ValueA {
			t.Fatalf("post-approval read: want %q, got %q", n2ValueA, got.Value)
		}

		// Bounded poll past the 3s TTL -- no injectable clock exists anywhere in this
		// repo (confirmed by grep across internal/core and server/http/middleware
		// during N0), so a short real TTL + bounded wait is the documented fallback.
		// NOTE: this adds up to ~20s of real wall-clock time to this journey's
		// runtime, on top of the 3s TTL itself -- the unavoidable cost of testing
		// real expiry without a mockable clock.
		deadline := time.Now().Add(20 * time.Second)
		var expiredEnv restEnvelope
		for {
			expiredEnv = restCall(t, s, outsiderToken, http.MethodGet, "/api/v1/secrets/value?ref="+url.QueryEscape(refA), nil)
			if expiredEnv.StatusCode == http.StatusForbidden {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("time-bound grant did not expire within 20s of its 3s TTL (last status %d)", expiredEnv.StatusCode)
			}
			time.Sleep(500 * time.Millisecond)
		}
		assertDenialLeaksNothing(t, expiredEnv, n2ValueA, n2ValueB, n2ProjectB)
	})
}

// assertSecretUnchanged reads secretID via the still-valid admin session and
// asserts its value is still want -- used after every denied write to prove
// the denial left state unchanged, not merely that it returned an error.
func assertSecretUnchanged(t *testing.T, s *harness.Server, adminToken string, secretID int, want string) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretID), nil, http.StatusOK)
	var got struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("decode admin readback of secret %d: %v\nraw: %s", secretID, err, env.Data)
	}
	if got.Value != want {
		t.Fatalf("secret %d changed despite a denied write: want %q, got %q", secretID, want, got.Value)
	}
}

// assertDenialLeaksNothing asserts a denied REST response (env) carries no
// Data payload AND that its full raw body contains none of forbidden as a
// bare substring -- catching a handler that returns the right status code
// but still embeds a value or project name it should never have revealed to
// this caller. env.Raw is ALWAYS the full raw response body (restCall sets
// it unconditionally, not only on JSON-decode failure), so this checks the
// real bytes the client received, not just the decoded envelope.
func assertDenialLeaksNothing(t *testing.T, env restEnvelope, forbidden ...string) {
	t.Helper()
	if len(env.Data) != 0 && string(env.Data) != "null" {
		t.Errorf("denied response carries a Data payload: %s", env.Data)
	}
	assertRawLeaksNothing(t, env, forbidden...)
}

// assertRawLeaksNothing is assertDenialLeaksNothing's substring half on its
// own: the full raw body contains none of forbidden. Used where the response
// is legitimately a 200 carrying a Data payload but still must not name
// something -- an empty least-privilege listing (#2780), where "carries no
// payload" is the wrong assertion but "names no project" is the right one.
func assertRawLeaksNothing(t *testing.T, env restEnvelope, forbidden ...string) {
	t.Helper()
	raw := string(env.Raw)
	for _, s := range forbidden {
		if strings.Contains(raw, s) {
			t.Errorf("response body leaks %q: %s", s, raw)
		}
	}
}

// assertNoSecretNamed confirms no secret named name exists in project/env --
// used after a denied create to prove it was never partially applied.
func assertNoSecretNamed(t *testing.T, s *harness.Server, adminToken string, projID, envID int, name string) {
	t.Helper()
	path := fmt.Sprintf("/api/v1/secrets?project_id=%d&environment_id=%d", projID, envID)
	env := restExpect(t, s, adminToken, http.MethodGet, path, nil, http.StatusOK)
	var data struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET %s: %v\nraw: %s", path, err, env.Data)
	}
	for _, sec := range data.Secrets {
		if sec.Name == name {
			t.Fatalf("secret %q exists in project %d env %d despite a denied create", name, projID, envID)
		}
	}
}
