// pat_restriction_read_family_test.go — PAT-GUARD-1: every read built outside
// Authorize/AuthorizeSecret honours the caller's PAT restriction (ADR-042).
//
// # The class
//
// A PAT restriction is enforced at the authorization chokepoint (Authorize,
// AuthorizePrincipal, AuthorizeSecret). A route whose gate runs Authorize at a
// scope that covers everything it returns inherits the restriction for free. The
// routes that do NOT are the ones that decide visibility themselves: the routes
// with no permission gate (noPermissionGateAllowlist in permission_sweep_test.go)
// and any gated route whose handler returns rows from outside the gate's scope.
// #3018's GET /shares/owned was one (SHARE-4). This file found more on main:
//
//   - GET /api/v1/secrets returned the owner's owned/shared/ACL-granted secrets in
//     every project to an environment-confined or users.read-only PAT, and to a
//     project-confined PAT asking ?project_id=<another project>
//     (core.ListSecretsWithSharingInfo never consulted the restriction);
//   - GET /api/v1/notifications returned every notification, naming secrets in
//     other projects;
//   - GET /api/v1/secret-access-requests[/{requestId}] listed and served requests
//     in every project, and PUT approved them: their only authorization is
//     requireAdminAuthorityAt, which resolves roles without Authorize;
//   - POST /api/v1/secret-access-requests resolved its target through
//     CheckSecretPermission, whose owner/share/ACL paths never reach Authorize;
//   - POST /api/v1/auth/tokens let a restricted PAT mint an unrestricted one,
//     escaping every restriction at once.
//
// # The guard: TestEveryGETRouteHonoursPATRestriction
//
// Behavioural, not AST. An AST guard can tell that a handler CALLS an authorizer;
// it cannot tell whether the rows it returns stay inside the scope that was
// authorized, and that is exactly how /shares/owned went wrong (it called the
// any-scope gate, then listed by membership). So the guard asks the question
// directly, over the real router:
//
//   - The route set is derived, not listed: chi.Walk over NewRouter, every GET
//     route. A new GET route is covered the moment it is registered.
//   - A canary project holds data whose every name carries patGuardCanary. Two
//     PAT owners — a project-only user and the global admin — are project_admin
//     there and in a decoy project; each owns a canary secret, shares it, has one
//     shared with them (so they hold a notification naming it), has a pending
//     secret access request of their own, and one awaiting their approval.
//   - Restricted personas — the owner's PATs confined to the decoy project, to the
//     decoy environment, to users.read only, to secrets.read in the decoy
//     project, and to system.read only (the gate of GET /dashboard/stats, whose
//     expiring-secrets list and own-activity rows name secrets) — call every GET route with every path parameter bound to each
//     canary object's id, with and without ?project_id/&environment_id naming the
//     canary scope. A 2xx body containing the canary is a violation.
//   - Non-vacuity: the SAME owner's session and unrestricted PAT must see the
//     canary on the same sweep (at least patGuardMinControlHits routes, including
//     every route this PR fixed). Without that, a sweep where every request fails
//     would pass.
//
// What it does NOT cover, said plainly: non-GET routes that only read (POST
// .../secrets/render, POST /connect/{name}/secret:read — all route-gated through
// RequireScopedPermission today); query parameters other than project_id and
// environment_id; ids other than the seeded canary objects'; data the canary
// fixture does not create (e.g. a dynamic-secret lease, a break-glass activation).
// gRPC has its own sweep in server/grpc/pat_restriction_read_family_test.go.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// patGuardCanary is carried by the name of every object in the canary project, so
// "did this response disclose canary data" is a substring check on the body.
const patGuardCanary = "pgcanary"

// patGuardMinControlHits is a floor on how many distinct GET routes the
// UNRESTRICTED personas see canary data through. The sweep measured 16 on main when
// this was written; the floor sits below that so ordinary route churn does not trip
// it, and well above zero so a broken fixture (nothing seeded, every request 401)
// does. Raise it when the fixture grows.
const patGuardMinControlHits = 12

// patRestrictionReadExempt maps a GET route to the reason a RESTRICTED PAT may
// legitimately see canary data through it. Empty today: the sweep found no route
// where that is correct. An entry needs a reason that says why the data is not
// governed by the token's project/environment/permission restriction; "it is
// self-service" is not one (GET /notifications was self-service and leaked).
var patRestrictionReadExempt = map[string]string{}

// patGuardRestrictedPersonas are the owner's restricted PATs. Each is denied the
// canary project by a different dimension of PATRestriction.Allows.
var patGuardRestrictedPersonas = []string{
	"pat_decoy_project",      // ProjectID: another project
	"pat_decoy_env",          // EnvironmentID: an environment of another project
	"pat_users_read_only",    // Permissions: no secrets.read at all
	"pat_secrets_read_decoy", // Permissions + ProjectID: the right permission, the wrong project
	"pat_system_read_only",   // Permissions: system.read only, which passes the GET /dashboard/stats gate
}

// patGuardControlPersonas are the same owner unrestricted. They must SEE the canary.
var patGuardControlPersonas = []string{"session", "pat_unrestricted"}

type patGuardWorld struct {
	server    *httptest.Server
	router    http.Handler
	core      *core.KeyorixCore
	canaryPID uint
	canaryEID uint
	decoyPID  uint
	decoyEID  uint
	ids       []uint // every canary object's id, for path-parameter binding
	tokens    map[string]string
	// accessRequests: "<owner prefix>mine" / "<owner prefix>pending" -> request id.
	accessRequests map[string]uint
	// ownedSecret: "<owner prefix>" -> the canary secret that owner owns.
	ownedSecret map[string]uint
}

func newPATGuardWorld(t *testing.T) *patGuardWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cs := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, cs)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	_ = createTestToken(t, cs) // bootstraps roles + permissions; user 1 is the admin
	ctx := context.Background()

	canary, err := cs.CreateProject(ctx, patGuardCanary+"-proj", patGuardCanary+" project")
	require.NoError(t, err)
	canaryEnv, err := cs.CreateEnvironment(ctx, canary.ID, patGuardCanary+"-env")
	require.NoError(t, err)
	decoy, err := cs.CreateProject(ctx, "decoyproj", "decoy project")
	require.NoError(t, err)
	decoyEnv, err := cs.CreateEnvironment(ctx, decoy.ID, "decoyenv")
	require.NoError(t, err)

	ownerID, ownerSess := mkUserWithGlobalRole(t, cs, "pgowner", "")
	peerID, _ := mkUserWithGlobalRole(t, cs, "pgpeer", "")
	admin, err := cs.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	adminSess, _, err := cs.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	require.NoError(t, err)
	for _, u := range []uint{ownerID, peerID, admin.ID} {
		require.NoError(t, cs.AddProjectMember(ctx, 1, canary.ID, u, "project_admin", false))
		require.NoError(t, cs.AddProjectMember(ctx, 1, decoy.ID, u, "project_admin", false))
	}

	w := &patGuardWorld{
		server: server, router: router, core: cs,
		canaryPID: canary.ID, canaryEID: canaryEnv.ID, decoyPID: decoy.ID, decoyEID: decoyEnv.ID,
		ids:            []uint{canary.ID, canaryEnv.ID, ownerID, peerID, admin.ID},
		tokens:         map[string]string{"session": ownerSess, "admin_session": adminSess.SessionToken},
		accessRequests: map[string]uint{},
		ownedSecret:    map[string]uint{},
	}
	// Two PAT owners, so the sweep covers both ways a restriction is reached: a
	// project-only owner (no global grant — visibility comes from membership and the
	// personal owned/shared/ACL set) and a global admin (whose token must be narrowed
	// below the admin bypass). Each owns a canary secret shared to the peer, and has
	// one shared to them by the peer (which also sends them a notification naming it).
	for _, o := range []struct {
		prefix, username string
		id               uint
	}{{"", "pgowner", ownerID}, {"admin_", "testadmin", admin.ID}} {
		// The owned secret expires inside the dashboard's 30-day window, so GET
		// /dashboard/stats's expiring-secrets list names it for its creator.
		expires := time.Now().UTC().Add(7 * 24 * time.Hour)
		owned, serr := cs.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: patGuardCanary + "-" + o.username + "-secret", Value: []byte("v"), ProjectID: canary.ID,
			EnvironmentID: canaryEnv.ID, Type: "password", CreatedBy: o.username, OwnerID: o.id, Expiration: &expires,
		})
		require.NoError(t, serr)
		sharedTo, serr := cs.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: patGuardCanary + "-to-" + o.username, Value: []byte("v"), ProjectID: canary.ID,
			EnvironmentID: canaryEnv.ID, Type: "password", CreatedBy: "pgpeer", OwnerID: peerID,
		})
		require.NoError(t, serr)
		share, serr := cs.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: owned.ID, RecipientID: peerID, Permission: "read", SharedBy: o.id})
		require.NoError(t, serr)
		_, serr = cs.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: sharedTo.ID, RecipientID: o.id, Permission: "read", SharedBy: peerID})
		require.NoError(t, serr)
		w.ids = append(w.ids, owned.ID, sharedTo.ID, share.ID)

		// Secret access requests, both directions: the owner's own request for a
		// peer secret it cannot read ("mine"), and the peer's request for the
		// owner's secret, pending the owner's approval as a canary project_admin.
		unshared, serr := cs.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: patGuardCanary + "-unshared-for-" + o.username, Value: []byte("v"), ProjectID: canary.ID,
			EnvironmentID: canaryEnv.ID, Type: "password", CreatedBy: "pgpeer", OwnerID: peerID,
		})
		require.NoError(t, serr)
		mine, serr := cs.RequestSecretAccess(ctx, unshared.ID, o.id, patGuardCanary+" reason of "+o.username)
		require.NoError(t, serr)
		pending, serr := cs.RequestSecretAccess(ctx, owned.ID, peerID, patGuardCanary+" reason for "+o.username)
		require.NoError(t, serr)
		w.ids = append(w.ids, unshared.ID, mine.ID, pending.ID)
		w.accessRequests[o.prefix+"mine"] = mine.ID
		w.accessRequests[o.prefix+"pending"] = pending.ID
		w.ownedSecret[o.prefix] = owned.ID

		mint := func(name string, scopes []string, pid, eid uint) {
			res, merr := cs.CreateOwnPAT(ctx, o.id, name, nil, scopes, pid, eid, nil)
			require.NoError(t, merr)
			w.tokens[o.prefix+name] = res.PlainToken
		}
		mint("pat_unrestricted", nil, 0, 0)
		mint("pat_decoy_project", nil, decoy.ID, 0)
		mint("pat_decoy_env", nil, decoy.ID, decoyEnv.ID)
		mint("pat_users_read_only", []string{"users.read"}, 0, 0)
		mint("pat_secrets_read_decoy", []string{"secrets.read"}, decoy.ID, 0)
		mint("pat_system_read_only", []string{"system.read"}, 0, 0)
	}
	return w
}

func (w *patGuardWorld) do(t *testing.T, method, token, path string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, w.server.URL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

func (w *patGuardWorld) get(t *testing.T, token, path string) (int, string) {
	t.Helper()
	return w.do(t, http.MethodGet, token, path, nil)
}

func (w *patGuardWorld) canaryQuery() string {
	return fmt.Sprintf("?project_id=%d&environment_id=%d", w.canaryPID, w.canaryEID)
}

// leaks reports whether a response disclosed canary data.
func leaks(code int, body string) bool {
	return code >= 200 && code < 300 && strings.Contains(body, patGuardCanary)
}

// TestPATRestriction_SecretListHonoursRestriction pins the GET /api/v1/secrets fix.
// The leak was the personal set (owned ∪ shared ∪ ACL-granted,
// core.ListSecretsWithSharingInfo), reached when the caller has no role-granted
// scope (tier 3 of ListReadableSecrets) or names a scope it is not authorized for.
func TestPATRestriction_SecretListHonoursRestriction(t *testing.T) {
	w := newPATGuardWorld(t)
	paths := map[string]string{
		"unscoped":            "/api/v1/secrets",
		"canary_scope":        "/api/v1/secrets" + w.canaryQuery(),
		"canary_project_only": fmt.Sprintf("/api/v1/secrets?project_id=%d", w.canaryPID),
		"shared_only":         "/api/v1/secrets?show_shared_only=true",
	}
	for name, path := range paths {
		for _, persona := range patGuardControlPersonas {
			t.Run(name+"/control_"+persona, func(t *testing.T) {
				code, body := w.get(t, w.tokens[persona], path)
				require.Equal(t, http.StatusOK, code, body)
				assert.Contains(t, body, patGuardCanary, "the unrestricted owner must see the canary, or the refusals below prove nothing")
			})
		}
		for _, persona := range patGuardRestrictedPersonas {
			t.Run(name+"/"+persona, func(t *testing.T) {
				code, body := w.get(t, w.tokens[persona], path)
				assert.False(t, leaks(code, body), "%s listed canary secrets through %s: %s", persona, path, body)
			})
		}
	}

	// The restriction narrows, it does not blank: a decoy-confined token still sees
	// a secret in the decoy project.
	t.Run("restricted_token_still_sees_its_own_scope", func(t *testing.T) {
		ctx := context.Background()
		owner, err := w.core.GetUserByEmail(ctx, "pgowner@example.com")
		require.NoError(t, err)
		_, err = w.core.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: "decoy-owned", Value: []byte("v"), ProjectID: w.decoyPID, EnvironmentID: w.decoyEID,
			Type: "password", CreatedBy: "pgowner", OwnerID: owner.ID,
		})
		require.NoError(t, err)
		for _, persona := range []string{"pat_decoy_project", "pat_decoy_env", "pat_secrets_read_decoy"} {
			code, body := w.get(t, w.tokens[persona], "/api/v1/secrets")
			require.Equal(t, http.StatusOK, code, body)
			assert.Contains(t, body, "decoy-owned", persona)
			assert.NotContains(t, body, patGuardCanary, persona)
		}
	})
}

// TestPATRestriction_NotificationsHonourRestriction pins the GET /notifications fix.
// A notification names the resource it is about (here: "You were granted read
// access to secret pgcanary-peer-secret"), so the feed is a read of project data,
// not just of the account.
func TestPATRestriction_NotificationsHonourRestriction(t *testing.T) {
	w := newPATGuardWorld(t)
	type feed struct {
		Data struct {
			Notifications []struct {
				ID uint `json:"id"`
			} `json:"notifications"`
			UnreadCount int `json:"unread_count"`
		} `json:"data"`
	}
	read := func(t *testing.T, persona string) (feed, string) {
		t.Helper()
		code, body := w.get(t, w.tokens[persona], "/api/v1/notifications")
		require.Equal(t, http.StatusOK, code, body)
		var f feed
		require.NoError(t, json.Unmarshal([]byte(body), &f), body)
		return f, body
	}
	for _, persona := range patGuardControlPersonas {
		t.Run("control_"+persona, func(t *testing.T) {
			f, body := read(t, persona)
			assert.Contains(t, body, patGuardCanary)
			assert.Positive(t, f.Data.UnreadCount)
		})
	}
	for _, persona := range patGuardRestrictedPersonas {
		t.Run(persona, func(t *testing.T) {
			f, body := read(t, persona)
			assert.NotContains(t, body, patGuardCanary)
			assert.Empty(t, f.Data.Notifications)
			assert.Zero(t, f.Data.UnreadCount, "the badge count must describe the list the token can see")
		})
	}
	// Writes on the feed follow the same visibility: a restricted token can neither
	// mark a notification it cannot see read, nor sweep it with read-all.
	t.Run("restricted_writes_do_not_reach_hidden_notifications", func(t *testing.T) {
		ctrl, _ := read(t, "session")
		require.NotEmpty(t, ctrl.Data.Notifications)
		id := ctrl.Data.Notifications[0].ID
		code, body := w.do(t, http.MethodPost, w.tokens["pat_decoy_project"], fmt.Sprintf("/api/v1/notifications/%d/read", id), nil)
		assert.Equal(t, http.StatusNotFound, code, body)
		code, body = w.do(t, http.MethodPost, w.tokens["pat_decoy_project"], "/api/v1/notifications/read-all", nil)
		require.Equal(t, http.StatusOK, code, body)
		after, _ := read(t, "session")
		assert.Equal(t, ctrl.Data.UnreadCount, after.Data.UnreadCount,
			"a restricted token's read-all must not mark notifications it cannot see")
	})
}

// TestPATRestriction_RestrictedPATCannotMintAPAT pins the POST /api/v1/auth/tokens
// fix. ADR-042's promise is that a leaked restricted token's blast radius is its
// restriction; a token that can mint an unrestricted sibling has the owner's whole
// authority. Refused for every restricted token, including a CIDR-only one, whose
// child would otherwise escape the network allowlist.
func TestPATRestriction_RestrictedPATCannotMintAPAT(t *testing.T) {
	w := newPATGuardWorld(t)
	body := []byte(`{"name":"child"}`)
	for _, persona := range patGuardControlPersonas {
		t.Run("control_"+persona, func(t *testing.T) {
			code, resp := w.do(t, http.MethodPost, w.tokens[persona], "/api/v1/auth/tokens", body)
			assert.Equal(t, http.StatusCreated, code, resp)
		})
	}
	for _, persona := range patGuardRestrictedPersonas {
		t.Run(persona, func(t *testing.T) {
			code, resp := w.do(t, http.MethodPost, w.tokens[persona], "/api/v1/auth/tokens", body)
			assert.Equal(t, http.StatusForbidden, code, resp)
			assert.NotContains(t, resp, "kx_pat_", "no token may be returned")
		})
	}
	t.Run("cidr_only_restriction", func(t *testing.T) {
		ctx := context.Background()
		owner, err := w.core.GetUserByEmail(ctx, "pgowner@example.com")
		require.NoError(t, err)
		res, err := w.core.CreateOwnPAT(ctx, owner.ID, "cidr-only", nil, nil, 0, 0, []string{"127.0.0.0/8", "::1/128"})
		require.NoError(t, err)
		code, resp := w.do(t, http.MethodPost, res.PlainToken, "/api/v1/auth/tokens", body)
		assert.Equal(t, http.StatusForbidden, code, resp)
	})
}

// TestPATRestriction_SecretAccessRequestsHonourRestriction pins the
// /secret-access-requests fix. Those routes have no permission gate: the
// requester-or-admin-authority check in core is their whole authorization, and
// requireAdminAuthorityAt resolves roles directly, so a token confined to another
// project could list, read and RESOLVE requests in the canary project.
func TestPATRestriction_SecretAccessRequestsHonourRestriction(t *testing.T) {
	w := newPATGuardWorld(t)
	for _, owner := range []string{"", "admin_"} {
		mineID, pendingID := w.accessRequests[owner+"mine"], w.accessRequests[owner+"pending"]
		for _, persona := range []string{owner + "pat_unrestricted", map[string]string{"": "session", "admin_": "admin_session"}[owner]} {
			t.Run("control_"+persona, func(t *testing.T) {
				code, body := w.get(t, w.tokens[persona], "/api/v1/secret-access-requests")
				require.Equal(t, http.StatusOK, code, body)
				assert.Contains(t, body, patGuardCanary+" reason of", "mine")
				assert.Contains(t, body, patGuardCanary+" reason for", "pending approval")
				for _, id := range []uint{mineID, pendingID} {
					code, body = w.get(t, w.tokens[persona], fmt.Sprintf("/api/v1/secret-access-requests/%d", id))
					assert.Equal(t, http.StatusOK, code, body)
				}
			})
		}
		for _, p := range patGuardRestrictedPersonas {
			persona := owner + p
			t.Run(persona, func(t *testing.T) {
				code, body := w.get(t, w.tokens[persona], "/api/v1/secret-access-requests")
				assert.False(t, leaks(code, body), body)
				for _, id := range []uint{mineID, pendingID} {
					code, body = w.get(t, w.tokens[persona], fmt.Sprintf("/api/v1/secret-access-requests/%d", id))
					assert.Equal(t, http.StatusNotFound, code, body)
				}
				code, body = w.do(t, http.MethodPut, w.tokens[persona],
					fmt.Sprintf("/api/v1/secret-access-requests/%d", pendingID), []byte(`{"action":"approve"}`))
				assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, code, body)
			})
		}
		// POST /secret-access-requests resolves the target through
		// GetSecretWithPermissionCheck -> CheckSecretPermission, whose owner/share/ACL
		// paths never reach Authorize. Before the fix a confined token got past that
		// visibility check for its owner's canary secret: a cross-project existence
		// oracle, and a request row written in a project outside the restriction.
		t.Run(owner+"create_request_for_out_of_scope_secret", func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"secret_id":%d,"reason":"probe"}`, w.ownedSecret[owner]))
			code, resp := w.do(t, http.MethodPost, w.tokens[owner+"pat_unrestricted"], "/api/v1/secret-access-requests", body)
			require.NotEqual(t, http.StatusNotFound, code, "control: the unrestricted token can see the secret: %s", resp)
			for _, p := range patGuardRestrictedPersonas {
				code, resp = w.do(t, http.MethodPost, w.tokens[owner+p], "/api/v1/secret-access-requests", body)
				assert.Equal(t, http.StatusNotFound, code, "%s: %s", owner+p, resp)
			}
		})
		// Still pending after every restricted attempt, and the unrestricted token
		// can resolve it: the refusals above are the restriction, not a broken route.
		t.Run(owner+"pending_request_untouched_then_resolvable", func(t *testing.T) {
			code, body := w.get(t, w.tokens[owner+"pat_unrestricted"], fmt.Sprintf("/api/v1/secret-access-requests/%d", pendingID))
			require.Equal(t, http.StatusOK, code, body)
			assert.Contains(t, body, `"pending"`)
			code, body = w.do(t, http.MethodPut, w.tokens[owner+"pat_unrestricted"],
				fmt.Sprintf("/api/v1/secret-access-requests/%d", pendingID), []byte(`{"action":"reject","reason":"no"}`))
			assert.Equal(t, http.StatusOK, code, body)
		})
	}
}

var patGuardParamRe = regexp.MustCompile(`\{[^}]+\}`)

// patGuardGETRoutes walks the real router for every GET route.
func patGuardGETRoutes(t *testing.T, router http.Handler) []string {
	t.Helper()
	routes, ok := router.(chi.Routes)
	require.True(t, ok, "router must expose chi.Routes for walking")
	set := map[string]bool{}
	require.NoError(t, chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet {
			set[route] = true
		}
		return nil
	}))
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// patGuardPaths binds a route's path parameters. Every parameter of one request
// gets the same canary id; each canary id is tried in turn.
func (w *patGuardWorld) patGuardPaths(route string) []string {
	var bases []string
	if patGuardParamRe.MatchString(route) {
		for _, id := range w.ids {
			bases = append(bases, patGuardParamRe.ReplaceAllString(route, fmt.Sprint(id)))
		}
	} else {
		bases = []string{route}
	}
	out := make([]string, 0, 2*len(bases))
	for _, b := range bases {
		out = append(out, b, b+w.canaryQuery())
	}
	return out
}

// TestEveryGETRouteHonoursPATRestriction is the family-wide guard (see the file
// header). Red on main before this PR: GET /api/v1/secrets/, /notifications,
// /secret-access-requests and /secret-access-requests/{requestId}.
func TestEveryGETRouteHonoursPATRestriction(t *testing.T) {
	w := newPATGuardWorld(t)
	routes := patGuardGETRoutes(t, w.router)
	require.Greater(t, len(routes), 100, "sanity: the walk should find the whole GET surface")

	controlHits := map[string]bool{}
	violations := map[string][]string{}
	for _, route := range routes {
		for _, p := range w.patGuardPaths(route) {
			for _, persona := range patGuardControlPersonas {
				if code, body := w.get(t, w.tokens[persona], p); leaks(code, body) {
					controlHits[route] = true
				}
			}
			if _, exempt := patRestrictionReadExempt[route]; exempt {
				continue
			}
			for _, persona := range patGuardRestrictedPersonas {
				if code, body := w.get(t, w.tokens[persona], p); leaks(code, body) {
					violations[route] = append(violations[route], fmt.Sprintf("%s via %s", persona, p))
				}
			}
		}
	}

	for route, how := range violations {
		t.Errorf("GET %s disclosed canary-project data to a PAT whose restriction excludes it (%s). "+
			"Its visibility is decided outside Authorize/AuthorizeSecret: apply patRestrictionFromContext "+
			"to the rows (see core/pat_restriction_listing.go), or add a reasoned entry to "+
			"patRestrictionReadExempt.", route, strings.Join(how, "; "))
	}

	assert.GreaterOrEqual(t, len(controlHits), patGuardMinControlHits,
		"the unrestricted owner saw canary data on too few routes: the fixture is not exercising the surface")
	for _, mustSee := range []string{
		"/api/v1/secrets/", "/api/v1/notifications", "/api/v1/secret-access-requests",
		"/api/v1/secret-access-requests/{requestId}", "/api/v1/dashboard/stats",
	} {
		assert.True(t, controlHits[mustSee], "positive control: the unrestricted owner must see canary data on GET %s", mustSee)
	}

	routeSet := map[string]bool{}
	for _, r := range routes {
		routeSet[r] = true
	}
	for route, reason := range patRestrictionReadExempt {
		assert.True(t, routeSet[route], "patRestrictionReadExempt entry %q is not a GET route any more: remove it", route)
		assert.NotEmpty(t, strings.TrimSpace(reason), "patRestrictionReadExempt entry %q needs a reason", route)
	}
}
