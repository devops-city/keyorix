// write_routes_deny_walk_test.go — AUTHZ-WALKS-HTTP-1 item 1: every mutating route
// refuses a caller it must refuse, and changes nothing while doing so.
//
// # The class
//
// The read side has a route-wide walk (pat_restriction_read_family_test.go). The
// write side did not: a POST/PUT/PATCH/DELETE handler that forgets its gate, or maps
// a core denial to a 5xx (#3416: a machine token reaching a user-only handler), was
// only found when somebody happened to write a test for that one route.
//
// # The walk: TestEveryWriteRouteRefusesAndChangesNothing_G0 .. _G3 and _Control
//
// One walk, split by route group into awRouteGroups top-level tests so CI can
// shard it (authz_walk_groups_test.go; TestAWRouteGroups_PartitionTheRouter proves
// every mutating route is in exactly one group); _Control runs the parts that need
// the whole surface (allowlist hygiene, shape check, admin control) once. Each test
// builds its own world.
//
// Behavioural, over the real router (see authz_walk_fixture_test.go for the fixture
// and the route shapes it skips). The route set is derived, not listed: chi.Walk over
// NewRouter, every POST/PUT/PATCH/DELETE. Each route is called as five callers that
// must NOT be able to do what the route does to the canary objects:
//
//	machine_zero         a machine token whose identity holds no role at all
//	awviewer             a user with only the system_viewer baseline
//	awprojviewer         a viewer member of the canary project
//	pat_decoy_project    the global admin's PAT confined to another project
//	pat_decoy_env        the global admin's PAT confined to another project's environment
//	pat_users_read_only  the global admin's PAT scoped to users.read
//
// Every {param} is bound twice over: typed (to the real canary object of that kind)
// and uniformly (to each canary id, and to an id that exists nowhere), with a
// minimal valid-looking union body (awBody). Oracle, two parts, both required:
//
//  1. the status is 4xx: never 2xx, never 5xx (a 5xx is a finding by itself);
//  2. a digest of EVERY table except awNoiseTables (rows hashed, so an UPDATE is
//     seen as well as an INSERT/DELETE) plus the audit event set is unchanged,
//     except that the audit log may gain denial events.
//
// Routes a low-privilege caller is MEANT to call (own profile, own PATs, own
// break-glass request, request access...) are the explicit awSelfServiceWrites
// allowlist, each with a reason: for them a 2xx is allowed and the caller's OWN rows
// may change, nothing else may, and the machine and restricted-PAT personas get no
// allowlist at all. A mutating route that is neither refused nor allowlisted fails
// the walk, so a new route is classified the day it is registered.
//
// Non-vacuity: the unrestricted admin session runs the same sweep last and must get
// a 2xx on at least awMinControlHits routes, including awControlMustHit. Without it
// a sweep where every request dies in validation would pass.
//
// What it does NOT cover, said plainly: the bodies are one union shape, so a route
// whose handler needs a field the union lacks is refused with 400 before its gate
// (the control run lists those: awControlMisses is logged, not asserted); query
// parameters; state a refusal could change that the digest cannot see (an in-memory
// cache, an external connector call); and the login/MFA/WebAuthn/setup/step-up/
// impersonation handlers, which other sessions own (their routes ARE walked here,
// as callers that must be refused, but fixes there are filed, not made).
package http

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// awAllow is one allowlist entry: why a low-privilege caller may call the route,
// and the tables where it legitimately adds rows for OTHER principals (a request
// notifies the approvers).
type awAllow struct {
	reason     string
	sideTables []string
}

// awSelfServiceWrites: mutating routes a low-privilege HUMAN caller is meant to call
// on its own objects. A 2xx is allowed for them, and so are changes to rows the
// caller owns (user_id/requester_id/owner_id == caller, or the caller's users row).
// Everything else about them is still held to the oracle, including the 5xx rule
// and the digest of every OTHER principal's rows (the canary victim's).
var awSelfServiceWrites = map[string]awAllow{
	"PUT /api/v1/auth/profile":                                        {reason: "own profile (ADR-021/027)"},
	"POST /api/v1/auth/change-password":                               {reason: "own password"},
	"POST /api/v1/auth/tokens":                                        {reason: "own personal access token"},
	"DELETE /api/v1/auth/tokens/{id}":                                 {reason: "revoke own PAT"},
	"DELETE /api/v1/auth/tokens/expired":                              {reason: "purge own expired PATs"},
	"DELETE /api/v1/auth/sessions/{id}":                               {reason: "revoke own session"},
	"POST /api/v1/auth/mfa/enroll":                                    {reason: "own MFA enrolment"},
	"POST /api/v1/auth/mfa/activate":                                  {reason: "own MFA enrolment"},
	"POST /api/v1/auth/mfa/disable":                                   {reason: "own MFA"},
	"POST /api/v1/auth/mfa/recovery-codes/regenerate":                 {reason: "own MFA recovery codes"},
	"POST /api/v1/auth/mfa/stepup":                                    {reason: "own step-up"},
	"POST /api/v1/auth/webauthn/register/begin":                       {reason: "own passkey enrolment"},
	"POST /api/v1/auth/webauthn/register/finish":                      {reason: "own passkey enrolment"},
	"POST /api/v1/auth/webauthn/reauth/begin":                         {reason: "own passkey re-auth"},
	"POST /api/v1/auth/webauthn/reauth/finish":                        {reason: "own passkey re-auth"},
	"DELETE /api/v1/auth/webauthn/credentials/{id}":                   {reason: "remove own passkey"},
	"POST /api/v1/auth/end-impersonation":                             {reason: "ends the caller's own impersonation session (400 when there is none)"},
	"POST /api/v1/notifications/read-all":                             {reason: "mark own notifications read"},
	"POST /api/v1/notifications/{id}/read":                            {reason: "mark own notification read"},
	"POST /api/v1/secret-access-requests":                             {reason: "request access to a secret (the request is the caller's own)", sideTables: []string{"notifications"}},
	"POST /api/v1/secret-access-requests/{requestId}/withdraw":        {reason: "withdraw own secret access request"},
	"POST /api/v1/projects/{id}/access-requests":                      {reason: "request access to a project (the request is the caller's own)", sideTables: []string{"notifications"}},
	"POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw": {reason: "withdraw own project access request"},
	"POST /api/v1/projects/{id}/break-glass":                          {reason: "request own break-glass activation", sideTables: []string{"notifications"}},
	"DELETE /api/v1/secrets/{id}/self-share":                          {reason: "a recipient drops its own share"},
}

// awReadOnlyPosts: POST routes that compute and return, never persist. A 2xx is
// allowed; the digest must still be unchanged.
var awReadOnlyPosts = map[string]string{
	"POST /api/v1/compliance/evidence/verify":     "verifies a caller-supplied evidence bundle",
	"POST /api/v1/projects/{id}/secrets/render":   "renders a template against secrets the caller can read",
	"POST /api/v1/connect/{name}/secret:read":     "connector read, gated by RequireScopedPermission",
	"POST /api/v1/secrets/{id}/rotation/simulate": "dry-run of a rotation",
}

// awKnownOpen: findings the walk reports that are already fixed in an open PR. Keyed
// "persona METHOD route", scoped to a 5xx from that one persona on that one route.
// An entry that no longer fires is logged as stale: remove it when the fix merges.
var awKnownOpen = map[string]string{
	"machine_zero DELETE /api/v1/auth/tokens/expired":     "#3416 (machine token -> 403 on user-only routes)",
	"machine_zero DELETE /api/v1/secrets/{id}/self-share": "#3416",
	"machine_zero POST /api/v1/auth/end-impersonation":    "#3416 (impersonation handler: FIX-3277's area, fixed there)",
}

// awMinControlHits is the floor of routes the unrestricted admin must get a 2xx on.
const awMinControlHits = 60

// awControlMustHit are routes the admin must reach with a 2xx: if they only ever fail
// validation the sweep proves nothing about them.
var awControlMustHit = []string{
	"POST /api/v1/secrets/", "PUT /api/v1/secrets/{id}", "POST /api/v1/groups/", "POST /api/v1/roles/",
	"POST /api/v1/projects", "POST /api/v1/secrets/{id}/share", "POST /api/v1/users/",
	"POST /api/v1/projects/{id}/members", "POST /api/v1/projects/{id}/environments",
}

var awPersonas = []string{
	"machine_zero", "awviewer", "awprojviewer", "pat_decoy_project", "pat_decoy_env", "pat_users_read_only",
}

func awIsMutating(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete
}

// awAssertNoUnrecognisedShapes: the header says the router has no multipart or
// websocket route, so the walk's JSON body reaches every handler. Fail the day that
// stops being true, so the claim is machine-checked, not asserted.
func awAssertNoUnrecognisedShapes(t *testing.T) {
	t.Helper()
	re := regexp.MustCompile(`ParseMultipartForm|MultipartReader|FormFile|websocket\.|Upgrade\(`)
	files, err := filepath.Glob("handlers/*.go")
	require.NoError(t, err)
	more, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, f := range append(files, more...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(f) // #nosec G304 -- fixed glob of this package's sources
		require.NoError(t, rerr)
		assert.False(t, re.Match(b), "%s uses multipart/websocket: the write walk sends JSON only, add a recognised-shape rule for it", f)
	}
}

// The walk is split into awRouteGroups tests, one per route group
// (authz_walk_groups_test.go), so CI can run them on different legs.
// TestAWRouteGroups_PartitionTheRouter proves the groups cover every route once;
// the whole-surface parts (allowlist hygiene, shape check, admin control) are
// TestEveryWriteRouteRefusesAndChangesNothing_Control.
func TestEveryWriteRouteRefusesAndChangesNothing_G0(t *testing.T) { awWriteWalkGroup(t, 0) }
func TestEveryWriteRouteRefusesAndChangesNothing_G1(t *testing.T) { awWriteWalkGroup(t, 1) }
func TestEveryWriteRouteRefusesAndChangesNothing_G2(t *testing.T) { awWriteWalkGroup(t, 2) }
func TestEveryWriteRouteRefusesAndChangesNothing_G3(t *testing.T) { awWriteWalkGroup(t, 3) }

func awWriteWalkGroup(t *testing.T, group int) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { awWriteWalk(t, backend, group) })
	}
}

func TestEveryWriteRouteRefusesAndChangesNothing_Control(t *testing.T) {
	awAssertNoUnrecognisedShapes(t)
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { awWriteControl(t, backend) })
	}
}

// awMutatingRoutes is the write walk's population: every non-public mutating route.
func awMutatingRoutes(t *testing.T, r *svReplica) []awRoute {
	t.Helper()
	routes := awWalkRoutes(t, r.router)
	require.Greater(t, len(routes), 300, "sanity: the walk should find the whole router")
	var mutating []awRoute
	for _, rt := range routes {
		if !awIsMutating(rt.Method) {
			continue
		}
		if awClassify(t, rt) == "public" {
			continue
		}
		mutating = append(mutating, rt)
	}
	require.Greater(t, len(mutating), 150, "sanity: the walk should find the whole mutating surface")
	return mutating
}

// awWriteControl is the whole-surface half of the write walk: allowlist hygiene
// and the admin positive control, over every mutating route.
func awWriteControl(t *testing.T, backend string) {
	w := newAWWorld(t, backend, 1)
	mutating := awMutatingRoutes(t, w.a)

	// Allowlist hygiene, both directions: no entry names a route that is gone, and
	// every entry carries a reason.
	known := map[string]bool{}
	for _, rt := range mutating {
		known[rt.key()] = true
	}
	for k, e := range awSelfServiceWrites {
		assert.True(t, known[k], "allowlist entry %q is not a mutating route any more: remove it", k)
		assert.NotEmpty(t, strings.TrimSpace(e.reason), "allowlist entry %q needs a reason", k)
	}
	for k, reason := range awReadOnlyPosts {
		assert.True(t, known[k], "allowlist entry %q is not a mutating route any more: remove it", k)
		assert.NotEmpty(t, strings.TrimSpace(reason), "allowlist entry %q needs a reason", k)
	}
	for k := range awRestrictedPATOwnRevocation {
		assert.True(t, known[k], "awRestrictedPATOwnRevocation entry %q is not a mutating route any more", k)
		p, ok := core.RestrictedPATUngatedWritePolicy(k)
		assert.True(t, ok && p.Allowed, "%s must be an Allowed entry of core.restrictedPATUngatedWrites", k)
	}
	for k := range awKnownOpen {
		assert.True(t, known[awKnownOpenRoute(k)], "awKnownOpen entry %q is not a mutating route any more: remove it", k)
	}

	// Non-vacuity: the admin reaches the mutation on enough routes.
	hit, misses := w.awControl(t, mutating, w.awBody())
	t.Logf("control: admin got a 2xx on %d/%d mutating routes; misses (body or fixture does not reach them): %s",
		len(hit), len(mutating), strings.Join(misses, ", "))
	assert.GreaterOrEqual(t, len(hit), awMinControlHits,
		"the unrestricted admin reached too few mutating routes: the fixture/body is not exercising the surface")
	for _, must := range awControlMustHit {
		assert.True(t, hit[must], "positive control: the admin must get a 2xx on %s", must)
	}
}

func awWriteWalk(t *testing.T, backend string, group int) {
	w := newAWWorld(t, backend, 1)
	r := w.a
	mutating := awRoutesOfGroup(awMutatingRoutes(t, r), group)
	require.NotEmpty(t, mutating, "route group %d has no mutating route", group)
	inGroup := map[string]bool{}
	for _, rt := range mutating {
		inGroup[rt.key()] = true
	}
	tables := awTables(t, r.db)
	body := w.awBody()

	knownOpenSeen := map[string]bool{}
	violations := map[string][]string{}
	note := func(rt awRoute, persona, path, what string) {
		v := fmt.Sprintf("%s via %s %s: %s", persona, rt.Method, path, what)
		if len(violations[rt.key()]) < 6 {
			violations[rt.key()] = append(violations[rt.key()], v)
		}
	}

	for _, persona := range awPersonas {
		human := strings.HasPrefix(persona, "aw")           // the session personas
		restrictedPAT := strings.HasPrefix(persona, "pat_") // the admin's narrowed PATs
		for _, rt := range mutating {
			self, selfService := awSelfServiceWrites[rt.key()]
			_, readOnlyPost := awReadOnlyPosts[rt.key()]
			allow2xx := readOnlyPost
			var callerID uint
			var side []string
			switch {
			case human && selfService:
				allow2xx, callerID, side = true, w.userIDs[persona], self.sideTables
			case restrictedPAT && awRestrictedPATOwnRevocation[rt.key()]:
				// By design (PAT-GUARD-2, core.restrictedPATUngatedWrites): a restricted
				// token may revoke its OWNER's own tokens/sessions.
				allow2xx, callerID = true, w.userIDs["admin"]
			}
			for _, path := range w.awPaths(rt.Path) {
				before := awTakeDigest(t, r.db, tables)
				code, resp := awDo(r, rt.Method, w.tokens[persona], path, body)
				after := awTakeDigest(t, r.db, tables)
				switch {
				case awFeatureOff(code, resp):
					// A feature switched off in this fixture (WebAuthn), answered 501 after
					// the principal check: a deployment fact, not a server fault.
				case code >= 500 && awKnownOpen[persona+" "+rt.key()] != "":
					knownOpenSeen[persona+" "+rt.key()] = true
				case code >= 500:
					note(rt, persona, path, fmt.Sprintf("%d (a 5xx is a finding by itself): %.200s", code, resp))
				case code >= 200 && code < 300 && !allow2xx:
					note(rt, persona, path, fmt.Sprintf("%d, expected a 4xx refusal: %.200s", code, resp))
				case code < 200 || (code >= 300 && code < 400):
					note(rt, persona, path, fmt.Sprintf("%d, expected a 4xx refusal", code))
				}
				if d := awDiff(before, after, callerID, side...); len(d) > 0 {
					note(rt, persona, path, fmt.Sprintf("status %d but state changed: %s", code, strings.Join(d, " | ")))
				}
				if (selfService || awRestrictedPATOwnRevocation[rt.key()]) && code == http.StatusUnauthorized {
					w.revive(t, persona)
				}
			}
		}
		w.revive(t, persona)
	}

	for k, why := range awKnownOpen {
		if inGroup[awKnownOpenRoute(k)] && !knownOpenSeen[k] {
			t.Logf("awKnownOpen entry %q (%s) no longer fires: remove it", k, why)
		}
	}
	keys := make([]string, 0, len(violations))
	for k := range violations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Errorf("%s: %s", k, strings.Join(violations[k], "\n    "))
	}

}

// awRestrictedPATOwnRevocation: the only mutating routes a restricted PAT is allowed
// to succeed on: it revokes its owner's own tokens/sessions (core.restrictedPATUngatedWrites,
// reasonOwnRevoke). The walk therefore also revives the credential it just ended.
var awRestrictedPATOwnRevocation = map[string]bool{
	"DELETE /api/v1/auth/tokens/{id}":    true,
	"DELETE /api/v1/auth/tokens/expired": true,
	"DELETE /api/v1/auth/sessions/{id}":  true,
}

// revive re-mints the credential of a persona that an own-revocation route (bound to
// its own id) just ended, so the rest of the sweep is not a run of vacuous 401s.
func (w *awWorld) revive(t *testing.T, persona string) {
	t.Helper()
	ctx := context.Background()
	if code, _ := awDo(w.a, http.MethodGet, w.tokens[persona], "/api/v1/auth/profile", nil); code != http.StatusUnauthorized {
		return
	}
	switch {
	case persona == "admin":
		sess, _, err := w.a.c.Login(ctx, &core.LoginRequest{Username: "svadmin", Password: svPassword})
		require.NoError(t, err)
		w.tokens[persona] = sess.SessionToken
	case strings.HasPrefix(persona, "aw"):
		sess, _, err := w.a.c.Login(ctx, &core.LoginRequest{Username: persona, Password: svPassword})
		require.NoError(t, err)
		w.tokens[persona] = sess.SessionToken
	case strings.HasPrefix(persona, "pat_"):
		spec := w.patSpecs[persona]
		res, err := w.a.c.CreateOwnPAT(ctx, w.adminID, persona, nil, spec.scopes, spec.pid, spec.eid, nil)
		require.NoError(t, err)
		w.tokens[persona] = res.PlainToken
	}
}

// awControl runs the sweep as the unrestricted admin session. Destructive routes go
// last, deepest path first, so removing a parent does not hide its children.
func (w *awWorld) awControl(t *testing.T, mutating []awRoute, body []byte) (map[string]bool, []string) {
	t.Helper()
	ordered := append([]awRoute(nil), mutating...)
	sort.SliceStable(ordered, func(i, j int) bool {
		di, dj := ordered[i].Method == http.MethodDelete, ordered[j].Method == http.MethodDelete
		if di != dj {
			return dj
		}
		if di {
			return len(ordered[i].Path) > len(ordered[j].Path)
		}
		return false
	})
	hit := map[string]bool{}
	codes := map[string]string{}
	for _, rt := range ordered {
		if rt.Path == "/api/v1/auth/change-password" || strings.HasPrefix(rt.Path, "/api/v1/auth/mfa") ||
			rt.Path == "/api/v1/admin/impersonate" {
			continue // would end the admin session the rest of the control run needs
		}
		path := w.awPaths(rt.Path)[0]
		code, resp := awDo(w.a, rt.Method, w.tokens["admin"], path, w.awBodyN(len(codes)+len(hit)+1))
		if code >= 200 && code < 300 {
			hit[rt.key()] = true
		} else {
			codes[rt.key()] = fmt.Sprintf("%d %.80s", code, resp)
		}
	}
	var misses []string
	for _, rt := range mutating {
		if !hit[rt.key()] {
			misses = append(misses, rt.key()+" ["+codes[rt.key()]+"]")
		}
	}
	sort.Strings(misses)
	return hit, misses
}
