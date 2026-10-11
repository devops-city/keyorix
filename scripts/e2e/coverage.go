//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// routeEntry mirrors server/http/route_inventory_test.go's routeInventoryEntry
// JSON shape (scripts/e2e/routes.json) -- duplicated rather than imported
// because that struct lives in a _test.go file in package http, which this
// package (a separate module-relative package under scripts/e2e, deliberately
// decoupled from server/http so it never needs to import internal packages
// just to make HTTP calls) cannot reach.
type routeEntry struct {
	Method       string `json:"method"`
	Pattern      string `json:"pattern"`
	FeatureGroup string `json:"feature_group"`
	Gated        bool   `json:"gated"`
	Line         int    `json:"router_go_line"`
}

func (e routeEntry) key() string { return e.Method + " " + e.Pattern }

// loadRoutes reads scripts/e2e/routes.json (I1's generated inventory).
func loadRoutes(t *testing.T) []routeEntry {
	t.Helper()
	root := harness.RepoRoot(t)
	path := filepath.Join(root, "scripts", "e2e", "routes.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path
	if err != nil {
		t.Fatalf("read %s: %v (run I1's TestRouteInventoryIsCurrent first)", path, err)
	}
	var routes []routeEntry
	if err := json.Unmarshal(raw, &routes); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(routes) == 0 {
		t.Fatal("routes.json parsed to 0 routes -- the coverage check would be vacuous")
	}
	return routes
}

// skipList is every route this driver deliberately does not exercise, with a
// reviewed reason -- same idiom as permission_sweep_test.go's
// permissionSweepAllowlist: a route missing from BOTH the client's hit set
// and this list fails TestAPISmoke_*'s coverage assertion, so a route that
// starts silently going untested (new route added, or an old one quietly
// stops being called) is a loud CI failure, not a silent gap.
var skipList = map[string]string{
	// Pre-auth SSO/SAML federation: requires a real external IdP (SAML
	// metadata exchange, OIDC discovery) to complete a login. Third-party
	// findings/mechanics for crewjam/saml specifically are also under the
	// pre-2026-10-19 embargo (COMMON-RULES "Security" section) -- exercising
	// these live is out of scope for an API smoke driver either way. Unit/
	// fuzz coverage for the SAML/OIDC/SSO paths lives in
	// server/http/handlers/*saml*_test.go, *sso*_test.go, not here.
	"POST /auth/saml/{provider}/acs":     "requires a real external SAML IdP to produce a valid assertion; see server/http/handlers/saml_*_test.go for mechanics coverage",
	"GET /auth/saml/{provider}/login":    "requires a configured SAML SP/IdP pair; redirects to an external IdP this driver cannot complete",
	"GET /auth/saml/{provider}/metadata": "static per-provider metadata XML; trivial and safe to skip, exercised by server/http/handlers/saml_metadata_test.go",
	"GET /auth/sso/providers":            "returns the configured SSO provider list; empty on a fresh install with none configured -- exercised by dedicated SSO unit tests, not a create/read/list/update/delete flow",
	"GET /auth/sso/{provider}/callback":  "requires a completed external OIDC/SAML authorization code exchange this driver cannot produce",
	"GET /auth/sso/{provider}/login":     "redirects to an external IdP this driver cannot complete",

	// WebAuthn: every one of these routes is one step of a real
	// challenge-response ceremony against a hardware/virtual authenticator's
	// private key. A pure HTTP smoke client has no authenticator to answer
	// the challenge with -- these are mechanically unreachable without a
	// WebAuthn simulator (out of scope here; see server/http/handlers/
	// webauthn_*_test.go, which DOES simulate an authenticator for unit
	// coverage).
	"POST /auth/webauthn/login/begin":               "WebAuthn ceremony start -- needs an authenticator to complete, see webauthn_*_test.go",
	"POST /auth/webauthn/login/finish":              "WebAuthn ceremony finish -- needs a real/simulated authenticator signature",
	"POST /auth/webauthn/passwordless/begin":        "WebAuthn ceremony start (passwordless variant)",
	"POST /auth/webauthn/passwordless/finish":       "WebAuthn ceremony finish (passwordless variant)",
	"GET /api/v1/auth/webauthn/credentials":         "lists enrolled WebAuthn credentials; empty with none enrolled (enrollment itself is unreachable here, see register/begin+finish below)",
	"DELETE /api/v1/auth/webauthn/credentials/{id}": "deletes an enrolled credential; nothing to delete since enrollment is unreachable here",
	"POST /api/v1/auth/webauthn/reauth/begin":       "WebAuthn step-up re-auth ceremony start",
	"POST /api/v1/auth/webauthn/reauth/finish":      "WebAuthn step-up re-auth ceremony finish",
	"POST /api/v1/auth/webauthn/register/begin":     "WebAuthn credential registration ceremony start",
	"POST /api/v1/auth/webauthn/register/finish":    "WebAuthn credential registration ceremony finish",

	// MFA TOTP enroll/activate needs a real TOTP secret round-tripped through
	// an authenticator app (or a TOTP library computing the current code from
	// the returned secret) -- feasible in principle but not yet automated in
	// this driver; tracked, not silently dropped. MFA unit coverage exists in
	// server/http/handlers/mfa_test.go / login_throttle_fuzz_test.go.
	"POST /api/v1/auth/mfa/enroll":                    "TOTP enrollment; would need a TOTP code computed from the returned secret to complete activate -- not yet automated here, see server/http/handlers/mfa_test.go for existing coverage",
	"POST /api/v1/auth/mfa/activate":                  "depends on mfa/enroll above",
	"POST /api/v1/auth/mfa/disable":                   "depends on mfa/enroll+activate above (nothing enrolled to disable)",
	"POST /api/v1/auth/change-password":               "would revoke this driver's own session mid-run; driven by journey 20",
	"GET /api/v1/auth/mfa/recovery-codes":             "depends on mfa/enroll+activate above",
	"POST /api/v1/auth/mfa/recovery-codes/regenerate": "depends on mfa/enroll+activate above",
	"POST /api/v1/auth/mfa/stepup":                    "depends on mfa/enroll+activate above (nothing to step up into)",
	"POST /auth/mfa/verify":                           "completes an MFA challenge issued during login; unreachable without an MFA-enrolled account (see mfa/enroll above)",

	// Impersonation: requires a second, lower-privileged user session to
	// impersonate, PLUS the impersonation flow itself intentionally alters
	// audit/session state in ways that could interact with the
	// single-shared-admin-session flows the rest of this driver depends on
	// if run in the same server instance. Covered by dedicated tests
	// (server/http/handlers/*impersonation*_test.go, admin_impersonation.go's
	// own suite) rather than folded into this driver's shared session.
	"POST /api/v1/auth/end-impersonation": "impersonation start/end is a session-state mutation exercised by server/http/handlers/*impersonation*_test.go; not folded into this driver's single shared admin session",

	// SCIM: provisioning-only surface, authenticated by a SEPARATE
	// out-of-band SCIM bearer token (customMiddleware.SCIMToken -- see
	// permission_sweep_test.go's header comment) that this driver's
	// session-token client cannot present without first minting one through
	// an admin-only SCIM-token-issuance flow this driver does not yet drive.
	// Tracked as a real gap, not silently dropped -- SESSION-I's report lists
	// this as a follow-up.
	"GET /scim/v2/ServiceProviderConfig": "SCIM provisioning surface, separate SCIMToken auth this driver does not yet mint -- tracked follow-up in the SESSION-I report",
	"GET /scim/v2/Users":                 "see ServiceProviderConfig above",
	"POST /scim/v2/Users":                "see ServiceProviderConfig above",
	"GET /scim/v2/Users/{id}":            "see ServiceProviderConfig above",
	"PUT /scim/v2/Users/{id}":            "see ServiceProviderConfig above",
	"PATCH /scim/v2/Users/{id}":          "see ServiceProviderConfig above",
	"DELETE /scim/v2/Users/{id}":         "see ServiceProviderConfig above",
	"GET /scim/v2/Groups":                "see ServiceProviderConfig above",
	"POST /scim/v2/Groups":               "see ServiceProviderConfig above",
	"GET /scim/v2/Groups/{id}":           "see ServiceProviderConfig above",
	"PATCH /scim/v2/Groups/{id}":         "see ServiceProviderConfig above",
	"PUT /scim/v2/Groups/{id}":           "see ServiceProviderConfig above",
	"DELETE /scim/v2/Groups/{id}":        "see ServiceProviderConfig above",

	// Static/infrastructure routes: no request/response cycle meaningfully
	// tests a "feature" here (no DB table backs them), and /metrics HANDLE
	// registers Prometheus's own internal mux, not a chi leaf route this
	// client can probe the same way. /health and /readyz ARE exercised
	// directly by the harness's own boot-polling (scripts/e2e/harness), just
	// not through client.call, so they're listed here rather than left unhit.
	"GET /health":         "polled directly by scripts/e2e/harness's boot sequence, not through client.call",
	"GET /readyz":         "readiness probe, same nature as /health; not a feature route",
	"POST /system/init":   "the bootstrap call itself, made directly by harness.StartServer before any client exists -- this route IS exercised, just not through client.call's coverage bookkeeping",
	"HANDLE /metrics":     "Prometheus's own internal mux mounted at this path, not a chi leaf route",
	"GET /openapi.yaml":   "static generated document, no feature/DB path to exercise",
	"MOUNT /swagger/":     "static Swagger UI asset mount, no feature/DB path to exercise",
	"GET /status":         "static build/version info, no feature/DB path to exercise",
	"GET /status-es":      "static build/version info (Elasticsearch-flavored variant), no feature/DB path to exercise",
	"GET /api/v1/version": "static build/version info, no feature/DB path to exercise",

	// Password reset / setup-token consume: both require an out-of-band
	// token (emailed reset link / admin-issued setup token) this driver has
	// no channel to receive. Covered by dedicated unit tests
	// (server/http/handlers/auth_*_test.go).
	"POST /auth/password-reset": "requires an out-of-band emailed reset token this driver cannot receive",
	"POST /auth/setup/consume":  "requires an out-of-band admin-issued setup token/link this driver cannot receive through this flow (user create in this driver goes through POST /api/v1/users directly, not the setup-token invite path)",
	"GET /auth/setup/{token}":   "see setup/consume above",

	// risk-exceptions approve enforces dual control (approver must be a
	// DIFFERENT system.write holder than the creator, internal/core's
	// risk_exceptions.go) -- this driver's single shared admin session
	// cannot satisfy that without a second distinct privileged account.
	"POST /api/v1/risk-exceptions/{id}/approve": "dual-control approval requires a second, DIFFERENT system.write-holding session than the one that created the exception -- not yet automated here",

	// audit/migrate-chain-encoding is a one-way, irreversible storage-format
	// migration of the live audit hash chain -- running it mid-smoke would
	// permanently alter the chain this same run's own verify-audit call
	// checks at the end, for no coverage benefit (the migration's own
	// correctness has dedicated tests elsewhere).
	"POST /api/v1/audit/migrate-chain-encoding": "one-way irreversible migration of the live audit chain; would interact with this run's own end-of-run verify-audit check for no coverage benefit -- has dedicated tests elsewhere",

	// admin/* job triggers beyond record-hygiene-snapshot (see
	// groupAdminAndSystem) mutate deployment-wide shared state (notification
	// dispatch, role/token expiry, audit-log deletion, inactive-user
	// suspension) that could interact with other groups' fixtures sharing
	// the same server/database in this run. Each already has (or should
	// have) its own dedicated, isolated test -- folding them into a shared
	// smoke session risks a false failure in an unrelated group instead of
	// a clean, attributable one.
	"POST /api/v1/admin/jobs/anomaly-alerts":         "deployment-wide job trigger with real notification side effects; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/check-read-quotas":      "deployment-wide job trigger; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/compliance-digest":      "deployment-wide job trigger with real notification side effects; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/expiry-reminders":       "deployment-wide job trigger with real notification side effects; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/purge-audit-logs":       "DELETES real audit-event rows this run's own end-of-run verify-audit chain check depends on -- never safe to run in a shared session",
	"POST /api/v1/admin/jobs/role-expiry-check":      "deployment-wide job trigger that may expire/notify real role grants other groups rely on; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/rotation-reminders":     "deployment-wide job trigger with real notification side effects; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/run-alert-escalation":   "deployment-wide job trigger with real notification side effects; see groupAdminAndSystem's doc comment",
	"POST /api/v1/admin/jobs/suspend-inactive-users": "SUSPENDS real non-admin users other groups still need active -- breaks groupShares/groupAccessRequests if run first",
	"POST /api/v1/admin/jobs/token-expiry-check":     "deployment-wide job trigger that may revoke real tokens other groups rely on; see groupAdminAndSystem's doc comment",
	"PUT /api/v1/admin/anomaly-config":               "replaces shared, deployment-wide anomaly-detection thresholds that could change groupAudit's anomaly-list assertions elsewhere in the same run",
	"POST /api/v1/admin/impersonate":                 "mutates session/cookie state; reversible via /auth/end-impersonation (also skipped, see above) but risky to interleave with this driver's single shared bearer-token session -- has dedicated tests in server/http/handlers/*impersonation*_test.go",

	// DELETE /auth/sessions/{id} would need a SECOND, non-current session to
	// delete non-destructively -- deleting THIS driver's own current session
	// mid-run would invalidate its own bearer token and break every later
	// authenticated call. POST /auth/logout and /auth/refresh are exercised
	// directly by runAPISmoke, as the very last two HTTP calls of the whole
	// run (after assertRouteCoverage) -- intentionally not through a group
	// function, since either one changes or ends the session this entire
	// driver depends on for every earlier call.
	"POST /api/v1/projects/{id}/break-glass/{activationId}/review": "post-incident review of a break-glass activation needs a prior activation by a second, non-admin session (see journeys/journey9_break_glass_test.go); not folded into this driver's single shared admin session",
	"DELETE /api/v1/auth/sessions/{id}":                            "would need a second, non-current session to delete non-destructively; deleting the driver's own current session would break every later authenticated call in this run",
}

// assertRouteCoverage is the completeness half of I2: every route.json entry
// must be either exercised through c (hit) or explicitly justified in
// skipList. A route in neither set is a silent gap and fails the test loudly,
// by name -- mirroring permission_sweep_test.go's own
// TestNoPermissionGateAllowlistEntriesStillExist idiom (an allowlist entry
// that stops matching a real route is ALSO a loud failure, so the list can't
// silently accumulate stale entries either).
func assertRouteCoverage(t *testing.T, routes []routeEntry, c *client) {
	t.Helper()
	hit := map[string]bool{}
	for _, k := range c.hitKeys() {
		hit[k] = true
	}

	var uncovered []string
	seenKeys := map[string]bool{}
	for _, r := range routes {
		k := r.key()
		seenKeys[k] = true
		if hit[k] {
			continue
		}
		if _, ok := skipList[k]; ok {
			continue
		}
		uncovered = append(uncovered, k)
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("%d route(s) in scripts/e2e/routes.json were neither exercised nor explicitly "+
			"skipped-with-reason in skipList (coverage.go) -- every route must be one or the other:\n  %s",
			len(uncovered), joinLines(uncovered))
	}

	var staleSkips []string
	for k := range skipList {
		if !seenKeys[k] {
			staleSkips = append(staleSkips, k)
		}
	}
	sort.Strings(staleSkips)
	if len(staleSkips) > 0 {
		t.Fatalf("%d skipList entr(y/ies) no longer match any route in routes.json (route moved/removed) -- "+
			"stale skip, update coverage.go:\n  %s", len(staleSkips), joinLines(staleSkips))
	}
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}
