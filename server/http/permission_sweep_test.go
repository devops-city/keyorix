// permission_sweep_test.go — the CP-001/CP-008 disclosure-family guard, structural
// counterpart to deployment_disclosure_family_test.go's behavioral regression tests.
//
// admin_usage.go and admin_billing.go were the 7th+ confirmed instance of the same
// mistake: gating a deployment-wide, cross-project/cross-user disclosure report on
// system.read (RequirePermission(permSystemRead) or
// RequireScopedPermission(permSystemRead, ...)) in server/http/router.go, when
// system.read is the universal system_viewer baseline auto-assigned to every user at
// creation (CreateUser), every SSO/JIT-provisioned user, and every SCIM-provisioned
// user — see control_framework.go, compliance_posture.go, deployment_hygiene.go,
// machine_token_hygiene.go, pat_hygiene.go, secrets_name_conformance_deployment.go,
// dashboard.go, admin_usage.go, and admin_billing.go's own header comments for the
// full list of prior instances.
//
// This is an AST sweep over server/http/router.go's source text (not the compiled
// package — the point is to catch a regression in the router WIRING itself, before
// any test that spins up the router even runs), asserting that every
// RequirePermission(permSystemRead)/RequireScopedPermission(permSystemRead, ...) call
// site found is explicitly reviewed and justified in the allowlist below. Mirrors
// internal/cli/writeguard's allowlist-with-reasoning convention: a call site the sweep
// finds must either not exist (gated on something stronger instead) or be justified
// here with a written reason, not just a line number. An empty justification, or an
// allowlist entry whose call site the sweep can no longer find, fails the test — see
// TestPermissionSweepAllowlistJustificationsAreNonEmpty and
// TestPermissionSweepAllowlistEntriesStillExist below.
//
// Verified RED against a reverted admin_usage.go/admin_billing.go fix (both routes
// put back on permSystemRead) — TestNoUnjustifiedSystemReadOnlyGates failed with both
// call sites reported as unallowed; GREEN once the fix (audit.read) was restored.
//
// Allowlist keys are ROUTE IDENTITY ("<HTTP METHOD> <full chi-mounted path>", e.g.
// "GET /api/v1/dashboard/stats"), never a source line number. router.go:LINE keys
// were the original design and broke on every PR that inserted or deleted lines
// anywhere earlier in the file: every later allowlist entry silently pointed at the
// wrong call site (or none), so TestNoUnjustifiedSystemReadOnlyGates/
// TestNoUngatedRoutes failed on PRs that never touched the routes in question — a
// stale justification could also silently attach to a different route entirely if
// the line shift happened to land on another gate call. A route's mounted path does
// not move when unrelated lines shift, so scanRouter (below) resolves the FULL
// mounted path for every route-registration call in NewRouter by walking chi's
// r.Route(...)/r.Group(...) nesting and accumulating each level's literal or
// const-resolvable path segment, exactly mirroring how chi itself builds the mount
// tree at startup. A permission gate applied at a group's own r.Use(...) — covering
// every route beneath it, not one specific route — is keyed "USE <group path>"
// instead of a method+path, since it is not owned by any single leaf route.
package http

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissionSweepAllowlist maps ROUTE IDENTITY ("<METHOD> <full mounted path>", or
// "USE <group path>" for a group-level r.Use(...) gate -- see the package doc above)
// to a written justification for why that route is safe to leave gated on the
// universal system_viewer baseline (system.read) alone, reviewed as part of the
// admin/usage + admin/billing/report fix. Every entry here was traced to its handler
// (and, where relevant, its core-layer implementation) to confirm it returns no
// cross-tenant/cross-user disclosure that system.read's universal grant would expose.
var permissionSweepAllowlist = map[string]string{
	"GET /api/v1/notification-channels/{id}/retry-policy": "GET /notification-channels/{id}/retry-policy returns only " +
		"max_retries/retry_backoff_ms for one channel ID -- numeric tuning knobs, no secret " +
		"values, no PII, no cross-tenant project/user enumeration. Weaker than the parent " +
		"resource's own read (system.write), a pre-existing minor inconsistency, but not the " +
		"cross-tenant-disclosure bug shape this sweep guards against.",
	"GET /api/v1/dashboard/stats": "GET /dashboard/stats is the caller's OWN home dashboard. " +
		"core.GetDashboardStats (internal/core/dashboard.go) separately scopes the " +
		"deployment-wide aggregate fields (active users, audit-event counts, failed-auth " +
		"counts) to audit.read INSIDE the handler -- a baseline caller gets their own numbers " +
		"with the org-wide aggregates zeroed, not the real deployment-wide figures. See " +
		"TestDashboardStats_PermissionTiers in deployment_disclosure_family_test.go.",
	"GET /api/v1/system/auth-config": "GET /system/auth-config returns a deliberately redacted, " +
		"non-per-tenant summary of server-wide auth config (session TTLs, password policy " +
		"shape, SSO provider names/types). No secrets (client secrets/SAML metadata/OIDC " +
		"details excluded by MakeAuthConfigHandler's own doc comment), no per-user or " +
		"per-project data to disclose cross-tenant.",
	"GET /api/v1/system/encryption-config": "GET /system/encryption-config returns a deliberately " +
		"redacted, non-per-tenant summary (encryption enabled + KEK provider TYPE only). Key " +
		"material locations (file paths, exec commands, env var names, KMS key IDs) are " +
		"explicitly excluded by MakeEncryptionConfigHandler's own doc comment.",
	"GET /api/v1/system/info": "GET /system/info returns server version/build/runtime info " +
		"(no per-tenant data) -- the same deployment-wide, non-disclosure-sensitive shape as " +
		"auth-config/encryption-config above.",
	"GET /api/v1/system/metrics": "GET /system/metrics returns process-level runtime metrics " +
		"(memory/GC/goroutines) with HTTP/Database/Secrets counters explicitly zeroed (not " +
		"instrumented at this layer per GetMetrics's own comment) -- no per-tenant data.",
	"GET /api/v1/audit/anomalies": "GET /audit/anomalies sits inside r.Route(\"/audit\", ...) " +
		"which calls r.Use(RequirePermission(permAuditRead)) as a GROUP-level middleware " +
		"(router.go:1056). chi's With() on a route registered inside that group ADDS to, " +
		"never replaces, the group's Use() middleware (verified against go-chi/chi/v5's " +
		"Mux.With/Route/handle: the group's non-inline Mux builds its own handler chain via " +
		"updateRouteHandler, and every route registered inside it -- inline or not -- is " +
		"dispatched through that chain first). So this route actually requires BOTH " +
		"audit.read AND system.read (AND, not OR) -- effectively gated at audit.read, the " +
		"stronger requirement, exactly as router.go's own ANOMALY-04 comment there intends. " +
		"Not a case of \"solely permSystemRead\" despite the literal string match.",
	"GET /api/v1/license/status": "GET /license/status returns deployment-wide license " +
		"metadata (plan/features/seat count/expiry) -- not scoped to any tenant/project/user, " +
		"nothing to cross-tenant-disclose.",
	"GET /api/v1/sod/policies": "GET /sod/policies returns policy DEFINITIONS (name + the " +
		"permission-a/permission-b pair) only -- no PII, no violator names. router.go's own " +
		"adjacent comment is explicit that this stays baseline while /sod/violations (which " +
		"DOES disclose violator names/emails) is separately gated on audit.read.",
	"GET /api/v1/admin/anomaly-config": "GET /admin/anomaly-config returns the DB-persisted anomaly " +
		"detection THRESHOLDS (config), not any user/project/alert data -- deployment-wide " +
		"config in the same non-disclosure-sensitive family as auth-config/encryption-config " +
		"above. Actual alert data (which does disclose SecretName/AccessedBy/IPAddress " +
		"deployment-wide) is the separate /audit/anomalies route (line 1074 above), already " +
		"gated at effective audit.read.",
	"GET /api/v1/audit/export": "GET /audit/export sits inside r.Route(\"/audit\", ...) " +
		"(router.go:1054), same group as /audit/anomalies above -- same chi With()-adds-to-" +
		"group's-Use() reasoning applies verbatim: this route actually requires BOTH " +
		"audit.read AND system.read (AND, not OR). Added FIX-1 (#2733's sibling class): " +
		"AuditExportEntry's full-fidelity shape includes IPAddress and the tamper-evidence " +
		"hash chain, deliberately excluded from /audit/logs and /audit/search -- same " +
		"disclosure shape /audit/anomalies' own elevation exists for.",
	"GET /api/v1/audit/export.csv": "GET /audit/export.csv -- see GET /api/v1/audit/export " +
		"immediately above, same route group, same elevation, same reasoning (CSV vs JSON " +
		"encoding of the identical AuditExportEntry-shaped data).",
}

// repoRoot resolves the repository root relative to THIS test file's own location (not
// the process cwd), so the sweep works regardless of how `go test` is invoked.
func permissionSweepRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must resolve this test file's path")
	// this file lives at server/http/permission_sweep_test.go
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	require.NoError(t, err)
	return root
}

// systemReadSite is one RequirePermission(permSystemRead)/
// RequireScopedPermission(permSystemRead, ...) call site found in server/http/
// router.go, resolved to the route it applies to. routeKey is either
// "<METHOD> <full mounted path>" for a gate chained directly onto one route via
// .With(...), or "USE <group path>" for a gate applied at an enclosing r.Use(...)
// group scope (covering every route beneath it, not one specific route).
type systemReadSite struct {
	routeKey string
	line     int
	fn       string // "RequirePermission" or "RequireScopedPermission"
	perm     string // the gated permission identifier, e.g. "permSystemRead" or "permSystemWrite"
}

// trackedGatePerms is every permission identifier this scan collects sites for.
// permSystemRead: this file's own CP-001/CP-008 sweep, below. permSystemWrite: the
// ADR-110 sweep (system_write_scope_test.go) reuses this same walk rather than
// duplicating it -- see that file's own package doc. permAlertsWrite: the F1
// (ADR-110 follow-up) alerting-operator sweep (alerts_write_scope_test.go)
// reuses the same walk for the same reason.
var trackedGatePerms = map[string]bool{"permSystemRead": true, "permSystemWrite": true, "permAlertsWrite": true}

// addSystemReadSite inserts a found call site (for any permission in
// trackedGatePerms) into found, keyed by routeKey. Two independent call sites that
// resolve to the exact same routeKey (a route registered twice, or two distinct gate
// calls somehow attached to the same route) are disambiguated by appending the gate
// function name and line rather than silently overwriting one with the other.
func addSystemReadSite(found map[string]systemReadSite, routeKey string, line int, fn string, perm string) {
	key := routeKey
	if existing, ok := found[key]; ok && existing.line != line {
		key = fmt.Sprintf("%s [%s@%d]", routeKey, fn, line)
	}
	found[key] = systemReadSite{routeKey: routeKey, line: line, fn: fn, perm: perm}
}

// TestNoUnjustifiedSystemReadOnlyGates is the guard itself: every
// RequirePermission(permSystemRead)/RequireScopedPermission(permSystemRead, ...) call
// site in server/http/router.go must appear in permissionSweepAllowlist. Reverting the
// admin_usage.go/admin_billing.go fix (putting either route back on permSystemRead)
// must fail this test -- verified RED against exactly that revert; see this file's
// package doc comment.
func TestNoUnjustifiedSystemReadOnlyGates(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	_, foundAll := scanRouter(t, routerGoPath)
	// scanRouter also collects permSystemWrite sites for system_write_scope_test.go's
	// ADR-110 sweep (same trackedGatePerms walk, see this file's package doc) -- filter
	// to permSystemRead only here, this test's own concern.
	found := map[string]systemReadSite{}
	for key, s := range foundAll {
		if s.perm == "permSystemRead" {
			found[key] = s
		}
	}
	if len(found) == 0 {
		t.Fatal("found 0 RequirePermission(permSystemRead)/RequireScopedPermission(permSystemRead, " +
			"...) call sites in router.go — this guard is now vacuous and is no longer checking " +
			"anything; fix the scan, not this assertion")
	}

	var unallowed []string
	for key, s := range found {
		if _, ok := permissionSweepAllowlist[key]; !ok {
			unallowed = append(unallowed, fmt.Sprintf("%s (router.go:%d, %s(permSystemRead))", key, s.line, s.fn))
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"server/http/router.go gates a route SOLELY on permSystemRead (the universal "+
			"system_viewer baseline every user holds) with no reviewed justification -- "+
			"either require a stricter permission (audit.read for any deployment-wide/"+
			"cross-tenant disclosure -- see admin_usage.go's header comment for why) or add "+
			"a reviewed allowlist entry here with a written justification: %v", unallowed)
}

// TestPermissionSweepAllowlistEntriesStillExist is the flip side of the guard above: an
// allowlist entry for a route that no longer exists (renamed, deleted, or --
// worse -- silently regressed back onto permSystemRead on a DIFFERENT route, which
// would leave the OLD entry masking the fact that the sweep no longer covers the
// real site) would hide a regression. A stale entry doesn't fail the sweep above
// (which only checks found-but-unallowed sites), so it's checked here explicitly.
func TestPermissionSweepAllowlistEntriesStillExist(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	_, found := scanRouter(t, routerGoPath)

	var stale []string
	for key := range permissionSweepAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"allowlist entry no longer matches any real RequirePermission(permSystemRead)/"+
			"RequireScopedPermission(permSystemRead, ...) call site in server/http/router.go "+
			"(the route moved, was fixed, or regressed onto a different route, without updating "+
			"this list): %v", stale)
}

// TestPermissionSweepAllowlistJustificationsAreNonEmpty guards against an allowlist
// entry added with an empty/placeholder reason, per this campaign's standing rule that
// an exemption needs a written justification, not just a line number.
func TestPermissionSweepAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range permissionSweepAllowlist {
		assert.NotEmpty(t, reason, "allowlist entry %q has no justification", key)
	}
}

// TestPermissionSweepScannerDetectsSystemReadOnlyGates is a self-check on the AST
// sweep itself: a guard that has never been observed to fail on a genuinely bad input
// is not a guard (a test asserting emptiness of a possibly-always-empty scan would
// pass even if the AST matching logic were broken, e.g. matching the wrong selector or
// missing RequireScopedPermission entirely). This proves the scanner actually detects
// both flagged call shapes when present, and does NOT flag permAuditRead or an
// unrelated call, independent of router.go's current contents.
func TestPermissionSweepScannerDetectsSystemReadOnlyGates(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

type mw struct{}

func (mw) RequirePermission(perm string) func() {return nil}
func (mw) RequireScopedPermission(perm string, scoper func()) func() {return nil}

var customMiddleware mw
var permSystemRead = "system.read"
var permAuditRead = "audit.read"

type fakeRouter struct{}

func (fakeRouter) With(mws ...func()) fakeRouter { return fakeRouter{} }
func (fakeRouter) Get(pattern string, h func())  {}

func NewRouter() {
	r := fakeRouter{}
	r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/bad1", nil)
	r.With(customMiddleware.RequireScopedPermission(permSystemRead, nil)).Get("/bad2", nil)
	r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/fine1", nil)
	r.With(customMiddleware.RequireScopedPermission(permAuditRead, nil)).Get("/fine2", nil)
}
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	_, found := scanRouter(t, path)

	require.Len(t, found, 2, "scanner must find exactly the two permSystemRead call sites, not the two permAuditRead ones")
	require.Contains(t, found, "GET /bad1")
	require.Contains(t, found, "GET /bad2")
	var fns []string
	for _, s := range found {
		fns = append(fns, s.fn)
	}
	sort.Strings(fns)
	assert.Equal(t, []string{"RequirePermission", "RequireScopedPermission"}, fns,
		"scanner must detect both RequirePermission and RequireScopedPermission call shapes")
}

// ---------------------------------------------------------------------------
// Broader guard: every registered route must have SOME permission check, not
// just "not solely permSystemRead". Closes the gap the sweep above does not
// cover: a route added with NO RequirePermission/RequireScopedPermission/
// RequireScopedSecretPermission/RequireScopedSecretRefPermission call anywhere
// in its middleware chain -- neither directly on the route nor via r.Use() at
// an enclosing r.Route(...)/r.Group(...) group level -- is a strictly WORSE
// version of the same under-gating shape admin_usage.go/admin_billing.go had
// (gated on nothing beats gated on a universal baseline), and nothing caught
// it before this.
//
// This does NOT replace TestNoUnjustifiedSystemReadOnlyGates above: that sweep
// catches a route gated on SOME permission that turns out to be baseline-
// equivalent (looks administrative, is actually granted to everyone); this one
// only catches a route gated on NO permission at all. A route solely on
// permSystemRead has a non-empty middleware chain, so this broader check sees
// "some permission check present" and passes it through silently -- it would
// NOT have caught the admin_usage.go/admin_billing.go bug this file was
// originally written for. The two checks are complementary, not redundant;
// both run.
//
// Scope: this scanner walks only the NewRouter function's own body (found by
// name in the parsed AST), not the whole file. registerWebUI (this file's
// other route-registering function) wires the SPA's static-asset host
// (/assets/*, /static/*, /sw.js, /manifest.json, /favicon.ico) and the
// client-side-routing NotFound fallback through its own serveStatic closure
// (`rr := r.With(mws...)`), an indirection this AST sweep does not attempt to
// resolve. Those routes serve pre-built, non-per-tenant static files (JS/CSS/
// HTML shell) with no permission concept -- the same public-by-design
// category as /health, /readyz, and /status -- and are out of scope by
// construction rather than silently passed.
//
// Recognizes two things as "some permission check applies", beyond the four
// literal middleware names:
//   - customMiddleware.SCIMToken(...) applied via r.Use() on the /scim/v2
//     group: RFC 7644 SCIM provisioning's own authentication+authorization
//     mechanism is a static shared-secret bearer token, not a per-user RBAC
//     permission grant -- there is no "permission" to check for a machine
//     credential that IS the authorization boundary by design. Every route
//     under /scim/v2 inherits this group-level gate; without recognizing it,
//     all twelve SCIM routes would need individually-repeated allowlist
//     entries pointing at the same one architectural fact.
//   - Group-level r.Use(...) middleware, exactly like the existing sweep's
//     ANOMALY-04 handling of GET /audit/anomalies (router.go:1062 in the
//     allowlist above): chi's With() on a route registered inside a group
//     ADDS to, never replaces, the group's own Use() middleware, and a
//     group's Use() middleware wraps every route dispatched through that
//     group's Mux -- inline or registered via a nested r.Route/r.Group --
//     because the wrapping happens in the Mux's own handler chain before
//     dispatch, not per individual route registration. This sweep reuses
//     that exact reasoning generically: it walks router.go's nesting
//     (r.Route/r.Group closures, and r.Use(...) calls found textually within
//     each) and computes, for every route-registration call
//     (Get/Post/Put/Delete/Patch/Head/Options/Connect/Trace/Handle/Mount),
//     the union of (a) every enclosing group's Use() middleware, walking
//     outward, and (b) every .With(...) call chained directly onto that one
//     route (including a multi-link chain like
//     .With(a).With(b).Post(...), collected by walking the CallExpr's
//     receiver chain back to its base). A route with an empty union in
//     both categories is "no permission check at all".
const (
	// justPreAuthOnboarding covers every route inside the top-level r.Group(...)
	// at router.go:173-213: login itself, MFA/WebAuthn/passkey login second
	// steps, human SSO/SAML flows, and credential-delivery setup links. No
	// session/principal exists yet at any of these -- that IS the point of the
	// route -- so there is no permission to check. The group has no r.Use() at
	// all (see its own header comment), unlike every authenticated group below
	// it.
	justPreAuthOnboarding = "Pre-authentication: no session/principal exists yet at this call (that is the " +
		"route's purpose -- minting one, or a step toward minting one). This whole " +
		"r.Group(...) (router.go:173-213) deliberately has no r.Use() at all -- see the " +
		"group's own header comment -- so every route inside it is unauthenticated by " +
		"design, not an oversight."

	// justPublicInfra covers the unauthenticated liveness/readiness/status/docs
	// family: no per-tenant data, explicitly documented as unauthenticated by
	// each route's own adjacent comment.
	justPublicInfra = "Unauthenticated liveness/readiness/status/docs endpoint, no per-tenant data -- " +
		"see the route's own adjacent comment for why it stays outside both authentication " +
		"and permission checks."

	// justSelfServiceOwnAccount covers the My Account / MFA / WebAuthn /
	// sessions / PAT / notifications family inside /api/v1: authenticated (the
	// group's Authentication/RequireCSRF/EnforceAccountSetup middleware all
	// still apply), but acts ONLY on the
	// calling principal's OWN account/session/token/notification, so no RBAC
	// permission concept applies -- ADR-021/ADR-024/ADR-027 establish this
	// whole family as authenticated-but-not-permission-gated by design.
	justSelfServiceOwnAccount = "Self-service: authenticated (this whole route sits inside the /api/v1 group's " +
		"Authentication/RequireCSRF/EnforceAccountSetup " +
		"middleware -- see router.go:304-325), but acts ONLY on the calling principal's " +
		"OWN account/session/token/notification. ADR-021/ADR-024/ADR-027 establish this " +
		"whole family (My Account, MFA/WebAuthn self-enrolment, session/PAT self-service, " +
		"in-app notifications) as authenticated-but-not-permission-gated by design -- every " +
		"user manages their own, with no administrative reach into anyone else's. See the " +
		"route's own adjacent comment."
)

// noPermissionGateAllowlist maps ROUTE IDENTITY ("<METHOD> <full mounted path>",
// e.g. "POST /api/v1/secrets") to a written justification for why that specific
// route is safe to leave with no permission-gating middleware anywhere in its
// chain. Every entry was traced to its handler (and, for the two in-handler-
// authorized entries, the actual authorization call inside it) to confirm the
// route is genuinely safe unauthorized/self-scoped, not merely unexamined.
var noPermissionGateAllowlist = map[string]string{
	"POST /auth/login": justPreAuthOnboarding + " POST /auth/login mints the session itself.",
	"POST /auth/logout": justPreAuthOnboarding + " POST /auth/logout accepts both session-cookie and " +
		"Bearer callers by design (see its own RequireCSRF-only With(), router.go:180) -- ending a " +
		"session needs no permission on the session's own contents.",
	"POST /auth/refresh": justPreAuthOnboarding + " POST /auth/refresh mints a new access token from a " +
		"still-valid refresh token -- the refresh token itself is the credential.",
	"POST /auth/password-reset": justPreAuthOnboarding + " POST /auth/password-reset is the pre-login reset-" +
		"request step (a reset link is emailed, not returned) -- no session to authorize against.",
	"POST /auth/mfa/verify": justPreAuthOnboarding + " POST /auth/mfa/verify's bearer is the single-use " +
		"login challenge issued by /auth/login, not a session.",
	"POST /auth/webauthn/login/begin": justPreAuthOnboarding + " POST /auth/webauthn/login/begin's bearer is the same " +
		"single-use login challenge.",
	"POST /auth/webauthn/login/finish": justPreAuthOnboarding + " POST /auth/webauthn/login/finish completes the same " +
		"unauthenticated ceremony as login/begin immediately above.",
	"POST /auth/webauthn/passwordless/begin": justPreAuthOnboarding + " POST /auth/webauthn/passwordless/begin is the " +
		"usernameless passkey login's first step (ADR-036 addendum) -- no session exists.",
	"POST /auth/webauthn/passwordless/finish": justPreAuthOnboarding + " POST /auth/webauthn/passwordless/finish completes " +
		"the same ceremony as passwordless/begin immediately above.",
	"POST /system/init": justPreAuthOnboarding + " POST /system/init bootstraps the FIRST admin " +
		"account/credentials on an empty deployment -- by definition no principal, let alone a " +
		"permission, exists yet.",
	"GET /auth/setup/{token}": justPreAuthOnboarding + " GET /auth/setup/{token}'s bearer is the single-use " +
		"setup token in the URL (ADR-028), not a session.",
	"POST /auth/setup/consume": justPreAuthOnboarding + " POST /auth/setup/consume's bearer is the same setup " +
		"token, consumed to mint the account's first real credentials.",
	"GET /auth/sso/providers": justPreAuthOnboarding + " GET /auth/sso/providers lists configured SSO " +
		"providers for the (pre-login) login page to render.",
	"GET /auth/sso/{provider}/login": justPreAuthOnboarding + " GET /auth/sso/{provider}/login redirects to the " +
		"IdP -- the IdP is the authenticator, not this server.",
	"GET /auth/sso/{provider}/callback": justPreAuthOnboarding + " GET /auth/sso/{provider}/callback is the IdP's " +
		"redirect back after IT authenticated the user.",
	"GET /auth/saml/{provider}/metadata": justPreAuthOnboarding + " GET /auth/saml/{provider}/metadata serves this SP's " +
		"own public SAML metadata document for the IdP admin to configure -- no user context at all.",
	"GET /auth/saml/{provider}/login": justPreAuthOnboarding + " GET /auth/saml/{provider}/login redirects to the " +
		"IdP's AuthnRequest endpoint, same as the OIDC login redirect above.",
	"POST /auth/saml/{provider}/acs": justPreAuthOnboarding + " POST /auth/saml/{provider}/acs is the SAML " +
		"Assertion Consumer Service -- the IdP's assertion IS the authentication, same trust model as " +
		"the OIDC callback above.",

	"GET /health": justPublicInfra + " GET /health is a liveness probe (no DB touch).",
	"POST /api/v1/secret-access-requests": "Self-service, same reasoning as CreateAccessRequest above: POST " +
		"/secret-access-requests lets an authenticated user request approval to read ONE restricted " +
		"secret's value they DO NOT YET HAVE. Visibility is enforced INSIDE the handler " +
		"(GetSecretWithPermissionCheck, mapped to an identical 404 for a nonexistent or invisible " +
		"secret -- no route-level permission check could express that anti-enumeration property " +
		"anyway) and core.RequestSecretAccess scopes the created row to the caller's own user ID. " +
		"See secret_access_requests.go's CreateSecretAccessRequest.",
	"GET /api/v1/secret-access-requests": "GET /secret-access-requests returns only rows core." +
		"ListSecretAccessRequestsForUser computes as visible to the CALLER: \"mine\" (the caller's own " +
		"requests) and \"pending_approval\" (pending requests at a project where the caller holds " +
		"admin authority, via requireAdminAuthorityAt -- the classification gate's own bar, not " +
		"roles.assign). The function itself is the authorization boundary; a route-level permission " +
		"gate would either be redundant (mine, always visible to its own owner) or wrong (pending_" +
		"approval's bar isn't a single static permission string). See ListSecretAccessRequests.",
	"GET /api/v1/secret-access-requests/{requestId}": "GET /secret-access-requests/{requestId} is authorized INSIDE core." +
		"GetSecretAccessRequest: visible only to the requester or an admin at the request's project " +
		"(requireAdminAuthorityAt), returning an IDENTICAL not-found for a nonexistent request, a " +
		"project/role request ID (out of scope for this accessor), and a real secret-scoped request " +
		"the caller may not see -- the same anti-enumeration property Create above relies on. See " +
		"GetSecretAccessRequest (handler) and its core-layer namesake.",
	"PUT /api/v1/secret-access-requests/{requestId}": "PUT /secret-access-requests/{requestId} (approve/reject) is authorized " +
		"INSIDE core.ApproveSecretAccessRequest/RejectSecretAccessRequest, both of which call " +
		"requireAdminAuthorityAt(ctx, approverID, req.ProjectID) before mutating -- the classification " +
		"gate's own bar (admin authority at the request's own project, resolved from the request row, " +
		"never a URL parameter this route's path doesn't even carry), not roles.assign " +
		"(classification_gate.go's own doc comment explains why the weaker project/role family's " +
		"permission doesn't fit a grant that carries no role at all). A route-level permission gate " +
		"here would either be wrong (roles.assign is not sufficient) or a duplicate of the exact " +
		"check core already performs. See ResolveSecretAccessRequest.",
	"POST /api/v1/secret-access-requests/{requestId}/withdraw": "Self-service, same reasoning as WithdrawAccessRequest above: POST " +
		"secret-access-requests/{requestId}/withdraw cancels only the CALLER'S OWN pending request " +
		"(core.WithdrawAccessRequest, reused unchanged, scopes to the requester -- #G14's identical " +
		"\"not found\" for a nonexistent request and one belonging to someone else). See " +
		"WithdrawSecretAccessRequest.",
	"GET /readyz": justPublicInfra + " GET /readyz is a readiness probe (DB reachability only).",
	"GET /api/v1/version": justPublicInfra + " GET /api/v1/version is the version-skew endpoint (ADR-108 " +
		"PR 0, docs/cli-split-inventory.md §5) -- unauthenticated like /health, so a thin CLI can check " +
		"compatibility before it has credentials. See router.go's own adjacent comment.",
	"HANDLE /metrics":   justPublicInfra + " /metrics is Prometheus scrape target; optionally protected by a separate static-bearer-token check (cfg.Server.HTTP.MetricsToken) when configured -- a deployment-perimeter control, not RBAC.",
	"GET /status":       justPublicInfra + " GET /status serves the public status dashboard (or falls back to the health check).",
	"GET /status-es":    justPublicInfra + " GET /status-es is the Spanish-language mirror of /status immediately above.",
	"MOUNT /swagger/":   justPublicInfra + " Swagger UI is gated by cfg.Server.HTTP.SwaggerEnabled (a deployment config flag, not a per-caller permission) -- see the adjacent comment; the machine-readable API surface it exposes is the same shape /openapi.yaml exposes below.",
	"GET /openapi.yaml": justPublicInfra + " GET /openapi.yaml is the raw OpenAPI spec, gated by the same cfg.Server.HTTP.SwaggerEnabled flag as the Swagger UI immediately above (#224 fixed the two having diverging on/off behavior; they must stay paired).",

	"GET /api/v1/auth/profile":                        justSelfServiceOwnAccount + " GET/PUT /auth/profile.",
	"PUT /api/v1/auth/profile":                        justSelfServiceOwnAccount + " GET/PUT /auth/profile.",
	"POST /api/v1/auth/change-password":               justSelfServiceOwnAccount + " POST /auth/change-password changes only the caller's own password.",
	"POST /api/v1/auth/mfa/enroll":                    justSelfServiceOwnAccount + " POST /auth/mfa/enroll starts enrolling the caller's OWN second factor; blocked under impersonation (BlockWhenImpersonating) so an admin acting as a user cannot plant a durable credential.",
	"POST /api/v1/auth/mfa/activate":                  justSelfServiceOwnAccount + " POST /auth/mfa/activate activates the caller's OWN pending enrolment; same impersonation block as enroll above.",
	"POST /api/v1/auth/mfa/disable":                   justSelfServiceOwnAccount + " POST /auth/mfa/disable disables only the caller's OWN MFA; same impersonation block.",
	"GET /api/v1/auth/mfa/recovery-codes":             justSelfServiceOwnAccount + " GET /auth/mfa/recovery-codes/status reads only the caller's OWN recovery-code status.",
	"POST /api/v1/auth/mfa/recovery-codes/regenerate": justSelfServiceOwnAccount + " POST recovery-codes/regenerate regenerates only the caller's OWN codes; same impersonation block.",
	"POST /api/v1/auth/mfa/stepup":                    justSelfServiceOwnAccount + " POST /auth/mfa/stepup re-verifies the caller's OWN TOTP/recovery code to open their own restricted-secret read window; same impersonation block.",
	"POST /api/v1/auth/webauthn/register/begin":       justSelfServiceOwnAccount + " POST webauthn/register/begin registers a passkey for the caller's OWN account; same impersonation block.",
	"POST /api/v1/auth/webauthn/register/finish":      justSelfServiceOwnAccount + " POST webauthn/register/finish completes the same ceremony as register/begin above.",
	"GET /api/v1/auth/webauthn/credentials":           justSelfServiceOwnAccount + " GET webauthn/credentials lists only the caller's OWN passkeys.",
	"DELETE /api/v1/auth/webauthn/credentials/{id}":   justSelfServiceOwnAccount + " DELETE webauthn/credentials/{id} deletes only the caller's OWN passkey (there is no admin API to remove another user's passkey); same impersonation block, since deleting the last passkey is the same durable MFA-downgrade /auth/mfa/disable is blocked from doing.",
	"POST /api/v1/auth/webauthn/reauth/begin":         justSelfServiceOwnAccount + " POST /auth/webauthn/reauth/begin starts a live passkey re-assertion for the caller's OWN account (the WebAuthn-only path to satisfy requireReauth); same impersonation block as the other WebAuthn/MFA self-service routes.",
	"POST /api/v1/auth/webauthn/reauth/finish":        justSelfServiceOwnAccount + " POST /auth/webauthn/reauth/finish completes the same ceremony as reauth/begin immediately above.",
	"GET /api/v1/auth/sessions":                       justSelfServiceOwnAccount + " GET /auth/sessions lists only the caller's OWN sessions.",
	"DELETE /api/v1/auth/sessions/{id}":               justSelfServiceOwnAccount + " DELETE /auth/sessions/{id} revokes only one of the caller's OWN sessions.",
	"GET /api/v1/auth/tokens":                         justSelfServiceOwnAccount + " GET /auth/tokens lists only the caller's OWN PATs.",
	"POST /api/v1/auth/tokens":                        justSelfServiceOwnAccount + " POST /auth/tokens mints a PAT for the caller's OWN account; blocked under impersonation so an admin acting as a user cannot plant a durable token.",
	"DELETE /api/v1/auth/tokens/{id}":                 justSelfServiceOwnAccount + " DELETE /auth/tokens/{id} revokes only one of the caller's OWN PATs.",
	"GET /api/v1/auth/tokens/expired":                 justSelfServiceOwnAccount + " GET tokens/expired lists only the caller's OWN expired PATs.",
	"DELETE /api/v1/auth/tokens/expired":              justSelfServiceOwnAccount + " DELETE tokens/expired bulk-revokes only the caller's OWN expired PATs.",
	"POST /api/v1/auth/end-impersonation":             justSelfServiceOwnAccount + " POST /auth/end-impersonation ends only the CALLER'S OWN impersonation session.",
	"GET /api/v1/notifications":                       justSelfServiceOwnAccount + " GET /notifications lists only the caller's OWN in-app notifications (ADR-024).",
	"POST /api/v1/notifications/read-all":             justSelfServiceOwnAccount + " POST notifications/read-all marks only the caller's OWN notifications read.",
	"POST /api/v1/notifications/{id}/read":            justSelfServiceOwnAccount + " POST notifications/{id}/read marks one of the caller's OWN notifications read.",

	"POST /api/v1/projects/{id}/access-requests": "Self-service (ADR-024): POST /projects/{id}/access-requests lets an " +
		"authenticated user request access to a project THEY DO NOT YET HAVE -- by definition they " +
		"cannot hold a project-scoped permission on it yet, so no permission check can gate the " +
		"request itself (core.RequestProjectAccess scopes the created row to the caller's own " +
		"user ID). See router.go's own adjacent comment (\"requesting + withdrawing are self-" +
		"service\") and handlers/invitations.go's CreateAccessRequest.",
	"POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw": "Self-service (ADR-024): POST access-requests/{requestId}/withdraw withdraws " +
		"only the CALLER'S OWN pending request (core.WithdrawAccessRequest scopes to the requester). " +
		"Same reasoning as CreateAccessRequest immediately above.",
	"POST /api/v1/projects/{id}/break-glass": "Self-service by design: POST /projects/{id}/break-glass activates " +
		"emergency access the caller currently LACKS -- the entire point of break-glass is bypassing " +
		"the normal grant path, so gating it on a permission would defeat its purpose. Controlled " +
		"instead by deployment config + a mandatory justification + full audit trail + automatic " +
		"expiry (NIS2/DORA incident response). Blocked under impersonation (BlockWhenImpersonating) " +
		"so an admin acting as a user cannot mint a durable emergency role grant attributed to the " +
		"target. See router.go's own adjacent comment.",

	"GET /api/v1/projects": "GET /projects (ListProjects) performs its own authorization INSIDE the handler " +
		"(#2780), exactly like GET /secrets below and for the same reason: the route used to require " +
		"secrets.read at the GLOBAL scope and then return EVERY project unfiltered, so a project-scoped " +
		"reader got a 403 while being able to read those same projects one at a time via " +
		"GET /projects/{id}. The handler now resolves core.VisibleProjects, which authorizes each project " +
		"at the PROJECT scope -- the same check GET /projects/{id} applies -- so every row returned is a " +
		"row this caller could already fetch by id, a global reader's list is unchanged, and a caller with " +
		"no grant gets an empty list rather than a 403. It also refuses a request with no user context " +
		"(401) and keeps ?include_deleted=true on the global grant, since a soft-deleted project is " +
		"unreadable by id to a scoped caller. See catalog.go's ListProjects doc comment.",
	"GET /api/v1/environments": "GET /environments (ListEnvironments) authorizes INSIDE the handler, " +
		"same change and same reasoning as GET /projects above (#2780, fix-siblings). It returns only " +
		"environments whose parent project the caller can read, resolved by the same " +
		"core.VisibleProjects answer. Load-bearing rather than cosmetic: the web New Secret dialog's " +
		"required Environment select reads THIS endpoint, so scoping the project list alone would leave " +
		"that dialog unsatisfiable for a project-scoped reader. Refuses a request with no user context " +
		"(401). See catalog.go's ListEnvironments doc comment.",
	"GET /api/v1/secrets": "GET /secrets (ListSecrets) performs its own authorization INSIDE the " +
		"handler so a project-scoped reader gets the union of their accessible scopes rather than a " +
		"403 on an unfiltered request -- see router.go's own adjacent comment and secrets_list.go. " +
		"An unscoped/no-permission caller still only ever sees the empty-or-narrowed result their " +
		"own scopes permit, never another caller's secrets.",
	"GET /api/v1/secrets/policy": "GET /secrets/policy returns the deployment's ACTIVE create-time naming/" +
		"value policy -- deployment-wide, non-per-tenant configuration every authenticated caller " +
		"needs visibility into before they can even attempt a create (the same policy a create " +
		"request would be validated against). No secret values, no per-tenant data. See router.go's " +
		"own adjacent comment (\"any authenticated caller\").",
	"POST /api/v1/secrets": "POST /secrets (CreateSecret) is authorized INSIDE the handler: scope " +
		"(project/environment) comes from the request body, not a URL path param a scope resolver " +
		"middleware could resolve ahead of the handler. See router.go's own adjacent comment " +
		"(\"Create: authorized inside the handler (scope comes from the body)\").",
	"DELETE /api/v1/secrets/{id}/self-share": "DELETE /secrets/{id}/self-share (RemoveSelfFromShare) removes only the " +
		"CALLER'S OWN direct share (core only removes a share whose RecipientID == the caller) -- " +
		"self-service on the caller's own grant, needs just authentication. See router.go's own " +
		"adjacent comment.",
	"POST /api/v1/folders": "POST /folders (CreateFolder) is authorized INSIDE the handler: scope " +
		"comes from the request body, the same in-handler-authorization pattern as CreateSecret " +
		"above. See router.go's own adjacent comment (\"Create authorizes in-handler (scope from the " +
		"body)\").",
	"POST /api/v1/rotation-policies": "POST /rotation-policies (Create) is authorized INSIDE the handler: scope " +
		"comes from the request body, the same in-handler pattern as CreateSecret/CreateFolder above. " +
		"See router.go's own adjacent comment (\"create authorizes in-handler against the body\").",
	"POST /api/v1/dynamic-secrets/configs": "POST /dynamic-secrets/configs (CreateConfig) is authorized INSIDE the " +
		"handler -- traced to the actual code, not just the group's header comment: " +
		"DynamicSecretHandler.CreateConfig (server/http/handlers/dynamic_secrets.go) calls " +
		"h.authorize(r, permSecretsWrite, scope) itself before creating the config.",
	"GET /api/v1/dynamic-secrets/configs": "GET /dynamic-secrets/configs (ListConfigs) is authorized INSIDE the " +
		"handler -- traced to the actual code: DynamicSecretHandler.ListConfigs " +
		"(server/http/handlers/dynamic_secrets.go) calls h.authorize(r, permSecretsRead, " +
		"core.Scope{ProjectID: projectID, EnvironmentID: environmentID}) itself before listing.",
}

// permissionGateMiddleware is every customMiddleware function name recognized
// as satisfying "some permission check applies" for the broader sweep below.
// The four permission-check shapes match this file's own package doc
// (RequirePermission/RequireScopedPermission/RequireScopedSecretPermission/
// RequireScopedSecretRefPermission). RequireNodeCredential is included for
// forward compatibility only -- it exists in server/middleware/node_credential.go
// but router.go does not currently call it anywhere (the /system group's node-
// credential arm, RequireNodeCredentialOrPermission, was removed by ADR-085;
// see router.go's own header comment on the /system group) -- if a future
// change reintroduces a node-credential gate, this sweep should recognize it
// without needing its own follow-up patch.
var permissionGateMiddleware = map[string]bool{
	"RequirePermission":                 true,
	"RequireScopedPermission":           true,
	"RequireScopedSecretPermission":     true,
	"RequireScopedSecretRefPermission":  true,
	"RequireNodeCredential":             true,
	"RequireNodeCredentialOrPermission": true,
	// SCIMToken is not permission-shaped (no `permission string` argument) but
	// is the sole, deliberate authentication+authorization mechanism for the
	// whole /scim/v2 group -- see the package doc above.
	"SCIMToken": true,
}

// chiRouteRegistrationMethods is every chi.Router method this sweep treats as
// registering a reachable route that needs authorization. "Route" and "Group"
// are handled separately (they open a new nested scope, not a route).
var chiRouteRegistrationMethods = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true,
	"Head": true, "Options": true, "Connect": true, "Trace": true,
	"Handle": true, "HandleFunc": true, "Mount": true,
}

// ungatedRoute is one route-registration call site in router.go's NewRouter
// function found to have no applicable permission-gating middleware, from
// neither a direct .With(...) chain on the call nor any enclosing group's
// r.Use(...). pattern holds the FULLY RESOLVED mounted path (every enclosing
// r.Route(...) prefix already joined in), not the literal text of this one
// call's own argument.
type ungatedRoute struct {
	line    int
	method  string
	pattern string
}

func (u ungatedRoute) key() string { return u.method + " " + u.pattern }

// gateCall is one customMiddleware.<fn>(...) call recognized as a permission
// (or permission-equivalent, e.g. SCIMToken) gate. perm is the identifier
// name of the call's first argument (e.g. "permSystemRead") when it is a
// simple identifier; empty for gates like SCIMToken that take no permission
// argument, or where the argument isn't a bare identifier.
type gateCall struct {
	fn   string
	perm string
}

// extractGateCall reports whether expr is a call of the shape
// customMiddleware.<one of permissionGateMiddleware>(...), and if so returns
// its function name and first-argument identifier name. Bare identifiers/
// selectors passed without being called (e.g. customMiddleware.
// BlockWhenImpersonating, which takes no config argument) are deliberately
// NOT matched -- every real permission-check middleware in this codebase
// takes at least a permission-string argument, so it is always invoked, never
// passed bare.
func extractGateCall(expr ast.Expr) (gateCall, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return gateCall{}, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return gateCall{}, false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "customMiddleware" {
		return gateCall{}, false
	}
	if !permissionGateMiddleware[sel.Sel.Name] {
		return gateCall{}, false
	}
	perm := ""
	if len(call.Args) > 0 {
		if id, ok := call.Args[0].(*ast.Ident); ok {
			perm = id.Name
		}
	}
	return gateCall{fn: sel.Sel.Name, perm: perm}, true
}

// collectWithArgs walks a chi call-chain receiver expression backward through
// any number of chained .With(...) calls (e.g. r.With(a).With(b), or the
// single-call r.With(a, b) form), collecting every argument passed to every
// With() found, and returns them alongside the chain's base expression (the
// router variable itself, e.g. the Ident "r").
func collectWithArgs(expr ast.Expr) (withArgs []ast.Expr, base ast.Expr) {
	for {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return withArgs, expr
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return withArgs, expr
		}
		if sel.Sel.Name != "With" {
			return withArgs, expr
		}
		withArgs = append(withArgs, call.Args...)
		expr = sel.X
	}
}

// exprSourceText renders an AST expression back to source text (e.g. a string
// literal, a named path constant like pathGroups, or a "/x/" + pathIDRestore
// concatenation) for a readable failure message, without needing to evaluate
// string constants.
func exprSourceText(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return "<unresolvable>"
	}
	return buf.String()
}

// resolveTopLevelConsts collects every top-level `const NAME = "literal"`
// declaration in f into a name->value map, so route-pattern expressions that
// reference a named path constant (e.g. pathGroups, pathMetrics) can be
// resolved to their actual string value instead of just their identifier
// text. Only simple string-literal RHS values are captured; anything else is
// silently skipped (evalPathExpr below fails closed on an unresolved
// identifier, so a future const this can't handle is a loud test failure,
// not a silently wrong route key).
func resolveTopLevelConsts(f *ast.File) map[string]string {
	consts := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				consts[name.Name] = val
			}
		}
	}
	return consts
}

// evalPathExpr resolves a route-pattern expression to its literal string
// value: a plain string literal, a reference to a top-level string const
// (resolved via consts), or a "a" + b string concatenation of any depth built
// from those two shapes -- the only forms server/http/router.go's route
// patterns and r.Route(...) prefixes actually use (verified by inspecting
// every Get/Post/Put/Delete/Patch/Head/Options/Connect/Trace/Handle/
// HandleFunc/Mount/Route call's first argument). Returns ok=false for any
// other shape (a variable, a function call, a ternary-style expression) so
// the caller can fail loudly rather than silently mis-key a route.
func evalPathExpr(expr ast.Expr, consts map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		val, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return val, true
	case *ast.Ident:
		val, ok := consts[e.Name]
		return val, ok
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, ok := evalPathExpr(e.X, consts)
		if !ok {
			return "", false
		}
		r, ok := evalPathExpr(e.Y, consts)
		if !ok {
			return "", false
		}
		return l + r, true
	default:
		return "", false
	}
}

// joinRoutePath mirrors chi's own mount-path joining: prefix is the fully
// resolved path accumulated from every enclosing r.Route(...), seg is this
// call's own pattern. A bare "/" seg registered inside a non-empty group
// (e.g. r.Route("/admin/anomaly-config", func(r){ r.Get("/", ...) })) mounts
// AT the group's own path, not a trailing-slash child of it.
func joinRoutePath(prefix, seg string) string {
	if prefix == "" {
		return seg
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	if seg == "/" || seg == "" {
		return trimmed
	}
	return trimmed + seg
}

// routeMethodLabel maps a chi.Router registration method name to the route-
// identity label used in allowlist keys. Handle/HandleFunc register a handler
// for every HTTP method (chi does not restrict it to one verb), so they get
// the generic "HANDLE" label rather than a specific verb; Mount attaches a
// whole sub-handler at a path prefix, labeled "MOUNT".
func routeMethodLabel(selName string) string {
	switch selName {
	case "Handle", "HandleFunc":
		return "HANDLE"
	case "Mount":
		return "MOUNT"
	default:
		return strings.ToUpper(selName)
	}
}

// findNewRouterFunc locates the top-level `func NewRouter(...)` declaration in
// the parsed file. The sweep is deliberately scoped to this one function --
// see the package doc above for why registerWebUI is out of scope.
func findNewRouterFunc(f *ast.File) *ast.FuncDecl {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "NewRouter" && fn.Body != nil {
			return fn
		}
	}
	return nil
}

// walkRouterBlock walks stmts (one block's statements -- the body of
// NewRouter itself, or the FuncLit body passed to an r.Route(...)/
// r.Group(...) call), resolving the full mounted path and permission-gate
// coverage of every route-registration call found, directly or in a nested
// r.Route/r.Group/if-statement scope. prefix is this block's own fully
// resolved mount path (accumulated from every enclosing r.Route(...); r.Group
// does not change it). inherited is whether some enclosing group's own
// r.Use(...) already carries a recognized permission gate. Every finding is
// recorded directly into ungated/systemRead, keyed by route identity
// (method+path, or "USE <group path>" for a group-level gate) rather than
// source line, so unrelated line shifts elsewhere in router.go never change a
// key here.
func walkRouterBlock(t *testing.T, fset *token.FileSet, consts map[string]string, stmts []ast.Stmt, prefix string, inherited bool, ungated map[string]ungatedRoute, systemRead map[string]systemReadSite) {
	t.Helper()
	blockGated := inherited
	for _, stmt := range stmts {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Use" {
			continue
		}
		for _, arg := range call.Args {
			gc, ok := extractGateCall(arg)
			if !ok {
				continue
			}
			blockGated = true
			if (gc.fn == "RequirePermission" || gc.fn == "RequireScopedPermission") && trackedGatePerms[gc.perm] {
				groupPath := prefix
				if groupPath == "" {
					groupPath = "/"
				}
				pos := fset.Position(call.Pos())
				addSystemReadSite(systemRead, "USE "+groupPath, pos.Line, gc.fn, gc.perm)
			}
		}
	}

	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			walkRouterExpr(t, fset, consts, s.X, prefix, blockGated, ungated, systemRead)
		case *ast.IfStmt:
			if s.Body != nil {
				walkRouterBlock(t, fset, consts, s.Body.List, prefix, blockGated, ungated, systemRead)
			}
			if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
				walkRouterBlock(t, fset, consts, elseBlock.List, prefix, blockGated, ungated, systemRead)
			}
		}
	}
}

// walkRouterExpr inspects one top-level statement expression. It recurses
// into r.Route(pattern, func(r chi.Router) {...}) (extending prefix by the
// resolved pattern) and r.Group(func(r chi.Router) {...}) (prefix unchanged)
// closures as nested scopes; for a chi route-registration call
// (Get/Post/.../Mount), it resolves the full mounted path, records a
// permSystemRead systemRead site for any matching direct .With(...) gate, and
// records the call as ungated if neither the inherited group gate nor any
// direct .With(...) gate applies.
func walkRouterExpr(t *testing.T, fset *token.FileSet, consts map[string]string, expr ast.Expr, prefix string, blockGated bool, ungated map[string]ungatedRoute, systemRead map[string]systemReadSite) {
	t.Helper()
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	switch sel.Sel.Name {
	case "Route":
		if len(call.Args) >= 2 {
			seg, ok := evalPathExpr(call.Args[0], consts)
			if !ok {
				t.Fatalf("router.go:%d: r.Route(...) prefix %q is not a literal/const-resolvable "+
					"string -- extend evalPathExpr or use a plain string/const here so the route "+
					"sweep can resolve a stable key", fset.Position(call.Pos()).Line,
					exprSourceText(fset, call.Args[0]))
			}
			if fn, ok := call.Args[1].(*ast.FuncLit); ok && fn.Body != nil {
				walkRouterBlock(t, fset, consts, fn.Body.List, joinRoutePath(prefix, seg), blockGated, ungated, systemRead)
			}
		}
		return
	case "Group":
		if len(call.Args) >= 1 {
			if fn, ok := call.Args[0].(*ast.FuncLit); ok && fn.Body != nil {
				walkRouterBlock(t, fset, consts, fn.Body.List, prefix, blockGated, ungated, systemRead)
			}
		}
		return
	}

	if !chiRouteRegistrationMethods[sel.Sel.Name] {
		return
	}
	if len(call.Args) == 0 {
		return
	}

	seg, ok := evalPathExpr(call.Args[0], consts)
	if !ok {
		t.Fatalf("router.go:%d: route pattern %q for %s(...) is not a literal/const-resolvable "+
			"string -- extend evalPathExpr or use a plain string/const here so the route sweep can "+
			"resolve a stable key", fset.Position(call.Pos()).Line, exprSourceText(fset, call.Args[0]),
			sel.Sel.Name)
	}
	fullPath := joinRoutePath(prefix, seg)
	method := routeMethodLabel(sel.Sel.Name)

	withArgs, _ := collectWithArgs(sel.X)
	gated := blockGated
	for _, arg := range withArgs {
		gc, ok := extractGateCall(arg)
		if !ok {
			continue
		}
		gated = true
		if (gc.fn == "RequirePermission" || gc.fn == "RequireScopedPermission") && trackedGatePerms[gc.perm] {
			pos := fset.Position(call.Pos())
			addSystemReadSite(systemRead, method+" "+fullPath, pos.Line, gc.fn, gc.perm)
		}
	}
	if gated {
		return
	}
	pos := fset.Position(call.Pos())
	r := ungatedRoute{line: pos.Line, method: method, pattern: fullPath}
	ungated[r.key()] = r
}

// scanRouter parses routerGoPath's AST and walks its NewRouter function once,
// resolving BOTH sweeps together (they share the exact same path-resolution
// and gate-detection logic, so a single walk keeps them from silently
// drifting apart): every route-registration call with no applicable
// permission-gating middleware at all (keyed by route identity, for
// TestNoUngatedRoutes), and every customMiddleware.RequirePermission/
// RequireScopedPermission(permSystemRead, ...) call site found -- whether
// chained directly onto one route via .With(...), or applied at an
// r.Use(...) group level -- resolved to the route(s) it applies to (for
// TestNoUnjustifiedSystemReadOnlyGates).
func scanRouter(t *testing.T, routerGoPath string) (ungated map[string]ungatedRoute, systemRead map[string]systemReadSite) {
	t.Helper()
	src, err := os.ReadFile(routerGoPath) // #nosec G304 -- fixed repo-internal path, not external input
	require.NoError(t, err)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, routerGoPath, src, 0)
	require.NoError(t, err)

	consts := resolveTopLevelConsts(f)
	newRouter := findNewRouterFunc(f)
	require.NotNil(t, newRouter, "server/http/router.go must declare func NewRouter(...)")

	ungated = map[string]ungatedRoute{}
	systemRead = map[string]systemReadSite{}
	walkRouterBlock(t, fset, consts, newRouter.Body.List, "", false, ungated, systemRead)
	return ungated, systemRead
}

// TestNoUngatedRoutes is the broader guard itself: every route registered in
// NewRouter must have some applicable permission check (see the package doc
// above for exactly what counts), or a reviewed allowlist entry here
// justifying why that specific route is safe to leave unauthorized (a public,
// pre-authentication, or genuinely self-service route) or authorizes itself
// a different way (in-handler, e.g. ListSecrets/CreateSecret's own
// authorization -- see secrets_list.go / secret_create.go).
func TestNoUngatedRoutes(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	found, _ := scanRouter(t, routerGoPath)
	if len(found) == 0 {
		t.Fatal("found 0 route-registration call sites in NewRouter — this guard is now " +
			"vacuous and is no longer checking anything; fix the scan, not this assertion")
	}

	var unallowed []string
	for key, u := range found {
		if _, ok := noPermissionGateAllowlist[key]; !ok {
			unallowed = append(unallowed, fmt.Sprintf("%s (router.go:%d)", key, u.line))
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"server/http/router.go registers a route with NO permission check anywhere in its "+
			"middleware chain (neither directly on the route nor via r.Use() at an enclosing "+
			"group) -- a strictly worse version of the admin_usage.go/admin_billing.go bug "+
			"(gated on nothing, not just gated on the universal baseline). Either add a "+
			"RequirePermission/RequireScopedPermission/RequireScopedSecretPermission/"+
			"RequireScopedSecretRefPermission gate (directly or via the enclosing group's "+
			"r.Use()), or add a reviewed allowlist entry here with a written justification: %v",
		unallowed)
}

// TestNoPermissionGateAllowlistEntriesStillExist mirrors
// TestPermissionSweepAllowlistEntriesStillExist above: an allowlist entry
// whose call site no longer exists (moved, deleted, or regressed onto a
// DIFFERENT now-ungated line) would silently stop covering anything.
func TestNoPermissionGateAllowlistEntriesStillExist(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	found, _ := scanRouter(t, routerGoPath)

	var stale []string
	for key := range noPermissionGateAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"allowlist entry no longer matches any real ungated route-registration call site in "+
			"server/http/router.go (the route moved, gained a permission gate, or regressed onto a "+
			"different route, without updating this list): %v", stale)
}

// TestNoPermissionGateAllowlistJustificationsAreNonEmpty mirrors
// TestPermissionSweepAllowlistJustificationsAreNonEmpty above.
func TestNoPermissionGateAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range noPermissionGateAllowlist {
		assert.NotEmpty(t, reason, "allowlist entry %q has no justification", key)
	}
}

// TestUngatedRouteScannerDetectsMissingPermissionChecks is the broader
// sweep's self-check, mirroring
// TestPermissionSweepScannerDetectsSystemReadOnlyGates above: proves the
// scanner actually flags a genuinely ungated route, does NOT flag a route
// gated directly via .With(...), does NOT flag a route gated only via an
// enclosing group's r.Use(...), correctly follows a chained
// .With(a).With(b) call, and correctly treats a nested r.Route(...) group
// inside another group as inheriting the OUTER group's gate too.
func TestUngatedRouteScannerDetectsMissingPermissionChecks(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

type mw struct{}

func (mw) RequirePermission(perm string) func() { return nil }
func (mw) BlockWhenImpersonating() {}

var customMiddleware mw
var permSecretsRead = "secrets.read"
var permSecretsWrite = "secrets.write"

type fakeRouter struct{}

func (fakeRouter) Use(mws ...func())                              {}
func (fakeRouter) With(mws ...func()) fakeRouter                  { return fakeRouter{} }
func (fakeRouter) Get(pattern string, h func())                   {}
func (fakeRouter) Post(pattern string, h func())                  {}
func (fakeRouter) Route(pattern string, fn func(r fakeRouter))    {}
func (fakeRouter) Group(fn func(r fakeRouter))                    {}

func NewRouter() {
	r := fakeRouter{}

	// (1) ungated: no With(), no enclosing group Use().
	r.Get("/ungated", nil)

	// (2) gated directly.
	r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/gated-direct", nil)

	// (3) NOT gated: With() present but only a non-permission middleware.
	r.With(customMiddleware.BlockWhenImpersonating).Post("/self-service-not-gated", nil)

	// (4) gated via a chained multi-With call.
	r.With(customMiddleware.BlockWhenImpersonating).With(customMiddleware.RequirePermission(permSecretsWrite)).Post("/gated-chained", nil)

	r.Route("/group", func(r fakeRouter) {
		r.Use(customMiddleware.RequirePermission(permSecretsRead))
		// (5) gated via the enclosing group's Use(), no direct With() at all.
		r.Get("/inherited", nil)

		r.Route("/nested", func(r fakeRouter) {
			// (6) gated via the OUTER group's Use(), two levels up.
			r.Get("/still-inherited", nil)
		})
	})
}
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	found, _ := scanRouter(t, path)

	var keys []string
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"GET /ungated", "POST /self-service-not-gated"}, keys,
		"scanner must flag exactly the two routes with no applicable permission gate, and "+
			"none of the four gated ones (direct, chained-With, group-inherited, "+
			"nested-group-inherited)")
}
