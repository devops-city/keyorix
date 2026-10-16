//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// route_user_path_ratchet.go closes a different gap than assertRouteCoverage
// (coverage.go): that check asserts every route is hit by THIS driver's own
// client or explicitly skip-listed. It says nothing about whether a route
// skip-listed here with a prose claim like "covered by journeyN" is actually
// true -- that claim was never machine-checked (QA-2 session, the bug class
// behind #2441/#2442: untested user paths that look covered on paper).
//
// This is a STATIC check -- no live server, just source text -- so it runs
// fast as part of TestAPISmoke_SQLite (see its call site) without adding a
// new CI job. It asks a narrower, sharper question than full route coverage:
// for every MUTATING or SECRET-DISCLOSING route (the two classes where an
// untested path is a real incident, not a cosmetic gap), is there at least
// one textual reference to it in ANY of the three places a real user path
// gets tested -- scripts/e2e/journeys (customer journeys), scripts/e2e's own
// api-smoke driver (THIS package), or web/e2e/real (Playwright against a
// real backend)?
//
// Deliberately conservative, same shape as check-api-contract.mjs's web-side
// twin (web/scripts/check-api-contract.mjs):
//   - Matching is LITERAL-PREFIX based (the route pattern's text up to its
//     first `{param}` segment must appear as a literal path prefix at some
//     scanned call site with a matching method). This can false-POSITIVE
//     (a call covering `/api/v1/secrets/` is credited to every route sharing
//     that prefix, e.g. both GET /api/v1/secrets/{id} and
//     GET /api/v1/secrets/{id}/acl) -- accepted because the failure mode this
//     check exists to catch is "nothing anywhere mentions this path at all",
//     not "exactly which sibling endpoint got exercised". It never produces
//     a false NEGATIVE from over-matching.
//   - web/e2e/real's Playwright specs mostly drive the UI (clicks/navigation)
//     rather than calling a path literal directly, so this scan's signal
//     there is weak by nature, not a limitation of the regex -- see its own
//     doc comment below. A route that's genuinely only covered via UI
//     interaction the spec file's text never names will show up as
//     uncovered here and need a knownUncoveredUserPaths entry, which is the
//     intended, honest fallback, not a bug in this checker.
//
// knownUncoveredUserPaths is the ratchet's allowlist, same shape as
// coverage.go's skipList and server/faultops's knownOpenTolerances: every
// pre-existing gap found by actually running this check against the repo
// today, named with a reason and (where one exists) an issue. A NEW gap not
// in this list fails the build.
var knownUncoveredUserPaths = map[string]string{
	// Verified 2026-10 (QA-2 session): every one of these is ALSO in
	// coverage.go's skipList with its own detailed reason (WebAuthn/TOTP
	// ceremonies needing a real authenticator, SSO/SAML needing a real IdP,
	// out-of-band tokens, etc.) -- this ratchet doesn't re-derive those,
	// it just accepts that an already-reviewed, already-documented
	// api-smoke skip is sufficient evidence this isn't a SILENT gap, even
	// though the literal-prefix scan (by construction) can't find a static
	// call site for something that's mechanically unreachable without a
	// real external ceremony.
	// POST /api/v1/auth/mfa/disable was here until this PR. It is now covered
	// by web/e2e/real/mfa-disable-dialog.spec.ts, which names the path literally
	// (it counts the POSTs to assert one click produces exactly one), so the
	// ratchet finds it and the allowlist entry is stale -- hence removed. Its
	// coverage.go skipList entry STAYS: that skip is about this Go driver, which
	// still has nothing enrolled to disable, and is a separate mechanism.
	"POST /api/v1/auth/mfa/recovery-codes/regenerate": "see coverage.go skipList -- depends on mfa/enroll+activate",
	"POST /api/v1/auth/mfa/stepup":                    "see coverage.go skipList -- depends on mfa/enroll+activate",
	"POST /auth/mfa/verify":                           "see coverage.go skipList -- needs an MFA-enrolled account",
	"POST /auth/webauthn/login/begin":                 "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /auth/webauthn/login/finish":                "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /auth/webauthn/passwordless/begin":          "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /auth/webauthn/passwordless/finish":         "see coverage.go skipList -- needs a real/simulated authenticator",
	"DELETE /api/v1/auth/webauthn/credentials/{id}":   "see coverage.go skipList -- nothing to delete, enrollment unreachable here",
	"POST /api/v1/auth/webauthn/reauth/begin":         "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /api/v1/auth/webauthn/reauth/finish":        "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /api/v1/auth/webauthn/register/begin":       "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /api/v1/auth/webauthn/register/finish":      "see coverage.go skipList -- needs a real/simulated authenticator",
	"POST /auth/password-reset":                       "see coverage.go skipList -- out-of-band emailed token",
	"POST /auth/setup/consume":                        "see coverage.go skipList -- out-of-band admin-issued setup token",
	"POST /api/v1/risk-exceptions/{id}/approve":       "see coverage.go skipList -- dual-control, needs a second distinct session",
	"POST /api/v1/audit/migrate-chain-encoding":       "see coverage.go skipList -- one-way irreversible migration of the live audit chain",
	"POST /api/v1/admin/impersonate":                  "see coverage.go skipList -- mutates shared session state",
	"DELETE /api/v1/auth/sessions/{id}":               "see coverage.go skipList -- would need a second non-current session",
	"PUT /api/v1/admin/anomaly-config":                "see coverage.go skipList -- replaces shared deployment-wide thresholds other groups' assertions depend on",
	"POST /api/v1/admin/jobs/anomaly-alerts":          "see coverage.go skipList -- deployment-wide job trigger with real side effects",
	"POST /api/v1/admin/jobs/check-read-quotas":       "see coverage.go skipList -- deployment-wide job trigger",
	"POST /api/v1/admin/jobs/compliance-digest":       "see coverage.go skipList -- deployment-wide job trigger with real side effects",
	"POST /api/v1/admin/jobs/expiry-reminders":        "see coverage.go skipList -- deployment-wide job trigger with real side effects",
	"POST /api/v1/admin/jobs/role-expiry-check":       "see coverage.go skipList -- may expire/notify real role grants other groups rely on",
	"POST /api/v1/admin/jobs/rotation-reminders":      "see coverage.go skipList -- deployment-wide job trigger with real side effects",
	"POST /api/v1/admin/jobs/run-alert-escalation":    "see coverage.go skipList -- deployment-wide job trigger with real side effects",
	"POST /api/v1/admin/jobs/suspend-inactive-users":  "see coverage.go skipList -- suspends real users other groups still need active",
	"POST /api/v1/admin/jobs/token-expiry-check":      "see coverage.go skipList -- may revoke real tokens other groups rely on",
	"POST /api/v1/auth/end-impersonation":             "see coverage.go skipList -- impersonation start/end mutates session state, exercised by dedicated impersonation tests, not folded into this driver's shared session",
	"POST /auth/saml/{provider}/acs":                  "see coverage.go skipList -- requires a real external SAML IdP to produce a valid assertion",
	"POST /system/init":                               "see coverage.go skipList -- the bootstrap call itself, made directly by harness.StartServer before any client exists (this route IS exercised, just not through a scanned call site)",
	"POST /scim/v2/Users":                             "SCIM provisioning surface -- see coverage.go skipList, same out-of-band-SCIMToken reasoning",
	"PATCH /scim/v2/Users/{id}":                       "see coverage.go skipList -- SCIM provisioning surface",
	"DELETE /scim/v2/Users/{id}":                      "see coverage.go skipList -- SCIM provisioning surface",
	"POST /scim/v2/Groups":                            "see coverage.go skipList -- SCIM provisioning surface",
	"PATCH /scim/v2/Groups/{id}":                      "see coverage.go skipList -- SCIM provisioning surface",
	"PUT /scim/v2/Groups/{id}":                        "see coverage.go skipList -- SCIM provisioning surface",
	"DELETE /scim/v2/Groups/{id}":                     "see coverage.go skipList -- SCIM provisioning surface",
	"PUT /scim/v2/Users/{id}":                         "see coverage.go skipList -- SCIM provisioning surface",
}

// mutatingMethods is deliberately exhaustive over HTTP verbs that write --
// GET/HEAD/OPTIONS never do, by the HTTP spec's own safe-method definition.
var mutatingMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// isMutatingOrSecretDisclosing is the machine-derived classifier for which
// routes this ratchet cares about. "Secret-disclosing" is permSecretsRead in
// the route's gate_perms (routes.json, I1) -- a real RBAC permission name,
// not a path-text guess, so it also catches GET routes that reveal secret
// VALUES (e.g. GET /api/v1/secrets/value, POST /api/v1/connect/{name}/secret:read
// is gated on connect.read instead and is NOT in this set by this definition
// -- it's still mutating-or-not; connect reads are covered separately if
// they're POST, otherwise this classifier's secret-disclosure net is
// specifically the native-secrets permission, not every read-adjacent one).
func isMutatingOrSecretDisclosing(r userPathRouteEntry) bool {
	if mutatingMethods[r.Method] {
		return true
	}
	for _, p := range r.GatePerms {
		if p == "permSecretsRead" {
			return true
		}
	}
	return false
}

type userPathRouteEntry struct {
	Method    string   `json:"method"`
	Pattern   string   `json:"pattern"`
	GatePerms []string `json:"gate_perms"`
}

func (e userPathRouteEntry) key() string { return e.Method + " " + e.Pattern }

// loadUserPathRoutes reads scripts/e2e/routes.json independently of
// coverage.go's loadRoutes -- same file, different struct (this one also
// reads gate_perms, which routeEntry doesn't need). Duplicated rather than
// shared for the same reason coverage.go's own header gives for not
// importing server/http's struct: keeping this file self-contained.
func loadUserPathRoutes(t *testing.T) []userPathRouteEntry {
	t.Helper()
	path := filepath.Join(harness.RepoRoot(t), "scripts", "e2e", "routes.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var routes []userPathRouteEntry
	if err := json.Unmarshal(raw, &routes); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(routes) == 0 {
		t.Fatal("routes.json parsed to 0 routes -- this ratchet would be vacuous")
	}
	return routes
}

// literalPrefix returns pattern's text up to (not including) its first
// `{param}` segment -- e.g. "/api/v1/secrets/{id}/acl" -> "/api/v1/secrets/".
// A pattern with no `{` returns itself unchanged.
func literalPrefix(pattern string) string {
	if i := strings.Index(pattern, "{"); i >= 0 {
		return pattern[:i]
	}
	return pattern
}

// httpMethodConst maps the http.MethodX identifiers journeys use to their
// plain string form. Exhaustive over net/http's own constant set.
var httpMethodConst = map[string]string{
	"MethodGet": "GET", "MethodHead": "HEAD", "MethodPost": "POST", "MethodPut": "PUT",
	"MethodPatch": "PATCH", "MethodDelete": "DELETE", "MethodConnect": "CONNECT",
	"MethodOptions": "OPTIONS", "MethodTrace": "TRACE",
}

// restCallRE matches scripts/e2e/journeys' two call-site shapes:
// restExpect(t, s, token, <method>, "<path...>", ...) and
// restCall(t, s, token, <method>, "<path...>", ...) -- both take method then
// path as their 4th/5th positional args (see helpers.go). <method> is either
// an http.MethodX selector or a bare string literal; \s matches newlines, so
// this tolerates the common multi-line call-site formatting in this repo.
var restCallRE = regexp.MustCompile(
	`\b(?:restExpect|restCall)\(\s*t,\s*s,\s*\w+,\s*(?:http\.(Method\w+)|"(\w+)")\s*,\s*"([^"]*)"`,
)

// clientCallRE matches scripts/e2e's own api-smoke driver call sites:
// c.call("METHOD", "METHOD /pattern", ...) / c.callExpect(...) / c.skip(...).
// The SECOND argument is already the exact "METHOD /pattern" bookkeeping key
// coverage.go's routeEntry.key() produces -- no prefix heuristic needed for
// this layer, just read the literal.
var clientCallRE = regexp.MustCompile(`\bc\.(?:call|callExpect|skip)\(\s*(?:"[A-Z]+"\s*,\s*)?"([A-Z]+ [^"]+)"`)

// playwrightPathRE is the web-real layer's signal: any literal
// "/api/v1/..." or "/auth/..." string appearing anywhere in a .spec.ts file
// under web/e2e/real. Deliberately method-blind and page-content-blind (see
// this file's header) -- Playwright specs mostly drive the UI rather than
// naming a path literal, so this is a weak, best-effort signal by nature,
// not a precision gap in the regex itself. A path literal found here is
// credited to every route sharing that literal as a prefix, same as the
// journeys/api-smoke layers.
var playwrightPathRE = regexp.MustCompile(`["'\x60](/(?:api/v1|auth)/[A-Za-z0-9_\-./{}]*)`)

// scanStaticUserPathCoverage walks journeys/*.go, scripts/e2e/*.go (this
// package, excluding itself and other _test.go infra that isn't the
// api-smoke driver), and web/e2e/real/*.spec.ts plus the .ts helpers they
// import (see playwrightScanFiles), returning the set of
// (method, literal-prefix) pairs found, as "METHOD prefix" keys.
func scanStaticUserPathCoverage(t *testing.T, repoRoot string) map[string]bool {
	t.Helper()
	found := map[string]bool{}

	addFromJourneys := func(path string) {
		raw, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path under a glob this function controls
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range restCallRE.FindAllStringSubmatch(string(raw), -1) {
			method := m[2] // bare string literal form, e.g. "GET"
			if m[1] != "" {
				method = httpMethodConst[m[1]]
			}
			if method == "" {
				continue // unrecognized method constant -- don't guess
			}
			found[method+" "+literalPrefix(m[3])] = true
		}
	}

	addFromClientCalls := func(path string) {
		raw, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path under a glob this function controls
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range clientCallRE.FindAllStringSubmatch(string(raw), -1) {
			// m[1] is already "METHOD /pattern" -- but store by literal
			// prefix too, for consistency with the prefix-based lookup
			// below (a pattern key and its own literal prefix agree
			// trivially when there's no {param}).
			parts := strings.SplitN(m[1], " ", 2)
			if len(parts) != 2 {
				continue
			}
			found[parts[0]+" "+literalPrefix(parts[1])] = true
		}
	}

	addFromPlaywright := func(path string) {
		raw, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path under a glob this function controls
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range playwrightPathRE.FindAllStringSubmatch(string(raw), -1) {
			// Method-blind: credit every mutating method AND secret-read
			// GET for this literal prefix. This is intentionally generous
			// (see this file's header on web-real's weak signal) -- the
			// alternative is crediting nothing at all from this layer for
			// a navigation-driven spec that never spells out a method.
			prefix := literalPrefix(m[1])
			for method := range mutatingMethods {
				found[method+" "+prefix] = true
			}
			found["GET "+prefix] = true
		}
	}

	journeysDir := filepath.Join(repoRoot, "scripts", "e2e", "journeys")
	journeyFiles, err := filepath.Glob(filepath.Join(journeysDir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", journeysDir, err)
	}
	if len(journeyFiles) == 0 {
		t.Fatalf("no journey files found under %s -- the journeys layer of this ratchet would be silently vacuous", journeysDir)
	}
	for _, f := range journeyFiles {
		addFromJourneys(f)
	}

	e2eDir := filepath.Join(repoRoot, "scripts", "e2e")
	e2eFiles, err := filepath.Glob(filepath.Join(e2eDir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", e2eDir, err)
	}
	for _, f := range e2eFiles {
		addFromClientCalls(f)
	}

	webRealDir := filepath.Join(repoRoot, "web", "e2e", "real")
	for _, f := range playwrightScanFiles(t, webRealDir) {
		addFromPlaywright(f)
	}

	return found
}

// tsRelativeImportRE captures the module specifier of a relative import or
// re-export ("from './helpers'", "from '../real/helpers.ts'") in a .ts file.
var tsRelativeImportRE = regexp.MustCompile(`\bfrom\s+["'](\.{1,2}/[^"']+)["']`)

// playwrightScanFiles returns every *.spec.ts in dir plus every .ts module
// they import (transitively, relative imports only). A path literal that
// lives in a shared helper (e.g. helpers.ts's POST /auth/login, moved there
// from mfa-login.spec.ts by #2789) is real coverage for every spec that
// calls the helper, so it must be scanned; but a helper no spec imports is
// dead code and is deliberately NOT credited.
func playwrightScanFiles(t *testing.T, dir string) []string {
	t.Helper()
	specs, err := filepath.Glob(filepath.Join(dir, "*.spec.ts"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	seen := map[string]bool{}
	queue := append([]string(nil), specs...)
	var out []string
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
		raw, err := os.ReadFile(f) // #nosec G304 -- path comes from the glob above or a resolved relative import inside the repo
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range tsRelativeImportRE.FindAllStringSubmatch(string(raw), -1) {
			base := filepath.Join(filepath.Dir(f), m[1])
			for _, cand := range []string{base, base + ".ts", filepath.Join(base, "index.ts")} {
				if !strings.HasSuffix(cand, ".ts") {
					continue
				}
				if st, err := os.Stat(cand); err == nil && !st.IsDir() {
					queue = append(queue, cand)
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// isCoveredByPrefix reports whether route is covered by anything in found:
// same method, and a scanned call's own literal prefix reaches AT LEAST as
// deep as route's distinguishing literal prefix (foundPrefix starts with
// routePrefix, or they're equal). The reverse is deliberately NOT accepted:
// a scanned call referencing only a SHORTER, more general prefix (e.g.
// web-real's weak "/auth/" capture, see playwrightPathRE) must not be
// credited as covering every deeper, more specific route under that
// general prefix (e.g. POST /auth/webauthn/register/begin) -- that direction
// produced real false positives during development (every webauthn/
// password-reset/setup-consume route looked "covered" by an unrelated
// shorter /auth/ reference) and was removed.
func isCoveredByPrefix(route userPathRouteEntry, found map[string]bool) bool {
	routePrefix := literalPrefix(route.Pattern)
	for key := range found {
		sp := strings.SplitN(key, " ", 2)
		if len(sp) != 2 || sp[0] != route.Method {
			continue
		}
		if strings.HasPrefix(sp[1], routePrefix) {
			return true
		}
	}
	return false
}

// findRouteCoverageViolations is the ratchet's pure evaluation core --
// factored out of TestRouteUserPathCoverageRatchet so TestRouteCoverageRatchet_SelfTest
// below can exercise it against a synthetic fixture without touching the
// real routes.json/journeys/web-real tree. logf is nil-safe (tests that
// don't care about the KNOWN log lines pass nil).
func findRouteCoverageViolations(routes []userPathRouteEntry, found map[string]bool, known map[string]string, logf func(string, ...any)) []string {
	var failures []string
	knownStillPresent := map[string]bool{}

	for _, r := range routes {
		if !isMutatingOrSecretDisclosing(r) {
			continue
		}
		key := r.key()
		if isCoveredByPrefix(r, found) {
			continue
		}
		if reason, ok := known[key]; ok {
			knownStillPresent[key] = true
			if logf != nil {
				logf("[route-user-path-ratchet] KNOWN %s: no journey/e2e/web-real reference found -- %s", key, reason)
			}
			continue
		}
		failures = append(failures,
			fmt.Sprintf("%s: mutating-or-secret-disclosing route has no journey/e2e/web-real reference and no knownUncoveredUserPaths entry", key))
	}

	for key := range known {
		if !knownStillPresent[key] {
			failures = append(failures,
				fmt.Sprintf("%s: in knownUncoveredUserPaths but no longer reproduces (now covered, or route moved/removed) -- remove the stale entry", key))
		}
	}
	sort.Strings(failures)
	return failures
}

// TestRouteUserPathCoverageRatchet is the ratchet itself -- see this file's
// header. Pure static analysis, no live server, so it's cheap to run as
// part of TestAPISmoke_SQLite (see that test's call site) without adding any
// new CI job or Makefile target.
func TestRouteUserPathCoverageRatchet(t *testing.T) {
	routes := loadUserPathRoutes(t)
	found := scanStaticUserPathCoverage(t, harness.RepoRoot(t))

	failures := findRouteCoverageViolations(routes, found, knownUncoveredUserPaths, t.Logf)
	if len(failures) > 0 {
		t.Fatalf("%d route-user-path-coverage violation(s):\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// TestRouteCoverageRatchet_SelfTest is the permanent red/green regression
// guard for the ratchet mechanism itself, against a synthetic fixture (no
// dependency on the real repo's current routes/journeys/web-real content,
// unlike the manual red-proof pasted in this change's PR description, which
// temporarily added a dummy route to the REAL routes.json and confirmed the
// same failure shape before reverting).
func TestRouteCoverageRatchet_SelfTest(t *testing.T) {
	routes := []userPathRouteEntry{
		{Method: "GET", Pattern: "/api/v1/widgets/{id}"},                                           // not mutating, not secret-disclosing -- never checked
		{Method: "POST", Pattern: "/api/v1/widgets", GatePerms: []string{"permWidgetsWrite"}},      // mutating, covered below
		{Method: "GET", Pattern: "/api/v1/secrets/value", GatePerms: []string{"permSecretsRead"}},  // secret-disclosing, covered below
		{Method: "POST", Pattern: "/api/v1/this-endpoint-does-not-exist-anywhere", GatePerms: nil}, // mutating, deliberately uncovered -- the red-proof
	}
	found := map[string]bool{
		"POST /api/v1/widgets":      true,
		"GET /api/v1/secrets/value": true,
	}

	t.Run("RED: an uncovered mutating route with no allowlist entry fails", func(t *testing.T) {
		failures := findRouteCoverageViolations(routes, found, map[string]string{}, nil)
		if len(failures) != 1 {
			t.Fatalf("want exactly 1 violation (the deliberately uncovered dummy route), got %d: %v", len(failures), failures)
		}
		if !strings.Contains(failures[0], "this-endpoint-does-not-exist-anywhere") {
			t.Fatalf("violation does not name the expected route: %s", failures[0])
		}
	})

	t.Run("GREEN: the same route passes once allowlisted", func(t *testing.T) {
		known := map[string]string{"POST /api/v1/this-endpoint-does-not-exist-anywhere": "synthetic fixture entry"}
		failures := findRouteCoverageViolations(routes, found, known, nil)
		if len(failures) != 0 {
			t.Fatalf("want 0 violations once allowlisted, got: %v", failures)
		}
	})

	t.Run("a stale allowlist entry that no longer reproduces fails loudly", func(t *testing.T) {
		known := map[string]string{
			"POST /api/v1/this-endpoint-does-not-exist-anywhere": "synthetic fixture entry",
			"POST /api/v1/widgets":                               "stale -- this route IS covered by `found` above",
		}
		failures := findRouteCoverageViolations(routes, found, known, nil)
		if len(failures) != 1 || !strings.Contains(failures[0], "no longer reproduces") {
			t.Fatalf("want exactly 1 stale-entry violation, got: %v", failures)
		}
	})

	t.Run("GET/non-mutating, non-secret routes are never checked at all", func(t *testing.T) {
		onlyGet := []userPathRouteEntry{{Method: "GET", Pattern: "/api/v1/widgets/{id}"}}
		failures := findRouteCoverageViolations(onlyGet, map[string]bool{}, map[string]string{}, nil)
		if len(failures) != 0 {
			t.Fatalf("want 0 -- a non-mutating, non-secret-disclosing route is out of scope, got: %v", failures)
		}
	})
}

// TestPlaywrightScanFiles_FollowsSpecImports pins the helper-import behavior
// against a synthetic web/e2e/real tree: a helper a spec imports is scanned
// (transitively), a helper nothing imports is not.
func TestPlaywrightScanFiles_FollowsSpecImports(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.spec.ts", "import { login } from './helpers';\n")
	write("helpers.ts", "import { post } from \"./deep.ts\";\nexport const x = 1;\n")
	write("deep.ts", "export const y = '/auth/login';\n")
	write("orphan.ts", "export const z = '/auth/orphan';\n")

	got := map[string]bool{}
	for _, f := range playwrightScanFiles(t, dir) {
		got[filepath.Base(f)] = true
	}
	for _, want := range []string{"a.spec.ts", "helpers.ts", "deep.ts"} {
		if !got[want] {
			t.Errorf("%s not scanned; got %v", want, got)
		}
	}
	if got["orphan.ts"] {
		t.Errorf("orphan.ts is imported by no spec and must not be credited; got %v", got)
	}
}
