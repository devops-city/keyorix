// role_grant_authority_guard_test.go — restores INV-1-grant-authority
// (docs/security-closures.tsv) after PR #2171 (ADR-108 Phase 6 step 14c-2)
// deleted TestEveryDirectRoleGrantChecksAuthority along with its entire
// target population: the guard only ever scanned /system proxy handlers for
// the #1578/#1582 shape, and that route group is gone. The bug class itself
// was never specific to /system proxies -- a handler that decodes a
// Role-shaped wire field and persists it via
// h.coreService.Storage().Create*/Update* without calling
// core.RequireAuthorityForRole/RequireGranterHoldsRolePermissions is the same
// shape wherever it occurs, and it was found three times independently
// (CreateInvitationProxy, CreateMembershipProxy, UpdateMembershipProxy). This
// file retargets the same detection logic at every handler method registered
// anywhere in router.go, using the same repo-wide, AST-derived route
// extractor raw_storage_bypass_guard_test.go's own repo-wide guard already
// relies on (extractAllRouterRoutes) -- not a hand-maintained list, so a
// router refactor can't shrink the population unnoticed (see
// minRoleGrantAuthorityPopulation below).
//
// Detection logic (roleFieldRe, directStorageWriteRe) is unchanged from the
// deleted file; only the population and the population-size tripwire are
// new.
package http

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// handlersDir is server/http/handlers, expressed the same way
// raw_storage_bypass_guard_test.go's buildHandlerStorageCallsIndex resolves
// it -- both this file's two handlerBodyText call sites need it.
var handlersDir = filepath.Join("..", "..", "server", "http", "handlers")

// roleFieldRe matches a Role-shaped wire field reference: `body.Role`,
// `.Role:` in a struct literal, `a.Role` in an assignments-loop variable
// (CreateInvitationProxy's per-assignment loop), or `SystemRole` (the
// substring match is deliberate — "SystemRole" is one identifier, not a
// separate word-bounded "Role", but is exactly the field
// RequireAuthorityForRole is also called for in CreateInvitationProxy).
var roleFieldRe = regexp.MustCompile(`\.Role\b|\bRole:|SystemRole`)

// directStorageWriteRe matches a direct, unmediated
// h.coreService.Storage().Create*/Update* call — the raw-storage-bypass
// shape, as opposed to routing through a core.KeyorixCore business-logic
// method (core.AssignUserRoleWithExpiry and similar never appear as
// `.Storage().Create`/`.Storage().Update` in a handler body).
var directStorageWriteRe = regexp.MustCompile(`\.Storage\(\)\.(Create|Update)[A-Za-z]*\(`)

// roleGrantShapeInBody reports whether body text both references a
// Role-shaped field and calls storage directly to persist it — the exact
// shape #1578/#1582 fixed. Split out from persistsRoleGrantDirectly (which
// reads a real handler's body off disk) so
// TestRoleGrantAuthorityDetectorCatchesSyntheticShapes can exercise the
// actual detection logic against a synthetic string, with no fixture file
// needed.
func roleGrantShapeInBody(body string) bool {
	return roleFieldRe.MatchString(body) && directStorageWriteRe.MatchString(body)
}

// persistsRoleGrantDirectly reports whether the named handler's body both
// references a Role-shaped field and calls storage directly to persist it.
func persistsRoleGrantDirectly(t *testing.T, handlerName string) bool {
	t.Helper()
	return roleGrantShapeInBody(roleGrantHandlerBody(t, handlerName))
}

// authorityCheckInBody reports whether body calls the escalation-by-proxy
// ceiling. FIX-1 deleted core.RequireAuthorityForRole (name-based: only
// fired for 4 canonical admin-tier role names) and replaced every caller
// with core.RequireGranterHoldsRolePermissions (derives the ceiling from the
// role's real bundled permissions); recognize both names so a handler still
// carrying the old symbol (pre-FIX-1) and one already migrated are equally
// detected as having a check. Confirmed 2026-09-27: only
// RequireGranterHoldsRolePermissions exists in internal/core today, but the
// second name costs nothing to keep recognizing.
func authorityCheckInBody(body string) bool {
	return strings.Contains(body, "RequireAuthorityForRole(") ||
		strings.Contains(body, "RequireGranterHoldsRolePermissions(")
}

// callsRequireAuthorityForRole reports whether the named handler's body
// calls the escalation-by-proxy ceiling anywhere (this guard does not check
// ordering relative to the storage write — a handler decoding, checking,
// THEN persisting is the only sane shape in practice, and ordering bugs are
// a different, more targeted review question than this guard's population
// check).
func callsRequireAuthorityForRole(t *testing.T, handlerName string) bool {
	t.Helper()
	return authorityCheckInBody(roleGrantHandlerBody(t, handlerName))
}

// roleGrantAuthorityAllowlist is the exhaustive, reasoned inventory of every
// handler this guard's scan flags as persisting a Role grant directly via
// storage WITHOUT calling RequireAuthorityForRole/
// RequireGranterHoldsRolePermissions, reviewed as safe for a stated reason
// (e.g. the Role field is never admin-tier by construction, or a different,
// equivalent ceiling already runs first). TestEveryDirectRoleGrantChecksAuthority
// fails if a flagged handler is missing from both this list and
// knownUnfixedRoleGrantAuthorityGaps, or if a listed entry stops
// reproducing.
var roleGrantAuthorityAllowlist = map[string]string{}

// knownUnfixedRoleGrantAuthorityGaps is the set of handlers confirmed, by
// individual review, to persist a Role grant directly with no authority
// check, not yet fixed. Grandfathered so this guard can go live immediately;
// each entry is a tracked gap, not a claim of safety.
var knownUnfixedRoleGrantAuthorityGaps = map[string]string{}

// minRoleGrantAuthorityPopulation is the same-shaped tripwire
// extractAllRouterRoutes already applies to the raw route count (there,
// 300): a router refactor that silently broke the AST walk, or a change
// that moved every handler out of router.go's recognized Route/Group/verb
// call shapes, would make this guard's population collapse to near-zero and
// pass vacuously -- exactly the "SURFACE REMOVED" failure mode that deleted
// this guard's predecessor. Router.go currently registers 350-380 routes
// resolving to well over 200 distinct handlers post-Phase-6; 50 is well
// below that with margin for further route deletions, not a tight bound.
const minRoleGrantAuthorityPopulation = 50

// TestEveryDirectRoleGrantChecksAuthority is the guard: for every handler
// registered anywhere in router.go that persists a Role-shaped field
// directly via storage, that handler must call RequireAuthorityForRole/
// RequireGranterHoldsRolePermissions, or have a reasoned entry in
// roleGrantAuthorityAllowlist or knownUnfixedRoleGrantAuthorityGaps.
// roleGrantHandlerBody resolves a router-registered handler's body. The shared
// handlerBodyText only matches methods (`func (h *T) Name(`); router.go also
// registers package-level functions (handlers.HealthCheck,
// handlers.UpdateAnomalyConfig, ...), which it returns "" for. An empty body
// would silently pass this guard, so this falls back to a package-level
// function match in the same directory.
func roleGrantHandlerBody(t *testing.T, handlerName string) string {
	t.Helper()
	if body := handlerBodyText(t, handlersDir, handlerName); strings.TrimSpace(body) != "" {
		return body
	}
	return packageFuncBodyText(t, handlersDir, handlerName)
}

// packageFuncBodyText is handlerBodyText's brace-depth capture for a
// receiver-less `func Name(` declaration.
func packageFuncBodyText(t *testing.T, dir, name string) string {
	t.Helper()
	funcRe := regexp.MustCompile(`^func ` + regexp.QuoteMeta(name) + `\(`)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out strings.Builder
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("reading %s: %v", n, err)
		}
		inFunc, depth, sawOpen := false, 0, false
		for line := range strings.SplitSeq(string(b), "\n") {
			if !inFunc && funcRe.MatchString(line) {
				inFunc, depth, sawOpen = true, 0, false
			}
			if inFunc {
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				if strings.Contains(line, "{") {
					sawOpen = true
				}
				out.WriteString(line)
				out.WriteByte('\n')
				if sawOpen && depth <= 0 {
					inFunc = false
				}
			}
		}
	}
	return out.String()
}

// roleGrantUnresolvableHandlers are router-registered handler names whose
// body is not in server/http/handlers at all, with the reason each can't
// carry the #1578/#1582 shape. Any OTHER unresolvable handler fails the guard
// rather than passing silently.
var roleGrantUnresolvableHandlers = map[string]string{
	"ServeHTTP": "customMiddleware.SchedulerMetricsHandler().ServeHTTP (GET /admin/scheduler-metrics): read-only metrics in server/http/middleware, no request body",
}

func TestEveryDirectRoleGrantChecksAuthority(t *testing.T) {
	routerPath := filepath.Join(".", "router.go")
	actual := extractAllRouterRoutes(t, routerPath)

	seenHandlers := map[string]bool{}
	var population []string
	for _, r := range actual {
		if r.Handler == "" || seenHandlers[r.Handler] {
			continue
		}
		seenHandlers[r.Handler] = true
		population = append(population, r.Handler)
	}
	if len(population) < minRoleGrantAuthorityPopulation {
		t.Fatalf("extracted only %d distinct handler(s) from router.go via extractAllRouterRoutes -- expected at "+
			"least %d; a router refactor may have silently broken this guard's population (see "+
			"minRoleGrantAuthorityPopulation's doc comment)", len(population), minRoleGrantAuthorityPopulation)
	}
	t.Logf("role-grant-authority guard: %d distinct handler(s) in population", len(population))

	var unresolved []string
	resolvedUnresolvable := map[string]bool{}
	for _, handler := range population {
		if strings.TrimSpace(roleGrantHandlerBody(t, handler)) != "" {
			continue
		}
		if _, ok := roleGrantUnresolvableHandlers[handler]; ok {
			resolvedUnresolvable[handler] = true
			continue
		}
		unresolved = append(unresolved, handler)
	}
	sort.Strings(unresolved)
	if len(unresolved) > 0 {
		t.Errorf("could not find the body of %d router-registered handler(s) in server/http/handlers: %v\n"+
			"An unresolved handler would pass this guard unchecked. Teach roleGrantHandlerBody where it lives, "+
			"or add a reasoned entry to roleGrantUnresolvableHandlers.", len(unresolved), unresolved)
	}
	for handler := range roleGrantUnresolvableHandlers {
		if !resolvedUnresolvable[handler] {
			t.Errorf("roleGrantUnresolvableHandlers entry %q is stale (now resolvable or no longer registered); remove it", handler)
		}
	}

	handlerFlagged := map[string]bool{}
	var flagged []string
	for _, handler := range population {
		if !persistsRoleGrantDirectly(t, handler) {
			continue
		}
		if callsRequireAuthorityForRole(t, handler) {
			continue
		}
		handlerFlagged[handler] = true
		_, safe := roleGrantAuthorityAllowlist[handler]
		_, unfixed := knownUnfixedRoleGrantAuthorityGaps[handler]
		if !safe && !unfixed {
			flagged = append(flagged, handler+" persists a Role-shaped field directly via storage with no "+
				"RequireAuthorityForRole/RequireGranterHoldsRolePermissions call")
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d handler(s) persisting a Role grant directly via storage with no authority check (the "+
			"#1578/#1582 shape): %v\nEither call h.coreService.RequireGranterHoldsRolePermissions(...) before "+
			"persisting, or add a reasoned entry to roleGrantAuthorityAllowlist (if genuinely safe) or "+
			"knownUnfixedRoleGrantAuthorityGaps (if it's a real, tracked, not-yet-fixed gap) in this file.",
			len(flagged), flagged)
	}

	checkStale := func(listName string, m map[string]string) {
		var stale []string
		for handler := range m {
			if !seenHandlers[handler] {
				stale = append(stale, handler+" (no longer registered anywhere in router.go)")
				continue
			}
			if !handlerFlagged[handler] {
				stale = append(stale, handler+" (no longer persists an unchecked Role grant)")
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s entr(y/ies) no longer reproduce: %v\nRemove the entry, or move it to the other list if "+
				"its status changed (e.g. a real gap just got fixed).", listName, stale)
		}
	}
	checkStale("roleGrantAuthorityAllowlist", roleGrantAuthorityAllowlist)
	checkStale("knownUnfixedRoleGrantAuthorityGaps", knownUnfixedRoleGrantAuthorityGaps)
}

// TestRoleGrantAuthorityDetectorCatchesSyntheticShapes is this guard's
// self-test, proving the detector can go both red and green: a synthetic
// handler body with the bad shape (Role field decoded off the wire,
// persisted directly via storage, no authority check) must be flagged, and
// the same shape with an authority check first (either recognized symbol)
// or without the direct-storage-write half must not be.
func TestRoleGrantAuthorityDetectorCatchesSyntheticShapes(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantFlagged bool
	}{
		{
			name: "bad shape: Role decoded from wire, persisted directly, no authority check",
			body: `func (h *Handler) CreateWidgetProxy(w http.ResponseWriter, r *http.Request) {
	var body createWidgetRequest
	json.NewDecoder(r.Body).Decode(&body)
	h.coreService.Storage().CreateWidget(r.Context(), &models.Widget{Role: body.Role})
}`,
			wantFlagged: true,
		},
		{
			name: "same shape, guarded by RequireAuthorityForRole first",
			body: `func (h *Handler) CreateWidgetProxy(w http.ResponseWriter, r *http.Request) {
	var body createWidgetRequest
	json.NewDecoder(r.Body).Decode(&body)
	if err := h.coreService.RequireAuthorityForRole(r.Context(), actorID(r), projectID, body.Role); err != nil {
		respondError(w, err)
		return
	}
	h.coreService.Storage().CreateWidget(r.Context(), &models.Widget{Role: body.Role})
}`,
			wantFlagged: false,
		},
		{
			name: "same shape, guarded by RequireGranterHoldsRolePermissions instead",
			body: `func (h *Handler) CreateWidgetProxy(w http.ResponseWriter, r *http.Request) {
	var body createWidgetRequest
	json.NewDecoder(r.Body).Decode(&body)
	if err := h.coreService.RequireGranterHoldsRolePermissions(r.Context(), actorID(r), body.RoleID, scope, false); err != nil {
		respondError(w, err)
		return
	}
	h.coreService.Storage().CreateWidget(r.Context(), &models.Widget{Role: body.Role})
}`,
			wantFlagged: false,
		},
		{
			name: "Role field present but no direct storage write -- routes through core instead",
			body: `func (h *Handler) AssignRoleProxy(w http.ResponseWriter, r *http.Request) {
	var body assignRoleRequest
	json.NewDecoder(r.Body).Decode(&body)
	core.AssignUserRoleWithExpiry(r.Context(), body.Role)
}`,
			wantFlagged: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shape := roleGrantShapeInBody(tc.body)
			flagged := shape && !authorityCheckInBody(tc.body)
			if flagged != tc.wantFlagged {
				t.Errorf("roleGrantShapeInBody=%v authorityCheckInBody=%v -> flagged=%v, want %v",
					shape, authorityCheckInBody(tc.body), flagged, tc.wantFlagged)
			}
		})
	}
}
