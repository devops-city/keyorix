// route_inventory_test.go generates scripts/e2e/routes.json, the full REST route
// inventory SESSION-I's fresh-install smoke driver (scripts/e2e) consumes to know every
// route it must either exercise or explicitly skip-with-reason.
//
// Deliberately reuses the exact same AST-walk primitives permission_sweep_test.go
// already validated against server/http/router.go (evalPathExpr, joinRoutePath,
// resolveTopLevelConsts, findNewRouterFunc, chiRouteRegistrationMethods,
// routeMethodLabel, collectWithArgs, extractGateCall) rather than hand-listing routes
// from router.go's source or re-deriving path resolution from scratch — a second,
// independently-written route resolver would drift from the first the moment router.go
// gains a new r.Route nesting shape or named path const, exactly the failure mode
// permission_sweep_test.go's own header comment (line-number keys silently pointing at
// the wrong route after an unrelated edit) already documents. This file does NOT modify
// permission_sweep_test.go, walkRouterBlock, or walkRouterExpr — it is a parallel walk
// (walkRouterBlockInventory/walkRouterExprInventory below) built from the same
// unexported low-level helpers, because those two functions are wired to only ever
// RECORD a route when it lacks a permission gate (ungated) — the inventory needs every
// route, gated or not.
//
// TestRouteInventoryIsCurrent is the "derive and check it" half (see CLAUDE.md's core
// engineering principle): it recomputes the inventory from router.go's live AST on every
// run and fails loudly if scripts/e2e/routes.json does not match byte-for-byte, so a
// route added/removed/regated in router.go without regenerating the committed file is a
// CI failure, not a silent drift. Regenerate with:
//
//	REGEN_ROUTE_INVENTORY=1 go test ./server/http/ -run TestRouteInventoryIsCurrent -v
package http

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// routeInventoryEntry is one route-registration call site in router.go's NewRouter,
// recorded regardless of gating status (unlike ungatedRoute, which only exists for
// ungated call sites).
type routeInventoryEntry struct {
	Method       string   `json:"method"`
	Pattern      string   `json:"pattern"`
	FeatureGroup string   `json:"feature_group"`
	Gated        bool     `json:"gated"`
	GateFns      []string `json:"gate_fns,omitempty"`
	GatePerms    []string `json:"gate_perms,omitempty"`
	Line         int      `json:"router_go_line"`
}

func (e routeInventoryEntry) key() string { return e.Method + " " + e.Pattern }

// routeInventoryFeatureGroup derives a human-scale feature grouping from a fully
// resolved mounted path: the first path segment after a recognized top-level mount
// (/api/v1, /scim/v2), or "root" for anything registered outside both (health/status/
// metrics/swagger/version — the pre-auth, pre-API-group routes).
func routeInventoryFeatureGroup(pattern string) string {
	trimmed := strings.TrimPrefix(pattern, "/")
	switch {
	case strings.HasPrefix(trimmed, "api/v1/"):
		trimmed = strings.TrimPrefix(trimmed, "api/v1/")
	case strings.HasPrefix(trimmed, "scim/v2"):
		return "scim"
	default:
		return "root"
	}
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return "root"
	}
	seg, _, _ := strings.Cut(trimmed, "/")
	if seg == "" {
		return "root"
	}
	return seg
}

// walkRouterBlockInventory mirrors walkRouterBlock's traversal exactly (same r.Use(...)
// group-gate detection, same recursion into if/else blocks) but records EVERY
// route-registration call it finds into out, not just ungated ones.
func walkRouterBlockInventory(t *testing.T, fset *token.FileSet, consts map[string]string, stmts []ast.Stmt, prefix string, inherited bool, inheritedFns, inheritedPerms []string, out map[string]routeInventoryEntry) {
	t.Helper()
	blockGated := inherited
	fns := append([]string{}, inheritedFns...)
	perms := append([]string{}, inheritedPerms...)

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
			fns = append(fns, gc.fn)
			if gc.perm != "" {
				perms = append(perms, gc.perm)
			}
		}
	}

	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			walkRouterExprInventory(t, fset, consts, s.X, prefix, blockGated, fns, perms, out)
		case *ast.IfStmt:
			if s.Body != nil {
				walkRouterBlockInventory(t, fset, consts, s.Body.List, prefix, blockGated, fns, perms, out)
			}
			if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
				walkRouterBlockInventory(t, fset, consts, elseBlock.List, prefix, blockGated, fns, perms, out)
			}
		}
	}
}

// walkRouterExprInventory mirrors walkRouterExpr's Route/Group recursion and direct
// .With(...) gate resolution, but always records the route (gated or not) rather than
// only recording it when ungated.
func walkRouterExprInventory(t *testing.T, fset *token.FileSet, consts map[string]string, expr ast.Expr, prefix string, blockGated bool, inheritedFns, inheritedPerms []string, out map[string]routeInventoryEntry) {
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
				t.Fatalf("router.go:%d: r.Route(...) prefix %q is not a literal/const-resolvable string",
					fset.Position(call.Pos()).Line, exprSourceText(fset, call.Args[0]))
			}
			if fn, ok := call.Args[1].(*ast.FuncLit); ok && fn.Body != nil {
				walkRouterBlockInventory(t, fset, consts, fn.Body.List, joinRoutePath(prefix, seg), blockGated, inheritedFns, inheritedPerms, out)
			}
		}
		return
	case "Group":
		if len(call.Args) >= 1 {
			if fn, ok := call.Args[0].(*ast.FuncLit); ok && fn.Body != nil {
				walkRouterBlockInventory(t, fset, consts, fn.Body.List, prefix, blockGated, inheritedFns, inheritedPerms, out)
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
		t.Fatalf("router.go:%d: route pattern %q for %s(...) is not a literal/const-resolvable string",
			fset.Position(call.Pos()).Line, exprSourceText(fset, call.Args[0]), sel.Sel.Name)
	}
	fullPath := joinRoutePath(prefix, seg)
	method := routeMethodLabel(sel.Sel.Name)

	fns := append([]string{}, inheritedFns...)
	perms := append([]string{}, inheritedPerms...)
	gated := blockGated
	withArgs, _ := collectWithArgs(sel.X)
	for _, arg := range withArgs {
		gc, ok := extractGateCall(arg)
		if !ok {
			continue
		}
		gated = true
		fns = append(fns, gc.fn)
		if gc.perm != "" {
			perms = append(perms, gc.perm)
		}
	}

	fns = dedupSortedStrings(fns)
	perms = dedupSortedStrings(perms)

	pos := fset.Position(call.Pos())
	entry := routeInventoryEntry{
		Method:       method,
		Pattern:      fullPath,
		FeatureGroup: routeInventoryFeatureGroup(fullPath),
		Gated:        gated,
		GateFns:      fns,
		GatePerms:    perms,
		Line:         pos.Line,
	}
	out[entry.key()] = entry
}

func dedupSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// buildRouteInventory parses routerGoPath's AST and walks NewRouter once, resolving
// every route-registration call to a routeInventoryEntry.
func buildRouteInventory(t *testing.T, routerGoPath string) []routeInventoryEntry {
	t.Helper()
	src, err := os.ReadFile(routerGoPath) // #nosec G304 -- fixed repo-internal path, not external input
	require.NoError(t, err)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, routerGoPath, src, 0)
	require.NoError(t, err)

	consts := resolveTopLevelConsts(f)
	newRouter := findNewRouterFunc(f)
	require.NotNil(t, newRouter, "server/http/router.go must declare func NewRouter(...)")

	out := map[string]routeInventoryEntry{}
	walkRouterBlockInventory(t, fset, consts, newRouter.Body.List, "", false, nil, nil, out)

	entries := make([]routeInventoryEntry, 0, len(out))
	for _, e := range out {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Pattern != entries[j].Pattern {
			return entries[i].Pattern < entries[j].Pattern
		}
		return entries[i].Method < entries[j].Method
	})
	return entries
}

func routeInventoryJSON(entries []routeInventoryEntry) []byte {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		panic(err) // marshaling a plain struct slice cannot fail
	}
	return append(b, '\n')
}

// TestRouteInventoryIsCurrent recomputes scripts/e2e/routes.json's content from
// router.go's live AST and fails if the committed file does not match byte-for-byte —
// the "derive and check it" half of the mechanism (see CLAUDE.md's core engineering
// principle). A route added, removed, or re-gated in router.go without regenerating the
// committed inventory is a loud CI failure here, not a silently stale fixture the e2e
// smoke driver trusts without checking.
//
// Regenerate with: REGEN_ROUTE_INVENTORY=1 go test ./server/http/ -run TestRouteInventoryIsCurrent -v
func TestRouteInventoryIsCurrent(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	routerGoPath := filepath.Join(root, "server", "http", "router.go")
	entries := buildRouteInventory(t, routerGoPath)
	if len(entries) == 0 {
		t.Fatal("found 0 route-registration call sites in NewRouter — the inventory walk is vacuous, fix the scan not this assertion")
	}
	want := routeInventoryJSON(entries)

	outPath := filepath.Join(root, "scripts", "e2e", "routes.json")

	if os.Getenv("REGEN_ROUTE_INVENTORY") == "1" {
		require.NoError(t, os.WriteFile(outPath, want, 0o600))
		t.Logf("wrote %d routes to %s", len(entries), outPath)
		return
	}

	got, err := os.ReadFile(outPath) // #nosec G304 -- fixed repo-internal path
	require.NoError(t, err, "scripts/e2e/routes.json does not exist -- generate it with "+
		"REGEN_ROUTE_INVENTORY=1 go test ./server/http/ -run TestRouteInventoryIsCurrent -v")
	require.Equal(t, string(want), string(got),
		"scripts/e2e/routes.json is stale relative to server/http/router.go's live route "+
			"set -- regenerate with REGEN_ROUTE_INVENTORY=1 go test ./server/http/ -run "+
			"TestRouteInventoryIsCurrent -v and commit the result")
}
