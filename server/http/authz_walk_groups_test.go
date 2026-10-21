// authz_walk_groups_test.go — the route walks run as awRouteGroups top-level tests
// each (CI-HTTP-SPLIT-1).
//
// # Why
//
// TestEveryRouteRefusesADeadCredential and TestEveryWriteRouteRefusesAndChangesNothing
// walked the whole router in one test each, ~20 and ~18 min in CI. The test-suite
// matrix shards server/http by top-level test name (scripts/ci-test-legs.sh,
// weighted_run_filter), so one test is one leg's floor. Each walk is now
// <Walk>_G0 .. <Walk>_G<awRouteGroups-1>, test k walking only the routes with
// awRouteGroup(route) == k on a world of its own; the legs then spread them.
//
// # Exactly once
//
// awRouteGroup is a pure function of "METHOD /path" with a value in
// [0, awRouteGroups), so every route is in exactly one group and a route added
// tomorrow lands in one without anybody listing it. TestAWRouteGroups_PartitionTheRouter
// proves that on the real router with the same function the walks use (the union
// of the groups is the route list, no route twice, no empty group), and proves
// from the source (go/ast) that each walk has exactly one test per group, each
// calling its walk with its own group number: a missing, duplicated or
// mis-numbered _Gk test fails there, not silently in coverage.
//
// What stays whole-router: the write walk's allowlist hygiene, the multipart /
// websocket shape check and the admin positive control
// (TestEveryWriteRouteRefusesAndChangesNothing_Control), and the "> 300 routes"
// sanity floor (the partition test). Not covered by the proof: the order routes
// are visited in within a group (a route now runs after a different predecessor
// than before; both walks require every request to change nothing, so order
// carries no state they rely on).
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"hash/fnv"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// awRouteGroups is how many top-level tests each route walk is split into.
// Changing it needs that many _Gk tests per walk (the partition test says which).
const awRouteGroups = 4

// awRouteGroup is the group of a route: FNV-1a of its key, mod awRouteGroups.
// Stable: adding or removing a route never moves another one.
func awRouteGroup(rt awRoute) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(rt.key()))
	return int(h.Sum32() % awRouteGroups)
}

// awRoutesOfGroup keeps the routes of group g, in their original order.
func awRoutesOfGroup(routes []awRoute, g int) []awRoute {
	var out []awRoute
	for _, rt := range routes {
		if awRouteGroup(rt) == g {
			out = append(out, rt)
		}
	}
	return out
}

// awKnownOpenRoute is the route key of an awKnownOpen entry ("persona METHOD /path").
func awKnownOpenRoute(entry string) string {
	_, route, _ := strings.Cut(entry, " ")
	return route
}

// awGroupedWalks: each split walk, by test-name prefix, with the file declaring
// its _Gk tests and the helper they call.
var awGroupedWalks = []struct{ prefix, file, helper string }{
	{"TestEveryRouteRefusesADeadCredential", "dead_credentials_walk_test.go", "awDeadWalkGroup"},
	{"TestEveryWriteRouteRefusesAndChangesNothing", "write_routes_deny_walk_test.go", "awWriteWalkGroup"},
}

func TestAWRouteGroups_PartitionTheRouter(t *testing.T) {
	w := newSVWorld(t, "sqlite", 1)
	routes := awWalkRoutes(t, w.a.router)
	require.Greater(t, len(routes), 300, "sanity: the walk should find the whole router")

	var mutating []awRoute
	for _, rt := range routes {
		if awIsMutating(rt.Method) {
			if _, public := awPublicRoutes[rt.key()]; !public {
				mutating = append(mutating, rt)
			}
		}
	}
	require.Greater(t, len(mutating), 150, "sanity: the walk should find the whole mutating surface")

	// The populations each walk splits: the dead walk takes every route, the write
	// walk the non-public mutating ones. Union of the groups == the population,
	// each route exactly once, and no group empty.
	for name, pop := range map[string][]awRoute{"all routes (dead walk)": routes, "mutating routes (write walk)": mutating} {
		count := map[string]int{}
		for g := range awRouteGroups {
			grp := awRoutesOfGroup(pop, g)
			assert.NotEmpty(t, grp, "%s: group %d is empty", name, g)
			t.Logf("%s: group %d has %d of %d routes", name, g, len(grp), len(pop))
			for _, rt := range grp {
				count[rt.key()]++
			}
		}
		for _, rt := range pop {
			g := awRouteGroup(rt)
			assert.True(t, g >= 0 && g < awRouteGroups, "%s: %s has group %d", name, rt.key(), g)
			assert.Equal(t, 1, count[rt.key()], "%s: %s must be walked by exactly one group", name, rt.key())
			delete(count, rt.key())
		}
		assert.Empty(t, count, "%s: groups walked routes that are not in the router", name)
	}

	// Each walk has exactly one top-level test per group, Prefix_Gk, whose whole
	// body is helper(t, k), and nothing else in the package calls the helper.
	re := regexp.MustCompile(`^(.*)_G([0-9]+)$`)
	files, err := filepath.Glob("*_test.go")
	require.NoError(t, err)
	calls := map[string]int{}
	for _, file := range files {
		f, perr := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		require.NoError(t, perr)
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok {
					calls[id.Name]++
				}
			}
			return true
		})
	}
	for _, gw := range awGroupedWalks {
		assert.Equal(t, awRouteGroups, calls[gw.helper],
			"%s must be called exactly once per group, from the %s_Gk tests only", gw.helper, gw.prefix)
		f, err := parser.ParseFile(token.NewFileSet(), gw.file, nil, 0)
		require.NoError(t, err)
		var got []int
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			m := re.FindStringSubmatch(fd.Name.Name)
			if m == nil || m[1] != gw.prefix {
				continue
			}
			k, _ := strconv.Atoi(m[2])
			got = append(got, k)
			assert.Equal(t, strconv.Itoa(k), awSoleCallGroupArg(fd, gw.helper),
				"%s must consist of exactly `%s(t, %d)`", fd.Name.Name, gw.helper, k)
		}
		slices.Sort(got)
		want := make([]int, awRouteGroups)
		for k := range want {
			want[k] = k
		}
		assert.Equal(t, want, got, "%s: want exactly one %s_Gk test for each k in [0, %d)", gw.file, gw.prefix, awRouteGroups)
	}
}

// awSoleCallGroupArg returns the literal second argument of fd's body when that
// body is exactly one call `helper(t, <int literal>)`, else "".
func awSoleCallGroupArg(fd *ast.FuncDecl, helper string) string {
	if fd.Body == nil || len(fd.Body.List) != 1 {
		return ""
	}
	es, ok := fd.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return ""
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return ""
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != helper {
		return ""
	}
	if id, ok := call.Args[0].(*ast.Ident); !ok || id.Name != "t" {
		return ""
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return ""
	}
	return lit.Value
}
