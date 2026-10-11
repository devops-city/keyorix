// secret_metadata_cache_generation_test.go — the read-path metadata cache's
// generation signals must change whenever ANY column of the cached value
// changes. Each test here corresponds to a writer that an earlier revision's
// timestamp-only generation did NOT cover, and each was red before the
// generation it exercises was derived from the cached columns instead of from
// updated_at alone (see secret_metadata_cache.go's header for the two live CI
// failures that produced these).
//
// TestSecretCacheGeneration_CoversEveryUpdateColumnWriter is the machine-check
// that keeps this list complete: a NEW hook-bypassing write to either cached
// table fails it rather than silently joining the uncovered set.
package store

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestGetSecret_NodeReadCountIncrementInvalidatesCache is the storage-layer
// form of the #133 max-reads defect that TestMaxReads_SurvivesRotateAndRollback
// caught end to end: TryIncrementSecretNodeReadCount writes read_count with
// UpdateColumn, which bypasses GORM's auto-timestamp callback, so updated_at
// does not move. A generation that is updated_at alone keeps matching, the
// warm entry keeps serving read_count=0, and RotateSecret's GetSecret →
// mutate → Save round-trip writes that stale zero back — a fresh read budget
// for a burn-after-N-reads secret.
func TestGetSecret_NodeReadCountIncrementInvalidatesCache(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	maxReads := 5
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, MaxReads: &maxReads,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	warm, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 0, warm.ReadCount)

	ok, err := ls.TryIncrementSecretNodeReadCount(ctx, created.ID, maxReads)
	require.NoError(t, err)
	require.True(t, ok)

	after, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 1, after.ReadCount,
		"the cache served a stale read_count: a read-modify-write caller would write this zero back and reset the max-reads budget")
}

// TestGetLatestSecretVersion_NewVersionWithoutNodeTouchInvalidatesCache pins
// why the version cache's generation is derived from the version rows and not
// from secret_nodes.updated_at. storeNextSecretVersion (RotateSecret's path)
// writes a version with NO transactional node write beside it — deliberately,
// see its own doc comment — and then re-reads the latest version in a retry
// loop. A node-timestamp generation makes that loop re-read its own stale
// cached answer, recompute the same next version_number, and exhaust all 20
// attempts against the unique index.
func TestGetLatestSecretVersion_NewVersionWithoutNodeTouchInvalidatesCache(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)

	v1, err := ls.GetLatestSecretVersion(ctx, created.ID) // warm
	require.NoError(t, err)
	require.Equal(t, 1, v1.VersionNumber)

	// A version write and NOTHING else — no UpdateSecret, no node touch at all.
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 2, CreatedAt: time.Now()})
	require.NoError(t, err)

	v2, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 2, v2.VersionNumber,
		"the cache served the pre-rotation version: the generation must come from the version rows, not from a node timestamp no version writer touches")
}

// TestGetLatestSecretVersion_VersionReadCountIncrementInvalidatesCache covers
// the sum(read_count) term: the cached version row exposes ReadCount (gRPC
// SecretService.ListVersions, cli/cmd/secret_versions.go), and
// TryIncrementSecretReadCount writes it with UpdateColumn — another
// hook-bypassing write that moves no timestamp on any table.
func TestGetLatestSecretVersion_VersionReadCountIncrementInvalidatesCache(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	v, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)

	warm, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 0, warm.ReadCount)

	ok, err := ls.TryIncrementSecretReadCount(ctx, v.ID, 5)
	require.NoError(t, err)
	require.True(t, ok)

	after, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 1, after.ReadCount, "the cache served a stale per-version read_count")
}

// TestGetLatestSecretVersion_NoVersionIsCachedUnderTheZeroGeneration pins the
// cached-negative case the aggregate generation makes possible: a secret with
// no versions aggregates to the zero generation, which is a perfectly valid
// stamp, and the first version create moves it off zero.
func TestGetLatestSecretVersion_NoVersionIsCachedUnderTheZeroGeneration(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)

	_, err = ls.GetLatestSecretVersion(ctx, created.ID)
	require.Error(t, err, "no versions yet")
	cached, ok := ls.secretMetaCache.getVersion(created.ID)
	require.True(t, ok, "the no-version answer is cacheable: the zero aggregate is a real generation")
	require.Nil(t, cached.latestVersion)

	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)

	got, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err, "the cached negative must not outlive the first version")
	require.Equal(t, 1, got.VersionNumber)
}

// ── the completeness machine-check ─────────────────────────────────────────

// cachedTableGenerationColumns names, per cached table, the columns a write
// may change while the read-path cache stays correct — because each is either
// read into that table's generation signal or is the signal itself. Every
// OTHER column of those tables is still fine to write: GORM's auto-timestamp
// callback advances updated_at for Save/Update/Updates, which IS the node
// signal. The only writes this test polices are the ones that bypass that
// callback — UpdateColumn/UpdateColumns — because those can change a cached
// column while leaving every timestamp alone.
//
// secret_versions has no timestamp at all, so for that table the whole
// aggregate (count, max(version_number), sum(read_count)) is the signal and
// read_count is the only column a hook-bypassing write may touch.
var cachedTableGenerationColumns = map[string]map[string]string{
	"SecretNode": {
		"updated_at": "the node generation's first term (secret_metadata_cache.go, nodeGeneration.updatedAt)",
		"read_count": "the node generation's second term — added precisely because this column's only writer is an UpdateColumn (#133 max-reads)",
	},
	"SecretVersion": {
		"read_count": "covered by the version generation's sum(read_count) term (liveVersionsGeneration)",
	},
}

// TestSecretCacheGeneration_CoversEveryUpdateColumnWriter fails when a
// hook-bypassing write (UpdateColumn/UpdateColumns) in this package targets a
// cached table with a column that no generation signal observes. Such a write
// changes a cached value without changing its stamp, so a warm entry keeps
// serving the pre-write value until something unrelated moves the stamp —
// GUARD-6's whole bug class.
//
// What this recognises, stated explicitly because an enumeration is only as
// complete as the idioms it knows about (CLAUDE.md): a method-call chain in a
// non-test file of this package containing BOTH a `Model(&models.X{})` call
// and an `UpdateColumn`/`UpdateColumns` call, where the updated columns are
// string literals (UpdateColumn's first argument, or the keys of
// UpdateColumns' map literal). What it does NOT recognise, and says so:
// raw `db.Exec` SQL strings (same stated boundary as INV-STORE-18's scanner),
// a chain whose model comes from a variable rather than a composite literal,
// a non-literal column name, and anything outside package store — including
// internal/encryption/sweep.go's DEK rewrap, which is named as a documented
// stopped-server exception in secret_metadata_cache.go's header instead.
func TestSecretCacheGeneration_CoversEveryUpdateColumnWriter(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	var violations []string
	recognised := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments)
		require.NoError(t, perr)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "UpdateColumn" && sel.Sel.Name != "UpdateColumns") {
				return true
			}
			model := modelOfChain(sel.X)
			cols, ok := cachedTableGenerationColumns[model]
			if !ok {
				return true // not a cached table (or the model isn't a literal we recognise)
			}
			recognised++
			for _, col := range updatedColumnNames(call) {
				if _, covered := cols[col]; !covered {
					violations = append(violations, fmt.Sprintf(
						"%s: %s writes %s.%s, which no generation signal observes — a warm cache entry would keep serving the pre-write value. Either include this column in that table's generation (secret_metadata_cache.go) or use Update/Updates so GORM's auto-timestamp callback advances updated_at.",
						fset.Position(call.Pos()), sel.Sel.Name, model, col))
				}
			}
			return true
		})
	}

	sort.Strings(violations)
	require.Empty(t, violations, "uncovered hook-bypassing write to a cached table:\n%s", strings.Join(violations, "\n"))
	// Calibration: a scanner that recognises nothing passes vacuously. The four
	// writes it must see today are CreateSecretVersion's (none, since the node
	// bump was reverted), IncrementSecretReadCount, TryIncrementSecretReadCount
	// and TryIncrementSecretNodeReadCount — three. If this count drops to zero
	// the scanner has stopped recognising the idiom, not the code stopped using
	// it.
	require.GreaterOrEqual(t, recognised, 3,
		"the scanner recognised only %d hook-bypassing writes to a cached table; it recognised 3 when written, so it has stopped matching the idiom rather than the code having stopped using it", recognised)
}

// modelOfChain walks back down a GORM method-call chain looking for
// Model(&models.X{}) and returns "X", or "" when the chain has no such call
// with a composite-literal argument.
func modelOfChain(expr ast.Expr) string {
	for {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if sel.Sel.Name == "Model" && len(call.Args) == 1 {
			if name := modelLiteralName(call.Args[0]); name != "" {
				return name
			}
		}
		expr = sel.X
	}
}

// modelLiteralName extracts "SecretNode" from `&models.SecretNode{}`.
func modelLiteralName(arg ast.Expr) string {
	unary, ok := arg.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return ""
	}
	lit, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return sel.Sel.Name
}

// updatedColumnNames returns the literal column names an
// UpdateColumn/UpdateColumns call writes. A non-literal name yields the
// sentinel "<non-literal>", which is deliberately NOT in any coverage map and
// therefore reported — an unreadable column name is an unproven one.
func updatedColumnNames(call *ast.CallExpr) []string {
	if len(call.Args) == 0 {
		return nil
	}
	if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return []string{s}
		}
		return []string{"<non-literal>"}
	}
	composite, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return []string{"<non-literal>"}
	}
	var out []string
	for _, elt := range composite.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			out = append(out, "<non-literal>")
			continue
		}
		lit, ok := kv.Key.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			out = append(out, "<non-literal>")
			continue
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			out = append(out, "<non-literal>")
			continue
		}
		out = append(out, s)
	}
	return out
}
