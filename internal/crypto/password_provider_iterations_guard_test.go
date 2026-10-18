// password_provider_iterations_guard_test.go is the machine-checked half of
// NewPasswordKeyProviderWithIterations's safety claim: that constructor exists so
// tests can skip the real 600,000-round PBKDF2 cost, and its doc comment promises no
// non-test file ever calls it with a weaker iteration count. A promise in a comment
// decays silently; this test computes the fact instead — an AST walk (not a
// string/regex match, so it isn't fooled by the call appearing in a comment or a
// string literal) over every non-_test.go file in the repo, repo-wide (not just
// internal/crypto or internal/encryption), since any package could import crypto and
// call it. Same style as internal/cli/writeguard/write_guard_test.go and
// internal/dynamic/egress_guard_test.go.
package crypto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"

	"github.com/stretchr/testify/require"
)

// guardedFnName is the constructor this guard forbids outside _test.go files.
const guardedFnName = "NewPasswordKeyProviderWithIterations"

// skipDirNames are directories this walk never descends into: VCS metadata, this
// session's own scratch/build-throwaway output, vendored/third-party trees, and test
// fixture directories (testdata is explicitly allowed to contain example/fixture Go
// source that isn't itself compiled into the module).
var skipDirNames = map[string]bool{
	".git":              true,
	".scratch":          true,
	".claude-worktrees": true,
	"vendor":            true,
	"node_modules":      true,
	"testdata":          true,
}

// repoRoot resolves the repository root relative to this test file's own location
// (not the process cwd), so the sweep works regardless of how `go test` is invoked.
// This file lives at internal/crypto/password_provider_iterations_guard_test.go.
func repoRoot(t *testing.T) string {
	t.Helper()
	thisFile := filepath.Join(srcpath.PkgDir(), "password_provider_iterations_guard_test.go")
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	require.NoError(t, err)
	return root
}

type guardedCallSite struct {
	relPath string
	line    int
}

// scanFileForGuardedCalls parses a single .go file and returns every call site that
// invokes a function/method named guardedFnName — matches both a bare call
// (NewPasswordKeyProviderWithIterations(...), from within package crypto itself) and a
// qualified call (crypto.NewPasswordKeyProviderWithIterations(...), from any importer).
func scanFileForGuardedCalls(fset *token.FileSet, path string) ([]guardedCallSite, error) {
	src, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path built from filepath.Walk below, not external input
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []guardedCallSite
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		default:
			return true
		}
		if name != guardedFnName {
			return true
		}
		pos := fset.Position(call.Pos())
		sites = append(sites, guardedCallSite{relPath: path, line: pos.Line})
		return true
	})
	return sites, nil
}

// findAllGuardedCalls walks the entire repo (from repoRoot), scanning every
// non-_test.go .go file for a call to guardedFnName.
func findAllGuardedCalls(t *testing.T, repo string) []guardedCallSite {
	t.Helper()
	fset := token.NewFileSet()
	var found []guardedCallSite
	err := filepath.Walk(repo, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirNames[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		sites, serr := scanFileForGuardedCalls(fset, path)
		if serr != nil {
			return serr
		}
		for _, s := range sites {
			relPath, rerr := filepath.Rel(repo, s.relPath)
			require.NoError(t, rerr)
			s.relPath = filepath.ToSlash(relPath)
			found = append(found, s)
		}
		return nil
	})
	require.NoError(t, err, "walking %s must not fail", repo)
	return found
}

// TestNewPasswordKeyProviderWithIterations_NoProductionCallers is the guard: zero
// non-_test.go files anywhere in the repo may call NewPasswordKeyProviderWithIterations
// — production always goes through NewPasswordKeyProvider (iterations left at its zero
// value, which KEK() resolves to PBKDF2Iterations), so a real deployment can never end
// up with a weaker-than-600000 KEK derivation. A future call site that plumbs an
// iteration count through from config (or anywhere else reachable outside a test
// binary) trips this the same way the write-guard and egress-guard sweeps trip on a
// forgotten sibling call site.
func TestNewPasswordKeyProviderWithIterations_NoProductionCallers(t *testing.T) {
	found := findAllGuardedCalls(t, repoRoot(t))
	if len(found) != 0 {
		var locs []string
		for _, s := range found {
			locs = append(locs, s.relPath+":"+strconv.Itoa(s.line))
		}
		t.Fatalf("%s must only ever be called from a _test.go file — found non-test caller(s): %v",
			guardedFnName, locs)
	}
}

// TestNewPasswordKeyProviderWithIterations_GuardSeesTestCallers is the flip side: the
// scan itself must actually find calls when they exist, proved against the real test
// suite rather than only against synthetic red/green fixtures. If this goes to 0, the
// guard above would pass unconditionally regardless of whether a production call site
// existed — a vacuous guard is worse than none (CLAUDE.md: "a check that always
// passes... teaches people to ignore it").
func TestNewPasswordKeyProviderWithIterations_GuardSeesTestCallers(t *testing.T) {
	fset := token.NewFileSet()
	found := 0
	repo := repoRoot(t)
	root := filepath.Join(repo, "internal", "encryption")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		sites, serr := scanFileForGuardedCalls(fset, path)
		if serr != nil {
			return serr
		}
		found += len(sites)
		return nil
	})
	require.NoError(t, err)
	if found == 0 {
		t.Fatal("expected at least one _test.go caller of " + guardedFnName +
			" under internal/encryption — if this legitimately dropped to 0, the guard " +
			"above is no longer checking anything real; fix the scan or this assertion, " +
			"not the other way around")
	}
}
