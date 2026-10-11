// mfa_stepup_purpose_guard_test.go — regression guard for the confused-deputy
// MFA step-up bypass fixed alongside this file (models.MFAStepUpGrant gained
// an explicit Purpose field; every CURRENT consumption site now requires an
// exact purpose match rather than accepting any live grant). Nothing
// structurally stops a FUTURE consumption site from repeating the exact
// mistake: calling the grant-lookup primitive and accepting whatever comes
// back without pinning down which purpose is actually required for that
// action -- that purpose-agnostic acceptance is precisely how the original
// bug arose.
//
// This is an AST sweep (go/parser, not string/regex matching) over every
// non-test *.go file in the repository for a call to HasActiveMFAStepUp,
// GetActiveMFAStepUpGrant, or ConsumeMFAStepUpGrant -- the functions that turn
// a stored grant row into an authorization decision (see
// internal/core/mfa_stepup.go and internal/core/storage/interface.go). All
// three share the same argument shape (ctx, userID, purpose, ...), so the
// purpose argument is always the third (index 2).
//
// Every call site found must be in mfaStepUpPurposeAllowlist below with a
// written justification, matching the house convention (see
// internal/cli/writeguard/write_guard_test.go,
// internal/core/g80_1530_machine_actor_attribution_guard_test.go). A call
// site is safe when its purpose argument is a HARDCODED
// models.MFAStepUpPurpose* constant matching the allowlist's recorded
// expectation for that exact site -- not a variable, not a struct field, not
// merely non-empty. A site whose purpose argument cannot be resolved to a
// literal constant must say so explicitly in its allowlist entry (expected =
// "") with a reason establishing it is not itself an authorization decision
// (e.g. a storage-layer passthrough forwarding a value some OTHER,
// separately-guarded call site already decided).
//
// This guard's own effectiveness was verified red-then-green: temporarily
// changing internal/core/mfa.go's requireReauth call from
// models.MFAStepUpPurposeReauth to models.MFAStepUpPurposeRestrictedSecretRead
// (recreating the confused-deputy shape -- accepting the ambient
// login-minted grant for an account-security-factor change) made
// TestMFAStepUpConsumersUseExpectedPurpose fail with exactly that mismatch;
// restoring the constant made it pass again.
package core

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
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

// mfaStepUpGuardedFuncs is the set of functions this sweep treats as turning
// a stored MFAStepUpGrant into an authorization decision. All three take
// (ctx, userID, purpose, ...) -- the purpose argument is always at index 2.
// ConsumeMFAStepUpGrant (added alongside requireReauth's single-use fix, a
// follow-up to #1775) is the atomic-consume sibling of GetActiveMFAStepUpGrant
// / HasActiveMFAStepUp -- it makes exactly the same purpose-confusion mistake
// possible if a future call site passed the wrong purpose constant, so it must
// be swept identically.
var mfaStepUpGuardedFuncs = map[string]bool{
	"HasActiveMFAStepUp":      true,
	"GetActiveMFAStepUpGrant": true,
	"ConsumeMFAStepUpGrant":   true,
}

// mfaPurposeArgIndex is the zero-based index of the purpose argument shared
// by both guarded functions' signatures.
const mfaPurposeArgIndex = 2

// mfaStepUpAllowEntry records, for one call site (keyed in
// mfaStepUpPurposeAllowlist by mfaStepUpSite.key(): repo-relative path,
// enclosing function, callee expression, and an ordinal for repeats -- never a
// line number), the purpose constant that call site is expected to hardcode --
// or "" when the site intentionally does not pass a literal, with reason
// explaining why that's still safe.
type mfaStepUpAllowEntry struct {
	expectedPurpose string // e.g. "MFAStepUpPurposeReauth"; "" means intentionally non-literal
	reason          string
}

// mfaStepUpPurposeAllowlist is the exhaustive, reasoned inventory of every
// call to HasActiveMFAStepUp/GetActiveMFAStepUpGrant/ConsumeMFAStepUpGrant in
// the repository. A call site missing from this list, or one whose purpose
// argument no longer matches its recorded expectedPurpose, fails
// TestMFAStepUpConsumersUseExpectedPurpose -- exactly the shape a future
// "accept any live grant" regression would take.
//
// Key format (see mfaStepUpSite.key): "<relpath>:<enclosing func>:<callee>",
// with "#2", "#3", ... appended to the second, third, ... call to the same
// callee expression inside the same function (source order). Keys used to be
// "<relpath>:<line>", which broke on every unrelated edit above a listed site
// and made every such PR conflict with every other one touching this map.
//
// Entries live one per file (mfa_stepup_purpose_allow_entry_<slug>_test.go,
// calling registerMFAStepUpPurposeAllow with the key above); this literal is
// empty on purpose. See registry_entries_test.go.
var mfaStepUpPurposeAllowlist = map[string]mfaStepUpAllowEntry{}

type mfaStepUpSite struct {
	relPath string
	line    int    // for messages only -- never part of the key
	encFunc string // enclosing top-level declaration, e.g. "(*KeyorixCore).requireReauth"
	callee  string // printed call.Fun, e.g. "c.storage.ConsumeMFAStepUpGrant"
	ordinal int    // 1-based position among calls with the same (encFunc, callee) in this file, source order
	fn      string // guarded function name, e.g. "ConsumeMFAStepUpGrant"
	purpose string // "" when the purpose argument isn't a literal models.MFAStepUpPurpose* constant
}

// key is the allowlist key: "<relpath>:<encFunc>:<callee>", plus "#<ordinal>"
// for every repeat after the first. Deliberately line-free, so an edit above a
// listed call site does not invalidate its entry.
//
// Strictness vs. the old "<relpath>:<line>" key: every distinct call site still
// gets a distinct key (two identical callee expressions in one function are
// told apart by the ordinal), so adding a call always produces one more key
// than the allowlist has -- the highest ordinal, or a new (func, callee)
// pair -- and removing one always leaves an allowlist key unmatched. What it
// does NOT do: when a new call is inserted BEFORE an existing identical one in
// the same function, the ordinals shift, so the "unlisted" report names the
// last call (#N) rather than the newly inserted one; the guard still fails.
// A call outside any function (a package-level var initializer) is keyed
// under encFunc "<package-scope>".
func (s mfaStepUpSite) key() string {
	k := s.relPath + ":" + s.encFunc + ":" + s.callee
	if s.ordinal > 1 {
		k += "#" + strconv.Itoa(s.ordinal)
	}
	return k
}

// mfaStepUpGuardRepoRoot locates the repository root relative to this test
// file's own location on disk (internal/core), not the test runner's cwd.
func mfaStepUpGuardRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must resolve this test file's path")
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	require.NoError(t, err)
	return root
}

// mfaStepUpPurposeLiteral extracts the models.MFAStepUpPurpose* constant name
// from expr, or "" if expr is not a bare `models.<Ident>` selector -- i.e.
// not a literal, hardcoded reference (a variable, a struct field like
// body.Purpose, a function call, etc. all yield "").
func mfaStepUpPurposeLiteral(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "models" {
		return ""
	}
	if !strings.HasPrefix(sel.Sel.Name, "MFAStepUpPurpose") {
		return ""
	}
	return sel.Sel.Name
}

// mfaStepUpNodeText renders an AST node back to normalized Go source
// (go/printer), so a key built from it is independent of the original file's
// whitespace and line breaks.
func mfaStepUpNodeText(fset *token.FileSet, n ast.Node) (string, error) {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, n); err != nil {
		return "", err
	}
	return b.String(), nil
}

// mfaStepUpDeclName names a top-level declaration for use in a key:
// "Func" for a plain function, "(<recv type>).Method" for a method (e.g.
// "(*KeyorixCore).requireReauth"), "<package-scope>" for anything else.
func mfaStepUpDeclName(fset *token.FileSet, d ast.Decl) (string, error) {
	fd, ok := d.(*ast.FuncDecl)
	if !ok {
		return "<package-scope>", nil
	}
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name, nil
	}
	recv, err := mfaStepUpNodeText(fset, fd.Recv.List[0].Type)
	if err != nil {
		return "", err
	}
	return "(" + recv + ")." + fd.Name.Name, nil
}

// scanMFAStepUpFile parses a single .go file and returns every call site to
// a guarded function found in it, by AST inspection. Every top-level
// declaration is walked (function bodies, including any function literals
// nested inside them, and package-level var initializers), so no call
// expression in the file is skipped.
func scanMFAStepUpFile(fset *token.FileSet, path string) ([]mfaStepUpSite, error) {
	src, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path built from filepath.WalkDir below, not external input
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []mfaStepUpSite
	ordinals := map[string]int{}
	for _, decl := range f.Decls {
		encFunc, derr := mfaStepUpDeclName(fset, decl)
		if derr != nil {
			return nil, derr
		}
		var ierr error
		ast.Inspect(decl, func(n ast.Node) bool {
			if ierr != nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !mfaStepUpGuardedFuncs[sel.Sel.Name] {
				return true
			}
			callee, perr := mfaStepUpNodeText(fset, call.Fun)
			if perr != nil {
				ierr = perr
				return false
			}
			purpose := ""
			if len(call.Args) > mfaPurposeArgIndex {
				purpose = mfaStepUpPurposeLiteral(call.Args[mfaPurposeArgIndex])
			}
			ordKey := encFunc + "\x00" + callee
			ordinals[ordKey]++
			sites = append(sites, mfaStepUpSite{
				relPath: path, line: fset.Position(call.Pos()).Line,
				encFunc: encFunc, callee: callee, ordinal: ordinals[ordKey],
				fn: sel.Sel.Name, purpose: purpose,
			})
			return true
		})
		if ierr != nil {
			return nil, ierr
		}
	}
	return sites, nil
}

// mfaStepUpGuardSkipDirs mirrors the skip list used by this campaign's other
// repo-wide guards (e.g. g80_1530_machine_actor_attribution_guard_test.go).
var mfaStepUpGuardSkipDirs = map[string]bool{
	".git":         true,
	".github":      true,
	".githooks":    true,
	".semgrep":     true,
	".task":        true,
	".scratch":     true,
	"node_modules": true,
	"web":          true,
	"vendor":       true,
}

// findAllMFAStepUpSites walks every non-test *.go file in the repository and
// returns every guarded-function call site found, keyed by mfaStepUpSite.key().
func findAllMFAStepUpSites(t *testing.T, repo string) map[string]mfaStepUpSite {
	t.Helper()
	fset := token.NewFileSet()
	found := map[string]mfaStepUpSite{}
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if mfaStepUpGuardSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		sites, serr := scanMFAStepUpFile(fset, path)
		if serr != nil {
			return serr
		}
		for _, s := range sites {
			rel, rerr := filepath.Rel(repo, path)
			require.NoError(t, rerr)
			s.relPath = filepath.ToSlash(rel)
			if prev, dup := found[s.key()]; dup {
				// Cannot happen while the ordinal is per (file, func, callee);
				// fail loudly rather than let one site shadow another.
				t.Fatalf("mfa step-up guard: key %q produced by two call sites (%s:%d and %s:%d)",
					s.key(), prev.relPath, prev.line, s.relPath, s.line)
			}
			found[s.key()] = s
		}
		return nil
	})
	require.NoError(t, err, "walking %s must not fail", repo)
	return found
}

// TestMFAStepUpConsumersUseExpectedPurpose is the guard: every call to
// HasActiveMFAStepUp/GetActiveMFAStepUpGrant repo-wide must be in
// mfaStepUpPurposeAllowlist, and every allowlisted site with a non-empty
// expectedPurpose must actually pass that exact literal constant as its
// purpose argument. A site that used to pass the right constant and now
// passes a different one (or a non-literal) fails here -- this is exactly
// the shape a reintroduced "accept any live grant" bug takes: a call site
// that no longer pins down which purpose it actually requires.
func TestMFAStepUpConsumersUseExpectedPurpose(t *testing.T) {
	t.Parallel()
	found := findAllMFAStepUpSites(t, mfaStepUpGuardRepoRoot(t))

	var unlisted []string
	var mismatched []string
	for key, s := range found {
		entry, ok := mfaStepUpPurposeAllowlist[key]
		if !ok {
			unlisted = append(unlisted, key+" ("+s.fn+", currently at line "+strconv.Itoa(s.line)+")")
			continue
		}
		if entry.expectedPurpose == "" {
			continue // intentionally non-literal / not a decision site; reason lives in the allowlist
		}
		if s.purpose != entry.expectedPurpose {
			got := s.purpose
			if got == "" {
				got = "<not a hardcoded models.MFAStepUpPurpose* literal>"
			}
			mismatched = append(mismatched, key+": expected purpose "+entry.expectedPurpose+", found "+got)
		}
	}
	sort.Strings(unlisted)
	sort.Strings(mismatched)

	assert.Empty(t, unlisted,
		"call site(s) to HasActiveMFAStepUp/GetActiveMFAStepUpGrant found with no reviewed allowlist "+
			"entry -- a new MFA step-up grant consumer must hardcode the exact models.MFAStepUpPurpose* "+
			"constant it requires and add a justified entry to mfaStepUpPurposeAllowlist (ONE NEW FILE mfa_stepup_purpose_allow_entry_<slug>_test.go calling registerMFAStepUpPurposeAllow, never an edit to a shared list), or it risks "+
			"repeating the confused-deputy bug this guard exists to catch: %v", unlisted)
	assert.Empty(t, mismatched,
		"call site(s) to HasActiveMFAStepUp/GetActiveMFAStepUpGrant no longer pass the purpose constant "+
			"mfaStepUpPurposeAllowlist expects -- this is exactly the bug shape this guard exists to catch: "+
			"a grant consumer accepting a purpose other than the one it actually requires: %v", mismatched)
}

// TestMFAStepUpPurposeAllowlistEntriesStillExist catches a stale allowlist
// entry -- the call site moved, was renamed, or was deleted -- which would
// otherwise silently stop protecting anything.
func TestMFAStepUpPurposeAllowlistEntriesStillExist(t *testing.T) {
	t.Parallel()
	found := findAllMFAStepUpSites(t, mfaStepUpGuardRepoRoot(t))

	var stale []string
	for key := range mfaStepUpPurposeAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"mfaStepUpPurposeAllowlist entry no longer matches any real "+
			"HasActiveMFAStepUp/GetActiveMFAStepUpGrant call site (the code moved, was renamed, or was "+
			"removed, without updating this list): %v", stale)
}

// TestMFAStepUpPurposeAllowlistJustificationsAreNonEmpty guards against an
// allowlist entry added with an empty/placeholder reason.
func TestMFAStepUpPurposeAllowlistJustificationsAreNonEmpty(t *testing.T) {
	t.Parallel()
	for key, entry := range mfaStepUpPurposeAllowlist {
		assert.NotEmpty(t, strings.TrimSpace(entry.reason), "allowlist entry %q has no justification", key)
	}
}

// TestMFAStepUpPurposeScannerDetectsCallSites is a self-check on the AST
// sweep: proves it actually extracts a hardcoded purpose constant when one
// is present, and correctly reports "" (non-literal) for a dynamic argument
// -- independent of the repository's current contents, so this guard can
// never pass merely because it never finds anything.
func TestMFAStepUpPurposeScannerDetectsCallSites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package fixture

import "github.com/keyorixhq/keyorix/internal/storage/models"

func hardcoded(c interface{ HasActiveMFAStepUp(int, int, models.MFAStepUpPurpose) (bool, error) }) {
	_, _ = c.HasActiveMFAStepUp(0, 0, models.MFAStepUpPurposeReauth)
}

func dynamic(c interface{ HasActiveMFAStepUp(int, int, models.MFAStepUpPurpose) (bool, error) }, p models.MFAStepUpPurpose) {
	_, _ = c.HasActiveMFAStepUp(0, 0, p)
}

func other(c interface{ SomethingElse() }) {
	c.SomethingElse()
}
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	fset := token.NewFileSet()
	sites, err := scanMFAStepUpFile(fset, path)
	require.NoError(t, err)
	require.Len(t, sites, 2, "scanner must find exactly the two HasActiveMFAStepUp calls, not SomethingElse")

	var gotHardcoded, gotDynamic bool
	for _, s := range sites {
		if s.purpose == "MFAStepUpPurposeReauth" {
			gotHardcoded = true
		}
		if s.purpose == "" {
			gotDynamic = true
		}
	}
	assert.True(t, gotHardcoded, "scanner must extract the literal MFAStepUpPurposeReauth constant")
	assert.True(t, gotDynamic, "scanner must report \"\" for a non-literal (variable) purpose argument")
}

// TestMFAStepUpPurposeScannerKeysAreLineFreeAndDistinct is a self-check on
// mfaStepUpSite.key(): two identical call expressions in one function get
// distinct keys (ordinal suffix), a method is named by its receiver type, a
// function literal's call is attributed to its enclosing declaration, and
// moving every call down by inserting lines above them changes no key.
func TestMFAStepUpPurposeScannerKeysAreLineFreeAndDistinct(t *testing.T) {
	t.Parallel()
	const body = `package fixture

import "github.com/keyorixhq/keyorix/internal/storage/models"

type S struct{ real interface{ ConsumeMFAStepUpGrant(int, int, models.MFAStepUpPurpose) (bool, error) } }

func (w *S) ConsumeMFAStepUpGrant(a, b int, p models.MFAStepUpPurpose) (bool, error) {
	if a > 0 {
		_, _ = w.real.ConsumeMFAStepUpGrant(a, b, p)
	}
	return w.real.ConsumeMFAStepUpGrant(a, b, p)
}

func plain(w *S) {
	f := func() { _, _ = w.real.ConsumeMFAStepUpGrant(0, 0, models.MFAStepUpPurposeReauth) }
	f()
}
`
	keysOf := func(src string) []string {
		dir := t.TempDir()
		path := filepath.Join(dir, "fixture.go")
		require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
		sites, err := scanMFAStepUpFile(token.NewFileSet(), path)
		require.NoError(t, err)
		var keys []string
		for _, s := range sites {
			s.relPath = "fixture.go"
			keys = append(keys, s.key())
		}
		sort.Strings(keys)
		return keys
	}
	want := []string{
		"fixture.go:(*S).ConsumeMFAStepUpGrant:w.real.ConsumeMFAStepUpGrant",
		"fixture.go:(*S).ConsumeMFAStepUpGrant:w.real.ConsumeMFAStepUpGrant#2",
		"fixture.go:plain:w.real.ConsumeMFAStepUpGrant",
	}
	assert.Equal(t, want, keysOf(body))
	shifted := strings.Replace(body, "package fixture\n", "package fixture\n\n// a\n// b\n// c\n", 1)
	assert.Equal(t, want, keysOf(shifted), "inserting lines above the call sites must not change any key")
}
