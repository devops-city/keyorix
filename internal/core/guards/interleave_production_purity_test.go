// interleave_production_purity_test.go — the machine-checked half of
// interleave_sync_points_test.go's central claim: the forced-interleaving
// machinery has ZERO production footprint.
//
// GUARD-5's brief asked for the sync points to live in production functions
// behind a build tag, and for a proof that they compile away ("a test that the
// production binary contains no hook symbols, or the hook is a compile-time
// constant false"). interleave_sync_points_test.go's header explains why the
// sync points live in test-only files instead. That choice makes the proof
// obligation DIFFERENT, not smaller, and this file discharges it:
//
//   - the Go toolchain never compiles a `_test.go` file into a non-test
//     binary. That is a property of the toolchain, not of this repo, and it
//     is strictly stronger than a build tag (which a stray `-tags` in a
//     release pipeline can switch on).
//   - therefore the only way the machinery can reach production is if someone
//     later moves it, or copies a piece of it, into a non-test `.go` file.
//     TestInterleaveSyncPointsAreTestOnly is the check that fails when that
//     happens.
//
// Composed, those two give the same guarantee the brief asked for, and the
// second half is checked on every run in milliseconds rather than by building
// a binary.
//
// Calibration: the scanner is exercised in BOTH directions on every run —
// green against the real repository, and red against a synthetic tree with a
// planted violation (TestInterleaveSyncPointPurityScanDetectsAViolation). A
// guard nobody has watched fail is not a guard (CLAUDE.md), and a guard that
// scans a tree which happens to be clean for unrelated reasons is
// indistinguishable from one whose matcher is broken.
//
// Independently calibrated once by hand against a real binary, recorded here
// so the claim is not purely static: `go build -o <bin> ./server` then
// `go tool nm <bin>` listed 98,917 symbols, of which zero matched
// syncPoint|runInterleav|interleaveOrder|requireForced|guard5. That is a
// one-off sanity check of the toolchain property above, deliberately NOT
// wired into CI: building ./server costs minutes, and a check that only ever
// runs when someone remembers to run it is not a guard — the static scan
// below is the guard, and it covers the only way the property can break.
package guards

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// interleaveSyncPointIdents are the identifiers that only the forced-
// interleaving driver defines or uses. Any one of them appearing in a
// non-test `.go` file means part of the driver has leaked towards a
// production build.
//
// This list is itself the thing a reviewer should check: it is complete with
// respect to interleave_sync_points_test.go's exported-to-the-package
// surface (every top-level type, func and const that file declares), and
// TestInterleaveSyncPointIdentsCoverTheDriver below derives the same list
// from the driver file's own source so the two cannot drift apart.
var interleaveSyncPointIdents = []string{
	"syncPointArrivalTimeout",
	"syncPoint",
	"syncPointName",
	"newSyncPoint",
	"interleaveOrder",
	"orderSerialAB",
	"orderSerialBA",
	"orderABAcAa",
	"orderABBaAa",
	"orderBABcBa",
	"orderBAAaBa",
	"allInterleavings",
	"interleaveResult",
	"runInterleaving",
	"runInterleavingTimeout",
	"interleavePauseA",
	"interleavePauseB",
	"requireForced",
	"removeFn",
	// The GORM callback-name prefix every sync point registers under. A
	// production file registering a callback under this prefix would be a
	// production-timing change even if it reused none of the identifiers.
	`"guard5:`,
}

// purityViolation is one non-test file that references driver machinery.
type purityViolation struct {
	File  string
	Ident string
	Line  int
}

// stripGoLineComment removes a trailing `//` comment and, for a line that is
// wholly inside a `/* */` block or starts with `//`, the whole line.
//
// Why this is needed at all, and what it deliberately does NOT handle: the
// first version of this scanner matched raw substrings and reported five
// "violations" that were all the English word "interleaving" inside ordinary
// production comments (server/main.go, internal/core/secrets.go,
// internal/core/account_sessions.go, internal/storage/store/local_secrets.go).
// A guard that fires on prose is a guard people route around. This is a
// line-oriented approximation, not a Go parser: a `//` inside a string
// literal would be treated as a comment start, and a multi-line `/* */` block
// is only recognised when the opener and closer are on the same line. Both
// over-strip rather than under-strip, i.e. they can only cause a missed
// violation, never a false one — and a driver identifier hidden inside a
// string literal after a `//` in a production file is not a failure mode worth
// a parser. The `inBlock` tracking below covers the ordinary multi-line case.
func stripGoLineComment(line string, inBlock *bool) string {
	if *inBlock {
		if _, after, ok := strings.Cut(line, "*/"); ok {
			*inBlock = false
			return after
		}
		return ""
	}
	if i := strings.Index(line, "/*"); i >= 0 {
		if j := strings.Index(line[i:], "*/"); j >= 0 {
			return line[:i] + line[i+j+2:]
		}
		*inBlock = true
		return line[:i]
	}
	if before, _, ok := strings.Cut(line, "//"); ok {
		return before
	}
	return line
}

// identRefRe builds a word-boundary matcher for a Go identifier, so `syncPoint`
// does not match `mySyncPointThing` and `interleaveOrder` does not match a
// longer name that happens to contain it.
func identRefRe(ident string) *regexp.Regexp {
	if strings.HasPrefix(ident, `"`) {
		// A string-literal prefix (the callback-name prefix) — matched
		// literally, not as an identifier.
		return regexp.MustCompile(regexp.QuoteMeta(ident))
	}
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`)
}

// scanForInterleaveMachinery walks root and reports every reference to one of
// `idents` from the CODE (comments stripped) of a `.go` file that is NOT a
// `_test.go` file. Vendor, testdata and .git are skipped (vendored
// third-party code is not ours to constrain, and testdata is not compiled).
//
// Factored out of the test so the same code path is exercised against the
// real repository AND against a synthetic tree with a planted violation —
// see this file's header on why a one-directional guard is not trusted here.
func scanForInterleaveMachinery(root string, idents []string) ([]purityViolation, int, error) {
	res := make([]*regexp.Regexp, len(idents))
	for i, id := range idents {
		res[i] = identRefRe(id)
	}
	var out []purityViolation
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path) //nolint:gosec // walking our own repo
		if readErr != nil {
			return readErr
		}
		scanned++
		inBlock := false
		for i, raw := range strings.Split(string(b), "\n") {
			line := stripGoLineComment(raw, &inBlock)
			if strings.TrimSpace(line) == "" {
				continue
			}
			for j, re := range res {
				if re.MatchString(line) {
					out = append(out, purityViolation{File: path, Ident: idents[j], Line: i + 1})
				}
			}
		}
		return nil
	})
	return out, scanned, err
}

// repoRootFromCore resolves the module root from this package's directory.
func repoRootFromCore(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Join(wd, "..", "..", "..")
	abs, err := filepath.Abs(root)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(abs, "go.mod"), "expected the module root three levels above internal/core/guards")
	return abs
}

// TestInterleaveSyncPointsAreTestOnly is the green direction: no non-test Go
// file anywhere in the repository references the forced-interleaving driver,
// so no production binary can contain it.
func TestInterleaveSyncPointsAreTestOnly(t *testing.T) {
	t.Parallel()
	root := repoRootFromCore(t)
	violations, scanned, err := scanForInterleaveMachinery(root, interleaveSyncPointIdents)
	require.NoError(t, err)
	require.Greater(t, scanned, 500,
		"scanned only %d non-test .go files — the walk is not reaching the repository, so a clean result means nothing", scanned)
	for _, v := range violations {
		t.Errorf("forced-interleaving machinery leaked into a production file: %s:%d references %s",
			v.File, v.Line, v.Ident)
	}
	t.Logf("scanned %d non-test .go files, %d violations", scanned, len(violations))
}

// TestInterleaveSyncPointPurityScanDetectsAViolation is the red direction: the
// same scanner, over a synthetic tree, must catch a planted reference from a
// non-test file — and must NOT flag the identical reference from a `_test.go`
// file, which is where the driver legitimately lives.
func TestInterleaveSyncPointPurityScanDetectsAViolation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "internal", "core"), 0o750))

	// Legitimate: the driver itself, in a _test.go file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "core", "driver_test.go"),
		[]byte("package core\n\nfunc newSyncPoint() {}\nvar _ = runInterleaving\n"), 0o600))
	// Planted violation: a production file reaching for the same machinery.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "core", "leaked.go"),
		[]byte("package core\n\nfunc hook() { runInterleaving() }\n"), 0o600))
	// Planted violation: a production file registering the callback prefix.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "core", "leaked_cb.go"),
		[]byte("package core\n\nfunc reg() { db.Callback().Create().Register(\"guard5:x\", nil) }\n"), 0o600))
	// Decoy that must NOT match: a production file mentioning neither.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "core", "innocent.go"),
		[]byte("package core\n\nfunc ordinary() {}\n"), 0o600))
	// Decoy that must NOT match: driver identifiers inside ordinary prose,
	// in a line comment and in a block comment. This is the exact false
	// positive the first version of this scanner produced five times over
	// against the real repository.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "core", "prose.go"),
		[]byte("package core\n\n// a stale read can happen when runInterleaving\n"+
			"// orderings like interleaveOrder overlap; see newSyncPoint notes.\n"+
			"/*\nsyncPoint and requireForced are discussed here in prose only.\n*/\nfunc prose() {}\n"), 0o600))
	// Decoy that must NOT match: a longer identifier that merely CONTAINS a
	// driver name, which a substring matcher would flag.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "core", "lookalike.go"),
		[]byte("package core\n\nfunc mySyncPointLike() {}\nvar interleaveOrderingsOfMine = 1\n"), 0o600))

	violations, scanned, err := scanForInterleaveMachinery(dir, interleaveSyncPointIdents)
	require.NoError(t, err)
	require.Equal(t, 5, scanned, "five non-test .go files in the synthetic tree")

	byFile := map[string][]string{}
	for _, v := range violations {
		byFile[filepath.Base(v.File)] = append(byFile[filepath.Base(v.File)], v.Ident)
	}
	require.Contains(t, byFile, "leaked.go", "the scanner must flag a production file using runInterleaving")
	require.Contains(t, byFile, "leaked_cb.go", "the scanner must flag a production file registering the guard5: callback prefix")
	require.NotContains(t, byFile, "driver_test.go", "the driver's own _test.go file is where it belongs and must not be flagged")
	require.NotContains(t, byFile, "innocent.go", "an unrelated production file must not be flagged")
	require.NotContains(t, byFile, "prose.go",
		"driver identifiers inside line and block COMMENTS must not be flagged — that false positive fired five times on the real repo")
	require.NotContains(t, byFile, "lookalike.go",
		"a longer identifier merely containing a driver name must not be flagged (word-boundary matching)")
}

// TestInterleaveSyncPointIdentsCoverTheDriver keeps interleaveSyncPointIdents
// from drifting behind the driver: every top-level declaration in
// interleave_sync_points_test.go must appear in the ident list, so adding a
// new piece of the driver without listing it fails here rather than silently
// shrinking what TestInterleaveSyncPointsAreTestOnly covers.
//
// "An enumeration is only as complete as the idioms it knows about"
// (CLAUDE.md): the declaration forms this derivation recognises are exactly
// `type X`, `func X(`, `func (r *interleaveResult) X(`, `const (`-block
// entries and `var X` at column 0. Methods on driver types are deliberately
// NOT required in the list — a method name alone cannot pull the driver into
// a production build without its receiver type, which IS listed.
func TestInterleaveSyncPointIdentsCoverTheDriver(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../interleave_sync_points_test.go")
	require.NoError(t, err)

	listed := map[string]bool{}
	for _, id := range interleaveSyncPointIdents {
		listed[id] = true
	}

	var missing []string
	inConstOrVar := false
	for line := range strings.SplitSeq(string(src), "\n") {
		switch line {
		case "const (", "var (":
			inConstOrVar = true
			continue
		case ")":
			inConstOrVar = false
			continue
		}
		var name string
		switch {
		case inConstOrVar:
			// `orderSerialAB interleaveOrder = "..."` or `orderSerialBA ...`
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 2 && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				name = f[0]
			}
		case strings.HasPrefix(line, "type "):
			name = strings.Fields(line)[1]
		case strings.HasPrefix(line, "func ") && !strings.HasPrefix(line, "func ("):
			name = strings.SplitN(strings.TrimPrefix(line, "func "), "(", 2)[0]
		case strings.HasPrefix(line, "var "):
			name = strings.Fields(line)[1]
		case strings.HasPrefix(line, "const "):
			name = strings.Fields(line)[1]
		}
		if name == "" || listed[name] {
			continue
		}
		missing = append(missing, name)
	}
	require.Empty(t, missing,
		"these top-level driver declarations are not in interleaveSyncPointIdents, so the purity guard does not cover them: %v", missing)
}
