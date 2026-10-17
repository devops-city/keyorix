// shared_cache_literal_guard_test.go keeps new shared-cache SQLite DSNs on
// this package (#2906 follow-up, STORAGE-HARDEN-1).
//
// A hand-written "...?mode=memory&cache=shared" DSN is how #2906's flake got
// in: whoever writes it has to remember the one-connection pool cap, and most
// call sites did not. The guard fails `go test` on any Go string literal that
// contains cache=shared in a file this table does not list, so a new fixture
// has to go through DSN/Open/OpenWithConfig/OpenWithDialector instead.
//
// What it recognises: string literals (interpreted and raw) in every .go file
// of the repository, found with go/scanner, so comments that mention the DSN
// shape do not count. What it does not: a DSN assembled from pieces
// ("cache=" + "shared"), or one read from a file or the environment. Those
// shapes do not exist in the tree today; this scan is a guard against the
// copy-paste shape that does.
package sqlitetest

import (
	"fmt"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const sharedCacheNeedle = "cache=shared"

// deliberateSharedCacheMarker must appear in a comment of every file in
// deliberateSharedCacheLiterals, next to the literal it excuses.
const deliberateSharedCacheMarker = "sqlitetest: deliberate cache=shared"

// deliberateSharedCacheLiterals are the files that need a shared-cache DSN
// literal because they test that very behaviour. Each carries
// deliberateSharedCacheMarker. Repo-relative, slash-separated.
var deliberateSharedCacheLiterals = map[string]string{
	"internal/testutil/sqlitetest/sqlitetest.go":                      "DSN itself: the one sanctioned shared-cache DSN",
	"internal/testutil/sqlitetest/shared_cache_literal_guard_test.go": "this guard: its needle, messages and scanner calibration input",
	"internal/testutil/sqlitetest/sqlitetest_test.go":                 "TestUncappedSharedCachePool_StillLocks: the uncapped-pool control that keeps TestOpen_ConcurrentAccessIsNeverLocked from passing vacuously",
}

// pendingSharedCacheLiterals are files not converted yet, each with the owner
// that converts it. This list only shrinks: an entry whose file no longer has
// a literal fails the guard until it is removed.
var pendingSharedCacheLiterals = map[string]string{
	// Login / auth-budget / rate-limit tests, owned by running sessions.
	"server/http/handlers/auth_budget_routes_guard_test.go":              "FIX-3277 / HARDEN-HTTP-1",
	"server/http/handlers/health_auth_rate_limit_test.go":                "FIX-3277 / HARDEN-HTTP-1",
	"server/http/handlers/login_budget_count_failures_test.go":           "FIX-3277 / HARDEN-HTTP-1",
	"server/http/handlers/login_budget_fallback_http_test.go":            "FIX-3277 / HARDEN-HTTP-1",
	"server/http/handlers/login_budget_identifiable_reservation_test.go": "FIX-3277 / HARDEN-HTTP-1",
	"server/http/handlers/login_completion_identical_response_test.go":   "FIX-3277 / HARDEN-HTTP-1",
	"server/http/handlers/login_lockout_no_oracle_test.go":               "FIX-3277 / HARDEN-HTTP-1",
}

// skipDirs are never Go source of this repository.
var skipDirs = map[string]bool{".git": true, "node_modules": true, ".scratch": true, ".gopath": true, "vendor": true}

// sharedCacheLiteralLines returns the 1-based lines of every string literal in
// src that contains cache=shared. Comments are not literals.
func sharedCacheLiteralLines(filename string, src []byte) []int {
	fset := token.NewFileSet()
	file := fset.AddFile(filename, -1, len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, 0) // mode 0: comments are skipped
	var lines []int
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return lines
		}
		if tok == token.STRING && strings.Contains(lit, sharedCacheNeedle) {
			lines = append(lines, fset.Position(pos).Line)
		}
	}
}

// repoRoot walks up from this package to the directory holding the root
// module's go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.Contains(string(b), "module github.com/keyorixhq/keyorix\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("root go.mod (module github.com/keyorixhq/keyorix) not found above the test's directory")
		}
		dir = parent
	}
}

// filesWithSharedCacheLiterals maps every repo-relative .go file with at least
// one cache=shared literal to the lines of those literals.
func filesWithSharedCacheLiterals(t *testing.T, root string) map[string][]int {
	t.Helper()
	found := map[string][]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), sharedCacheNeedle) {
			return nil
		}
		if lines := sharedCacheLiteralLines(path, src); len(lines) > 0 {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found[filepath.ToSlash(rel)] = lines
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found
}

// TestNoNewSharedCacheLiterals is the guard: a cache=shared literal outside the
// two tables fails, so does a table entry whose file no longer has one, and so
// does a deliberate entry without its marker comment.
func TestNoNewSharedCacheLiterals(t *testing.T) {
	root := repoRoot(t)
	found := filesWithSharedCacheLiterals(t, root)

	var unlisted []string
	for path, lines := range found {
		_, deliberate := deliberateSharedCacheLiterals[path]
		_, pending := pendingSharedCacheLiterals[path]
		if !deliberate && !pending {
			unlisted = append(unlisted, fmt.Sprintf("%s (lines %v)", path, lines))
		}
	}
	slices.Sort(unlisted)
	if len(unlisted) > 0 {
		t.Errorf("hand-written shared-cache SQLite DSN literal(s); open the database with sqlitetest.Open/OpenWithConfig/"+
			"OpenWithDialector, or build the DSN with sqlitetest.DSN and cap the pool to one connection (#2906). "+
			"If the test is about shared-cache behaviour itself, add a %q comment and a deliberateSharedCacheLiterals entry:\n  %s",
			deliberateSharedCacheMarker, strings.Join(unlisted, "\n  "))
	}

	var stale []string
	for _, table := range []map[string]string{deliberateSharedCacheLiterals, pendingSharedCacheLiterals} {
		for path := range table {
			if _, ok := found[path]; !ok {
				stale = append(stale, path)
			}
		}
	}
	slices.Sort(stale)
	if len(stale) > 0 {
		t.Errorf("allowlisted file(s) no longer contain a cache=shared literal; remove them from the table so the allowlist only shrinks:\n  %s",
			strings.Join(stale, "\n  "))
	}

	for path := range deliberateSharedCacheLiterals {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			continue // reported as stale above
		}
		if !strings.Contains(string(src), deliberateSharedCacheMarker) {
			t.Errorf("%s is a deliberate shared-cache file but has no %q comment next to its literal", path, deliberateSharedCacheMarker)
		}
	}
}

// TestSharedCacheLiteralLines_FindsLiteralsNotComments calibrates the scanner
// both ways: literals of both kinds are found, comments and other strings are
// not.
func TestSharedCacheLiteralLines_FindsLiteralsNotComments(t *testing.T) {
	src := []byte("package p\n" +
		"// file:x?mode=memory&cache=shared in a comment\n" +
		"/* cache=shared in a block comment */\n" +
		"var a = \"file:a?mode=memory&cache=shared\"\n" +
		"var b = `file:b?mode=memory&cache=shared`\n" +
		"var c = \"file:c?mode=memory&cache=private\"\n")
	got := sharedCacheLiteralLines("p.go", src)
	if !slices.Equal(got, []int{4, 5}) {
		t.Fatalf("sharedCacheLiteralLines = %v, want [4 5] (the two literals, not the comments or the private-cache DSN)", got)
	}
}
