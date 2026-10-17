package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGeneratedStateMapMatchesCheckedIn regenerates docs/state-map/*.tsv into a
// temp dir with the exact code path `go run ./cmd/statemapgen` uses and fails on
// ANY differing row, in ANY column.
//
// Why this exists next to internal/statemap's TestCompletenessGuard_...: that
// guard compares entrypoints.tsv by (kind,id) occurrence count plus the class
// column, and stores.tsv by key/count. It deliberately does not look at the
// file, line, handler or reason columns, so a regenerate on an unchanged tree
// could rewrite 102 rows (every line number below an unrelated edit) while that
// guard stayed green. This test closes that gap by comparing whole rows.
//
// What it still does not see: the "#" header comment lines (they are compared
// too, but only as text, never interpreted), the hand-curated memory/external
// rows of stores.tsv (regenerated from curatedStores, so they are compared, but a
// wrong fact in that list is not detected), and class-overrides.tsv itself (read,
// never regenerated).
func TestGeneratedStateMapMatchesCheckedIn(t *testing.T) {
	root, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if _, err := generate(root, tmp); err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, name := range []string{"entrypoints.tsv", "stores.tsv"} {
		want := readLines(t, filepath.Join(root, "docs", "state-map", name))
		got := readLines(t, filepath.Join(tmp, name))
		if diffs := diffLines(want, got); len(diffs) > 0 {
			t.Errorf("docs/state-map/%s differs from a fresh `go run ./cmd/statemapgen` in %d row(s); regenerate and commit. First rows:\n%s",
				name, len(diffs), strings.Join(firstN(diffs, 5), "\n"))
		}
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reads fixed paths under the repo and its own temp dir
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(data), "\n")
}

// diffLines reports every line index where the two files differ, including a
// length difference (extra or missing rows).
func diffLines(want, got []string) []string {
	var out []string
	n := max(len(want), len(got))
	for i := 0; i < n; i++ {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			out = append(out, "  checked-in: "+w+"\n  generated:  "+g)
		}
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
