package statemap

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGeneratedStateMap_MatchesCommitted runs cmd/statemapgen into a temp dir (same inputs: the
// source tree and docs/state-map/class-overrides.tsv) and compares the result byte for byte with
// the committed docs/state-map/entrypoints.tsv and stores.tsv. completeness_test.go compares the
// SET of entry points; this one also catches what that skips: source line numbers, handler names,
// classes and reasons, so a refactor that only moves code leaves the committed map stale.
// It does not check class-overrides.tsv (hand-written input, not generated).
//
// On a merge/rebase conflict in a generated file, regenerate; never hand-merge.
func TestGeneratedStateMap_MatchesCommitted(t *testing.T) {
	root := repoRoot(t)
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	tmp := t.TempDir()
	cmd := exec.Command(goBin, "run", "./cmd/statemapgen", "-out", tmp) // #nosec G204 -- fixed in-repo command
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go run ./cmd/statemapgen -out %s: %v\n%s", tmp, err, out)
	}
	for _, name := range []string{"entrypoints.tsv", "stores.tsv"} {
		want, err := os.ReadFile(filepath.Join(tmp, name)) // #nosec G304 -- temp dir we just wrote
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(root, "docs", "state-map", name)) // #nosec G304 -- fixed in-repo path
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("docs/state-map/%s is stale (differs from what cmd/statemapgen generates).\n"+
				"Fix: go run ./cmd/statemapgen   and commit docs/state-map/ (never hand-merge: regenerate)", name)
		}
	}
}
