// pending_dek_cleanup_guard_test.go — no production code discards
// dek.key.pending without reading the DEK-rotation redo marker
// (REVIEW-COVERAGE-2).
package encryption

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// cleanPendingDEKCallRe matches a call (not the declaration) of CleanPendingDEK.
var cleanPendingDEKCallRe = regexp.MustCompile(`\.CleanPendingDEK\(\)`)

// allowedCleanPendingDEKCalls is every production file allowed to call
// CleanPendingDEK, with how many calls. A bare call deletes dek.key.pending
// unconditionally; after a rotation killed between its sweep commit and the
// rename, that file is the only copy of the DEK the rows are under. Everyone
// else must go through RecoverInterruptedRotation(db), which promotes it when
// the redo marker committed.
var allowedCleanPendingDEKCalls = map[string]int{
	// RecoverInterruptedRotation itself (no DB, no table, no marker) and the
	// Service wrapper's delegation to the key manager.
	"internal/encryption/service_rotation.go": 4,
	// The remote-storage branch: a remote backend runs no local sweep, so no
	// marker can exist.
	"server/main.go": 1,
}

// TestCleanPendingDEK_OnlyBehindTheRedoMarker fails when a production file
// calls CleanPendingDEK outside the allowlist, or when an allowlisted file's
// call count changes (review the new call). Before REVIEW-COVERAGE-2,
// internal/encryptionops' upgrade-aad and rotate-kek called it bare.
//
// It does NOT see: a pending file removed by path (os.Remove on
// "dek.key.pending") or overwritten by another writer; those are pinned
// behaviourally by internal/encryptionops
// TestKeyWriters_AfterInterruptedRotation_NewDEKSurvives. Nested modules are
// not scanned.
func TestCleanPendingDEK_OnlyBehindTheRedoMarker(t *testing.T) {
	root := srcpath.RepoRoot()
	got := map[string]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			if rel != "." {
				if _, serr := os.Stat(filepath.Join(path, "go.mod")); serr == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- repo source walked by a test
		if err != nil {
			return err
		}
		if n := len(cleanPendingDEKCallRe.FindAll(src, -1)); n > 0 {
			got[rel] = n
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for f, n := range got {
		want, ok := allowedCleanPendingDEKCalls[f]
		switch {
		case !ok:
			t.Errorf("%s calls CleanPendingDEK %d time(s): use RecoverInterruptedRotation(db) under the exclusive key lock instead (a bare call can delete the only copy of a committed rotation's DEK)", f, n)
		case n != want:
			t.Errorf("%s calls CleanPendingDEK %d time(s), the allowlist says %d: review the change, then update allowedCleanPendingDEKCalls", f, n, want)
		}
	}
	for f := range allowedCleanPendingDEKCalls {
		if got[f] == 0 {
			t.Errorf("allowlisted %s no longer calls CleanPendingDEK: remove the stale entry", f)
		}
	}
}
