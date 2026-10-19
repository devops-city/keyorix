// remote_storage_importer_allowlist_test.go — post ADR-108 Phase 6 step 14b-2: RemoteStorage
// itself (internal/storage/store/remote_*.go) and its only two production/tooling callers
// (internal/storage/factory.go's "remote" case, scripts/analysis/remote_storage_stub_rewrite.go)
// are now all deleted. This guard's allowlist is empty and MUST STAY empty: it fails the build
// the moment ANY non-test file outside this package references store.RemoteStorage /
// store.NewRemoteStorage — those identifiers no longer exist in package store at all, so a
// match here can only mean a new file was added that still imports/names a type that no longer
// exists (a compile error waiting to happen) or, if package store's RemoteStorage type were ever
// reintroduced, a caller building on it without deliberately updating this guard first.
package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// remoteStorageImporterAllowlist is every non-test file, outside this package, that references
// store.RemoteStorage/store.NewRemoteStorage. Empty since ADR-108 Phase 6 step 14b-2 deleted
// both entries that used to be here (internal/storage/factory.go's "remote" case and
// scripts/analysis/remote_storage_stub_rewrite.go) along with RemoteStorage itself -- must stay
// empty; TestNoNewRemoteStorageImportersOutsideAllowlist below is the guard that keeps it that
// way.
var remoteStorageImporterAllowlist = map[string]string{}

var remoteStorageQualifiedRefRe = regexp.MustCompile(`\bstore\.(NewRemoteStorage|RemoteStorage)\b`)

// remoteStorageMentioned is deliberately broader than remoteStorageQualifiedRefRe -- used only
// to verify the (small, hand-vetted) allowlist itself hasn't gone stale, never for the repo-wide
// sweep. A plain substring check, not a \b-bounded regex: "RemoteStorage" is itself a suffix of
// "NewRemoteStorage" with no word boundary between "New" and "Remote" (both are letters), so a
// \bRemoteStorage\b regex would silently miss factory.go's own "store.NewRemoteStorage" call --
// confirmed by this test failing red against exactly that file before switching to Contains.
// scripts/analysis/remote_storage_stub_rewrite.go separately needs this looser check because it
// matches "RemoteStorage" as an AST identifier string, not a package-qualified Go reference (it
// doesn't import package store at all).
func remoteStorageMentioned(data []byte) bool {
	return strings.Contains(string(data), "RemoteStorage")
}

func remoteStorageGuardRepoRoot(t *testing.T) string {
	t.Helper()
	thisFile := filepath.Join(srcpath.PkgDir(), "remote_storage_importer_allowlist_test.go")
	// this file lives at internal/storage/store/remote_storage_importer_allowlist_test.go
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// skipDirs are subtrees this sweep never descends into: VCS metadata, the frontend (a different
// language entirely), and vendored/generated trees with no bearing on a Go import guard.
var remoteStorageSweepSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "web": true, ".scratch": true,
}

// TestNoNewRemoteStorageImportersOutsideAllowlist is the guard itself: every .go file in the
// repo except this package's own files and _test.go files anywhere must not package-qualify-
// reference RemoteStorage unless it's in the allowlist above.
func TestNoNewRemoteStorageImportersOutsideAllowlist(t *testing.T) {
	root := remoteStorageGuardRepoRoot(t)
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if remoteStorageSweepSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/storage/store/") {
			return nil // this package's own non-test files (remote_*.go itself) are expected to reference RemoteStorage.
		}
		if _, ok := remoteStorageImporterAllowlist[rel]; ok {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- repo-relative path from a controlled filepath.Walk, not user/network input
		if err != nil {
			return err
		}
		if remoteStorageQualifiedRefRe.Match(data) {
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	for _, o := range offenders {
		t.Errorf("new RemoteStorage reference outside the allowlist: %s -- add it to remoteStorageImporterAllowlist with a reason if this is genuinely intentional (the allowlist should only shrink toward PR 14, never grow)", o)
	}
}

// TestRemoteStorageAllowlistEntriesStillExistAndStillReference guards the allowlist itself
// against staleness in both directions: an entry for a file that no longer exists, or that no
// longer actually references RemoteStorage, would silently widen what the guard above accepts
// without anyone noticing -- matching this repo's other allowlist-with-reasoning sweeps
// (server/http/permission_sweep_test.go's TestPermissionSweepAllowlistEntriesStillExist).
func TestRemoteStorageAllowlistEntriesStillExistAndStillReference(t *testing.T) {
	root := remoteStorageGuardRepoRoot(t)
	for rel, reason := range remoteStorageImporterAllowlist {
		if reason == "" {
			t.Errorf("allowlist entry %q has no reason", rel)
		}
		data, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- fixed allowlist keys, not user/network input
		if err != nil {
			t.Errorf("allowlist entry %q: %v", rel, err)
			continue
		}
		if !remoteStorageMentioned(data) {
			t.Errorf("allowlist entry %q no longer references RemoteStorage -- remove it (the guard should shrink toward PR 14)", rel)
		}
	}
}
