// fuzz_cross_replica_invariants_pending_seeds_test.go — promotion gate for
// cross_replica_invariants_fuzz_test.go's pending seed corpus
// (testdata/fuzz-pending/<issue>/). A seed for an issue whose fix is not yet
// on main cannot live in the real corpus (testdata/fuzz/FuzzCrossReplicaInvariants/)
// — it would fail this package's tests on main today. It sits in
// testdata/fuzz-pending/<issue>/ instead until that issue's fix PR merges.
//
// TestPendingSeedsPromotedAfterFix is this package's half of closing that
// loop: once an issue's fix PR has merged, its pending seed MUST be promoted
// (moved into the live corpus dir) in the SAME PR that removes it from this
// table — a seed sitting in fuzz-pending/ after its fix landed is a
// regression test that was never actually wired in. Requires GH_TOKEN (a
// live PR-merge-state lookup); skips cleanly without it, same as this repo's
// other GH-API-dependent checks (scripts/report-unlisted-security-issues.sh).
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pendingSeedFix maps an issue whose fix is not yet on main to the PR that
// closes it. Remove a row the moment its PR merges AND its seed has been
// promoted out of testdata/fuzz-pending/<issue>/ into
// testdata/fuzz/FuzzCrossReplicaInvariants/ — both in the same commit.
//
// Rows are registered one per file (pending_seed_fix_entry_<issue>_test.go,
// calling registerPendingSeedFix; see registry_entries_test.go), not written
// into this literal.
var pendingSeedFix = map[string]int{}

func TestPendingSeedsPromotedAfterFix(t *testing.T) {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		t.Skip("GH_TOKEN not set — skipping pending-seed promotion check")
	}

	entries, err := os.ReadDir("testdata/fuzz-pending")
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading testdata/fuzz-pending: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		issue := e.Name()
		pr, known := pendingSeedFix[issue]
		if !known {
			t.Errorf("testdata/fuzz-pending/%s/ has no entry in pendingSeedFix — add one pointing at the PR that fixes #%s, or promote the seed if it's already fixed", issue, issue)
			continue
		}
		if pr == 0 {
			continue // reopened: no fix PR yet
		}
		merged, err := prIsMerged(client, token, pr)
		if err != nil {
			t.Fatalf("checking PR #%d (fixes #%s): %v", pr, issue, err)
		}
		if merged {
			seedFiles, _ := filepath.Glob(filepath.Join("testdata", "fuzz-pending", issue, "*"))
			t.Errorf("PR #%d (fixes #%s) has merged, but its seed(s) %v are still in testdata/fuzz-pending/%s/ — "+
				"promote them into testdata/fuzz/FuzzCrossReplicaInvariants/, wire the pair into FuzzCrossReplicaInvariants's f.Add seeds, "+
				"and delete the pendingSeedFix row for #%s", pr, issue, seedFiles, issue, issue)
		}
	}
}

func prIsMerged(client *http.Client, token string, pr int) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://api.github.com/repos/keyorixhq/keyorix/pulls/%d", pr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}
	var body struct {
		Merged bool `json:"merged"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	return body.Merged, nil
}
