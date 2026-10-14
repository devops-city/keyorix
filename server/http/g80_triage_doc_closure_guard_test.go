// g80_triage_doc_closure_guard_test.go — Task 0b's guard: a "FIXED" claim in
// the G80 triage docs (docs/g80-raw-storage-bypass-triage.md,
// docs/g80-documented-exception-sweep-findings.md) that references a PR
// number is not itself evidence the fix reached `main` — see this session's
// own headline finding: PRs #1563-#1566 all showed "Merged" on GitHub while
// each was actually merged into the PREVIOUS PR's feature branch, never
// `main` (CLAUDE.md's "a merge badge is not a merge").
//
// IMPORTANT scope note (corrected 2026-08-25, see CLAUDE.md's fuller
// correction): `git merge-base --is-ancestor <sha> HEAD` is sound HERE
// because every claim below names one specific, already-resolved commit SHA
// -- checking whether a known object is included in HEAD's history is a
// valid question regardless of squash-merge. It would NOT be sound to run
// `--is-ancestor <branch-tip> origin/main` instead: this repo squash-merges
// every PR, minting a brand-new commit, so a correctly-landed branch's own
// pre-squash commits are never ancestors of that squash commit either --
// that check returns false unconditionally, landed or not. This guard never
// does that; it only ever checks named, resolved SHAs, never a branch ref.
//
// This is NOT a claim that every referenced commit fixes what it says it
// fixes -- that's the triage doc's own job. This guard only checks the
// narrower, mechanical fact a merge badge cannot be trusted to report:
// is the commit actually reachable from HEAD.
//
// Entries with no single commit to point at (the #1563-#1566 + ADR-085
// content, re-applied as one flat diff onto a fresh branch rather than
// individually-attributable commits -- see this file's own registry entry
// below for the full reasoning) are listed explicitly with a stated reason,
// not silently exempted from this file's registry -- a missing entry would
// look identical to "nothing more to verify," which is exactly the kind of
// silent gap this guard exists to prevent.
package http

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// g80ClosureMarker is the "still present" half of a closure claim -- an
// ancestor-of-HEAD check on a SHA only answers "did this land"; it says
// nothing about whether a LATER commit reverted, refactored away, or lost
// the fix in a bad merge resolution. A later commit can't remove itself from
// an earlier commit's ancestry, so the SHA check stays green forever even
// after the fix is gone. Exactly one of mustExist/mustNotExist is set.
type g80ClosureMarker struct {
	// file is the repo-relative path the marker is checked against. Empty
	// means repo-wide (via `git grep`) -- used for mustNotExist markers
	// where the fix's signature is the absence of a symbol anywhere, not
	// its presence in one particular file (the ADR-085 entry below).
	file string
	// mustExist is a literal substring that must still be present in `file`
	// (or repo-wide if file is empty) for the fix to be considered intact.
	mustExist string
	// mustNotExist is a literal substring that must still be ABSENT from
	// `file` (or repo-wide if file is empty) for the fix to be considered
	// intact -- e.g. a removed function's own name.
	mustNotExist string
}

// g80ClosureClaim is one triage-doc reference this guard verifies (or
// explicitly declines to, with a stated reason).
type g80ClosureClaim struct {
	// label identifies the claim for a failure message -- doc + PR reference,
	// not a full description of what the PR does (the triage docs own that).
	label string
	// sha is the full commit hash the claim rests on. Empty means "no single
	// commit exists" -- noSingleCommitReason must be set instead.
	sha string
	// noSingleCommitReason is set (and sha left empty) when the referenced
	// fix does not correspond to one attributable commit -- e.g. content
	// re-applied as a flat diff after a tangled branch-into-branch merge
	// chain. Reading this field IS the explicit statement Task 0b requires;
	// it is not a silent exemption because it appears in this file's
	// registry and is asserted non-empty by the test below.
	noSingleCommitReason string
	// marker is the "still present" check, independent of the SHA's ancestry
	// -- see g80ClosureMarker's doc. Required for every entry: an entry with
	// no marker is exactly the unverifiable-closure shape this guard exists
	// to catch, whether or not it also carries a SHA.
	marker g80ClosureMarker
}

// g80TriageClosureClaims is the registry TestG80TriageDocClosuresAreAncestorsOfHEAD
// checks. Add an entry here whenever a triage doc records a new "FIXED"
// claim against a real commit; add a noSingleCommitReason entry instead when
// the fix has no single commit to point at. Every entry needs a marker.
var g80TriageClosureClaims = []g80ClosureClaim{
	// docs/g80-raw-storage-bypass-triage.md "Fix wave complete (2026-08-25)"
	// section, verified against origin/main by this same correction pass
	// (2026-08-25) -- see that section's own "Corrections from an
	// independent verification session" subsection.
	//
	// PRs #1557, #1558, #1560, #1561, #1562 retired (ADR-108 Phase 6): each
	// entry's marker pointed at a server/http/handlers/*_proxy.go file (or a
	// router.go route registration) that no longer exists -- the entire
	// /system RemoteStorage proxy tier these fixes closed a bypass in was
	// deleted, so the vulnerable surface itself, not just the fix, is gone.
	// Surface removed, not silently dropped: docs/security-closures.tsv rows
	// for the same PRs get the identical "surface removed" retirement.
	// #1559 (SoD policy/risk-exception authority) is unaffected -- its marker
	// (internal/core/sod.go's isGlobalAdminRoleName) is core-layer, not
	// proxy-layer, and still exists -- kept below.
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1559 (SoD policy and risk-exception authority gaps)",
		sha: "f83d63c63a03a6bedc79a4440eb84def3805a471",
		marker: g80ClosureMarker{file: "internal/core/sod.go",
			mustExist: "isGlobalAdminRoleName"}},
	// PRs #1563-#1566 (server/http proxy Tier-2 fixes) and the ADR-085
	// node-credential-arm removal: an independent verification session's
	// headline finding (2026-08-25) is that all four PRs showed
	// "Merged" on GitHub while none were ancestors of origin/main -- each
	// was merged into the previous PR's feature branch. The content was
	// recovered from the worktree it existed in only as uncommitted work and
	// re-applied as ONE flat diff (`git apply`) onto a fresh branch off
	// origin/main, because the squash-merge history made the original
	// per-PR commits unrecoverable as individually-attributable objects (a
	// pre-squash commit is never an ancestor of its own post-squash
	// equivalent). There is no single commit that represents "PR #1563's
	// fix" (or #1564/#1565/#1566's) anymore, distinct from the whole
	// re-applied stack -- stated explicitly here, not silently exempted.
	// Its marker is repo-wide absence of RequireNodeCredentialOrPermission,
	// the exact function ADR-085 deletes -- the natural, and only, marker
	// for a stack with no single commit to point at.
	{label: "PRs #1563-#1566 + ADR-085 node-credential-arm removal",
		noSingleCommitReason: "re-applied as one flat diff onto a fresh branch (git apply, not a rebase) after " +
			"the original branch-into-branch merge chain was found to never reach main and the pre-squash " +
			"commits were confirmed unrecoverable as ancestors of their post-squash equivalents; verify this " +
			"content's presence by reading the diff/tests it introduced, not by any single commit hash",
		marker: g80ClosureMarker{mustNotExist: "func RequireNodeCredentialOrPermission"}},
}

// ensureFullHistory deepens a shallow clone before this guard runs its
// ancestor checks. Found 2026-08-25: CI's default actions/checkout does a
// shallow clone (fetch-depth: 1) for every job except the one gitleaks step
// that opts into fetch-depth: 0 -- under a shallow clone, `git merge-base
// --is-ancestor <sha> HEAD` doesn't report "not an ancestor" for an older,
// genuinely-landed commit, it fails outright with "fatal: Not a valid commit
// name <sha>" because the object was never fetched at all. That made this
// guard fail unconditionally in CI regardless of whether the claims it
// checks were true -- exactly the "a check that always fails is as useless
// as one that always passes" anti-pattern this campaign has fought
// elsewhere (CLAUDE.md). Confirmed via the actual CI failure log (test-suite
// http-3, PR #1568) before writing this fix, not guessed. Self-heals here
// instead of requiring every CI job that might run this package to carry a
// fetch-depth: 0 override.
func ensureFullHistory(t *testing.T) {
	t.Helper()
	shallow, err := exec.Command("git", "rev-parse", "--is-shallow-repository").CombinedOutput()
	if err != nil {
		t.Logf("could not determine shallow-repository status: %v (%s) -- proceeding as-is", err, strings.TrimSpace(string(shallow)))
		return
	}
	if strings.TrimSpace(string(shallow)) != "true" {
		return
	}
	if out, err := exec.Command("git", "fetch", "--unshallow", "--quiet").CombinedOutput(); err != nil {
		t.Logf("git fetch --unshallow failed: %v (%s) -- ancestor checks below may report false negatives "+
			"(commit unresolvable) rather than a genuine non-ancestor finding", err, strings.TrimSpace(string(out)))
	}
}

// fileContains reports whether path's current working-tree content contains
// substr in a NON-COMMENT line. path is repo-relative; this test binary runs
// with its package directory (server/http) as cwd, so path is resolved
// against "../..". Comment lines (trimmed content starting with "//") are
// skipped before searching -- mirrors wire_actor_identity_forgery_guard_test.go's
// actorFieldReads, and for the same reason: a doc comment mentioning a
// removed symbol's name (this file's own fix commentary routinely does
// exactly that, describing what a fix now checks) must not itself satisfy a
// mustExist marker after the real call is gone -- that would make the
// marker unable to fail on a genuine revert, which defeats the point of
// having it.
func fileContains(t *testing.T, path, substr string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// repoContains reports whether substr appears ANYWHERE in the current
// working tree's tracked *.go files -- used for mustNotExist markers that
// check a symbol's absence repo-wide (a removed function could be
// re-introduced under a different file without a single-file check catching
// it). Excludes THIS file from the scan: a mustNotExist marker necessarily
// spells out the exact string it's checking for as a Go string literal in
// g80TriageClosureClaims below, which would otherwise self-match on every
// run regardless of whether the real symbol is actually gone.
func repoContains(t *testing.T, substr string) bool {
	t.Helper()
	out, err := exec.Command("git", "-C", "../..", "grep", "-q", "-F", substr, "--",
		"*.go", ":!server/http/g80_triage_doc_closure_guard_test.go").CombinedOutput()
	if err == nil {
		return true
	}
	if len(out) == 0 {
		return false
	}
	t.Fatalf("git grep failed unexpectedly for %q repo-wide: %v (%s)", substr, err, string(out))
	return false
}

// checkMarker evaluates one g80ClosureMarker against the current working
// tree and returns a non-empty failure description if the marker doesn't
// hold (empty string means the marker is satisfied).
func checkMarker(t *testing.T, m g80ClosureMarker) string {
	t.Helper()
	switch {
	case m.mustExist != "" && m.mustNotExist != "":
		return "marker malformed: both mustExist and mustNotExist set -- pick one"
	case m.mustExist == "" && m.mustNotExist == "":
		return "marker malformed: neither mustExist nor mustNotExist set -- every closure claim needs a marker"
	case m.mustExist != "":
		var present bool
		if m.file != "" {
			present = fileContains(t, m.file, m.mustExist)
		} else {
			present = repoContains(t, m.mustExist)
		}
		if !present {
			where := m.file
			if where == "" {
				where = "anywhere in the repo"
			}
			return "marker NOT satisfied: " + m.mustExist + " no longer found in " + where +
				" -- the fix this entry claims may have been reverted, refactored away, or lost in a merge"
		}
	case m.mustNotExist != "":
		var present bool
		if m.file != "" {
			present = fileContains(t, m.file, m.mustNotExist)
		} else {
			present = repoContains(t, m.mustNotExist)
		}
		if present {
			where := m.file
			if where == "" {
				where = "the repo"
			}
			return "marker NOT satisfied: " + m.mustNotExist + " is back in " + where +
				" -- this entry's closure claims its removal, but it has reappeared"
		}
	}
	return ""
}

// TestG80TriageDocClosuresAreAncestorsOfHEAD is Task 0b's guard, now two
// independent checks per entry: the SHA answers "did this land" (git
// merge-base --is-ancestor <sha> HEAD -- a merge badge, a PR's "Merged"
// label, or an approval is never sufficient evidence on its own), and the
// marker answers "is the fix still present" (a later commit can revert,
// refactor away, or lose a fix in a bad merge resolution without ever
// removing the original SHA from HEAD's ancestry, so the SHA check alone
// stays green forever after the fix is gone -- see g80ClosureMarker's doc).
// Every claim with no single commit must say so via noSingleCommitReason,
// not be silently absent from this registry. Every claim, with or without a
// SHA, must carry a marker.
func TestG80TriageDocClosuresAreAncestorsOfHEAD(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	ensureFullHistory(t)
	var notAncestor []string
	var unresolvable []string
	var malformed []string
	var markerFailed []string
	for _, c := range g80TriageClosureClaims {
		if m := checkMarker(t, c.marker); m != "" {
			markerFailed = append(markerFailed, c.label+": "+m)
		}
		if c.sha == "" {
			if strings.TrimSpace(c.noSingleCommitReason) == "" {
				malformed = append(malformed, c.label+" (neither sha nor noSingleCommitReason set)")
			} else {
				t.Logf("NO SINGLE COMMIT for %q: %s", c.label, c.noSingleCommitReason)
			}
			continue
		}
		if c.noSingleCommitReason != "" {
			malformed = append(malformed, c.label+" (both sha and noSingleCommitReason set -- pick one)")
			continue
		}
		if _, err := exec.Command("git", "cat-file", "-e", c.sha).CombinedOutput(); err != nil {
			unresolvable = append(unresolvable, c.label+" (commit "+c.sha+" could not be resolved even after "+
				"attempting to deepen the clone -- this is NOT evidence the commit is missing from main, only "+
				"that this checkout couldn't fetch it; investigate the fetch failure, don't read this as a "+
				"closure regression)")
			continue
		}
		cmd := exec.Command("git", "merge-base", "--is-ancestor", c.sha, "HEAD")
		out, err := cmd.CombinedOutput()
		if err != nil {
			notAncestor = append(notAncestor, c.label+" (commit "+c.sha+"): "+strings.TrimSpace(string(out))+" ["+err.Error()+"]")
		}
	}
	if len(malformed) > 0 {
		t.Errorf("%d closure claim(s) malformed in this file's registry: %v", len(malformed), malformed)
	}
	if len(markerFailed) > 0 {
		t.Errorf("%d closure claim(s) failed their marker check (SHA landed, but the fix is no longer present in "+
			"the working tree): %v", len(markerFailed), markerFailed)
	}
	if len(unresolvable) > 0 {
		t.Errorf("%d closure claim(s) reference a commit this checkout could not resolve, even after attempting "+
			"to deepen a shallow clone: %v", len(unresolvable), unresolvable)
	}
	if len(notAncestor) > 0 {
		t.Errorf("%d closure claim(s) reference a commit that is NOT an ancestor of HEAD -- a merge badge or PR "+
			"label is not evidence of a merge, verify with git merge-base --is-ancestor before trusting a FIXED "+
			"claim: %v", len(notAncestor), notAncestor)
	}
}
