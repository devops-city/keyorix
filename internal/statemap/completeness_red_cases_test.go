package statemap

import (
	"fmt"
	"strings"
	"testing"
)

// These tests watch diffEntryCounts, the (kind,id) comparison inside
// TestCompletenessGuard_EntrypointsAndStoresMatchCode, fail and not fail, on small
// inputs, so the guard's two red cases and its line-shift green case are pinned
// rather than assumed:
//
//   - a route/RPC/job the code has but the checked-in TSV lacks (missing row) is red;
//   - a row the TSV carries but the code no longer has (extra row) is red;
//   - the same entries at different source lines are green. Entry.Line is not
//     persisted and not compared, so an edit that only shifts server/main.go must
//     never fail the merge queue (MERGE-FIX-AUTO-10171611: the old TSV carried the
//     line and 102 rows went stale on unrelated edits).
//
// They do not read the repo: the real-tree comparison is the guard itself and
// cmd/statemapgen's TestGeneratedStateMapMatchesCheckedIn.

// recordingT observes a guard's verdict without ending the calling test.
type recordingT struct {
	testing.TB
	errs []string
}

func (r *recordingT) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func entryFixtureRows() []entrypointsRow {
	return []entrypointsRow{
		{kind: "rest", id: "GET /api/v1/secrets", class: "none"},
		{kind: "job", id: "anomaly_detection", class: "none"},
	}
}

func entryFixtureEntries(lineOffset int) []Entry {
	return []Entry{
		{Kind: "rest", ID: "GET /api/v1/secrets", File: "server/http/router.go", Line: 10 + lineOffset, Class: "none"},
		{Kind: "job", ID: "anomaly_detection", File: "server/main.go", Line: 1453 + lineOffset, Class: "none"},
	}
}

func TestDiffEntryCounts_MatchingRowsAreGreen(t *testing.T) {
	r := &recordingT{TB: t}
	diffEntryCounts(r, entryFixtureRows(), entryFixtureEntries(0))
	if len(r.errs) != 0 {
		t.Fatalf("identical rows and entries must not be reported, got: %v", r.errs)
	}
}

func TestDiffEntryCounts_LineShiftIsNotDrift(t *testing.T) {
	r := &recordingT{TB: t}
	diffEntryCounts(r, entryFixtureRows(), entryFixtureEntries(250))
	if len(r.errs) != 0 {
		t.Fatalf("the same entry points at different source lines must not be drift (Entry.Line is not part of a row), got: %v", r.errs)
	}
}

func TestDiffEntryCounts_MissingRowIsRed(t *testing.T) {
	r := &recordingT{TB: t}
	rows := entryFixtureRows()[:1] // the checked-in TSV lacks the job the code has
	diffEntryCounts(r, rows, entryFixtureEntries(0))
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "job\tanomaly_detection (checked-in: 0, code: 1)") {
		t.Fatalf("a code entry point with no TSV row must be reported with its key, got: %v", r.errs)
	}
}

func TestDiffEntryCounts_ExtraRowIsRed(t *testing.T) {
	r := &recordingT{TB: t}
	rows := append(entryFixtureRows(), entrypointsRow{kind: "rest", id: "DELETE /api/v1/removed", class: "none"})
	diffEntryCounts(r, rows, entryFixtureEntries(0))
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "rest\tDELETE /api/v1/removed (checked-in: 1, code: 0)") {
		t.Fatalf("a TSV row with no code entry point must be reported with its key, got: %v", r.errs)
	}
}
