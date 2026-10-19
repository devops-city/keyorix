package statemap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// validClasses are the only acceptable values for entrypoints.tsv's class
// column. A/S/B/C/D/F/R/X/L mirror docs/atomicity-exempt.tsv's own classes
// (reused, not redefined). "none" is a single/no-write or read-only-by-
// design entry. "REVIEW" is this generator's own 1-hop write-count scan
// flagging a candidate that needs a human (mirrors atomicity-exempt.tsv's
// TEMP-A precedent for "flagged, not yet triaged") -- ratcheted by
// TestReviewClassCountDoesNotGrow below so it cannot silently accumulate.
// "gap" is an entry-point CATEGORY this generator doesn't enumerate at all
// (see KnownGapRows in statemap.go).
var validClasses = map[string]bool{
	"A": true, "S": true, "B": true, "C": true, "D": true, "F": true, "R": true, "X": true, "L": true,
	"none": true, "REVIEW": true, "gap": true,
}

// maxReviewRows is a RATCHET, not a target: the checked-in entrypoints.tsv
// may have at most this many class=REVIEW rows. Lower it as rows get
// triaged into a real class via class-overrides.tsv (see overrides.go);
// raising it requires a human to have looked at why the count grew, not
// just re-running the generator after an unrelated code change. Set to the
// actual count after this round's classifier fixes (the job classifier was
// off-by-one before this round and flagged all scheduled jobs; see the PR).
const maxReviewRows = 9 // SESSION-AR batch 5/5 (AT0 REVIEW triage, FINAL): 28 more rows triaged into class-overrides.tsv (3 D, 1 B, 24 C); 9 rows left at REVIEW total, all deferred to Session AT (backup/restore, last-admin guard, or cascade delete) -- see docs/state-map/class-overrides.tsv's per-batch header comments for the full list and reasons. AT0 REVIEW triage is now complete from Session AR's side; every remaining REVIEW row is explicitly out of scope, not unclassified.

// TestCompletenessGuard_EntrypointsAndStoresMatchCode is AT0(f): re-runs the
// same extractors/classifier cmd/statemapgen uses and fails if
// docs/state-map/*.tsv has drifted from what's actually in code (a new/
// removed route, RPC, scheduled job, CLI command, or MCP tool -- compared by
// per-(kind,id) OCCURRENCE COUNT, not mere presence, so two entries that
// legitimately render the same ID string still catch a THIRD one silently
// appearing or one of the two disappearing), a new/removed DB table, or a
// new/removed non-test file-write call site (by file+func COUNT, not line
// number -- see AggregateFileWriteSites's doc for why). Also fails if any
// entrypoints row's class column is empty or not one of validClasses, if
// any KnownGapRows entry is missing, or if the REVIEW-class count exceeds
// maxReviewRows. It does NOT compare the file, handler or reason columns of
// entrypoints.tsv (only kind, id and class); whole-row drift is caught by
// cmd/statemapgen's TestGeneratedStateMapMatchesCheckedIn, which regenerates
// both TSVs into a temp dir and compares every line. Mirrors internal/core/atomicity_guard_test.go's shape (an
// AST/text scan compared against a checked-in file), for the same reason: a
// hand-maintained inventory silently rots; a regenerate-and-diff check
// cannot.
func TestCompletenessGuard_EntrypointsAndStoresMatchCode(t *testing.T) {
	root := repoRoot(t)

	gotEntries, err := AllEntries(root)
	if err != nil {
		t.Fatalf("AllEntries: %v", err)
	}
	gotClassified, err := Classify(root, gotEntries)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	wantRows, err := readEntrypointsTSV(filepath.Join(root, "docs", "state-map", "entrypoints.tsv"))
	if err != nil {
		t.Fatalf("reading checked-in entrypoints.tsv: %v", err)
	}
	overrides, err := LoadOverrides(filepath.Join(root, "docs", "state-map", "class-overrides.tsv"))
	if err != nil {
		t.Fatalf("reading class-overrides.tsv: %v", err)
	}
	checkOverridesValid(t, overrides, gotClassified)
	gotFinal := ApplyOverrides(gotClassified, overrides)

	diffEntryCounts(t, wantRows, gotFinal)
	checkClasses(t, wantRows)
	checkClassesMatchComputed(t, wantRows, gotFinal)
	checkGapRowsPresent(t, wantRows)
	checkReviewRatchet(t, wantRows, gotFinal)

	gotTables, err := DBTables(root)
	if err != nil {
		t.Fatalf("DBTables: %v", err)
	}
	gotSites, err := FileWriteSites(root)
	if err != nil {
		t.Fatalf("FileWriteSites: %v", err)
	}
	wantTables, wantFileWrites, err := readStoresTSV(filepath.Join(root, "docs", "state-map", "stores.tsv"))
	if err != nil {
		t.Fatalf("reading checked-in stores.tsv: %v", err)
	}
	diffCounts(t, "docs/state-map/stores.tsv (db_table rows)", "internal/storage/all_models.go", wantTables, tableCounts(gotTables))
	diffCounts(t, "docs/state-map/stores.tsv (file_write rows)", "a file-write call site scan", wantFileWrites, AggregateFileWriteSites(gotSites))
}

// entrypointsRow is one parsed row of entrypoints.tsv.
type entrypointsRow struct {
	kind, id, class string
}

func diffEntryCounts(t *testing.T, want []entrypointsRow, got []Entry) {
	t.Helper()
	wantCount := map[string]int{}
	for _, r := range want {
		if r.kind == "gap" {
			continue // no code-derived counterpart; checked separately by checkGapRowsPresent
		}
		wantCount[r.kind+"\t"+r.id]++
	}
	gotCount := map[string]int{}
	for _, e := range got {
		gotCount[e.Kind+"\t"+e.ID]++
	}
	var mismatches []string
	for k, wc := range wantCount {
		if gc := gotCount[k]; gc != wc {
			mismatches = append(mismatches, k+" (checked-in: "+strconv.Itoa(wc)+", code: "+strconv.Itoa(gc)+")")
		}
	}
	for k, gc := range gotCount {
		if _, ok := wantCount[k]; !ok {
			mismatches = append(mismatches, k+" (checked-in: 0, code: "+strconv.Itoa(gc)+")")
		}
	}
	if len(mismatches) > 0 {
		t.Errorf("docs/state-map/entrypoints.tsv has drifted from code for %d (kind,id) key(s) -- run `go run ./cmd/statemapgen` and commit the diff -- e.g. %v", len(mismatches), sample(mismatches, 8))
	}
}

// checkClasses fails if any non-gap row's class is empty or not a member of
// validClasses -- AT0(f)'s "unclassified rows must fail" requirement.
func checkClasses(t *testing.T, rows []entrypointsRow) {
	t.Helper()
	var bad []string
	for _, r := range rows {
		if !validClasses[r.class] {
			bad = append(bad, r.kind+"\t"+r.id+"\t(class=\""+r.class+"\")")
		}
	}
	if len(bad) > 0 {
		t.Errorf("docs/state-map/entrypoints.tsv has %d row(s) with an empty or invalid class column (must be one of A/S/B/C/D/F/R/X/L/none/REVIEW/gap) -- %v", len(bad), sample(bad, 8))
	}
}

// checkGapRowsPresent fails if any KnownGapRows entry is missing from the
// checked-in TSV -- diffEntryCounts skips kind=gap rows entirely (they have
// no code-derived counterpart), so without this, deleting a gap row would
// otherwise pass silently.
func checkGapRowsPresent(t *testing.T, rows []entrypointsRow) {
	t.Helper()
	present := map[string]bool{}
	for _, r := range rows {
		if r.kind == "gap" {
			present[r.id] = true
		}
	}
	for _, g := range KnownGapRows() {
		if !present[g.ID] {
			t.Errorf("docs/state-map/entrypoints.tsv is missing known-gap row %q -- either it was deleted (run `go run ./cmd/statemapgen`) or KnownGapRows changed without regenerating", g.ID)
		}
	}
}

// checkReviewRatchet fails if the REVIEW-class count exceeds maxReviewRows --
// see that constant's own doc comment. It counts BOTH the checked-in TSV and
// the classes the code computes (Classify + ApplyOverrides): counting only the
// TSV would let a hand-edit of REVIEW->none pass CI and then silently revert on
// the next regeneration.
func checkReviewRatchet(t *testing.T, rows []entrypointsRow, computed []Entry) {
	t.Helper()
	nTSV := 0
	for _, r := range rows {
		if r.class == "REVIEW" {
			nTSV++
		}
	}
	nCode := 0
	for _, e := range computed {
		if e.Class == "REVIEW" {
			nCode++
		}
	}
	for _, c := range []struct {
		label string
		n     int
	}{{"docs/state-map/entrypoints.tsv", nTSV}, {"Classify+ApplyOverrides", nCode}} {
		if c.n > maxReviewRows {
			t.Errorf("%s has %d class=REVIEW rows, exceeding the maxReviewRows ratchet (%d) -- a human must look at what grew this (a real new multi-write candidate needing triage, or a classifier regression) before raising the ceiling", c.label, c.n, maxReviewRows)
		}
	}
}

// checkClassesMatchComputed fails if any (kind,id)'s checked-in class multiset
// differs from what Classify+ApplyOverrides computes from code right now. The
// only supported way to change a row's class is class-overrides.tsv (which the
// generator preserves); hand-editing entrypoints.tsv's class column is exactly
// what this catches.
func checkClassesMatchComputed(t *testing.T, want []entrypointsRow, computed []Entry) {
	t.Helper()
	wantClasses := map[string][]string{}
	for _, r := range want {
		if r.kind == "gap" {
			continue
		}
		k := r.kind + "\t" + r.id
		wantClasses[k] = append(wantClasses[k], r.class)
	}
	gotClasses := map[string][]string{}
	for _, e := range computed {
		k := e.Kind + "\t" + e.ID
		gotClasses[k] = append(gotClasses[k], e.Class)
	}
	var mismatches []string
	for k, wc := range wantClasses {
		gc, ok := gotClasses[k]
		if !ok {
			continue // presence/count drift is diffEntryCounts' job
		}
		sort.Strings(wc)
		sort.Strings(gc)
		if strings.Join(wc, ",") != strings.Join(gc, ",") {
			mismatches = append(mismatches, k+" (checked-in: "+strings.Join(wc, ",")+", computed: "+strings.Join(gc, ",")+")")
		}
	}
	if len(mismatches) > 0 {
		sort.Strings(mismatches)
		t.Errorf("docs/state-map/entrypoints.tsv class column disagrees with Classify+ApplyOverrides for %d key(s) -- record a human classification in class-overrides.tsv (not by editing entrypoints.tsv) and run `go run ./cmd/statemapgen` -- e.g. %v", len(mismatches), sample(mismatches, 8))
	}
}

// checkOverridesValid fails on override rows whose class isn't a member of
// validClasses, or whose (kind,id) no longer matches any code-derived entry
// (a stale override for a renamed/removed route would otherwise be silently
// ignored forever).
func checkOverridesValid(t *testing.T, overrides map[string]Override, entries []Entry) {
	t.Helper()
	live := map[string]bool{}
	for _, e := range entries {
		live[e.Kind+"\t"+e.ID] = true
	}
	var bad []string
	for k, ov := range overrides {
		if !validClasses[ov.Class] || ov.Class == "gap" {
			bad = append(bad, k+" (invalid class \""+ov.Class+"\")")
		}
		if !live[k] {
			bad = append(bad, k+" (stale: no matching entry in code)")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("docs/state-map/class-overrides.tsv has %d invalid or stale row(s) -- %v", len(bad), sample(bad, 8))
	}
}

func diffCounts(t *testing.T, wantLabel, gotLabel string, want, got map[string]int) {
	t.Helper()
	var mismatches []string
	for k, wc := range want {
		if gc := got[k]; gc != wc {
			mismatches = append(mismatches, k+" (checked-in: "+strconv.Itoa(wc)+", "+gotLabel+": "+strconv.Itoa(gc)+")")
		}
	}
	for k, gc := range got {
		if _, ok := want[k]; !ok {
			mismatches = append(mismatches, k+" (checked-in: 0, "+gotLabel+": "+strconv.Itoa(gc)+")")
		}
	}
	if len(mismatches) > 0 {
		t.Errorf("%s has drifted from %s for %d key(s) -- run `go run ./cmd/statemapgen` and commit the diff -- e.g. %v", wantLabel, gotLabel, len(mismatches), sample(mismatches, 8))
	}
}

func tableCounts(tables []DBTable) map[string]int {
	out := map[string]int{}
	for _, tb := range tables {
		out[tb.Model]++
	}
	return out
}

func sample(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func readEntrypointsTSV(path string) ([]entrypointsRow, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed relative path under the checked-out repo
	if err != nil {
		return nil, err
	}
	var out []entrypointsRow
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		// kind, id, file, handler, class, reason (no line column: see the
		// generator's header). A short row used to be skipped silently; it is an
		// error now so a mangled row cannot hide from the class check.
		if len(fields) != 6 {
			return nil, fmt.Errorf("%s: want 6 tab-separated fields, got %d in row %q", path, len(fields), line)
		}
		out = append(out, entrypointsRow{kind: fields[0], id: fields[1], class: fields[4]})
	}
	return out, nil
}

// readStoresTSV splits stores.tsv into its db_table and file_write row
// counts (by store key, using the explicit count column -- not row count,
// since a file_write key is already file+func aggregated to one row with a
// count by the generator), ignoring the hand-curated memory/external rows
// below the marker comment (those have no code-derived counterpart and are
// explicitly NOT guarded, per the generator's own header comment).
func readStoresTSV(path string) (tables, fileWrites map[string]int, err error) {
	data, rerr := os.ReadFile(path) // #nosec G304 -- fixed relative path under the checked-out repo
	if rerr != nil {
		return nil, nil, rerr
	}
	tables = map[string]int{}
	fileWrites = map[string]int{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		count, cerr := strconv.Atoi(fields[3])
		if cerr != nil {
			continue
		}
		switch fields[1] {
		case "db_table":
			tables[fields[0]] += count
		case "file_write":
			// fields[0] is "file (func)" -- convert back to the "file\tfunc"
			// key AggregateFileWriteSites uses so the two sides compare on
			// the identical key shape.
			key := fileWriteKeyFromDisplay(fields[0])
			fileWrites[key] += count
		}
	}
	return tables, fileWrites, nil
}

// fileWriteKeyFromDisplay reverses the "%s (%s)" display format
// cmd/statemapgen's writeStores uses for a file_write row's store column
// back into the "file\tfunc" key AggregateFileWriteSites produces.
func fileWriteKeyFromDisplay(display string) string {
	i := strings.LastIndex(display, " (")
	if i < 0 || !strings.HasSuffix(display, ")") {
		return display
	}
	file := display[:i]
	fn := display[i+2 : len(display)-1]
	return file + "\t" + fn
}
