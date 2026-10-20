package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/statemap"
)

// TestWriteEntrypoints_ShiftedLinesWriteIdenticalBytes pins that entrypoints.tsv
// carries no source line: the same entry points found at different lines must be
// written byte for byte the same. Before the line column was dropped, an edit that
// only moved code in server/main.go rewrote every row below it and failed
// TestCompletenessGuard_EntrypointsAndStoresMatchCode in the merge queue
// (MERGE-FIX-AUTO-10171611). TestGeneratedStateMapMatchesCheckedIn compares the real
// tree, which is only line-stable as long as this holds.
//
// The control half changes a persisted column (Handler) and requires different bytes,
// so an unchanged output cannot come from the comparison being vacuous.
func TestWriteEntrypoints_ShiftedLinesWriteIdenticalBytes(t *testing.T) {
	entries := func(lineOffset int, handler string) []statemap.Entry {
		return []statemap.Entry{
			{Kind: "rest", ID: "GET /api/v1/secrets", File: "server/http/router.go", Line: 10 + lineOffset, Handler: handler, Class: "none", Reason: "r"},
			{Kind: "job", ID: "anomaly_detection", File: "server/main.go", Line: 1453 + lineOffset, Handler: "h", Class: "none", Reason: "r"},
		}
	}
	write := func(name string, es []statemap.Entry) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := writeEntrypoints(path, es); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path) // #nosec G304 -- temp dir this test just wrote
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	base := write("entrypoints.tsv", entries(0, "h"))
	if shifted := write("entrypoints.tsv", entries(300, "h")); shifted != base {
		t.Errorf("shifting every entry's source line by 300 changed entrypoints.tsv: a line number is being persisted, " +
			"so any unrelated edit above a handler would rewrite its row and fail the drift guards")
	}
	if changed := write("entrypoints.tsv", entries(0, "other")); changed == base {
		t.Errorf("changing a persisted column (Handler) did not change entrypoints.tsv: this test would not notice a real difference")
	}
}
