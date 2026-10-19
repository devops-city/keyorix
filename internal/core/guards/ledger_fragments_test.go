package guards

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ledgerRow is one non-comment line of a tab-separated ledger, with where it
// came from (for error messages).
type ledgerRow struct {
	fields   []string
	source   string // "<file>:<line>"
	fragment bool
}

// readLedgerRows reads a tab-separated ledger the dual-read way
// (C-MERGE-FRICTION): the flat legacy file at legacyPath PLUS every
// <fragDir>/*.tsv file, each of which must hold exactly one row in the same
// format. A new row is a new fragment file, so two PRs adding two rows never
// touch the same line of a shared file. Existing legacy rows are never moved
// by this function — scripts/ledgers/migrate-to-fragments.sh does that, once,
// in a quiet merge window.
//
// It returns an error (never a partial result) when:
//   - the legacy file cannot be read (a missing fragment directory is fine:
//     zero fragments);
//   - a row has fewer than minFields tab-separated fields;
//   - a fragment holds zero or more than one row;
//   - the same key (field 0) appears twice where at least one of the two rows
//     is a fragment.
//
// A key duplicated purely WITHIN the legacy file is returned in
// legacyDups instead of failing: the legacy loader never rejected that (it
// built a set), so making it fatal now could turn an already-approved PR red
// inside the merge queue. scripts/ledgers/migrate-to-fragments.sh refuses to
// migrate a ledger with a legacy duplicate, and after migration every row is
// a fragment, so the rule becomes fatal there.
//
// What it does NOT check: the meaning of any column beyond the field count,
// and fragment file NAMES (scripts/ledgers/migrate-to-fragments.sh names them
// after the key, but a hand-added fragment may be named anything ending .tsv —
// uniqueness is enforced on the key, not the file name).
func readLedgerRows(legacyPath, fragDir string, minFields int) (rows []ledgerRow, legacyDups []string, err error) {
	parse := func(path string, data []byte) ([]ledgerRow, error) {
		var out []ledgerRow
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, "\t")
			src := fmt.Sprintf("%s:%d", path, i+1)
			if len(fields) < minFields {
				return nil, fmt.Errorf("%s: expected %d tab-separated fields, got %d: %q", src, minFields, len(fields), line)
			}
			out = append(out, ledgerRow{fields: fields, source: src})
		}
		return out, nil
	}

	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read %s: %w", legacyPath, err)
	}
	legacy, err := parse(legacyPath, data)
	if err != nil {
		return nil, nil, err
	}
	rows = append(rows, legacy...)

	frags, err := filepath.Glob(filepath.Join(fragDir, "*.tsv"))
	if err != nil {
		return nil, nil, fmt.Errorf("globbing %s: %w", fragDir, err)
	}
	sort.Strings(frags)
	for _, f := range frags {
		fdata, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot read fragment %s: %w", f, err)
		}
		frows, err := parse(f, fdata)
		if err != nil {
			return nil, nil, err
		}
		if len(frows) != 1 {
			return nil, nil, fmt.Errorf("fragment %s holds %d rows — a ledger fragment must hold exactly one", f, len(frows))
		}
		frows[0].fragment = true
		rows = append(rows, frows[0])
	}

	seen := map[string]ledgerRow{}
	var dups []string
	for _, r := range rows {
		prev, ok := seen[r.fields[0]]
		if !ok {
			seen[r.fields[0]] = r
			continue
		}
		d := fmt.Sprintf("%q at %s and %s", r.fields[0], prev.source, r.source)
		if prev.fragment || r.fragment {
			dups = append(dups, d)
		} else {
			legacyDups = append(legacyDups, d)
		}
	}
	if len(dups) > 0 {
		return nil, nil, fmt.Errorf("duplicate key(s) across %s and %s/*.tsv:\n  %s", legacyPath, fragDir, strings.Join(dups, "\n  "))
	}
	return rows, legacyDups, nil
}

// TestReadLedgerRows_DualRead is readLedgerRows's own red/green calibration:
// every rejection path above must reject, and a legacy+fragment ledger must
// read back every row exactly once.
func TestReadLedgerRows_DualRead(t *testing.T) {
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const header = "# header\n# function\tclass\treason\n"
	cases := []struct {
		name      string
		legacy    string
		frags     map[string]string
		wantErr   string // substring; "" = must succeed
		wantCount int
		wantLDups int
	}{
		{name: "legacy only", legacy: header + "F1\tA\tr\nF2\tA\tr\n", wantCount: 2},
		{name: "no fragment dir at all", legacy: header + "F1\tA\tr\n", frags: nil, wantCount: 1},
		{name: "legacy + fragments", legacy: header + "F1\tA\tr\n",
			frags: map[string]string{"F2.tsv": "# comment ok\nF2\tA\tr\n", "F3.tsv": "F3\tA\tr"}, wantCount: 3},
		{name: "fragments only", legacy: header,
			frags: map[string]string{"F2.tsv": "F2\tA\tr\n"}, wantCount: 1},
		{name: "non-.tsv files in the fragment dir are ignored", legacy: header + "F1\tA\tr\n",
			frags: map[string]string{"README.md": "F1\tA\tr\n"}, wantCount: 1},
		{name: "duplicate within legacy only: reported, not fatal", legacy: header + "F1\tA\tr\nF1\tB\tr\n", wantCount: 2, wantLDups: 1},
		{name: "fragment duplicates legacy", legacy: header + "F1\tA\tr\n",
			frags: map[string]string{"F1.tsv": "F1\tB\tr\n"}, wantErr: "duplicate key"},
		{name: "two fragments, same key", legacy: header,
			frags: map[string]string{"a.tsv": "F9\tA\tr\n", "b.tsv": "F9\tA\tr\n"}, wantErr: "duplicate key"},
		{name: "fragment with two rows", legacy: header,
			frags: map[string]string{"a.tsv": "F8\tA\tr\nF9\tA\tr\n"}, wantErr: "exactly one"},
		{name: "empty fragment", legacy: header,
			frags: map[string]string{"a.tsv": "# only a comment\n"}, wantErr: "exactly one"},
		{name: "short legacy row", legacy: header + "F1\tA\n", wantErr: "expected 3 tab-separated fields"},
		{name: "short fragment row", legacy: header,
			frags: map[string]string{"a.tsv": "F1\tA\n"}, wantErr: "expected 3 tab-separated fields"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			legacy := filepath.Join(dir, "ledger.tsv")
			fragDir := filepath.Join(dir, "ledger.d")
			write(t, legacy, tc.legacy)
			for name, body := range tc.frags {
				write(t, filepath.Join(fragDir, name), body)
			}
			rows, ldups, err := readLedgerRows(legacy, fragDir, 3)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v (rows=%d)", tc.wantErr, err, len(rows))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rows) != tc.wantCount {
				t.Fatalf("got %d rows, want %d", len(rows), tc.wantCount)
			}
			if len(ldups) != tc.wantLDups {
				t.Fatalf("got %d legacy-only duplicates %v, want %d", len(ldups), ldups, tc.wantLDups)
			}
		})
	}

	t.Run("missing legacy file is an error, not zero rows", func(t *testing.T) {
		dir := t.TempDir()
		_, _, err := readLedgerRows(filepath.Join(dir, "absent.tsv"), filepath.Join(dir, "absent.d"), 3)
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("want fs.ErrNotExist, got %v", err)
		}
	})
}
