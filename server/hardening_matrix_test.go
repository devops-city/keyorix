package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// hardeningMatrixTestRef matches one `path/to/file_test.go:TestName` reference in a
// matrix row's Test cell.
var hardeningMatrixTestRef = regexp.MustCompile("`([A-Za-z0-9_./-]+_test\\.go):(Test[A-Za-z0-9_]*)`")

// TestHardeningMatrixRowsNameExistingTests keeps docs/security/production-hardening-matrix.d/
// honest: every table row's last cell names at least one test, and every named test
// file exists and declares that func. A renamed or deleted test turns its row red here
// instead of leaving the matrix claiming a guard that is gone. Existence only: CI's
// normal go test run is what makes each named test pass.
//
// Recognised row shape: a Markdown table line starting with "|" whose last cell holds
// the references; header and separator lines (a cell of only dashes) are skipped.
func TestHardeningMatrixRowsNameExistingTests(t *testing.T) {
	root := hardeningMatrixRepoRoot(t)
	dir := filepath.Join(root, "docs", "security", "production-hardening-matrix.d")
	frags, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) == 0 {
		t.Fatalf("no matrix fragments under %s: the check would be vacuous", dir)
	}
	rows := 0
	for _, frag := range frags {
		data, err := os.ReadFile(frag) // #nosec G304 -- repo-internal docs path
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(frag)
		inTable := false
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "|") {
				inTable = false
				continue
			}
			cells := strings.Split(strings.Trim(line, "|"), "|")
			last := strings.TrimSpace(cells[len(cells)-1])
			if !inTable {
				inTable = true // header row
				continue
			}
			if strings.Trim(last, "-: ") == "" {
				continue // separator row
			}
			rows++
			refs := hardeningMatrixTestRef.FindAllStringSubmatch(last, -1)
			if len(refs) == 0 {
				t.Errorf("%s:%d: row names no test (`path/file_test.go:TestName`): %s", name, i+1, line)
				continue
			}
			for _, ref := range refs {
				src, err := os.ReadFile(filepath.Join(root, ref[1])) // #nosec G304 -- path from a repo-internal doc, read-only
				if err != nil {
					t.Errorf("%s:%d: test file %s: %v", name, i+1, ref[1], err)
					continue
				}
				if !strings.Contains(string(src), "func "+ref[2]+"(t *testing.T)") {
					t.Errorf("%s:%d: %s declares no func %s(t *testing.T)", name, i+1, ref[1], ref[2])
				}
			}
		}
	}
	if rows == 0 {
		t.Fatal("matrix fragments contain no table rows: the check would be vacuous")
	}
}

func hardeningMatrixRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test's working directory")
		}
		dir = parent
	}
}
