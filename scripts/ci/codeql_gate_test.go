package ci_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run scripts/ci/codeql-gate.sh, the merge-queue gate that replaces
// the SARIF upload (which failed on the already-deleted gh-readonly-queue
// branch), against synthetic SARIF. They need jq, as the ubuntu runners have.

func sarif(rules, results string) string {
	return fmt.Sprintf(`{"runs":[{"tool":{"driver":{"rules":[%s]}},"results":[%s]}]}`, rules, results)
}

func rule(id, sev string) string {
	if sev == "" {
		return fmt.Sprintf(`{"id":%q,"properties":{}}`, id)
	}
	return fmt.Sprintf(`{"id":%q,"properties":{"security-severity":%q}}`, id, sev)
}

func result(id, path string) string {
	return fmt.Sprintf(`{"ruleId":%q,"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},"region":{"startLine":7}}}]}`, id, path)
}

func runGate(t *testing.T, sarifs map[string]string, baseline string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	dir := t.TempDir()
	for name, body := range sarifs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(t.TempDir(), "open.tsv")
	if err := os.WriteFile(base, []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "codeql-gate.sh", dir) //nolint:gosec // this repo's own script
	cmd.Env = append(os.Environ(), "GATE_BASELINE_TSV="+base)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestCodeQLGate(t *testing.T) {
	high := rule("go/sql-injection", "8.8")
	medium := rule("go/log-injection", "6.1")
	quality := rule("go/keyorix-ssrf", "")
	cases := []struct {
		name     string
		sarifs   map[string]string
		baseline string
		wantFail bool
		wantMsg  string
	}{
		{"no results", map[string]string{"go.sarif": sarif(high, "")}, "", false, ""},
		{"medium and unscored results do not gate", map[string]string{"go.sarif": sarif(medium+","+quality, result("go/log-injection", "a.go")+","+result("go/keyorix-ssrf", "b.go"))}, "", false, ""},
		{"new high result fails", map[string]string{"go.sarif": sarif(high, result("go/sql-injection", "a.go"))}, "", true, "go/sql-injection"},
		{"high result already open on main passes", map[string]string{"go.sarif": sarif(high, result("go/sql-injection", "a.go"))}, "go/sql-injection\ta.go\n", false, ""},
		{"known rule in a new file fails", map[string]string{"go.sarif": sarif(high, result("go/sql-injection", "new.go"))}, "go/sql-injection\ta.go\n", true, "new.go"},
		{"one bad file among several fails", map[string]string{
			"a.sarif": sarif(high, ""),
			"b.sarif": sarif(high, result("go/sql-injection", "x.go")),
		}, "", true, "x.go"},
		{"no sarif written fails closed", map[string]string{}, "", true, "no .sarif files"},
		{"unreadable sarif fails closed", map[string]string{"go.sarif": "not json"}, "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runGate(t, tc.sarifs, tc.baseline)
			if (err != nil) != tc.wantFail {
				t.Fatalf("failed=%v, want %v\n%s", err != nil, tc.wantFail, out)
			}
			if tc.wantMsg != "" && !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("output lacks %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// The workflow must analyse without uploading in the merge queue and gate on
// the SARIF it wrote: this is what makes the "ref not found" failure impossible.
func TestCodeQLMergeGroupDoesNotUpload(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "codeql.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"upload: ${{ github.event_name == 'merge_group' && 'never' || 'always' }}",
		"upload-database: ${{ github.event_name != 'merge_group' }}",
	} {
		if got := strings.Count(s, want); got != 3 {
			t.Errorf("%q appears %d times, want once per analyze job (3)", want, got)
		}
	}
	if got := strings.Count(s, `scripts/ci/codeql-gate.sh "$SARIF_DIR"`); got != 3 {
		t.Errorf("gate step appears %d times, want 3", got)
	}
}
