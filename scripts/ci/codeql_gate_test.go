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
		{"high result absent from the baseline fails (go/clear-text-logging)", map[string]string{"go.sarif": sarif(rule("go/clear-text-logging", "7.5"), result("go/clear-text-logging", "a.go"))}, "go/sql-injection\ta.go\n", true, "go/clear-text-logging"},
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

// runGateAPI runs the gate through the alerts API path with a fake `gh` that
// serves one TSV per alert state (the real call passes --jq, so the fake prints
// the already-filtered "ruleId<TAB>path" lines). failState, when set, makes the
// call for that state exit non-zero.
func runGateAPI(t *testing.T, sarifs map[string]string, byState map[string]string, failState string) (string, error) {
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
	bin := t.TempDir()
	fake := `#!/usr/bin/env bash
state=$(printf '%s\n' "$*" | sed -n 's/.*state=\([a-z]*\).*/\1/p')
if [ "$state" = "$FAKE_GH_FAIL_STATE" ]; then echo "HTTP 502" >&2; exit 1; fi
f="$FAKE_GH_DIR/$state.tsv"
if [ -f "$f" ]; then cat "$f"; fi
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fake), 0o700); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	for state, body := range byState {
		if err := os.WriteFile(filepath.Join(bin, state+".tsv"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "codeql-gate.sh", dir) //nolint:gosec // this repo's own script
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"REPO=owner/name", "FAKE_GH_DIR="+bin, "FAKE_GH_FAIL_STATE="+failState,
		"GATE_RETRY_SLEEP=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A result that matches a DISMISSED alert on main (a human already decided
// "won't fix" / "false positive") is accepted; anything new still fails.
func TestCodeQLGateDismissedAlerts(t *testing.T) {
	logging := rule("go/clear-text-logging", "7.5")
	res := func(id, path string) map[string]string {
		return map[string]string{"go.sarif": sarif(logging, result(id, path))}
	}
	cases := []struct {
		name      string
		sarifs    map[string]string
		byState   map[string]string
		failState string
		wantFail  bool
		wantMsg   string
	}{
		{"dismissed-only baseline passes", res("go/clear-text-logging", "a.go"),
			map[string]string{"dismissed": "go/clear-text-logging\ta.go\n"}, "", false, ""},
		{"open-only baseline passes", res("go/clear-text-logging", "a.go"),
			map[string]string{"open": "go/clear-text-logging\ta.go\n"}, "", false, ""},
		{"open and dismissed combine", map[string]string{"go.sarif": sarif(logging+","+rule("go/sql-injection", "8.8"),
			result("go/clear-text-logging", "a.go")+","+result("go/sql-injection", "b.go"))},
			map[string]string{"open": "go/sql-injection\tb.go\n", "dismissed": "go/clear-text-logging\ta.go\n"}, "", false, ""},
		{"rule absent from both states fails", res("go/clear-text-logging", "a.go"),
			map[string]string{"open": "go/sql-injection\ta.go\n", "dismissed": "go/other\ta.go\n"}, "", true, "go/clear-text-logging"},
		{"dismissed rule in a new path fails", res("go/clear-text-logging", "new.go"),
			map[string]string{"dismissed": "go/clear-text-logging\ta.go\n"}, "", true, "new.go"},
		{"dismissed query failing is fail closed", res("go/clear-text-logging", "a.go"),
			map[string]string{"open": "go/clear-text-logging\ta.go\n"}, "dismissed", true, "failing closed"},
		{"open query failing is fail closed", res("go/clear-text-logging", "a.go"),
			map[string]string{"dismissed": "go/clear-text-logging\ta.go\n"}, "open", true, "failing closed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runGateAPI(t, tc.sarifs, tc.byState, tc.failState)
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
