package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests pin how .github/workflows/codeql.yml decides to run the JS/TS
// analysis in the merge queue: only when the group diff touches web/**. Since
// CI-LIGHT-1, CodeQL runs only on merge_group, push to main and the weekly
// schedule; on pull_request every job is skipped. They execute the real
// `changes` job script (extracted from the workflow, `gh` stubbed, context
// values passed through env: as the workflow does), so a regression in the
// filter is caught here, not by an alert that never appears. They do not prove
// CodeQL itself runs; that is CI's job.

type workflow struct {
	Jobs map[string]struct {
		If    string `yaml:"if"`
		Steps []struct {
			ID  string `yaml:"id"`
			Run string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "codeql.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// runFilter executes the `changes` job's filter script for the given event and
// changed-file list and returns the key=value pairs it wrote to GITHUB_OUTPUT.
func runFilter(t *testing.T, event string, files []string) map[string]string {
	t.Helper()
	var script string
	for _, s := range loadWorkflow(t).Jobs["changes"].Steps {
		if s.ID == "filter" {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatal("changes job has no step with id: filter")
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\nprintf '%s\\n' \"$FAKE_FILES\"\n"
	if len(files) == 0 {
		stub = "#!/bin/sh\nexit 0\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(stub), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	out := filepath.Join(dir, "output")
	cmd := exec.Command("bash", "-e", "-c", script) //nolint:gosec // script is this repo's own workflow step
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_OUTPUT="+out,
		"FAKE_FILES="+strings.Join(files, "\n"),
		"EVENT_NAME="+event,
		"REPO=keyorixhq/keyorix",
		"MG_BASE_SHA=base",
		"MG_HEAD_SHA=head",
	)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("filter script failed: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for l := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		got[k] = v
	}
	return got
}

func TestCodeQLWebChanged(t *testing.T) {
	cases := []struct {
		name  string
		event string
		files []string
		want  string
	}{
		{"group touching web", "merge_group", []string{"web/src/App.tsx", "server/x.go"}, "true"},
		{"group touching only web", "merge_group", []string{"web/package.json"}, "true"},
		{"group touching only go", "merge_group", []string{"server/x.go", "internal/y.go"}, "false"},
		{"group touching a look-alike dir", "merge_group", []string{"website/x.ts", "docs/web/a.md"}, "false"},
		{"group touching only the workflow", "merge_group", []string{".github/workflows/codeql.yml"}, "false"},
		{"group with empty file list fails safe", "merge_group", nil, "true"},
		{"push keeps full scan", "push", []string{"server/x.go"}, "true"},
		{"schedule keeps full scan", "schedule", nil, "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runFilter(t, tc.event, tc.files)["web_changed"]
			if got != tc.want {
				t.Fatalf("web_changed = %q, want %q", got, tc.want)
			}
		})
	}
}

// The Go legs must keep their own gating: a web-only group must not turn them on.
func TestCodeQLWebOnlyGroupDoesNotRunGoLegs(t *testing.T) {
	got := runFilter(t, "merge_group", []string{"web/src/App.tsx"})
	for _, k := range []string{"root_go_changed", "operator_go_changed"} {
		if got[k] != "false" {
			t.Errorf("%s = %q for a web-only group, want false", k, got[k])
		}
	}
	if got["docs_only"] != "false" || got["go_unaffected"] != "false" || got["operator_only"] != "false" {
		t.Errorf("web-only group must not be classed docs-only/go-unaffected/operator-only: %v", got)
	}
}

// CodeQL is merge-queue-only (CI-LIGHT-1): the changes job, and with it every
// analyze job that needs it, is skipped on pull_request.
func TestCodeQLSkippedOnPullRequest(t *testing.T) {
	cond := loadWorkflow(t).Jobs["changes"].If
	if !strings.Contains(cond, "github.event_name != 'pull_request'") {
		t.Errorf("changes must be skipped on pull_request, got: %q", cond)
	}
}

func TestCodeQLAnalyzeWebGate(t *testing.T) {
	cond := loadWorkflow(t).Jobs["analyze-web"].If
	if !strings.Contains(cond, "needs.changes.outputs.web_changed == 'true'") {
		t.Errorf("analyze-web must be gated on web_changed, got: %s", cond)
	}
	if strings.Contains(cond, "github.event_name != 'pull_request'") {
		t.Errorf("analyze-web is skipped on pull_request through the changes job; its own if: must not repeat that, got: %s", cond)
	}
	for _, keep := range []string{"docs_only != 'true'", "go_unaffected != 'true'", "operator_only != 'true'"} {
		if !strings.Contains(cond, keep) {
			t.Errorf("analyze-web lost the %s gate: %s", keep, cond)
		}
	}
}
