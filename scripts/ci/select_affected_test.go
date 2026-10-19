package ci_test

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests pin scripts/ci/select-affected.py, the merge-queue selection
// (CI-SELECT-1): which test-suite legs and path-gated jobs a merge_group run
// executes. They run the real script against this checkout's real package
// graph through its --changed hook (a file list instead of a git diff), in both
// directions: every FULL trigger must widen to the full suite, and a change that
// cannot reach a leg must leave it out. A selection that silently stopped
// narrowing would only waste runners; one that stopped widening would let an
// untested change reach main, so the widening cases are the load-bearing ones.

type selection struct {
	Mode   string            `json:"mode"`
	Reason string            `json:"reason"`
	Legs   map[string]string `json:"legs"`
	Gates  map[string]bool   `json:"gates"`
	Seeds  map[string]string `json:"seeds"`
}

// leafTest is a test file in a package nothing else depends on through it.
// Joined from pieces on purpose: a literal naming this path would make
// scripts/ci itself (this file) one of its readers, and select root-4 too.
var leafTest = filepath.Join("internal", "utils", "safeconv", "safeconv_test.go")

func runSelect(t *testing.T, args ...string) selection {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", append([]string{"scripts/ci/select-affected.py", "--json"}, args...)...)
	cmd.Dir = root
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("select-affected.py %v: %v\n%s", args, err, stderr.String())
	}
	var s selection
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("select-affected.py %v: bad JSON: %v\n%s", args, err, out)
	}
	return s
}

func changed(t *testing.T, files ...string) selection {
	t.Helper()
	return runSelect(t, append([]string{"--changed"}, files...)...)
}

func legNames(s selection) []string {
	names := make([]string, 0, len(s.Legs))
	for l := range s.Legs {
		names = append(names, l)
	}
	slices.Sort(names)
	return names
}

func TestSelectAffected_FullTriggersRunEverything(t *testing.T) {
	for _, f := range []string{
		"go.mod",
		"go.sum",
		"cli/go.mod",
		"operator/go.sum",
		"internal/testutil/sqlitetest/sqlitetest.go",
		".github/workflows/ci.yml",
		"scripts/ci/select-affected.py",
		"scripts/ci/run-guards.sh",
		"scripts/ci-test-legs.sh",
		"scripts/ci-test-quick.py",
		"server/proto/keyorix.proto",
		"buf.gen.yaml",
		"internal/faultstorage/gen/main.go",
	} {
		s := changed(t, leafTest, f)
		if s.Mode != "full" {
			t.Errorf("%s changed: mode=%q (%s), want full", f, s.Mode, s.Reason)
		}
		for g, on := range s.Gates {
			if !on {
				t.Errorf("%s changed: gate %s closed in a full run", f, g)
			}
		}
	}
}

func TestSelectAffected_GitFailureFallsBackToFull(t *testing.T) {
	s := runSelect(t, "--base", "0000000000000000000000000000000000000000", "--head", "HEAD")
	if s.Mode != "full" {
		t.Fatalf("unfetchable base: mode=%q (%s), want full", s.Mode, s.Reason)
	}
}

// A _test.go file compiles into its own package's test binary only, so a
// test-only change selects that package's leg and nothing that imports it.
func TestSelectAffected_TestOnlyChangeSelectsItsPackageOnly(t *testing.T) {
	s := changed(t, leafTest)
	if s.Mode != "selected" {
		t.Fatalf("mode=%q (%s), want selected", s.Mode, s.Reason)
	}
	pkg := "github.com/keyorixhq/keyorix/" + filepath.ToSlash(filepath.Dir(leafTest))
	if got := legNames(s); !slices.Equal(got, []string{"root-2"}) {
		t.Errorf("legs=%v, want [root-2] (%s is pinned to root-2)", got, pkg)
	}
	if s.Legs["root-2"] != pkg {
		t.Errorf("root-2 runs %q, want only %s", s.Legs["root-2"], pkg)
	}
	for g, on := range s.Gates {
		if on {
			t.Errorf("gate %s open for a test-only change to a leaf package", g)
		}
	}
}

// A code change selects every package that imports the changed one:
// server/http imports internal/core, so the http and handlers shards run.
func TestSelectAffected_CodeChangeSelectsImporters(t *testing.T) {
	s := changed(t, "internal/core/access_review_campaign.go")
	if s.Mode != "selected" {
		t.Fatalf("mode=%q (%s), want selected", s.Mode, s.Reason)
	}
	for _, leg := range []string{"core", "http-1", "http-8", "handlers-1", "handlers-2"} {
		if _, ok := s.Legs[leg]; !ok {
			t.Errorf("leg %s not selected for an internal/core code change; legs=%v", leg, legNames(s))
		}
	}
	for _, g := range []string{"docker_boot", "helm_boot", "demo", "web_e2e"} {
		if !s.Gates[g] {
			t.Errorf("gate %s closed although ./server imports internal/core", g)
		}
	}
	// ./server (root-3) is a main package; `go list ./...` reports its Deps
	// as "pkg [github.com/keyorixhq/keyorix/server]" variants, which must be
	// normalised or the package never counts as an importer.
	if !slices.Contains(strings.Fields(s.Legs["root-3"]), "github.com/keyorixhq/keyorix/server") {
		t.Errorf("root-3 runs %q, want it to include ./server (imports internal/core)", s.Legs["root-3"])
	}
}

// A data file outside every package is selected through the tests that name
// it: internal/storage/store's full-row-write guard reads this ledger.
func TestSelectAffected_DataFileSelectsItsReaders(t *testing.T) {
	s := changed(t, "docs/full-row-write-exempt.tsv")
	if _, ok := s.Legs["storage-store-1"]; !ok {
		t.Errorf("storage-store-1 not selected for its guard's ledger; legs=%v seeds=%v", legNames(s), s.Seeds)
	}
}

// A file only server tests read (server/admin's docs test reads the
// self-hosting guide) changes no compiled code of the server binary, so the
// image smokes stay skipped while server/admin's own leg runs.
func TestSelectAffected_TestSeedInServerDepsKeepsImageGatesClosed(t *testing.T) {
	s := changed(t, filepath.Join("docs", "SELF_HOSTING.md"))
	if _, ok := s.Seeds["github.com/keyorixhq/keyorix/server/admin"]; !ok {
		t.Fatalf("server/admin (its docs test reads the file) not selected; seeds=%v", s.Seeds)
	}
	for _, g := range []string{"docker_boot", "helm_boot", "demo", "web_e2e"} {
		if s.Gates[g] {
			t.Errorf("gate %s open for a docs file only tests read", g)
		}
	}
}

func TestSelectAffected_PathGates(t *testing.T) {
	s := changed(t, "deploy/helm/keyorix/values.yaml")
	for g, want := range map[string]bool{"helm": true, "helm_boot": true, "operator": false, "migrate": false, "fuzz_targets": false} {
		if s.Gates[g] != want {
			t.Errorf("chart change: gate %s=%v, want %v", g, s.Gates[g], want)
		}
	}
	s = changed(t, "internal/saml/parse_response_fuzz_test.go")
	if !s.Gates["fuzz_targets"] || !s.Gates["fuzz_reach"] {
		t.Errorf("file with a Fuzz target changed: fuzz_targets=%v fuzz_reach=%v, want both true", s.Gates["fuzz_targets"], s.Gates["fuzz_reach"])
	}
	s = changed(t, "operator/internal/controller/doc.go")
	if !s.Gates["operator"] || s.Gates["migrate"] {
		t.Errorf("operator change: operator=%v migrate=%v, want true/false", s.Gates["operator"], s.Gates["migrate"])
	}
}

// A failure message with a newline in it must not split GITHUB_OUTPUT: a second
// line would parse as another key=value (or an invalid line that fails the
// step), so the reason the queue sees is always exactly one line.
func TestSelectAffected_GithubOutputIsOneLinePerKey(t *testing.T) {
	out := filepath.Join(t.TempDir(), "github_output")
	s := runSelect(t, "--changed", "--inject-failure", "boom\nmode=selected\r\nlegs={}", "--github-output", out)
	if s.Mode != "full" {
		t.Fatalf("injected failure: mode=%q (%s), want full", s.Mode, s.Reason)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	counts := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, _, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			t.Errorf("GITHUB_OUTPUT line without key=value: %q", sc.Text())
			continue
		}
		counts[key]++
	}
	for _, k := range []string{"mode", "reason", "legs"} {
		if counts[k] != 1 {
			t.Errorf("GITHUB_OUTPUT has %d %s= lines, want exactly 1", counts[k], k)
		}
	}
	if raw, _ := os.ReadFile(out); strings.Contains(string(raw), "\r") {
		t.Errorf("GITHUB_OUTPUT contains a CR: %q", raw)
	}
}
