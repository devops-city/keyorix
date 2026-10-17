// Package docsdrift holds machine checks that fail when an operator-facing
// document names something (a config key, a server flag, an environment
// variable, a link target) that does not exist in the code (DOCS-DRIFT-1).
//
// It contains tests only. Pilot customers follow docs/ literally, so a doc that
// names a key the loader rejects, or a flag the binary does not have, is a bug
// the customer finds first; these tests find it before they do.
package docsdrift

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot returns the repository root (two levels above this package).
func repoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// configDocs are the documents whose YAML examples and key tables are checked
// against the config struct. The task brief names docs/QUICK_START.md; the file
// lives at the repository root.
var configDocs = []string{
	"docs/CONFIGURATION.md",
	"docs/SELF_HOSTING.md",
	"QUICK_START.md",
}

// commandDocs are the documents whose `keyorix-server` lines and KEYORIX_*
// variables are checked: configDocs plus docs/operator/*.md and the air-gap
// runbook.
func commandDocs(t testing.TB) []string {
	t.Helper()
	root := repoRoot(t)
	out := append([]string{}, configDocs...)
	out = append(out, "docs/AIRGAP_RUNBOOK.md")
	matches, err := filepath.Glob(filepath.Join(root, "docs", "operator", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		rel, _ := filepath.Rel(root, m)
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

func readDoc(t testing.TB, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// fence is one fenced code block of a markdown document.
type fence struct {
	Lang  string
	Body  string
	Line  int // 1-based line of the first body line
	Lines []string
}

var fenceOpen = regexp.MustCompile("^\\s*(```+|~~~+)\\s*([A-Za-z0-9_+-]*)")

// fences returns every fenced code block of a document.
func fences(doc string) []fence {
	var out []fence
	var cur *fence
	var marker string
	for i, line := range strings.Split(doc, "\n") {
		if cur == nil {
			if m := fenceOpen.FindStringSubmatch(line); m != nil {
				marker = m[1][:3]
				cur = &fence{Lang: strings.ToLower(m[2]), Line: i + 2}
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), marker) {
			cur.Body = strings.Join(cur.Lines, "\n")
			out = append(out, *cur)
			cur = nil
			continue
		}
		cur.Lines = append(cur.Lines, line)
	}
	return out
}

// proseLines returns the document's lines outside fenced code blocks, with their
// 1-based line numbers.
func proseLines(doc string) (lines []string, nums []int) {
	inFence := false
	marker := ""
	for i, line := range strings.Split(doc, "\n") {
		if m := fenceOpen.FindStringSubmatch(line); m != nil && (!inFence || strings.HasPrefix(strings.TrimSpace(line), marker)) {
			if !inFence {
				marker = m[1][:3]
			}
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		lines = append(lines, line)
		nums = append(nums, i+1)
	}
	return lines, nums
}
