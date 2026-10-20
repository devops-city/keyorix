package docsdrift

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// DOCS-DRIFT-1 item 4: relative links and #anchors in the docs must resolve.
//
// scripts/check-doc-links.py already implements this (links, anchors, and with
// --refs backticked repo paths) but is "not wired into CI on purpose": nothing
// ran it, so nothing failed. This is the same rule set as a Go test, so a plain
// `go test ./...` enforces it without Python or a workflow change. The script
// stays for --refs (stale backticked file paths) and for ad-hoc runs. The two
// implement the same rules independently; if they ever disagree, the script's
// output on the tree is the tie-breaker to investigate.
//
// Checked, in every *.md under docs/ plus QUICK_START.md and README.md:
//   - a relative [text](target) or ![alt](target) whose file or directory does not
//     exist (a leading "/" is relative to the repository root);
//   - a #fragment (same file or cross file) naming a .md file that has no heading
//     with that GitHub-style slug, and no <a name|id="..."> with that name.
//
// Not checked: http(s)/mailto/other-scheme links (no network), links inside
// fenced code blocks or inline code spans (quotations), reference-style links
// ([text][ref]), HTML <a href>, and fragments into non-markdown targets.

var (
	mdLink      = regexp.MustCompile(`(?:^|[^!])\[[^\]\n]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	mdImage     = regexp.MustCompile(`!\[[^\]\n]*\]\(([^)\s]+)`)
	mdHeading   = regexp.MustCompile(`^#{1,6}\s+(.*?)\s*#*\s*$`)
	mdHTMLName  = regexp.MustCompile(`<a\s+(?:name|id)="([^"]+)"`)
	mdScheme    = regexp.MustCompile(`^[a-z][a-z0-9+.\-]*:`)
	mdCodeSpan  = regexp.MustCompile("`[^`\n]*`")
	mdLinkInTxt = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
)

// headingSlug mirrors GitHub's anchor generation as scripts/check-doc-links.py
// does: lowercase, drop backticks, keep link text, drop everything but letters,
// digits, underscore, hyphen and space, then spaces become hyphens.
func headingSlug(text string) string {
	text = strings.ToLower(strings.TrimSpace(text))
	text = strings.ReplaceAll(text, "`", "")
	text = mdLinkInTxt.ReplaceAllString(text, "$1")
	var b strings.Builder
	for _, r := range text {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// docAnchors returns the set of anchors a markdown document defines (lowercase).
func docAnchors(doc string) map[string]bool {
	out := map[string]bool{}
	seen := map[string]int{}
	inFence := false
	for line := range strings.SplitSeq(doc, "\n") {
		if fenceOpen.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if m := mdHeading.FindStringSubmatch(line); m != nil {
			s := headingSlug(m[1])
			n := seen[s]
			seen[s]++
			if n == 0 {
				out[s] = true
			} else {
				out[s+"-"+strconv.Itoa(n)] = true
			}
		}
		for _, m := range mdHTMLName.FindAllStringSubmatch(line, -1) {
			out[strings.ToLower(m[1])] = true
		}
	}
	return out
}

type linkFinding struct {
	File   string // repo-relative
	Line   int
	Target string
	Why    string
}

// checkDocLinks checks the markdown file at path (inside root) and returns its
// problems. anchorsOf loads (and caches) another file's anchors.
func checkDocLinks(root, path string, anchorsOf func(string) map[string]bool) []linkFinding {
	b, err := os.ReadFile(path) // #nosec G304 -- walking the repo's docs
	if err != nil {
		return []linkFinding{{File: path, Why: err.Error()}}
	}
	rel, _ := filepath.Rel(root, path)
	rel = filepath.ToSlash(rel)
	base := filepath.Dir(path)
	var out []linkFinding
	inFence := false
	for n, line := range strings.Split(string(b), "\n") {
		if fenceOpen.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		prose := mdCodeSpan.ReplaceAllString(line, "")
		var targets []string
		for _, m := range mdLink.FindAllStringSubmatch(prose, -1) {
			targets = append(targets, m[1])
		}
		for _, m := range mdImage.FindAllStringSubmatch(prose, -1) {
			targets = append(targets, m[1])
		}
		for _, target := range targets {
			if mdScheme.MatchString(target) || strings.HasPrefix(target, "//") {
				continue
			}
			filePart, frag, _ := strings.Cut(target, "#")
			dest := path
			if filePart != "" {
				if strings.HasPrefix(filePart, "/") {
					dest = filepath.Join(root, filePart)
				} else {
					dest = filepath.Join(base, filePart)
				}
			}
			st, err := os.Stat(dest)
			if err != nil {
				out = append(out, linkFinding{rel, n + 1, target, "target does not exist"})
				continue
			}
			if frag != "" && strings.HasSuffix(dest, ".md") && !st.IsDir() {
				if !anchorsOf(dest)[strings.ToLower(frag)] {
					out = append(out, linkFinding{rel, n + 1, target, "no heading or anchor named #" + frag})
				}
			}
		}
	}
	return out
}

func newAnchorCache() func(string) map[string]bool {
	cache := map[string]map[string]bool{}
	return func(path string) map[string]bool {
		if a, ok := cache[path]; ok {
			return a
		}
		b, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			cache[path] = map[string]bool{}
			return cache[path]
		}
		cache[path] = docAnchors(string(b))
		return cache[path]
	}
}

func TestDocLinksResolve(t *testing.T) {
	root := repoRoot(t)
	anchors := newAnchorCache()
	var files []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, "QUICK_START.md"), filepath.Join(root, "README.md"))
	if len(files) < 50 {
		t.Fatalf("found only %d markdown files: the walk has drifted", len(files))
	}
	for _, f := range files {
		for _, p := range checkDocLinks(root, f, anchors) {
			t.Errorf("%s:%d: link %s: %s", p.File, p.Line, p.Target, p.Why)
		}
	}
}

// TestDocLinkCheckCatchesPlantedErrors is the red proof: a missing file, a missing
// cross-file anchor, a missing same-file anchor and a missing image must each be
// reported; working links of the same shapes (including a duplicate-heading
// suffix and an <a name>) must not.
func TestDocLinkCheckCatchesPlantedErrors(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("other.md", "# Other\n\n## Same name\n\n## Same name\n\n<a name=\"legacy\"></a>\n\n## What `is` this? (v2)\n")
	bad := write("bad.md", "[a](missing.md)\n[b](other.md#nope)\n[c](#nowhere)\n![d](img/gone.png)\n")
	good := write("good.md", "# Top\n\n[a](other.md)\n[b](other.md#same-name-1)\n[c](other.md#legacy)\n[d](#top)\n"+
		"[e](other.md#what-is-this-v2)\n[f](https://example.invalid/x#y)\n`[g](nothere.md)`\n```\n[h](nothere.md)\n```\n")

	if got := checkDocLinks(root, bad, newAnchorCache()); len(got) != 4 {
		t.Fatalf("planted doc: %d findings, want 4: %+v", len(got), got)
	}
	if got := checkDocLinks(root, good, newAnchorCache()); len(got) != 0 {
		t.Fatalf("working links reported: %+v", got)
	}
}
