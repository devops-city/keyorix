// Package refusaldocs keeps docs/operator/startup-refusals.md honest.
//
// The page tells an operator what each start-up refusal looks like and how to
// fix it. Every entry carries a "Match" text: the stable part of the message.
// TestDocumentedRefusalsExistInCode fails when a Match text is no longer a
// string in the Go sources (the message was reworded or removed, so the page
// would send an operator searching for text that no build prints).
//
// Direction: docs -> code only is fatal. This direction cannot conflict with
// another PR: reworking a message is the author's job and the failure names the
// page entry to update.
//
// The other direction, code -> docs, is logged and NOT fatal
// (TestUndocumentedRefusalsAreListed prints the list; run with -v). Parallel
// work adds refusals to server/main.go and internal/config all the time, and a
// test that failed for each new one would block unrelated PRs on a docs edit
// they may not own. The list is the to-do for the page's next update.
//
// What the test cannot see (stated here so a green run is not over-read):
//   - Messages built from variables or helpers at run time. Literals are
//     found, and "a" + "b" concatenations of literals are folded (that is how
//     multi-line messages and the single_writer constants are written), but a
//     message that includes a named constant, a Sprintf'd fragment or text read
//     from a file is only matched on its literal pieces.
//   - Whether the page's "Real output" blocks are what the binary prints today.
//     Only the Match text is checked; the pasted output was produced by hand.
//   - Whether the cause or fix text is right.
//   - Refusals that never pass through fmt.Errorf / errors.New / log.Fatalf
//     with a literal first argument (for example a message passed through an
//     i18n lookup). The code -> docs list is built from those three call
//     forms in the boot-path packages only; see candidateDirs.
//   - Go sources outside server/ and internal/ (the cli module).
package refusaldocs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const docPath = "docs/operator/startup-refusals.md"

// sourceRoots are the directories whose non-test Go files make up the corpus
// a Match text is looked up in.
var sourceRoots = []string{"server", "internal"}

// candidateDirs are the boot-path locations scanned for the code -> docs list.
// A candidate is a literal passed to fmt.Errorf, errors.New or log.Fatal(f)
// that reads as a refusal (contains "refus"), plus every log.Fatalf message in
// server/main.go, which are refusals by construction.
var candidateDirs = []string{
	"server/main.go",
	"server/admin",
	"internal/config",
	"internal/storage/factory.go",
	"internal/storage/postgres_open.go",
	"internal/serverguard",
	"internal/solewriter",
	"internal/keyfiles",
	"internal/startup",
	"internal/secretenv",
	"internal/crypto/passphrase.go",
	"internal/encryption/exclusive_lock.go",
	"internal/encryptionops",
}

// minMatchLen keeps a Match from being a word that appears everywhere.
const minMatchLen = 15

var (
	matchLine = regexp.MustCompile(`^\*\*Match:\*\*(.*)$`)
	codeSpan  = regexp.MustCompile("`([^`]+)`")

	formatVerb = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)
)

// docMatches returns the Match texts of the page: every `code` span in a
// "**Match:**" paragraph (the line that starts with it and any lines that
// follow it up to the next blank line), and the first-column code span of each
// row of a table whose header's first cell is "Match".
func docMatches(markdown string) []string {
	var out []string
	inMatchTable := false
	inMatchPara := false
	for line := range strings.SplitSeq(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			inMatchPara = false
		}
		if m := matchLine.FindStringSubmatch(trimmed); m != nil {
			inMatchPara = true
			for _, s := range codeSpan.FindAllStringSubmatch(m[1], -1) {
				out = append(out, s[1])
			}
			continue
		}
		if inMatchPara {
			for _, s := range codeSpan.FindAllStringSubmatch(trimmed, -1) {
				out = append(out, s[1])
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "|") {
			inMatchTable = false
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		first := strings.TrimSpace(cells[0])
		switch {
		case first == "Match":
			inMatchTable = true
		case inMatchTable && !strings.HasPrefix(first, "---"):
			for _, s := range codeSpan.FindAllStringSubmatch(first, -1) {
				out = append(out, s[1])
			}
		}
	}
	return out
}

// foldString returns the value of e when it is a string literal or a +
// concatenation of them (parenthesised or not).
func foldString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return foldString(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok := foldString(x.X)
		if !ok {
			return "", false
		}
		r, ok := foldString(x.Y)
		if !ok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// goFiles lists non-test .go files under root/rel (rel may be a file).
func goFiles(root, rel string) ([]string, error) {
	var files []string
	start := filepath.Join(root, rel)
	info, err := os.Stat(start)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return []string{start}, nil
	}
	err = filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", ".scratch", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// literals returns every string a file spells out: each literal, and each
// folded concatenation of literals.
func literals(path string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BasicLit, *ast.BinaryExpr:
			if s, ok := foldString(e.(ast.Expr)); ok {
				out = append(out, s)
			}
		}
		return true
	})
	return out, nil
}

// candidates returns the refusal-looking messages of one file, keyed by text.
func candidates(path string, isMain bool) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		name := pkg.Name + "." + sel.Sel.Name
		fatal := name == "log.Fatalf" || name == "log.Fatal"
		if name != "fmt.Errorf" && name != "errors.New" && !fatal {
			return true
		}
		s, ok := foldString(call.Args[0])
		if !ok {
			return true
		}
		// "Configuration is invalid: %v" style wrappers only name the stage that
		// refused; the page describes the stages once, in "How to read an entry".
		if len(strings.TrimSpace(formatVerb.ReplaceAllString(s, ""))) < 25 {
			return true
		}
		if strings.Contains(strings.ToLower(s), "refus") || (fatal && isMain) {
			out = append(out, s)
		}
		return true
	})
	return out, nil
}

// result is what one check of a tree produced.
type result struct {
	matches      []string // Match texts found in the page
	missing      []string // Match texts with no string in the sources
	short        []string // Match texts too short to mean anything
	undocumented []string // refusal-looking messages no Match text is part of
}

// check compares the page under root with the Go sources under root.
func check(root string) (result, error) {
	var r result
	doc, err := os.ReadFile(filepath.Join(root, docPath))
	if err != nil {
		return r, err
	}
	r.matches = docMatches(string(doc))

	var corpus []string
	for _, rel := range sourceRoots {
		files, err := goFiles(root, rel)
		if err != nil {
			return r, err
		}
		for _, f := range files {
			lits, err := literals(f)
			if err != nil {
				return r, err
			}
			corpus = append(corpus, lits...)
		}
	}
	for _, m := range r.matches {
		if len(m) < minMatchLen {
			r.short = append(r.short, m)
			continue
		}
		found := false
		for _, s := range corpus {
			if strings.Contains(s, m) {
				found = true
				break
			}
		}
		if !found {
			r.missing = append(r.missing, m)
		}
	}

	seen := map[string]bool{}
	for _, rel := range candidateDirs {
		files, err := goFiles(root, rel)
		if err != nil {
			return r, err
		}
		for _, f := range files {
			cands, err := candidates(f, strings.HasSuffix(filepath.ToSlash(f), "server/main.go"))
			if err != nil {
				return r, err
			}
			for _, c := range cands {
				if seen[c] {
					continue
				}
				seen[c] = true
				documented := false
				for _, m := range r.matches {
					if strings.Contains(c, m) {
						documented = true
						break
					}
				}
				if !documented {
					r.undocumented = append(r.undocumented, c)
				}
			}
		}
	}
	sort.Strings(r.undocumented)
	return r, nil
}

// repoRoot is the module root, or KEYORIX_REFUSALDOCS_ROOT when set (a scratch
// copy of the tree, used to show the test red).
func repoRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("KEYORIX_REFUSALDOCS_ROOT"); v != "" {
		return v
	}
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
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// TestDocumentedRefusalsExistInCode is the fatal direction: docs -> code.
func TestDocumentedRefusalsExistInCode(t *testing.T) {
	r, err := check(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.matches) == 0 {
		t.Fatalf("%s has no Match texts: the page lost its machine-checked entries", docPath)
	}
	for _, m := range r.short {
		t.Errorf("%s: Match text %q is shorter than %d characters; a short text matches unrelated code, name the stable part of the message", docPath, m, minMatchLen)
	}
	for _, m := range r.missing {
		t.Errorf("%s: Match text %q is not a string in any Go file under %s: the message was reworded or removed; update the page entry (message, cause, fix) to the new text",
			docPath, m, strings.Join(sourceRoots, ", "))
	}
	t.Logf("%d Match texts checked against the Go sources", len(r.matches))
}

// TestUndocumentedRefusalsAreListed is the code -> docs direction: it logs,
// never fails. See the package comment for why.
func TestUndocumentedRefusalsAreListed(t *testing.T) {
	r, err := check(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d refusal-looking messages in the boot-path packages have no Match text on %s (not a failure; update the page when convenient):",
		len(r.undocumented), docPath)
	for _, u := range r.undocumented {
		if len(u) > 160 {
			u = u[:160] + "..."
		}
		t.Logf("  undocumented: %s", strings.ReplaceAll(u, "\n", " "))
	}
}

// TestCheckerSeesRenamedMessage shows the checker red and green on a tiny
// synthetic tree, so the guard has been watched to fail without touching the
// real sources: the page's Match text is present, then the message is renamed.
func TestCheckerSeesRenamedMessage(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	doc := "**Match:** `the widget is not configured`\n\n" +
		"| Match | meaning |\n|---|---|\n| `split across a concatenation` | x |\n"
	write(docPath, doc)
	good := "package x\nimport \"fmt\"\nfunc f() error {\n" +
		"\treturn fmt.Errorf(\"the widget is not configured: %w\", nil)\n}\n" +
		"var g = \"split across \" +\n\t\"a concatenation\"\n"
	write("internal/x/x.go", good)

	r, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.matches) != 2 || len(r.missing) != 0 || len(r.short) != 0 {
		t.Fatalf("green case: matches=%v missing=%v short=%v", r.matches, r.missing, r.short)
	}

	write("internal/x/x.go", strings.Replace(good, "the widget is not configured", "the gadget is not configured", 1))
	r, err = check(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.missing) != 1 || r.missing[0] != "the widget is not configured" {
		t.Fatalf("red case: renamed message not reported: missing=%v", r.missing)
	}
}

func TestDocMatchesParsing(t *testing.T) {
	md := "**Match:** `first text here`, `second text here`,\n`continued on next line`\n\n" +
		"prose with `not a match`\n\n" +
		"| Match | What |\n|---|---|\n| `row one match` | `ignored span` |\n\n" +
		"| Other | What |\n|---|---|\n| `not in a match table` | y |\n"
	got := strings.Join(docMatches(md), "|")
	want := "first text here|second text here|continued on next line|row one match"
	if got != want {
		t.Fatalf("docMatches = %q, want %q", got, want)
	}
}
