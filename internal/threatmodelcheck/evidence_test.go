package threatmodelcheck

// THREAT-MODELS-2 item 6: the Evidence cell of every threat-model row must cite
// things that exist.
//
// For each table in docs/security/threat-models/*.md (README.md excluded) whose
// header has "ID" and "Evidence link" columns, every backticked token in a row's
// Evidence cell is classified and checked:
//
//   - a Go test or fuzz function name (Test..., Fuzz...) must be declared as
//     `func TestX(` / `func FuzzX(` in some _test.go file of the repository;
//   - a path (contains "/" or ends in a known extension; a trailing ":123" or
//     "#anchor" is ignored; "./" and "../" resolve against the document, anything
//     else against the repository root; "*" globs must match at least once) must
//     exist as a file or directory. A bare file name with no directory
//     ("csrf.go") is accepted only in a frozen document, and only if a file of
//     that name exists in the document's own directory or anywhere in the
//     repository (so it can name the wrong one of several; a new document cites
//     the full path);
//   - a Go identifier (requireShareAuthority) or Type.Method (WebhookSink.Deliver)
//     must occur as a whole word in at least one .go file cited in the SAME cell.
//
// A document that is not in frozenDocs is held to two more rules: every row's
// Evidence cell must contain at least one Test/Fuzz name (a mitigation with no
// proving test is written as a GAP row that cites the test that exists, never as
// a claim), and every backticked token must be one of the three shapes above.
//
// WHAT THIS DOES NOT CHECK, and the test says so in its log:
//
//   - that a cited test PROVES the mitigation it is cited for. It checks
//     existence only. A test can exist, pass, and be about something else; only a
//     reviewer reading the test, or running it red against the unmitigated code,
//     can say it proves anything. Do not read a green run here as "this threat
//     model is verified";
//   - that a cited test is not skipped, or that it passes (go test does that);
//   - un-backticked citations ("ADR-076", "§ Install"), and any cell of a
//     document in frozenDocs that holds a token of none of the three shapes (they
//     are counted and logged, not failed);
//   - the Mitigation, Description and Residual columns, including the GAP issue
//     numbers written there.
//
// The checker takes a root directory so TestEvidenceCheckerCalibration can show
// it red and green on a synthetic tree; the real test runs it on this repository.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const modelsDir = "docs/security/threat-models"

// frozenDocs are the threat models written before this check existed. They are
// checked for existence of what they cite but not held to the one-test-per-row
// rule. Do not add to this list: a new document is held to the full rule.
var frozenDocs = map[string]bool{
	"audit-chain.md": true, "authentication.md": true, "authorization-rbac.md": true,
	"backup-restore.md": true, "connectors.md": true, "ha-consistency.md": true,
	"kubernetes-operator.md": true, "mcp-server.md": true,
	"secret-storage-key-hierarchy.md": true, "server-api.md": true,
	"update-bundles-airgap.md": true, "web-ui.md": true,
}

var (
	reBacktick = regexp.MustCompile("`([^`]+)`")
	reTest     = regexp.MustCompile(`^(Test|Fuzz)[A-Za-z0-9_]+$`)
	reIdent    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reDotted   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	reSuffix   = regexp.MustCompile(`(:[0-9]+(-[0-9]+)?)?(#[A-Za-z0-9_.-]+)?$`)
	reTestDecl = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
)

var pathExts = map[string]bool{
	".go": true, ".md": true, ".tsv": true, ".yaml": true, ".yml": true,
	".sh": true, ".sql": true, ".proto": true, ".json": true, ".toml": true,
}

// skipDirs are never walked for test names.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".scratch": true, ".claude": true,
	".gocache": true, ".gopath": true, "vendor": true,
}

type stats struct {
	rows, tests, paths, idents, unclassified, noEvidence int
}

func repoRootDir(t testing.TB) string {
	t.Helper()
	return srcpath.RepoRoot()
}

// repoIndex is what one walk of the repository finds: every Test/Fuzz function
// declared in a _test.go file, and the base name of every file (for the bare
// file names frozen documents use).
type repoIndex struct {
	tests map[string]bool
	names map[string]bool
}

func scanRepo(root string) (repoIndex, error) {
	idx := repoIndex{tests: map[string]bool{}, names: map[string]bool{}}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		idx.names[d.Name()] = true
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- walking the repository
		if rerr != nil {
			return nil
		}
		for _, m := range reTestDecl.FindAllSubmatch(b, -1) {
			idx.tests[string(m[1])] = true
		}
		return nil
	})
	return idx, err
}

// splitCells splits a markdown table row on "|" that is neither escaped ("\|")
// nor inside a backtick span.
func splitCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var cells []string
	var cur strings.Builder
	inTick := false
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\\' && i+1 < len(rs) && rs[i+1] == '|':
			cur.WriteRune('|')
			i++
		case r == '`':
			inTick = !inTick
			cur.WriteRune(r)
		case r == '|' && !inTick:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

type row struct {
	line     int
	id       string
	evidence string
}

// parseRows returns the data rows of every table in doc that has "ID" and
// "Evidence link" header cells, and the problems found with the tables' shape.
func parseRows(doc string) (rows []row, problems []string) {
	lines := strings.Split(doc, "\n")
	idCol, evCol, width := -1, -1, 0
	inTable := false
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "|") {
			inTable, idCol, evCol = false, -1, 0
			continue
		}
		cells := splitCells(l)
		if !inTable {
			idCol, evCol = -1, -1
			for ci, c := range cells {
				switch strings.TrimSpace(c) {
				case "ID":
					idCol = ci
				case "Evidence link":
					evCol = ci
				}
			}
			inTable = true
			if idCol < 0 || evCol < 0 {
				idCol, evCol = -1, -1
			}
			width = len(cells)
			continue
		}
		if idCol < 0 {
			continue // some other table (trust boundaries, README-style lists)
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue // the |---|---| separator
		}
		if len(cells) != width {
			problems = append(problems, fmt.Sprintf("line %d: row has %d cells, header has %d (an unescaped | in a cell?)", i+1, len(cells), width))
			continue
		}
		rows = append(rows, row{line: i + 1, id: cells[idCol], evidence: cells[evCol]})
	}
	return rows, problems
}

func isPathToken(tok string) bool {
	return strings.Contains(tok, "/") || pathExts[strings.ToLower(filepath.Ext(tok))]
}

// checkDoc checks one document. cited .go files of a cell are the files an
// identifier in that cell is searched in.
func checkDoc(root, rel string, idx repoIndex, strict bool) (problems []string, st stats) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", rel, err)}, st
	}
	docDir := filepath.Dir(filepath.Join(root, filepath.FromSlash(rel)))
	rows, shape := parseRows(string(b))
	for _, p := range shape {
		problems = append(problems, rel+": "+p)
	}
	for _, r := range rows {
		st.rows++
		where := fmt.Sprintf("%s:%d (%s)", rel, r.line, r.id)
		toks := reBacktick.FindAllStringSubmatch(r.evidence, -1)
		if len(toks) == 0 {
			st.noEvidence++
			if strict {
				problems = append(problems, where+": Evidence cell cites nothing in backticks")
			}
			continue
		}
		var goFiles []string
		var idents []string
		sawTest := false
		for _, m := range toks {
			tok := strings.TrimSpace(m[1])
			switch {
			case reTest.MatchString(tok):
				st.tests++
				sawTest = true
				if !idx.tests[tok] {
					problems = append(problems, fmt.Sprintf("%s: test %s is not declared in any _test.go file", where, tok))
				}
			case isPathToken(tok) && !strings.ContainsAny(tok, " \t"):
				st.paths++
				clean := reSuffix.ReplaceAllString(tok, "")
				full := filepath.Join(root, filepath.FromSlash(clean))
				if strings.HasPrefix(clean, "./") || strings.HasPrefix(clean, "../") {
					full = filepath.Join(docDir, filepath.FromSlash(clean))
				}
				if strings.Contains(clean, "*") {
					matches, _ := filepath.Glob(full)
					if len(matches) == 0 {
						problems = append(problems, fmt.Sprintf("%s: path pattern %s matches nothing", where, tok))
					}
					continue
				}
				if _, serr := os.Stat(full); serr != nil {
					if !strict && !strings.Contains(clean, "/") {
						// A bare file name in a frozen document: the document's own
						// directory, else any file of that name in the repository.
						if _, derr := os.Stat(filepath.Join(docDir, clean)); derr == nil || idx.names[clean] {
							continue
						}
					}
					problems = append(problems, fmt.Sprintf("%s: path %s does not exist", where, tok))
					continue
				}
				if strings.HasSuffix(clean, ".go") {
					goFiles = append(goFiles, full)
				}
			case reIdent.MatchString(tok) || reDotted.MatchString(tok):
				st.idents++
				idents = append(idents, tok)
			default:
				st.unclassified++
				if strict {
					problems = append(problems, fmt.Sprintf("%s: `%s` is not a test name, a path or an identifier (cite a file path instead of a bare ID)", where, tok))
				}
			}
		}
		if strict && !sawTest {
			problems = append(problems, where+": Evidence cell names no Test/Fuzz function (a mitigation with no proving test is written as a GAP row citing the test that does exist)")
		}
		for _, id := range idents {
			if len(goFiles) == 0 {
				if strict {
					problems = append(problems, fmt.Sprintf("%s: identifier %s needs a .go file cited in the same cell", where, id))
				}
				continue
			}
			if !identInAny(goFiles, id) {
				problems = append(problems, fmt.Sprintf("%s: identifier %s does not occur in any .go file cited in the same cell", where, id))
			}
		}
	}
	return problems, st
}

func identInAny(files []string, ident string) bool {
	for part := range strings.SplitSeq(ident, ".") {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(part) + `\b`)
		found := false
		for _, f := range files {
			if b, err := os.ReadFile(f); err == nil && re.Match(b) { // #nosec G304
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// checkAll checks every threat model under root.
func checkAll(root string) (problems []string, total stats, docs []string, err error) {
	idx, err := scanRepo(root)
	if err != nil {
		return nil, total, nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(modelsDir)))
	if err != nil {
		return nil, total, nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		docs = append(docs, name)
		p, st := checkDoc(root, modelsDir+"/"+name, idx, !frozenDocs[name])
		problems = append(problems, p...)
		total.rows += st.rows
		total.tests += st.tests
		total.paths += st.paths
		total.idents += st.idents
		total.unclassified += st.unclassified
		total.noEvidence += st.noEvidence
	}
	sort.Strings(problems)
	return problems, total, docs, nil
}

// TestThreatModelEvidence_CitedFilesAndTestsExist fails when a threat-model
// Evidence cell cites a file, test or identifier that does not exist. It checks
// existence, not that the cited test proves the mitigation (see the file comment).
func TestThreatModelEvidence_CitedFilesAndTestsExist(t *testing.T) {
	problems, st, docs, err := checkAll(repoRootDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) == 0 || st.rows == 0 {
		t.Fatalf("found %d documents and %d rows: the checker is looking at nothing", len(docs), st.rows)
	}
	t.Logf("checked %d documents, %d threat rows: %d test names, %d paths, %d identifiers; "+
		"skipped %d un-classifiable tokens and %d rows without backticked evidence (frozen documents only)",
		len(docs), st.rows, st.tests, st.paths, st.idents, st.unclassified, st.noEvidence)
	for _, p := range problems {
		t.Error(p)
	}
}

// TestThreatModelsReadmeIndexesEveryDocument fails when a document in the
// directory has no link from README.md, or README links a document that is not
// there.
func TestThreatModelsReadmeIndexesEveryDocument(t *testing.T) {
	root := repoRootDir(t)
	dir := filepath.Join(root, filepath.FromSlash(modelsDir))
	b, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		if !strings.Contains(readme, "]("+name+")") {
			t.Errorf("README.md has no link to %s", name)
		}
	}
	for _, m := range regexp.MustCompile(`\]\(([A-Za-z0-9_.-]+\.md)\)`).FindAllStringSubmatch(readme, -1) {
		if _, err := os.Stat(filepath.Join(dir, m[1])); err != nil {
			t.Errorf("README.md links %s, which does not exist", m[1])
		}
	}
}

// TestEvidenceCheckerCalibration shows the checker red and green on a synthetic
// tree, so a green run on the real documents means the checker can fail ("a
// guard nobody has watched fail is not a guard").
func TestEvidenceCheckerCalibration(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("pkg/a.go", "package pkg\n\nfunc realFunc() {}\n")
	write("pkg/a_test.go", "package pkg\n\nimport \"testing\"\n\nfunc TestReal(t *testing.T) {}\n\nfunc FuzzReal(f *testing.F) {}\n")
	const header = "| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |\n|---|---|---|---|---|---|\n"
	row := func(id, evidence string) string {
		return "| " + id + " | S | d | m | " + evidence + " | r |\n"
	}
	write(modelsDir+"/good.md", header+
		row("G-1", "`pkg/a.go` `realFunc`; `TestReal`; `FuzzReal`; `../../../pkg/a_test.go`")+
		row("G-2", "`pkg/*.go`; `TestReal` (Postgres-gated)"))
	problems, st, _, err := checkAll(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 || st.rows != 2 {
		t.Fatalf("green case: want 0 problems over 2 rows, got %d problems over %d rows: %v", len(problems), st.rows, problems)
	}

	bad := map[string]string{
		"renamed test":          row("B-1", "`pkg/a.go` `realFunc`; `TestRenamed`"),
		"missing path":          row("B-2", "`pkg/gone.go`; `TestReal`"),
		"missing identifier":    row("B-3", "`pkg/a.go` `goneFunc`; `TestReal`"),
		"no test cited":         row("B-4", "`pkg/a.go`"),
		"glob matches nothing":  row("B-5", "`pkg/*.rs`; `TestReal`"),
		"bare id not a path":    row("B-6", "`INV-X-1`; `TestReal`"),
		"identifier without go": row("B-7", "`realFunc`; `TestReal`"),
		"nothing backticked":    row("B-8", "ADR-1"),
		"bare file name":        row("B-10", "`a.go`; `TestReal`"),
		"unescaped pipe":        "| B-9 | S | d | m | `TestReal` | r | extra |\n",
	}
	for name, body := range bad {
		write(modelsDir+"/bad.md", header+body)
		problems, _, _, err := checkAll(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) == 0 {
			t.Errorf("red case %q: the checker reported nothing", name)
		}
	}
}
