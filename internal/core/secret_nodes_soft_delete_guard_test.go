// secret_nodes_soft_delete_guard_test.go — INV-CORE-30's completeness sweep:
// GORM auto-scopes model-based queries on models.SecretNode to
// `deleted_at IS NULL`, but NOT a raw statement, a Table("secret_nodes") chain
// or a Joins("... secret_nodes ..."). Before this file only point tests
// (catalog_delete_project_test.go) covered those, so a new raw read of
// secret_nodes silently returned (or rewrote) trashed secrets.
//
// WHAT IT CHECKS. For every non-test .go file under internal/storage/store and
// internal/core (recursive) it parses with go/parser and looks at each LEAF
// STATEMENT (assignment, expression, return, defer, go, declaration — one
// gorm call chain or one SQL string is one leaf). If the string literals of a
// leaf make a SOURCE REFERENCE to the secret_nodes table, the same leaf must
// also say `deleted_at IS NULL` (any case/spacing), say `deleted_at IS NOT
// NULL` (an explicit trash-only reader), or call `.Unscoped()` (the explicit
// opt-in to soft-deleted rows). Otherwise the enclosing function must be in
// secretNodesRawSQLAllowlist with a reviewed reason (restore, purge,
// "including deleted" readers, DDL/metadata).
//
// SOURCE REFERENCE — the recognised forms (this list is the guard's
// definition of "raw secret_nodes access"; a reviewer can check it):
//
//  1. a literal containing `FROM secret_nodes`, `JOIN secret_nodes`,
//     `UPDATE secret_nodes`, `INSERT INTO secret_nodes` or
//     `DELETE FROM secret_nodes` (word boundary, any case, any whitespace);
//     covers Raw(, Exec(, Joins(, Select(, Where("x IN (SELECT ... FROM
//     secret_nodes)"), fmt.Sprintf templates and package-level SQL constants;
//  2. a literal that IS the table name: exactly `secret_nodes`, or
//     `secret_nodes <alias>` / `secret_nodes AS <alias>` — what Table(...) and
//     helper arguments such as countByProject(ctx, "secret_nodes", ...) carry.
//
// WHAT IT DOES NOT SEE (stated because "what does it silently skip, and does
// it say so?"):
//
//   - Column qualifiers (`secret_nodes.created_by = ?`) are not source
//     references: they presuppose the table is already in the query, normally
//     through Model(&models.SecretNode{}), which GORM scopes. A chain that
//     adds `Unscoped()` to a Model(&models.SecretNode{}) is therefore not
//     tracked at all — it needs type information this AST pass does not have.
//   - SQL assembled from fragments across several statements, or from a
//     constant defined in another file/package, is judged per literal-bearing
//     leaf: a source reference in one statement is NOT satisfied by an IS NULL
//     in a different statement of the same function. Such a function needs a
//     row (none do today). A leaf naming secret_nodes twice (two subqueries) is
//     satisfied by one predicate on it.
//   - Aliases: a predicate qualified by another table's alias (`p.deleted_at
//     IS NULL`) does not satisfy a secret_nodes reference; one qualified by
//     secret_nodes, by an alias given to it in the same leaf, or unqualified
//     does. The alias is read from `secret_nodes [AS] x` in the same leaf only.
//   - Raw SQL naming a view or a differently-spelled table, quoted identifiers
//     (`"secret_nodes"`), schema-qualified names (`public.secret_nodes`).
//   - Other packages (internal/storage/remote, server/...), generated code,
//     and the metadata/DDL spelled in a way that matches no form above (those
//     pass silently, which is fine: they are not row access).
//   - The check is textual per leaf; it does not know whether a path SHOULD
//     see deleted rows. The allowlist reason carries that judgement.
//
// Proof it goes red: TestSecretNodesSoftDelete_ScannerFixture plants each shape
// on every run; TestSecretNodesSoftDelete_MutationKillsPredicate removes a real
// `deleted_at IS NULL` from a copy of internal/storage/store and requires the
// scan to report that function.
package core

import (
	"fmt"
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

// secretNodesRawSQLAllowEntry is one reviewed row: a function whose raw
// secret_nodes access intentionally does not filter on deleted_at.
type secretNodesRawSQLAllowEntry struct {
	reason string
}

// secretNodesRawSQLAllowlist is keyed "<repo-relative file>:<function>". One
// file per row: secret_nodes_allow_entry_<slug>_test.go calling
// registerSecretNodesRawSQLAllow. This literal is empty on purpose.
var secretNodesRawSQLAllowlist = map[string]secretNodesRawSQLAllowEntry{}

var secretNodesRawSQLAllowReg = mapRegistry[secretNodesRawSQLAllowEntry]{table: secretNodesRawSQLAllowlist, label: "secretNodesRawSQLAllowlist"}

func registerSecretNodesRawSQLAllow(key string, e secretNodesRawSQLAllowEntry) {
	secretNodesRawSQLAllowReg.add(key, e)
}

var (
	snSourceRefRe = regexp.MustCompile(`(?i)\b(?:from|join|update|into)\s+secret_nodes\b`)
	snTableNameRe = regexp.MustCompile(`(?i)^\s*secret_nodes(?:\s+(?:as\s+)?[a-z_][a-z0-9_]*)?\s*$`)
	// snPredRe finds `[qualifier.]deleted_at IS [NOT] NULL`, capturing the qualifier.
	snPredRe = regexp.MustCompile(`(?i)(?:\b([a-z_][a-z0-9_]*)\.)?\bdeleted_at\s+is\s+(?:not\s+)?null\b`)
	// snAliasRe finds `secret_nodes [AS] alias` (the alias must not be an SQL keyword).
	snAliasRe = regexp.MustCompile(`(?i)\bsecret_nodes\s+(?:as\s+)?([a-z_][a-z0-9_]*)\b`)
)

var snSQLKeywords = map[string]bool{
	"on": true, "where": true, "set": true, "join": true, "left": true, "right": true, "inner": true,
	"outer": true, "cross": true, "group": true, "order": true, "limit": true, "using": true, "and": true,
	"or": true, "values": true, "for": true, "returning": true, "as": true, "union": true, "having": true,
}

// snPredicateOnSecretNodes reports whether the joined literals contain a
// deleted_at IS [NOT] NULL predicate that is unqualified, or qualified by
// secret_nodes or an alias given to it — NOT one qualified by another table's
// alias (a join of secret_nodes and projects with only `p.deleted_at IS NULL`
// must not pass).
func snPredicateOnSecretNodes(joined string) bool {
	aliases := map[string]bool{"secret_nodes": true}
	for _, m := range snAliasRe.FindAllStringSubmatch(joined, -1) {
		if a := strings.ToLower(m[1]); !snSQLKeywords[a] {
			aliases[a] = true
		}
	}
	for _, m := range snPredRe.FindAllStringSubmatch(joined, -1) {
		if q := strings.ToLower(m[1]); q == "" || aliases[q] {
			return true
		}
	}
	return false
}

// Floors under which a green result means the scanner broke (current: 23
// source-reference leaves, 19 of them satisfied in place, 4 allowlisted functions).
const (
	snMinSourceRefs = 15
	snMinSatisfied  = 10
)

type snHit struct {
	key       string // "<file>:<func>"
	line      int
	satisfied bool
}

type snScan struct {
	hits []snHit
	refs int
}

func snScanRoots(t *testing.T, repo string, roots ...string) *snScan {
	t.Helper()
	out := &snScan{}
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(repo, root), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, "generated") {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", p, perr)
			}
			rel, _ := filepath.Rel(repo, p)
			rel = filepath.ToSlash(rel)
			for _, decl := range f.Decls {
				switch dd := decl.(type) {
				case *ast.FuncDecl:
					if dd.Body != nil {
						snScanNode(fset, rel, dd.Name.Name, dd.Body, out)
					}
				case *ast.GenDecl:
					snScanNode(fset, rel, "<package-level>", dd, out)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("secret_nodes soft-delete guard: %v", err)
		}
	}
	return out
}

func snScanNode(fset *token.FileSet, rel, fn string, root ast.Node, out *snScan) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.AssignStmt, *ast.ExprStmt, *ast.ReturnStmt, *ast.DeclStmt, *ast.DeferStmt, *ast.GoStmt:
			snLeaf(fset, rel, fn, st, out)
		case *ast.GenDecl:
			if st != root {
				return true
			}
			snLeaf(fset, rel, fn, st, out)
			return false
		}
		return true
	})
}

func snLeaf(fset *token.FileSet, rel, fn string, node ast.Node, out *snScan) {
	var lits []string
	unscoped := false
	ast.Inspect(node, func(m ast.Node) bool {
		switch v := m.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if s, err := strconv.Unquote(v.Value); err == nil {
					lits = append(lits, s)
				}
			}
		case *ast.SelectorExpr:
			if v.Sel.Name == "Unscoped" {
				unscoped = true
			}
		}
		return true
	})
	ref := false
	for _, l := range lits {
		if snSourceRefRe.MatchString(l) || snTableNameRe.MatchString(l) {
			ref = true
			break
		}
	}
	if !ref {
		return
	}
	out.refs++
	joined := strings.Join(lits, " ")
	out.hits = append(out.hits, snHit{
		key:       rel + ":" + fn,
		line:      fset.Position(node.Pos()).Line,
		satisfied: unscoped || snPredicateOnSecretNodes(joined),
	})
}

// unsatisfied returns the distinct function keys with a source reference that
// does not carry its own deleted_at handling, with the first line seen.
func (s *snScan) unsatisfied() map[string]int {
	out := map[string]int{}
	for _, h := range s.hits {
		if h.satisfied {
			continue
		}
		if cur, ok := out[h.key]; !ok || h.line < cur {
			out[h.key] = h.line
		}
	}
	return out
}

func snRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s has no go.mod: %v", root, err)
	}
	return root
}

// TestSecretNodesSoftDelete_RawSQLRespectsDeletedAt is the guard proper.
func TestSecretNodesSoftDelete_RawSQLRespectsDeletedAt(t *testing.T) {
	t.Parallel()
	s := snScanRoots(t, snRepoRoot(t), "internal/storage/store", "internal/core")
	var bad []string
	for key, line := range s.unsatisfied() {
		if _, ok := secretNodesRawSQLAllowlist[key]; !ok {
			bad = append(bad, fmt.Sprintf("%s (first at line %d)", key, line))
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("INV-CORE-30: %d function(s) touch secret_nodes through raw SQL / Table / Joins without `deleted_at IS NULL` "+
			"(GORM auto-scopes only model queries) and are not allowlisted. Add the predicate, or — for a restore, purge or "+
			"\"including deleted\" reader — add ONE NEW FILE secret_nodes_allow_entry_<slug>_test.go calling "+
			"registerSecretNodesRawSQLAllow with the reason:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
}

// TestSecretNodesSoftDelete_NoStaleAllowlistRows: a row for a function that now
// filters (or no longer exists) pre-approves the shape coming back.
func TestSecretNodesSoftDelete_NoStaleAllowlistRows(t *testing.T) {
	t.Parallel()
	s := snScanRoots(t, snRepoRoot(t), "internal/storage/store", "internal/core")
	unsat := s.unsatisfied()
	var stale []string
	for key, e := range secretNodesRawSQLAllowlist {
		if strings.TrimSpace(e.reason) == "" {
			t.Errorf("allowlist row %q has no reason", key)
		}
		if _, ok := unsat[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("INV-CORE-30: allowlist row(s) match no function with an unfiltered secret_nodes reference; delete them:\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// TestSecretNodesSoftDelete_ScanPreconditionHolds guards the population, not
// only the verdict: zero unsatisfied hits is vacuous if the scanner finds no
// secret_nodes references at all.
func TestSecretNodesSoftDelete_ScanPreconditionHolds(t *testing.T) {
	t.Parallel()
	s := snScanRoots(t, snRepoRoot(t), "internal/storage/store", "internal/core")
	satisfied := 0
	for _, h := range s.hits {
		if h.satisfied {
			satisfied++
		}
	}
	if s.refs < snMinSourceRefs {
		t.Errorf("only %d secret_nodes source reference(s) found, floor %d: the matcher stopped matching", s.refs, snMinSourceRefs)
	}
	if satisfied < snMinSatisfied {
		t.Errorf("only %d reference(s) satisfied in place, floor %d: the deleted_at matcher stopped matching", satisfied, snMinSatisfied)
	}
}

// TestSecretNodesSoftDelete_ScannerFixture plants each shape so the guard can
// be seen red and green independent of the repository's contents.
func TestSecretNodesSoftDelete_ScannerFixture(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	dir := filepath.Join(repo, "internal", "storage", "store")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	src := "package fixture\n\n" +
		"func rawBad(db DB)   { db.Raw(\"SELECT id FROM secret_nodes WHERE project_id = ?\", 1) }\n" +
		"func execBad(db DB)  { db.Exec(\"UPDATE secret_nodes SET purge_at = NULL WHERE id = ?\", 1) }\n" +
		"func tableBad(db DB) { db.Table(\"secret_nodes AS s\").Where(\"s.project_id = ?\", 1) }\n" +
		"func joinBad(db DB)  { db.Joins(\"JOIN secret_nodes s ON s.id = l.secret_node_id\") }\n" +
		"func helperBad(db DB) { countByProject(db, \"secret_nodes\") }\n" +
		"const pkgBad = \"DELETE FROM secret_nodes WHERE id = 1\"\n" +
		"func rawGood(db DB)   { db.Raw(\"SELECT id FROM secret_nodes WHERE deleted_at IS NULL\") }\n" +
		"func joinGood(db DB)  { db.Joins(\"JOIN secret_nodes s ON s.id = l.id AND s.deleted_at   is  null\") }\n" +
		"func trashGood(db DB) { db.Raw(\"SELECT id FROM secret_nodes WHERE deleted_at IS NOT NULL\") }\n" +
		"func unscopedGood(db DB) { db.Unscoped().Table(\"secret_nodes\") }\n" +
		"func columnOnly(db DB) { db.Where(\"secret_nodes.project_id = ?\", 1).Order(\"secret_nodes.created_at\") }\n" +
		"func metadata(db DB)   { db.Exec(\"SELECT COUNT(*) FROM sqlite_master WHERE name = 'secret_nodes'\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	s := snScanRoots(t, repo, "internal/storage/store")
	got := map[string]bool{}
	for k := range s.unsatisfied() {
		got[strings.TrimPrefix(k, "internal/storage/store/fixture.go:")] = true
	}
	for _, want := range []string{"rawBad", "execBad", "tableBad", "joinBad", "helperBad", "<package-level>"} {
		if !got[want] {
			t.Errorf("planted violation %s not reported (guard cannot go red); got %v", want, got)
		}
	}
	for _, safe := range []string{"rawGood", "joinGood", "trashGood", "unscopedGood", "columnOnly", "metadata"} {
		if got[safe] {
			t.Errorf("safe form %s reported (guard cannot go green)", safe)
		}
	}
	if len(got) != 6 {
		t.Errorf("expected exactly 6 planted violations, got %d: %v", len(got), got)
	}
}

// TestSecretNodesSoftDelete_MutationKillsPredicate is the red proof against the
// real tree, kept permanent: copy internal/storage/store's non-test sources,
// delete one real `deleted_at IS NULL` predicate in the COPY, and require the
// scan to report that function. The anchor must occur exactly once, so a
// refactor that moves it fails here instead of making the proof vacuous.
func TestSecretNodesSoftDelete_MutationKillsPredicate(t *testing.T) {
	t.Parallel()
	const file, anchor, wantFn = "local_secrets.go",
		"LEFT JOIN secret_nodes s ON s.project_id = p.id AND s.deleted_at IS NULL", "ListProjectsWithCounts"
	repo := t.TempDir()
	dst := filepath.Join(repo, "internal", "storage", "store")
	if err := os.MkdirAll(dst, 0o750); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(snRepoRoot(t), "internal", "storage", "store")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(src, n))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if n == file {
			if c := strings.Count(string(b), anchor); c != 1 {
				t.Fatalf("mutation anchor occurs %d times in %s (want 1): the code moved, update the anchor", c, n)
			}
			b = []byte(strings.Replace(string(b), anchor, "LEFT JOIN secret_nodes s ON s.project_id = p.id", 1))
		}
		if werr := os.WriteFile(filepath.Join(dst, n), b, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	if _, ok := snScanRoots(t, snRepoRoot(t), "internal/storage/store").unsatisfied()["internal/storage/store/"+file+":"+wantFn]; ok {
		t.Fatalf("%s is already unfiltered on the real tree; the mutation proves nothing", wantFn)
	}
	if _, ok := snScanRoots(t, repo, "internal/storage/store").unsatisfied()["internal/storage/store/"+file+":"+wantFn]; !ok {
		t.Errorf("removing the deleted_at predicate from %s did not make the guard report it: the guard cannot go red on the real tree", wantFn)
	}
}
