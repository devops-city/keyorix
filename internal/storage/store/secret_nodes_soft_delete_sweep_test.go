// secret_nodes_soft_delete_sweep_test.go — INV-CORE-30 (#2498) repo-wide
// structural guard.
//
// SecretNode.DeletedAt is a soft delete (ADR-033). GORM adds
// "deleted_at IS NULL" automatically to queries built from the model
// (db.Model(&models.SecretNode{}), db.Find(&[]models.SecretNode{}), ...), but
// NOT to SQL that names the table itself: Raw/Exec text, Table("secret_nodes"),
// a Joins("JOIN secret_nodes ...") from another model, or a
// "... IN (SELECT id FROM secret_nodes ...)" subquery. ADR-033 had to fix six
// such sites by hand; before this test only point tests covered individual
// ones. This walks every non-test .go file in the repository with go/ast and
// requires every SQL table reference to secret_nodes to either filter
// deleted_at or be allowlisted with a reason.
//
// Call forms this RECOGNISES (a Go string literal, quoted or raw, whose value
// is one of):
//   - "... FROM secret_nodes ...", "... JOIN secret_nodes ...",
//     "UPDATE secret_nodes ...", "INSERT INTO secret_nodes ..." (any case,
//     anywhere in the literal, optional alias after the table name);
//   - exactly "secret_nodes" or "secret_nodes [AS] <alias>" -- the argument
//     shape of Table(...), and of helpers that take a table name and pass it to
//     Table(...) (countByProject in local_billing.go).
//
// A recognised site is SATISFIED when:
//   - it has an alias: some string literal in the same enclosing top-level
//     function contains "<alias>.deleted_at" -- function scope, because a
//     chain is often built across statements
//     (q := ...Table("secret_nodes AS s"); q = q.Where("s.deleted_at IS NULL"));
//   - it is an unaliased FROM/JOIN/UPDATE/INTO reference: the alias is
//     "secret_nodes" itself, so "secret_nodes.deleted_at" is required. An
//     unqualified deleted_at is NOT accepted here: in
//     "secret_id IN (SELECT id FROM secret_nodes WHERE ...) AND deleted_at IS NULL"
//     the unqualified column belongs to the OUTER table (DeleteProject's real
//     share-revocation query has exactly this shape);
//   - it is a bare table-name argument with no alias (Table("secret_nodes"),
//     countByProject(ctx, "secret_nodes", ...)): some string literal in the
//     same enclosing STATEMENT contains an unqualified "deleted_at" -- such a
//     query has one table, so an unqualified column is unambiguous, but only
//     within that one statement.
//
// Filtering "deleted_at IS NOT NULL" (trash listing, purge) also satisfies the
// check: the rule is that the query handles soft-delete explicitly, not that
// it excludes deleted rows.
//
// What this does NOT see, by construction:
//   - a table name assembled at runtime from pieces ("secret_" + "nodes",
//     fmt.Sprintf("%s_nodes", ...)), or obtained from a Go expression rather
//     than a literal (stmt.Table, a TableName() method -- SecretNode declares
//     none today);
//   - whether the deleted_at mention is actually correct (e.g. "s.deleted_at"
//     inside a comment-like SQL string, or on the wrong side of an OR) -- it is
//     a presence check, not a SQL parser;
//   - a same-named alias in the same function that belongs to another query;
//   - a deliberate Unscoped() on a model-based query -- that is an explicit
//     opt-out GORM already makes visible, not a silent bypass.
//
// Validated against the real defects, not only planted ones: run over the
// source tree as of d33316e6^ (just before ADR-033 added the filters), this
// recognises and flags exactly ADR-033's six historical sites --
// ListProjectsWithCounts, MostAccessedSecrets, UnusedSecrets,
// ListProjectSecretsForDrift, and both ListSharedSecrets queries.
//
// Migration code (DDL, backfills) is exempted by file below, deliberately:
// schema changes and backfills must reach every row, soft-deleted included.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// secretNodesSweepExemptFiles are files whose secret_nodes references are
// migration/backfill SQL, keyed by repo-relative path. Each must still exist,
// so a rename cannot silently widen the exemption to nothing (or the next file
// to take its name).
var secretNodesSweepExemptFiles = map[string]string{
	"internal/storage/factory.go":            "migrateDatabase DDL and backfills: schema changes must reach every row, soft-deleted included",
	"internal/storage/normalize_backfill.go": "name_folded backfill: must normalize soft-deleted rows too, or a restore lands an un-normalized name",
	// Same class as factory.go's entry, just living in this package so the
	// cache's own tests build their schema with the one definition rather than a
	// second copy that could drift (see that file's header). Two kinds of
	// statement, neither of which can filter deleted_at: ALTER TABLE / CREATE
	// TRIGGER are DDL with no WHERE clause at all, and the SQLite trigger body's
	// nested `UPDATE secret_nodes SET cache_epoch = ... WHERE id = NEW.id` must
	// fire for EVERY updated row including a soft-deleted one — a soft-deleted
	// row is still a row, and skipping its stamp would let a cache entry survive
	// a restore. Soft-delete scoping for this cache belongs in the READ path
	// (readLiveNodeStamp and GetSecret both go through Model(&SecretNode{}),
	// which auto-scopes deleted_at IS NULL), not in the trigger.
	"internal/storage/store/secret_node_cache_epoch.go": "cache_epoch DDL and trigger body: schema changes and the trigger's own nested UPDATE must reach every row, soft-deleted included",
}

// secretNodesSoftDeleteAllowlist names query sites that deliberately do NOT
// filter secret_nodes.deleted_at, keyed "<repo-relative file>:<function>", with
// the reason. Every entry must still match at least one unfiltered site, so a
// stale entry fails instead of silently pre-approving a future one.
var secretNodesSoftDeleteAllowlist = map[string]string{
	"internal/storage/store/local_secrets.go:deleteProjectCascade":                "revokes ShareRecords for every secret in the project via a subquery that must ALSO reach the secrets this same transaction just soft-deleted (#119 residual / #370) -- filtering deleted_at would skip exactly the rows it exists for",
	"internal/storage/store/local_secret_acl.go:DeleteSecretACLsByUserAndProject": "offboarding (RemoveProjectMember, CWE-284): removes the user's ACL grants on soft-deleted secrets too -- otherwise a later restore would silently revive access for a user no longer in the project",
}

// secretNodesSweepKnownSites are functions the recogniser must find as
// secret_nodes table-reference sites. They pin each recognised call form to a
// real instance, so a regex or walk regression that goes blind to one form
// fails here instead of passing vacuously.
var secretNodesSweepKnownSites = []string{
	"internal/storage/store/local_sharing.go:ListSharedSecrets",                   // Raw "FROM secret_nodes s"
	"internal/storage/store/local_audit.go:MostAccessedSecrets",                   // Joins("JOIN secret_nodes s ...")
	"internal/storage/store/local_audit.go:UnusedSecrets",                         // Table("secret_nodes AS s") + later Where
	"internal/storage/store/local_usage.go:GetProjectUsageStats",                  // Table("secret_nodes"), unaliased
	"internal/storage/store/local_billing.go:billingCountsByProject",              // helper arg "secret_nodes"
	"internal/storage/store/local_secret_acl.go:DeleteSecretACLsByUserAndProject", // IN (SELECT ... FROM secret_nodes ...)
}

var (
	// FROM/JOIN/UPDATE/INTO secret_nodes, optional [AS] alias.
	secretNodesSQLRef = regexp.MustCompile(`(?i)\b(?:from|join|update|into)\s+secret_nodes\b(?:\s+(?:as\s+)?([a-z_][a-z0-9_]*))?`)
	// A literal that is only the table name (Table(...) / table-name helper arg).
	secretNodesTableArg  = regexp.MustCompile(`(?i)^\s*secret_nodes(?:\s+(?:as\s+)?([a-z_][a-z0-9_]*))?\s*$`)
	unqualifiedDeletedAt = regexp.MustCompile(`(?i)(?:^|[^.a-z0-9_])deleted_at\b`)
)

// sqlKeywordsNotAlias are words that can follow "secret_nodes" in SQL without
// being an alias.
var sqlKeywordsNotAlias = map[string]bool{
	"where": true, "on": true, "join": true, "left": true, "right": true, "inner": true,
	"outer": true, "cross": true, "group": true, "order": true, "limit": true, "set": true,
	"union": true, "having": true, "using": true, "natural": true, "full": true, "values": true,
	"returning": true, "offset": true, "for": true, "default": true,
}

type secretNodesSite struct {
	File, Func string
	Line       int
	Alias      string // "" when unaliased
	Satisfied  bool
}

func (s secretNodesSite) key() string { return s.File + ":" + s.Func }

func TestSecretNodesRawQueries_FilterSoftDelete(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed -- cannot locate the repo root")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..") // internal/storage/store -> root

	for rel := range secretNodesSweepExemptFiles {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Errorf("exempt file %s no longer exists -- remove or update its secretNodesSweepExemptFiles entry: %v", rel, err)
		}
	}

	sites := discoverSecretNodesSites(t, repoRoot)

	found := map[string]bool{}
	for _, s := range sites {
		found[s.key()] = true
	}
	for _, k := range secretNodesSweepKnownSites {
		if !found[k] {
			t.Errorf("known secret_nodes query site %s was not recognised -- the sweep has gone blind to one of its call forms (or the function was renamed; update secretNodesSweepKnownSites)", k)
		}
	}
	if len(sites) < 10 {
		t.Fatalf("recognised only %d secret_nodes query site(s); expected at least 10 -- the walk is almost certainly skipping files", len(sites))
	}

	usedAllow := map[string]bool{}
	var violations []string
	for _, s := range sites {
		if s.Satisfied {
			continue
		}
		if reason, ok := secretNodesSoftDeleteAllowlist[s.key()]; ok {
			usedAllow[s.key()] = true
			t.Logf("allowlisted unfiltered secret_nodes site %s:%d: %s", s.File, s.Line, reason)
			continue
		}
		want := "unqualified deleted_at in the same statement"
		if s.Alias != "" {
			want = s.Alias + ".deleted_at in the same function"
		}
		violations = append(violations, s.File+":"+strconv.Itoa(s.Line)+" ("+s.Func+"): no "+want)
	}
	for k := range secretNodesSoftDeleteAllowlist {
		if !usedAllow[k] {
			t.Errorf("secretNodesSoftDeleteAllowlist entry %s matches no unfiltered secret_nodes site any more -- delete the entry", k)
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("found %d SQL reference(s) to secret_nodes that do not filter deleted_at:\n  %s\n"+
			"GORM's soft-delete scope does not apply to Raw/Table/Joins/subquery SQL that names the table (ADR-033). "+
			"Add \"<alias>.deleted_at IS NULL\" (or IS NOT NULL, if the query is about deleted rows), "+
			"use db.Model(&models.SecretNode{}) instead, or -- only if reaching soft-deleted secrets is the point -- "+
			"add the function to secretNodesSoftDeleteAllowlist with the reason.",
			len(violations), strings.Join(violations, "\n  "))
	}
}

func discoverSecretNodesSites(t *testing.T, root string) []secretNodesSite {
	t.Helper()
	fset := token.NewFileSet()
	var sites []secretNodesSite
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "web" || name == "dist" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if _, exempt := secretNodesSweepExemptFiles[rel]; exempt {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !strings.Contains(string(src), "secret_nodes") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		sites = append(sites, secretNodesSitesInFile(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return sites
}

func secretNodesSitesInFile(fset *token.FileSet, f *ast.File, rel string) []secretNodesSite {
	var sites []secretNodesSite
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			// Package-level SQL constants are attributed to no function; none
			// reference secret_nodes today. If one ever does, the site is
			// still found at its use only if the use is a literal -- see the
			// file comment's "does NOT see" list.
			continue
		}
		funcLits := stringLiterals(fn.Body)
		// Walk statements, tracking the innermost enclosing statement for
		// each literal.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			stmt, ok := n.(ast.Stmt)
			if !ok {
				return true
			}
			if _, isBlock := stmt.(*ast.BlockStmt); isBlock {
				return true
			}
			for _, lit := range directLiterals(stmt) {
				alias, isRef := secretNodesRef(lit.value)
				if !isRef {
					continue
				}
				site := secretNodesSite{File: rel, Func: fn.Name.Name, Line: fset.Position(lit.pos).Line, Alias: alias}
				if alias != "" {
					needle := strings.ToLower(alias) + ".deleted_at"
					for _, v := range funcLits {
						if strings.Contains(strings.ToLower(v), needle) {
							site.Satisfied = true
							break
						}
					}
				} else {
					for _, v := range stringLiterals(stmt) {
						if unqualifiedDeletedAt.MatchString(v) {
							site.Satisfied = true
							break
						}
					}
				}
				sites = append(sites, site)
			}
			return true
		})
	}
	return sites
}

// secretNodesRef reports whether a literal's value references secret_nodes as
// a table, and the alias it is referenced by: the declared alias, or
// "secret_nodes" itself for a FROM/JOIN/UPDATE/INTO reference with none (SQL
// can then qualify columns as secret_nodes.col), or "" for a bare table-name
// argument (Table("secret_nodes")), whose columns are written unqualified.
func secretNodesRef(v string) (alias string, ok bool) {
	if m := secretNodesTableArg.FindStringSubmatch(v); m != nil {
		if m[1] != "" && !sqlKeywordsNotAlias[strings.ToLower(m[1])] {
			return m[1], true
		}
		return "", true
	}
	m := secretNodesSQLRef.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	if m[1] != "" && !sqlKeywordsNotAlias[strings.ToLower(m[1])] {
		return m[1], true
	}
	// Unaliased inside a SQL statement: require the qualified form -- see the
	// file comment for the subquery shape an unqualified match would misread.
	return "secret_nodes", true
}

type strLit struct {
	value string
	pos   token.Pos
}

// directLiterals returns the string literals belonging to stmt itself, not to
// statements nested inside it (an if/for body is attributed to its own inner
// statements, so a literal is reported exactly once, at its innermost
// statement).
func directLiterals(stmt ast.Stmt) []strLit {
	var out []strLit
	ast.Inspect(stmt, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if inner, ok := n.(ast.Stmt); ok && inner != stmt {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false // a closure's statements are visited on their own
		}
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if v, err := strconv.Unquote(bl.Value); err == nil {
				out = append(out, strLit{v, bl.Pos()})
			}
		}
		return true
	})
	return out
}

func stringLiterals(n ast.Node) []string {
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if v, err := strconv.Unquote(bl.Value); err == nil {
				out = append(out, v)
			}
		}
		return true
	})
	return out
}
