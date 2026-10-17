package storage

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

// TestNoStarSelectInProductionSQL guards INV-STORE-explicit-column-reads: no
// production query may let the database expand `*` or `alias.*` into the result
// columns. With gorm.Config.QueryFields (gormConfig) gorm names the columns of
// its own SELECTs, but a hand-written `SELECT s.* FROM ...` or Select("c.*, ...")
// is expanded by the database, so a column added by the next release makes an
// older replica's cached plan fail mid-rolling-upgrade (Postgres 0A000) or scans
// a shape it never saw.
//
// It inspects Go string literals (not comments) in non-test sources under
// internal/ and server/, and flags:
//   - a literal containing SELECT [DISTINCT] [alias.]*
//   - a literal containing `alias.*` followed by `,`, FROM or the end, in a SQL
//     fragment that also says SELECT, or passed to a .Select( call
//
// What it does NOT see: a literal assembled from pieces at run time, and
// Select("*") (legitimate on UPDATE ... Select("*").Updates, which names every
// column on purpose). Those are covered by the behavioural run
// `go test -tags nplus1 ./internal/storage/... ./internal/core/...`
// (factory_nplus1_hook.go), which adds a column to every table.
func TestNoStarSelectInProductionSQL(t *testing.T) {
	selectStar := regexp.MustCompile(`(?i)\bselect\s+(distinct\s+)?([a-z_][a-z0-9_]*\.)?\*`)
	aliasStar := regexp.MustCompile(`(?i)(^|[\s,(])[a-z_][a-z0-9_]*\.\*\s*(,|\bfrom\b|$)`)
	hasSelect := regexp.MustCompile(`(?i)\bselect\b`)

	// Known exceptions. Each is a path-suffix + literal-fragment pair with the reason
	// and the condition for removing it.
	allow := []struct{ file, fragment, why string }{
		{
			"internal/storage/sqlitedialect/migrator.go", "FROM PRAGMA_index_list",
			"SQLite's own table-valued pragma, not an application table: a migration adding a column to one of ours cannot change its shape.",
		},
		{
			"internal/storage/store/local_machine_credentials.go", "c.*, m.state",
			"GORM fallback of the credential lookup (the raw path in credential_lookup_raw.go names its columns). " +
				"The file belongs to OPT-READPATH-2's read-path work; replace with " +
				"modelColumns(ls.db, &models.MachineIdentityCredential{}, \"c\") once that merges, then delete this entry.",
		},
	}

	root := filepath.Join("..", "..")
	var hits []string
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "server"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path) // #nosec G304 -- walking this repository's own sources
			if err != nil {
				return err
			}
			f, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				return err
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
			selectArgs := map[*ast.BasicLit]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Select" {
					for _, a := range call.Args {
						ast.Inspect(a, func(m ast.Node) bool {
							if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
								selectArgs[lit] = true
							}
							return true
						})
					}
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				bad := selectStar.MatchString(s) ||
					(aliasStar.MatchString(s) && (hasSelect.MatchString(s) || selectArgs[lit]))
				if !bad {
					return true
				}
				for _, a := range allow {
					if strings.HasSuffix(rel, a.file) && strings.Contains(s, a.fragment) {
						return true
					}
				}
				hits = append(hits, rel+":"+strconv.Itoa(fset.Position(lit.Pos()).Line)+": "+strings.TrimSpace(firstLine(s)))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(hits)
	for _, h := range hits {
		t.Errorf("star select in production SQL (name the columns, e.g. modelColumns in internal/storage/store): %s", h)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
