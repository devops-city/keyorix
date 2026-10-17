package pgdsn

// shared_database_lock_guard_test.go — the guard for #3295's class: a
// Postgres test that collides with another package's test on a database-wide
// advisory lock. go test runs packages in parallel against the one
// KEYORIX_TEST_PG_DSN database, and schema isolation does not separate
// advisory locks (they are per database), so:
//
//   - a test that runs the audit index build (BuildAuditListIndexesPostgres,
//     which takes the database-wide build lock and fails fast when it is held)
//     must run it on its own database (IsolatedDatabase or the storage
//     package's pgIsolatedDatabaseDSN), never on a search_path schema;
//   - a query that reads advisory locks from pg_locks must scope it to the
//     test's own database or backend (pg_locks lists every database's locks).
//
// What it recognizes: Go string literals in _test.go files under internal/ and
// server/ (a pg_locks query built by concatenating several literals, or held
// in a non-test file, is not seen), and a schema-isolated DSN by a call to a
// function whose name contains "IsolatedSchemaDSN" or "SearchPathDSN" in the
// same file as a BuildAuditListIndexesPostgres call (a schema DSN handed in
// from another file is not seen).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.HasPrefix(string(b), "module github.com/keyorixhq/keyorix\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root (go.mod of github.com/keyorixhq/keyorix) not found")
		}
		dir = parent
	}
}

type sharedDBLockFinding struct{ pos, msg string }

// boundPid: the query names one backend (pid = $1, pid = ?, pg_backend_pid()),
// not a join on pid, which scopes nothing.
var boundPid = regexp.MustCompile(`pid\s*=\s*(\$\d|\?|pg_backend_pid\(\))`)

// scanSharedDatabaseLockUse applies both rules to one parsed test file.
func scanSharedDatabaseLockUse(fset *token.FileSet, f *ast.File) []sharedDBLockFinding {
	var out []sharedDBLockFinding
	var buildCalls []token.Pos
	schemaDSN := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(n.Value)
			if err != nil {
				return true
			}
			low := strings.ToLower(s)
			if strings.Contains(low, "pg_locks") && strings.Contains(low, "'advisory'") &&
				!strings.Contains(low, "current_database()") && !boundPid.MatchString(low) {
				out = append(out, sharedDBLockFinding{fset.Position(n.Pos()).String(),
					"advisory pg_locks query is not scoped to this test's database (database = (SELECT oid FROM pg_database WHERE datname = current_database())) or to one backend (pid = ...)"})
			}
		case *ast.CallExpr:
			name := ""
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if name == "BuildAuditListIndexesPostgres" {
				buildCalls = append(buildCalls, n.Pos())
			}
			if strings.Contains(name, "IsolatedSchemaDSN") || strings.Contains(name, "SearchPathDSN") {
				schemaDSN = true
			}
		}
		return true
	})
	if schemaDSN {
		for _, p := range buildCalls {
			out = append(out, sharedDBLockFinding{fset.Position(p).String(),
				"BuildAuditListIndexesPostgres in a file that isolates by schema: the build lock is database-wide, run it on pgdsn.IsolatedDatabase"})
		}
	}
	return out
}

func TestSharedDatabaseLockGuard(t *testing.T) {
	root := repoRoot(t)
	files := 0
	for _, top := range []string{"internal", "server"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "shared_database_lock_guard_test.go" {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files++
			for _, fd := range scanSharedDatabaseLockUse(fset, f) {
				rel, _ := filepath.Rel(root, fd.pos)
				t.Errorf("%s: %s", rel, fd.msg)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 100 {
		t.Fatalf("scanned only %d test files: the walk is not covering the repository", files)
	}
}

// TestSharedDatabaseLockGuard_Calibration: each rule fires on the shape #3295
// had and stays quiet on the fixed one.
func TestSharedDatabaseLockGuard_Calibration(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"build on a schema DSN (the #3295 store test)", `package x
func f() { db := open(pgIsolatedSchemaDSN(t, base)); _ = BuildAuditListIndexesPostgres(ctx, db, false, t.Logf) }`, 1},
		{"build on its own database", `package x
func f() { db := open(pgdsn.IsolatedDatabase(t, base, "x")); _ = store.BuildAuditListIndexesPostgres(ctx, db, false, t.Logf) }`, 0},
		{"unscoped advisory pg_locks count", "package x\nvar q = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND classid = $1`", 1},
		{"advisory pg_locks scoped to the database", "package x\nvar q = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`", 0},
		{"advisory pg_locks joined on pid but unscoped", "package x\nvar q = `SELECT a.state FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE l.locktype = 'advisory' AND l.classid = ?`", 1},
		{"advisory pg_locks scoped to one backend", `package x
var q = "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND locktype = 'advisory' AND NOT granted)"`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x_test.go", c.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(scanSharedDatabaseLockUse(fset, f)); got != c.want {
			t.Errorf("%s: %d findings, want %d", c.name, got, c.want)
		}
	}
}
