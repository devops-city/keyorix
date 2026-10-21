// pg_trigger_registry_guard_test.go — no production PostgreSQL trigger escapes
// the ENABLE ALWAYS convergence test (REVIEW-COVERAGE-2).
package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// pgCreateTriggerRe matches a CREATE TRIGGER in a Go string literal.
var pgCreateTriggerRe = regexp.MustCompile(`(?i)CREATE\s+(OR\s+REPLACE\s+)?(CONSTRAINT\s+)?TRIGGER`)

// pgTriggerBodyRe matches the PostgreSQL form (a trigger that calls a function).
// SQLite triggers carry their body inline (BEGIN ... END) and have no
// ENABLE ALWAYS / session_replication_role semantics.
var pgTriggerBodyRe = regexp.MustCompile(`(?i)EXECUTE\s+(PROCEDURE|FUNCTION)`)

// TestPGTriggerInstallersAreRegistered derives the set of production Go files
// that can create a PostgreSQL trigger (CREATE TRIGGER and EXECUTE
// PROCEDURE/FUNCTION in the same non-test file) and requires each to be in
// pgTriggerInstallers (converged by
// TestPGTriggerInstallers_ConvergeToEnableAlways_Postgres) or
// pgTriggerInstallersElsewhere (named test). Also fails on a registry entry
// whose file no longer creates a trigger.
//
// What it does NOT see: a trigger statement assembled so that neither phrase
// appears in one file (for example the function call kept in another file), a
// trigger created from SQL files at run time, and the nested modules (cli,
// operator, migrate, devtools). The legacy migrations/*.sql files are pinned by
// migrations/trigger_dialect_test.go.
func TestPGTriggerInstallersAreRegistered(t *testing.T) {
	root := srcpath.RepoRoot()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "testdata" ||
				fileExists(filepath.Join(path, "go.mod"))) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- repo source walked by a test
		if err != nil {
			return err
		}
		if pgCreateTriggerRe.Match(src) && pgTriggerBodyRe.Match(src) {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	registered := map[string]bool{}
	for _, inst := range pgTriggerInstallers {
		registered[inst.file] = true
	}
	for f := range pgTriggerInstallersElsewhere {
		registered[f] = true
	}
	for _, f := range found {
		if !registered[f] {
			t.Errorf("%s creates a PostgreSQL trigger but is not in pgTriggerInstallers: add it so the convergence test proves "+
				"the next migration turns an ordinary/replica-only/disabled trigger back into ENABLE ALWAYS", f)
		}
	}
	for f := range registered {
		if !slices.Contains(found, f) {
			t.Errorf("registry names %s, which no longer creates a PostgreSQL trigger: remove the stale entry", f)
		}
	}
	if len(found) == 0 {
		t.Fatal("found no PostgreSQL trigger installer at all: the scan is broken")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
