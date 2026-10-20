package migrations

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// createTriggerRe captures the name of every CREATE TRIGGER statement.
var createTriggerRe = regexp.MustCompile(`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([A-Za-z0-9_]+)"?(.*?);`)

// pgTriggerBodyRe marks the PostgreSQL form: the trigger calls a function.
var pgTriggerBodyRe = regexp.MustCompile(`(?i)EXECUTE\s+(PROCEDURE|FUNCTION)`)

// pgTriggersWithoutEnableAlways returns the PostgreSQL-form triggers created in
// sql that the same file never turns ENABLE ALWAYS. A SQLite trigger (inline
// BEGIN ... END body) has no session_replication_role semantics and is skipped.
func pgTriggersWithoutEnableAlways(sql string) []string {
	var missing []string
	for _, m := range createTriggerRe.FindAllStringSubmatch(sql, -1) {
		name, rest := m[1], m[2]
		if !pgTriggerBodyRe.MatchString(rest) {
			continue
		}
		enable := regexp.MustCompile(`(?i)ENABLE\s+ALWAYS\s+TRIGGER\s+"?` + regexp.QuoteMeta(name) + `"?\b`)
		if !enable.MatchString(sql) {
			missing = append(missing, name)
		}
	}
	return missing
}

// TestPGTriggersInMigrationsAreEnableAlways: every PostgreSQL trigger a file in
// migrations/ creates is made ENABLE ALWAYS in the same file. An ordinary
// trigger does not fire for a session_replication_role = replica writer (the
// #3361 class), which a Helm postgresql.settings server default can make every
// server session (#3246). Today every trigger here is SQLite-form; this pins
// that a PostgreSQL one cannot be added without ENABLE ALWAYS.
//
// The live PostgreSQL triggers are installed from Go, not from these files:
// internal/storage/store TestPGTriggerInstallersAreRegistered covers those.
func TestPGTriggersInMigrationsAreEnableAlways(t *testing.T) {
	files, err := filepath.Glob("*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no migrations found: the glob is broken")
	}
	triggers := 0
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- fixed glob in this directory
		if err != nil {
			t.Fatal(err)
		}
		triggers += len(createTriggerRe.FindAllString(string(src), -1))
		for _, name := range pgTriggersWithoutEnableAlways(string(src)) {
			t.Errorf("%s creates PostgreSQL trigger %s without ALTER TABLE ... ENABLE ALWAYS TRIGGER %s in the same file", f, name, name)
		}
	}
	if triggers == 0 {
		t.Fatal("found no CREATE TRIGGER at all (005 and 010 have three): the matcher is broken")
	}
}

// TestPGTriggersWithoutEnableAlways_Matcher shows the check both ways.
func TestPGTriggersWithoutEnableAlways_Matcher(t *testing.T) {
	cases := []struct {
		name, sql string
		want      int
	}{
		{"sqlite form", "CREATE TRIGGER t1 AFTER INSERT ON a BEGIN UPDATE b SET x = 1; END;", 0},
		{"pg form, no enable", "CREATE TRIGGER t2 BEFORE UPDATE ON a FOR EACH ROW EXECUTE FUNCTION f();", 1},
		{"pg form, ordinary enable only", "CREATE TRIGGER t3 BEFORE UPDATE ON a FOR EACH ROW EXECUTE PROCEDURE f();\nALTER TABLE a ENABLE TRIGGER t3;", 1},
		{"pg form, enable always", "CREATE TRIGGER t4 BEFORE UPDATE ON a FOR EACH ROW EXECUTE PROCEDURE f();\nALTER TABLE a ENABLE ALWAYS TRIGGER t4;", 0},
		{"pg form, enable always on another trigger", "CREATE TRIGGER t5 BEFORE UPDATE ON a FOR EACH ROW EXECUTE PROCEDURE f();\nALTER TABLE a ENABLE ALWAYS TRIGGER t55;", 1},
		{"pg form, quoted, or replace", `CREATE OR REPLACE TRIGGER "t6" AFTER INSERT ON a FOR EACH STATEMENT EXECUTE FUNCTION f(); ALTER TABLE a ENABLE ALWAYS TRIGGER "t6";`, 0},
	}
	for _, tc := range cases {
		if got := pgTriggersWithoutEnableAlways(tc.sql); len(got) != tc.want {
			t.Errorf("%s: got %v, want %d missing", tc.name, got, tc.want)
		}
	}
}
