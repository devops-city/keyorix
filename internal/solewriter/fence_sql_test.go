package solewriter

import (
	"regexp"
	"strings"
	"testing"
)

// TestTriggerSpecs_EveryDMLGuardIsPerRow is the class guard for
// REVIEW-SINGLE-WRITER-2 N2: a statement-level trigger fires only for the
// table a statement names, so a write through a parent or partition root
// skips it. Only TRUNCATE (which has no row form, and fires every truncated
// child's statement trigger) may be guarded per statement.
func TestTriggerSpecs_EveryDMLGuardIsPerRow(t *testing.T) {
	covered := map[string]map[string]bool{}
	for _, s := range triggerSpecs("sch") {
		perRow := strings.Contains(s.rest, "FOR EACH ROW")
		for e := range strings.SplitSeq(s.events, " OR ") {
			e = strings.TrimSpace(e)
			if e != "TRUNCATE" && !perRow {
				t.Errorf("%s on %s guards %s per statement; a write through a parent skips it", s.name, s.table, e)
			}
			if covered[s.table] == nil {
				covered[s.table] = map[string]bool{}
			}
			covered[s.table][e] = true
		}
	}
	for _, tbl := range coveredTableNames() {
		for _, e := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
			if !covered[tbl][e] {
				t.Errorf("%s has no %s guard", tbl, e)
			}
		}
	}
}

// sqlCall matches a lower-case name followed by "(": a function call in the
// SQL below (keywords are upper case there).
var sqlCall = regexp.MustCompile(`[a-z_%][a-zA-Z0-9_.%]*\(`)

// sqlHint is the RAISE's HINT text, advice to a person (it names
// pg_terminate_backend), not SQL the function runs. Dynamic SQL inside
// format() literals is still scanned.
var sqlHint = regexp.MustCompile(`HINT = '(?:[^']|'')*'`)

// TestFenceSQL_QualifiesEveryFunction is the class guard for
// REVIEW-SINGLE-WRITER-2 N1: no function the fence or the guard calls is
// resolved through a search_path. Each call is pg_catalog-qualified or a
// Keyorix function qualified with the fired table's schema (%I.). The
// relations and operators are pinned by funcSearchPath / pinSessionSchema
// (TestFence_NameResolutionCannotBeHijacked shows an operator shadow red
// without that).
func TestFenceSQL_QualifiesEveryFunction(t *testing.T) {
	sources := map[string]string{
		"checkFuncBody": checkFuncBody(), "guardFuncBody": guardFuncBody(), "fenceOnlyFuncBody": fenceOnlyFuncBody(),
		"lockHeldExpr": lockHeldExpr("pid", "sch"), "fingerprintSQL": fingerprintSQL, "fenceCountSQL": fenceCountSQL,
		"belowSQLQuery": belowSQLQuery,
	}
	for _, s := range triggerSpecs("sch") {
		sources[s.name+" on "+s.table] = s.rest
	}
	allowed := map[string]bool{"coalesce(": true} // a keyword, not a function
	for name, src := range sources {
		for _, call := range sqlCall.FindAllString(sqlHint.ReplaceAllString(src, ""), -1) {
			if allowed[call] || strings.HasPrefix(call, "pg_catalog.") || strings.HasPrefix(call, "%I.") || strings.HasPrefix(call, `"sch".`) {
				continue
			}
			t.Errorf("%s calls %s unqualified: it resolves through the writer's search_path", name, call)
		}
	}
	if !strings.HasPrefix(funcSearchPath, "pg_catalog,") || !strings.HasSuffix(funcSearchPath, "pg_temp") {
		t.Errorf("funcSearchPath = %q: pg_catalog must come first and pg_temp last", funcSearchPath)
	}
}
