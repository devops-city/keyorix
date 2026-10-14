package store

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/solewriter"
)

// TestFoldedCredentialSQL_ReadsOnlyFencedTables is the condition the memo
// (local_folded_credential_memo.go) rests on: every table the folded statement
// reads is fenced by single_writer, so no write the fence lets through can
// change its answer without the tracker seeing it. Derived from the
// statement's own text, every shape; pg_catalog/sqlite_master reads (the
// trigger proofs) are catalogs, not data, and are listed explicitly.
func TestFoldedCredentialSQL_ReadsOnlyFencedTables(t *testing.T) {
	catalogs := []string{"pg_trigger", "sqlite_master"}
	tableRE := regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)`)
	fenced := solewriter.FencedTableNames()
	for _, trig := range []string{"EXISTS (SELECT 1 FROM pg_trigger)", "EXISTS (SELECT 1 FROM sqlite_master)"} {
		for _, gen := range []string{"gen.value"} {
			for _, want := range []bool{true, false} {
				q := foldedCredentialSQL(trig, gen, want)
				var seen []string
				for _, m := range tableRE.FindAllStringSubmatch(q, -1) {
					name := strings.ToLower(m[1])
					if name == "select" || slices.Contains(catalogs, name) {
						continue
					}
					seen = append(seen, name)
					if !slices.Contains(fenced, name) {
						t.Errorf("the folded statement reads %s, which single_writer does not fence: the memo could serve a stale answer after a write to it", name)
					}
				}
				if len(seen) < 5 {
					t.Fatalf("harness: expected the statement's tables, found %v in:\n%s", seen, q)
				}
			}
		}
	}
}
