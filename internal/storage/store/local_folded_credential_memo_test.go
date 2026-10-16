package store

import (
	"context"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/solewriter"
	"github.com/keyorixhq/keyorix/internal/solewriter/swstate"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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

// vouching is an authority that always vouches (memo tests only).
type vouching struct{}

func (vouching) Authoritative() bool     { return true }
func (vouching) BeginFill() swstate.Fill { return vouchingFill{} }
func (vouching) Valid(uint64) bool       { return true }

type vouchingFill struct{}

func (vouchingFill) Gen() uint64 { return 1 }
func (vouchingFill) Store() bool { return true }

// fillPointers points every nil pointer field of the struct v points to at a
// fresh zero value, so a shallow copy would share each one.
func fillPointers(t *testing.T, v any) {
	t.Helper()
	rv := reflect.ValueOf(v).Elem()
	n := 0
	for _, f := range rv.Fields() {
		if f.Kind() == reflect.Pointer && f.CanSet() {
			f.Set(reflect.New(f.Type().Elem()))
			n++
		}
	}
	if n == 0 {
		t.Fatalf("harness: %T has no pointer fields", v)
	}
}

// sharedPointers names the pointer fields of a and b (same struct type) that
// point to the same value.
func sharedPointers(a, b any) []string {
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	var out []string
	for sf, fa := range ra.Fields() {
		fb := rb.FieldByIndex(sf.Index)
		if fa.Kind() == reflect.Pointer && !fa.IsNil() && fa.Pointer() == fb.Pointer() {
			out = append(out, sf.Name)
		}
	}
	return out
}

// TestFoldMemo_HitIsADeepCopy: a memo hit hands each request its own
// credential and rows, pointer fields included, so nothing a caller does to
// them reaches the entry the next request is served from. Every pointer field
// of both types is checked (reflection), so a new one is covered too.
func TestFoldMemo_HitIsADeepCopy(t *testing.T) {
	defer swstate.Set(nil)
	swstate.Set(vouching{})
	var cred models.MachineIdentityCredential
	fillPointers(t, &cred)
	var row readPathPrefetchRow
	fillPointers(t, &row)
	ls := &LocalStorage{foldMemo: newFoldMemo()}
	ls.foldMemo.set(foldMemoKey("q", nil), foldMemoEntry{gen: 1, storedAt: time.Now(), cred: cred, state: "active",
		nodeRows: []readPathPrefetchRow{row}, hasNode: true})
	noQuery := func() (rowScanner, func(), error) {
		t.Fatal("a vouched memo hit must not run the statement")
		return nil, nil, nil
	}
	c, _, rows, ok := ls.foldedStatement(context.Background(), "q", nil, false, noQuery)
	if !ok || c == nil || len(rows) != 1 {
		t.Fatalf("expected a memo hit, got ok=%v cred=%v rows=%d", ok, c, len(rows))
	}
	e, _ := ls.foldMemo.get(foldMemoKey("q", nil), time.Now())
	if s := sharedPointers(*c, e.cred); len(s) > 0 {
		t.Errorf("the served credential shares %v with the memo entry", s)
	}
	if s := sharedPointers(rows[0], e.nodeRows[0]); len(s) > 0 {
		t.Errorf("the served row shares %v with the memo entry", s)
	}
}
