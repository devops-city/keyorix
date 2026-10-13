// full_row_write_callers_guard_test.go — the caller-chain half of the stale
// full-row-write guard, ported from the closed duplicate #2725 onto #2727's guard
// (#2926).
//
// fullRowWriteHits (full_row_write_guard_test.go) sees the PRIMITIVE: the Save /
// Select("*").Updates call inside a LocalStorage method. It does not see the stale
// write one hop away: a caller that reads a row, edits it in memory and hands the
// whole struct to such a method is the stale writer, even though the Save lives in
// the callee (#2650: SetSecretAutoRotate -> UpdateSecret). This scan finds those
// callers so each one is classified in docs/full-row-write-exempt.tsv.
//
// How it works. The writer set is DERIVED from the primitive scan: every
// `(*LocalStorage).M` method that fullRowWriteHits reports (so a new full-row writer
// is covered with no edit here). Then every non-test .go file under
// internal/storage/store and internal/core is scanned for a call `<recv>.M(...)`.
// Each call is a hit keyed (file, enclosing function, "calls:M"); it needs a ledger
// row with that key, and a caller row that matches no call fails as stale (rows
// carrying `arrives with #N` excepted, as in the primitive guard).
//
// Call forms recognised, stated so a reviewer can check the list: any selector call
// whose method NAME is a writer, on any receiver expression — `ls.M`,
// `c.storage.M`, a `tx` / `st` storage handle passed as a parameter or closure
// argument (claimItemDecisionOn's `st.UpdateAccessReviewItem`, the revert in
// activateBreakGlassLocked's `c.storage.UpdateBreakGlassActivation`), a storage
// handle held in a struct field.
//
// What it does NOT see:
//   - A call through a function value or method value (`f := st.M; f(x)`), or an
//     interface method of a different name that wraps the writer.
//   - Callers outside internal/storage/store and internal/core (server handlers, cli,
//     migrate).
//   - A call with the bare receiver identifier `c` is skipped: in internal/core `c`
//     is the *KeyorixCore receiver and its methods share names with storage methods
//     (core UpdateUser vs storage UpdateUser); the primitive is only ever reached as
//     `c.storage.M`, which is seen. A storage handle that someone names `c` would be
//     invisible.
//   - Which argument is passed. A caller that builds a fresh column-scoped struct is
//     still a hit; the ledger row says why it is safe.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fullRowWriterMethods derives the LocalStorage methods that perform a full-row
// write from the primitive hits (a method named in a "(*LocalStorage).M" hit).
func fullRowWriterMethods(hits []fullRowHit) map[string]bool {
	const prefix = "(*LocalStorage)."
	out := map[string]bool{}
	for _, h := range hits {
		if strings.HasPrefix(h.Func, prefix) {
			out[strings.TrimPrefix(h.Func, prefix)] = true
		}
	}
	return out
}

// fullRowCallerHits scans roots for calls to any writer method (see the file
// comment for the recognised forms). Model is "calls:<method>".
func fullRowCallerHits(t *testing.T, roots []string, writers map[string]bool) []fullRowHit {
	t.Helper()
	var hits []fullRowHit
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel := repoRelPath(t, path)
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fn := funcDisplayName(fd)
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := ce.Fun.(*ast.SelectorExpr)
					if !ok || !writers[sel.Sel.Name] {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "c" {
						return true // the core method of the same name, not the primitive
					}
					// The writer's own body recursing into itself is its definition,
					// not a caller (the primitive scan already covers it).
					if fn == "(*LocalStorage)."+sel.Sel.Name {
						return true
					}
					hits = append(hits, fullRowHit{
						File: rel, Func: fn, Model: fullRowCallerModelPrefix + sel.Sel.Name,
						Call: "calls", Line: fset.Position(ce.Pos()).Line,
					})
					return true
				})
			}
			return nil
		})
		require.NoError(t, err)
	}
	return hits
}

// checkFullRowCallerHits returns the problems found comparing caller hits with the
// caller rows of the ledger: un-exempted callers, and stale rows.
func checkFullRowCallerHits(hits []fullRowHit, rows []fullRowExemptRow) (unexempted, stale []string) {
	exempt := map[string]fullRowExemptRow{}
	for _, r := range rows {
		if isFullRowCallerRow(r) {
			exempt[r.key()] = r
		}
	}
	matched := map[string]bool{}
	for _, h := range hits {
		if _, ok := exempt[h.key()]; ok {
			matched[h.key()] = true
			continue
		}
		unexempted = append(unexempted, h.File+":"+strconv.Itoa(h.Line)+" "+h.Func+" calls "+strings.TrimPrefix(h.Model, fullRowCallerModelPrefix)+
			" — a full-row writer of a security-state model; hand it a column-scoped write instead, or add a reviewed row to docs/full-row-write-exempt.tsv")
	}
	for _, r := range rows {
		if isFullRowCallerRow(r) && !matched[r.key()] && !fullRowArrivesRe.MatchString(r.Reason) {
			stale = append(stale, fullRowExemptPath+":"+strconv.Itoa(r.Line)+" "+r.File+" "+r.Func+" "+r.Model)
		}
	}
	sort.Strings(unexempted)
	sort.Strings(stale)
	return unexempted, stale
}

// TestFullRowWriteGuard_NoUnexemptedCallerOfFullRowWriter is the caller-chain guard.
func TestFullRowWriteGuard_NoUnexemptedCallerOfFullRowWriter(t *testing.T) {
	prims, _ := fullRowWriteHits(t, fullRowWriteRoots)
	writers := fullRowWriterMethods(prims)
	require.NotEmpty(t, writers, "the primitive scan found no full-row-writing LocalStorage method at all: either every one was fixed (then delete this guard) or the scan stopped recognising them")
	callers := fullRowCallerHits(t, fullRowWriteRoots, writers)
	unexempted, stale := checkFullRowCallerHits(callers, loadFullRowExempt(t))
	if len(unexempted) > 0 {
		t.Errorf("%d un-exempted caller(s) of a full-row writer:\n  %s", len(unexempted), strings.Join(unexempted, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d caller exemption row(s) no longer match any call — delete them (an exemption must not outlive its site):\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
}

// TestFullRowWriteGuard_CallerScanCalibration is the red direction on a planted
// fixture: the scan must report the call shapes that matter (a storage handle
// parameter as in claimItemDecisionOn, a struct-field handle, c.storage.M as in
// activateBreakGlassLocked) and must NOT report the bare-receiver core method of the
// same name, the writer's own definition, or a call to a non-writer. It also
// proves the ledger comparison fails both ways.
func TestFullRowWriteGuard_CallerScanCalibration(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import "github.com/keyorixhq/keyorix/internal/storage/models"
func (ls *LocalStorage) UpdateThing(t *models.User) error { return ls.db.Save(t).Error }
func (ls *LocalStorage) SetThing(id uint) error { return ls.db.Model(&models.User{}).Where("id = ?", id).Updates(map[string]any{"a": 1}).Error }
func (c *KeyorixCore) claimOn(st Storage, u *models.User) error { return st.UpdateThing(u) }
func (c *KeyorixCore) viaField(u *models.User) error { return c.storage.UpdateThing(u) }
func (c *KeyorixCore) UpdateThing(u *models.User) error { return c.UpdateThing(u) }
func (c *KeyorixCore) columnScoped(id uint) error { return c.storage.SetThing(id) }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600))
	prims, _ := fullRowWriteHits(t, []string{dir})
	writers := fullRowWriterMethods(prims)
	require.Equal(t, map[string]bool{"UpdateThing": true}, writers, "only the Save-ing method is a writer; the map-Updates one is column-scoped")

	got := fullRowCallerHits(t, []string{dir}, writers)
	var funcs []string
	for _, h := range got {
		funcs = append(funcs, h.Func+"->"+h.Model)
	}
	sort.Strings(funcs)
	require.Equal(t, []string{
		"(*KeyorixCore).claimOn->calls:UpdateThing",
		"(*KeyorixCore).viaField->calls:UpdateThing",
	}, funcs)

	// Ledger comparison, both directions.
	unexempted, stale := checkFullRowCallerHits(got, nil)
	require.Len(t, unexempted, 2, "with no ledger rows every caller is un-exempted")
	require.Empty(t, stale)
	rows := []fullRowExemptRow{
		{File: got[0].File, Func: got[0].Func, Model: got[0].Model, Reason: "SAFE: test", Line: 1},
		{File: got[1].File, Func: got[1].Func, Model: got[1].Model, Reason: "SAFE: test", Line: 2},
		{File: "gone.go", Func: "(*KeyorixCore).deleted", Model: fullRowCallerModelPrefix + "UpdateThing", Reason: "SAFE: test", Line: 3},
	}
	unexempted, stale = checkFullRowCallerHits(got, rows)
	require.Empty(t, unexempted)
	require.Len(t, stale, 1, "a caller row whose call is gone must fail as stale")
}
