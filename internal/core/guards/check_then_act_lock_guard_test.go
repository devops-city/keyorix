// check_then_act_lock_guard_test.go — GUARD-2's Item 4 structural guard: fails
// when a non-test function in internal/core calls a security-check method
// (require*/guard* — this package's own naming convention for an authorizer,
// role, SoD, or admin-count/last-admin decision; confirmed by enumerating
// every existing (*KeyorixCore).require*/guard* method before writing this
// regex, not assumed) followed by a storage/core write in the SAME function,
// with NEITHER call inside the same storage.WithNamedLock acquisition, and is
// not listed in docs/check-then-act-lock-exempt.tsv with a reviewed class and
// reason.
//
// Modeled directly on atomicity_guard_test.go's TestAtomicityGuard_AuditBeforeWrite
// (Session O's O5/O-followup guard) — same shape, same caveats, different
// pattern: that guard asks "does a SUCCESS audit event precede a later
// write?"; this one asks "does a security check precede a later write with no
// shared lock between them?" Both are AST walks with NO control-flow
// awareness: a check on one branch and a write on a mutually exclusive branch
// (an if/else, a switch) is flagged exactly like a true sequential
// check-then-write. A human classifies each hit; this guard only enforces
// that every hit STAYS classified as the code changes.
//
// What this does NOT catch (stated explicitly, per this repo's own
// "ask of any mechanism: what does it silently skip, and does it say so"
// discipline):
//   - A check/write pair serialized by a ROW LOCK (SELECT ... FOR UPDATE
//     inside WithTransaction, e.g. login_lockout.go's recordFailedLogin)
//     rather than WithNamedLock: those sites don't call a require*/guard*
//     method at all (the lock IS the check), so they never enter this scan's
//     candidate set in the first place — not a gap in the walk, just outside
//     what a require*/guard*-named call can represent.
//   - A check/write pair where the write is wrapped in WithNamedLock but the
//     CHECK is a free function (not a (*KeyorixCore) method), e.g.
//     machine_identities.go's canTransitionMachine — this scan only matches
//     `c.<name>(...)` selector calls, by construction (mirroring
//     atomicityHits' own c.<Write> matching), so a free-function check is
//     invisible to it. Confirmed by direct grep: canTransitionMachine is the
//     only non-method decision function found during this guard's own
//     construction; if a future one appears, it will silently not be
//     covered — this is a known, stated limitation, not a silent one.
//   - A check and a write that are genuinely on the same WithNamedLock
//     acquisition but reached through two different helper functions this
//     scan doesn't inline (it does not do interprocedural analysis at all).
//   - A write reached only through a `tx` parameter (a storage.Storage
//     transaction handle passed into a WithTransaction closure), rather than
//     `c.storage.<Write>` or `c.<Write>` — this scan only matches those two
//     selector shapes (mirroring atomicityHits' own matching), so
//     `tx.<Write>(...)` is invisible to it. CONFIRMED to matter in practice,
//     not just theoretically: on the pre-fix code this guard's own
//     construction ran against, UpdateSCIMUser's and DeprovisionSCIMUser's
//     real last-admin-guarded writes (scim.go, GUARD-2's inventory finding)
//     all go through `tx`, so this guard did NOT independently flag that
//     gap — it was found by this session's manual inventory sweep
//     (docs/specs/check-then-act-inventory.md) instead, and this guard was
//     only verified against it retroactively. Stated here rather than
//     silently leaving the impression this guard would have caught it.
package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// checkThenActCheckCallRe matches this package's own naming convention for a
// security-check method: every existing (*KeyorixCore) authorizer/role/SoD/
// last-admin decision function in internal/core, enumerated by
// `grep -rhoE 'func \(c \*KeyorixCore\) (require|guard)[A-Za-z]+' internal/core/*.go`
// before this regex was written (2026-10-03; 30 matches, all require*/guard*
// — no third naming idiom found), is named with a require* or guard* prefix.
var checkThenActCheckCallRe = regexp.MustCompile(`^(require|guard)[A-Z]`)

type checkThenActHit struct {
	fn        string
	file      string
	checkName string
	checkLine int
	writeName string
	writeLine int
}

// scanCheckThenActHits walks every non-test, non-generated *.go file directly
// under internal/core for (*KeyorixCore) functions where a require*/guard*
// call precedes a later storage/core write, with neither inside the same
// storage.WithNamedLock closure. Mirrors scanAuditBeforeWriteHits's shape
// (atomicity_guard_test.go) almost exactly, substituting "is it inside
// WithNamedLock" for "is it inside WithTransaction", and "the last unlocked
// write" for "the last write" (a write that IS inside WithNamedLock is never
// added to the candidate list at all, so it can't be the "last write" either
// — unlike WithTransaction, which atomicity_guard_test.go tracks as fully
// exempting its OWN interior from the write-count scan but still considers
// visible to the audit-before-write scan's "lastWrite" search; the two guards
// intentionally differ here because WithNamedLock, not WithTransaction, is
// this guard's unit of safety).
func scanCheckThenActHits(t *testing.T, root string) []checkThenActHit {
	t.Helper()
	var hits []checkThenActHit
	fset := token.NewFileSet()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("check-then-act lock guard: cannot read %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		p := filepath.Join(root, name)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("check-then-act lock guard: cannot parse %s: %v", p, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			recvType := atomicityExprStr(fd.Recv.List[0].Type)
			if recvType != "*KeyorixCore" {
				continue
			}
			fnName := "(" + recvType + ")." + fd.Name.Name

			type posCall struct {
				pos  token.Pos
				name string
			}
			var checks []posCall
			var lastWrite posCall

			var walk func(n ast.Node, inLock bool)
			walk = func(n ast.Node, inLock bool) {
				ast.Inspect(n, func(m ast.Node) bool {
					call, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if sel.Sel.Name == "WithNamedLock" {
						for _, a := range call.Args {
							walk(a, true)
						}
						return false
					}
					if inLock {
						return true
					}
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "storage" {
						if atomicityWriteVerbRe.MatchString(sel.Sel.Name) && call.Pos() > lastWrite.pos {
							lastWrite = posCall{pos: call.Pos(), name: "storage." + sel.Sel.Name}
						}
						return true
					}
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "c" {
						if checkThenActCheckCallRe.MatchString(sel.Sel.Name) {
							checks = append(checks, posCall{pos: call.Pos(), name: sel.Sel.Name})
						} else if atomicityWriteVerbRe.MatchString(sel.Sel.Name) && call.Pos() > lastWrite.pos {
							lastWrite = posCall{pos: call.Pos(), name: sel.Sel.Name}
						}
					}
					return true
				})
			}
			walk(fd.Body, false)

			if lastWrite.pos == 0 {
				continue
			}
			for _, chk := range checks {
				if chk.pos < lastWrite.pos {
					hits = append(hits, checkThenActHit{
						fn: fnName, file: name,
						checkName: chk.name, checkLine: fset.Position(chk.pos).Line,
						writeName: lastWrite.name, writeLine: fset.Position(lastWrite.pos).Line,
					})
					break // one report per function, matching scanAuditBeforeWriteHits
				}
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].fn < hits[j].fn })
	return hits
}

// loadCheckThenActExemptions reads docs/check-then-act-lock-exempt.tsv
// (function\tclass\treason, same 3-field format as docs/atomicity-exempt.tsv)
// PLUS every docs/check-then-act-lock-exempt.d/*.tsv fragment (one row each —
// new exemptions go there, see that directory's README.md) into a set of
// exempted function names. A duplicate involving a fragment, a fragment that
// is not exactly one row, or a short row fails the test (readLedgerRows); a
// duplicate purely within the legacy file is logged, as it never failed before.
func loadCheckThenActExemptions(t *testing.T, path, fragDir string) map[string]bool {
	t.Helper()
	rows, legacyDups, err := readLedgerRows(path, fragDir, 3)
	if err != nil {
		t.Fatalf("check-then-act lock guard: %v", err)
	}
	for _, d := range legacyDups {
		t.Logf("check-then-act lock guard: LEGACY DUPLICATE (not failing until scripts/ledgers/migrate-to-fragments.sh, which refuses it): %s", d)
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r.fields[0]] = true
	}
	return out
}

// TestCheckThenActLockGuard_UnlockedSecurityCheck is GUARD-2's Item 4 guard:
// every internal/core function where a require*/guard* security-check call
// precedes a later storage/core write with no shared storage.WithNamedLock
// between them must be a reviewed, reasoned entry in
// docs/check-then-act-lock-exempt.tsv. A hit with no entry is either a
// genuine new cross-replica check-then-act race (fix it, per
// docs/specs/check-then-act-inventory.md's own method — wrap in
// storage.WithNamedLock keyed on the contended principal) or a function whose
// hit is a false positive from this scan's control-flow blindness (classify
// it with a one-line reason and file a `race-gap` issue per entry, per
// GUARD-2's brief) — never silently ignored.
func TestCheckThenActLockGuard_UnlockedSecurityCheck(t *testing.T) {
	hits := scanCheckThenActHits(t, "..")
	exempt := loadCheckThenActExemptions(t, "../../../docs/check-then-act-lock-exempt.tsv", "../../../docs/check-then-act-lock-exempt.d")

	var unclassified []string
	for _, h := range hits {
		if !exempt[h.fn] {
			unclassified = append(unclassified, fmt.Sprintf("%s (%s): %s@%d precedes %s@%d, no shared WithNamedLock",
				h.fn, h.file, h.checkName, h.checkLine, h.writeName, h.writeLine))
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("check-then-act lock guard: %d function(s) have a require*/guard* security check preceding a "+
			"later storage/core write with no shared storage.WithNamedLock between them, and no reviewed entry "+
			"in docs/check-then-act-lock-exempt.tsv or docs/check-then-act-lock-exempt.d/. Either wrap the check+write in storage.WithNamedLock keyed on "+
			"the contended principal (see docs/specs/check-then-act-inventory.md), or add a reviewed one-row fragment "+
			"docs/check-then-act-lock-exempt.d/<function>.tsv with a "+
			"class, a one-line reason, and a filed race-gap issue if it's a real gap left open. Unclassified:\n  %s",
			len(unclassified), strings.Join(unclassified, "\n  "))
	}
}
