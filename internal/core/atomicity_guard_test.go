// atomicity_guard_test.go — Session O's O5 repo guard: fails when a non-test
// function in internal/core makes 2+ storage writes (either c.storage.<Write>
// calls, or calls to OTHER *KeyorixCore write methods — the shape O1's
// blind-spot sweep found SetUserRoles in, invisible to a storage-only scan)
// outside a WithTransaction closure, and is not listed in
// docs/atomicity-exempt.tsv with a reviewed class and reason.
//
// This is the coordinator's txscan (scratch/txscan/main.go) and its
// corescan sibling (built during O1, not checked in), turned into a
// permanent CI-enforced guard instead of a one-off scan. Like txscan, this
// is an AST walk with no control-flow awareness: a function with two
// matching calls on MUTUALLY EXCLUSIVE branches (an if/else, a switch) is
// flagged exactly the same as one with a true sequential multi-write — O1's
// triage found this is common (11 of the original 32 txscan hits). A human
// must classify each hit; this guard only enforces that every hit HAS been
// classified and stays classified as the code changes.
//
// Session O follow-up (2026-09-29): the coordinator's second scanner,
// scratch/txscan2, adds two more checks folded in below:
//   - TestAtomicityGuard_TransactionEscape (ESCAPE): a <x>.storage.<call>
//     INSIDE a WithTransaction closure escapes the rollback (and risks a
//     SQLite single-connection deadlock) — always an error, never exempt.
//   - TestAtomicityGuard_AuditBeforeWrite (AUDIT-BEFORE-WRITE): a SUCCESS
//     audit event (writeAuditEvent/writeAuditEventFull/Log<X> that is not a
//     *Denied or writeAuditEventFailed call) that textually precedes a later
//     storage write in the same function must move after the write/commit,
//     or be listed in docs/atomicity-exempt.tsv (keyed "AUDIT:<fn>" to stay
//     distinct from the write-count exemptions above, since the same
//     function can legitimately need both kinds of entry for different
//     reasons) with a reason. Denial/failure events are exempt by
//     construction (their whole point is reporting that nothing happened).
package core

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

// atomicityWriteVerbRe decides which called method names count as writes. It is
// an ENUMERATION, with an enumeration's failure mode: a write verb missing from
// it makes the call invisible, and a function whose SECOND write uses such a
// verb silently drops below this guard's 2-write threshold and is never flagged.
//
// HOW THE LIST WAS ESTABLISHED COMPLETE (ORACLE-A-1, 2026-10-05), rather than
// extended one verb at a time: every distinct method name called as
// `c.storage.X(...)` or `c.X(...)` anywhere in internal/core's non-test,
// non-generated files was extracted (454 names), the names this regex already
// matches were subtracted, read-shaped prefixes (Get/List/Count/Is/Has/Load/
// Resolve/Require/Check/Verify/...) were subtracted, and the 23-name remainder
// was read individually. Re-run that derivation rather than guessing if a new
// write family appears.
//
// ADDED by that pass, each verified against a real mutator before being added
// (not from the prefix reading like a write):
//
//	Suspend    -- SuspendUser -> setAccountState, which "persists a new account
//	              state and writes an audit event". This was the live gap: it
//	              made (*KeyorixCore).MigrateUserToMachine show only ONE write
//	              (CreateMachineIdentity) instead of two, so it sat below the
//	              threshold and was never flagged despite committing an identity
//	              and then suspending a user in two separate transactions. That
//	              function is now atomic (#2867), so it needs no ledger row and
//	              this guard correctly does not flag it -- the verb is kept
//	              because the next function to pair a Suspend with another write
//	              should be caught, not invisible.
//	Transition -- TransitionMachineIdentityState / TransitionSecretStatus /
//	              TransitionProjectMembershipState / TransitionDynamicSecretConfigDisabled,
//	              the conditional-UPDATE state-write primitives CLAUDE.md calls
//	              load-bearing. No function trips it today; added so the first
//	              one that pairs two of them outside a transaction is caught.
//	Prune      -- PruneLoginAttempts / PruneMFAStepUpGrants / PrunePasswordHistory,
//	              deletes on storage.Storage. Also trips nothing today.
//
// DELIBERATELY NOT ADDED, both confirmed read-only despite a write-shaped
// prefix -- adding either would make this guard flag functions that write
// nothing, which is a weakening by noise:
//
//	Reauthorize -- ReauthorizeImpersonation only calls GetUser and GetSession.
//	Attest      -- AttestAccessReviewGrant's own doc: "It changes no state --
//	               the access_review.attested event is the evidence". An
//	               audit-only write is not business state, and audit ordering
//	               has its own `AUDIT:` namespace in the ledger.
//
// STILL UNVERIFIED, left out on purpose so nothing here is unconfirmed: Reserve,
// Release, Reconcile, Resume, Acknowledge, Copy, Migrate, BulkRevoke (and the
// Generate* family, which may or may not persist). Each is plausibly a write,
// none currently makes a function reach two, and the Reauthorize/Attest pair
// above is why they are not added on the strength of the prefix alone.
var atomicityWriteVerbRe = regexp.MustCompile(`^(Create|Update|Delete|Assign|Unassign|Set|Remove|Add|Revoke|Insert|Upsert|Save|Mark|Record|Increment|Rotate|Restore|Purge|Archive|Grant|Link|Unlink|Replace|Put|Store|Clear|Reset|Enable|Disable|Lock|Unlock|Consume|Approve|Reject|Expire|Touch|Bump|Append|Move|Rename|Transfer|Finalize|Complete|Cancel|Provision|Deprovision|Patch|Activate|Deactivate|Issue|Open|Close|Withdraw|Suspend|Transition|Prune)`)

type atomicityHit struct {
	fn     string // "(*KeyorixCore).Foo"
	file   string // basename, e.g. "project_members.go"
	writes []string
}

// scanAtomicityHits walks every non-test, non-generated *.go file directly
// under internal/core (not subpackages — storage/, ports/, rules/ have their
// own concerns) for funcs on *KeyorixCore or *AnomalyDetector with 2+
// storage-write or core-to-core-write calls outside WithTransaction.
func scanAtomicityHits(t *testing.T, root string) []atomicityHit {
	t.Helper()
	var hits []atomicityHit
	fset := token.NewFileSet()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		p := filepath.Join(root, name)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("atomicity guard: cannot parse %s: %v", p, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			recvType := atomicityExprStr(fd.Recv.List[0].Type)
			if recvType != "*KeyorixCore" && recvType != "*AnomalyDetector" {
				continue
			}
			var writes []string
			var walk func(n ast.Node, inTx bool)
			walk = func(n ast.Node, inTx bool) {
				ast.Inspect(n, func(m ast.Node) bool {
					call, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if sel.Sel.Name == "WithTransaction" {
						walk(sel.X, inTx)
						for _, a := range call.Args {
							walk(a, true)
						}
						return false
					}
					if inTx {
						return true
					}
					// c.storage.<Write>(...)
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "storage" {
						if atomicityWriteVerbRe.MatchString(sel.Sel.Name) {
							writes = append(writes, fmt.Sprintf("storage.%s@%d", sel.Sel.Name, fset.Position(call.Pos()).Line))
						}
						return true
					}
					// c.<Write>(...) — core-to-core write call (the SetUserRoles shape).
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "c" {
						if atomicityWriteVerbRe.MatchString(sel.Sel.Name) {
							writes = append(writes, fmt.Sprintf("%s@%d", sel.Sel.Name, fset.Position(call.Pos()).Line))
						}
					}
					return true
				})
			}
			walk(fd.Body, false)
			if len(writes) >= 2 {
				hits = append(hits, atomicityHit{
					fn:     "(" + recvType + ")." + fd.Name.Name,
					file:   name,
					writes: writes,
				})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].fn < hits[j].fn })
	return hits
}

// loadAtomicityExemptions reads docs/atomicity-exempt.tsv (function\tclass\treason,
// '#'-prefixed lines and blank lines ignored) into a set of exempted function names.
func loadAtomicityExemptions(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", path, err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			t.Fatalf("atomicity guard: %s:%d: expected 3 tab-separated fields (function, class, reason), got %d: %q", path, i+1, len(fields), line)
		}
		// A duplicate key is rejected, not merged. Both readers of this ledger
		// key on the function name and keep the LAST row, so a second plain row
		// for an already-listed function silently RECLASSIFIES it -- and for a
		// class-B function that breaks the oracle exemption resting on that class
		// (server/faultops TestConsumeFirstExemptions_MatchAtomicityLedger
		// requires B, and would start failing, or worse pass against the wrong
		// row). A function needing a second, independent classification uses a
		// key namespace instead ("AUDIT:", "JIT:" -- see the file's header).
		if out[fields[0]] {
			t.Fatalf("atomicity guard: %s:%d: duplicate entry for %q. Two rows for one function silently "+
				"reclassify it in every reader of this ledger; give the second one its own key namespace "+
				"(e.g. \"JIT:%s\") so it documents without shadowing", path, i+1, fields[0], fields[0])
		}
		out[fields[0]] = true
	}
	return out
}

// TestAtomicityGuard_UnclassifiedMultiWriteFunction is Session O's O5 guard:
// every internal/core function with 2+ storage/core writes outside
// WithTransaction must be a reviewed, reasoned entry in
// docs/atomicity-exempt.tsv. A hit with no entry is either a genuine new
// atomicity bug (fix it) or a function that needs its class/reason recorded
// (classify it per SESSION-O's A/B/C/D rubric and add the line) — never
// silently ignored.
func TestAtomicityGuard_UnclassifiedMultiWriteFunction(t *testing.T) {
	hits := scanAtomicityHits(t, ".")
	exempt := loadAtomicityExemptions(t, "../../docs/atomicity-exempt.tsv")

	var unclassified []string
	for _, h := range hits {
		if !exempt[h.fn] {
			unclassified = append(unclassified, fmt.Sprintf("%s (%s): %s", h.fn, h.file, strings.Join(h.writes, ", ")))
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("atomicity guard: %d function(s) with 2+ storage/core writes outside WithTransaction have no "+
			"reviewed entry in docs/atomicity-exempt.tsv. Classify each per SESSION-O's A/B/C/D rubric (A: wrap "+
			"in one transaction, don't exempt; B/C/D: add a line to docs/atomicity-exempt.tsv with the class and "+
			"a one-line reason). Unclassified:\n  %s", len(unclassified), strings.Join(unclassified, "\n  "))
	}
}

func atomicityExprStr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + atomicityExprStr(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// escapeHit is one <x>.storage.<call> found inside a WithTransaction closure.
type escapeHit struct {
	file, fn string
	line     int
	call     string
}

// scanEscapeHits walks every non-test, non-generated *.go file directly under
// internal/core for a WithTransaction call whose closure body contains a
// <x>.storage.<call> — a write escaping the transaction it appears to be
// inside (never rolled back with the rest; on SQLite's single-connection
// pool, a second connection acquired for the escaping call while the first
// is mid-transaction can deadlock). A nested WithTransaction call on the
// SAME tx handle (a savepoint) is fine and not flagged — this only matches
// a literal `.storage.` selector, which a correctly-written closure never
// uses (it uses the `tx` parameter).
func scanEscapeHits(t *testing.T, root string) []escapeHit {
	t.Helper()
	var hits []escapeHit
	fset := token.NewFileSet()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		p := filepath.Join(root, name)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("atomicity guard: cannot parse %s: %v", p, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			recvType := atomicityExprStr(fd.Recv.List[0].Type)
			if recvType != "*KeyorixCore" && recvType != "*AnomalyDetector" {
				continue
			}
			fnName := "(" + recvType + ")." + fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WithTransaction" {
					return true
				}
				for _, a := range call.Args {
					fl, ok := a.(*ast.FuncLit)
					if !ok {
						continue
					}
					ast.Inspect(fl.Body, func(m ast.Node) bool {
						c2, ok := m.(*ast.CallExpr)
						if !ok {
							return true
						}
						s2, ok := c2.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						if inner, ok := s2.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "storage" {
							hits = append(hits, escapeHit{
								file: name, fn: fnName, line: fset.Position(c2.Pos()).Line,
								call: fmt.Sprintf("%s.storage.%s", atomicityExprStr(inner.X), s2.Sel.Name),
							})
						}
						return true
					})
				}
				return true
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].fn < hits[j].fn })
	return hits
}

// TestAtomicityGuard_TransactionEscape is Session O follow-up's ESCAPE check
// (scratch/txscan2): NEVER exempt — a storage call escaping its own
// WithTransaction closure is always a bug (it isn't rolled back with
// everything else, and can deadlock SQLite's single connection), so there is
// no reviewed-and-safe version of this to list in the exempt TSV. Fix the
// call site (use the `tx` parameter) instead.
func TestAtomicityGuard_TransactionEscape(t *testing.T) {
	hits := scanEscapeHits(t, ".")
	if len(hits) == 0 {
		return
	}
	var lines []string
	for _, h := range hits {
		lines = append(lines, fmt.Sprintf("%s (%s:%d): %s", h.fn, h.file, h.line, h.call))
	}
	t.Fatalf("atomicity guard: %d storage call(s) escape their own WithTransaction closure -- never rolled "+
		"back with the rest of the transaction, and a real deadlock risk on SQLite's single connection. This "+
		"is always a bug, never exemptable: use the tx parameter the closure was given instead of the "+
		"receiver's own storage field. Escapes:\n  %s", len(hits), strings.Join(lines, "\n  "))
}

var atomicityAuditRe = regexp.MustCompile(`^(writeAuditEvent|writeAuditEventFull|Log[A-Z])`)
var atomicityDenialRe = regexp.MustCompile(`Denied$`)

// auditBeforeWriteHit is one function where an audit call textually precedes
// a later c.storage.<write> call in the same source.
type auditBeforeWriteHit struct {
	file, fn  string
	auditLine int
	auditCall string
	writeLine int
	writeCall string
}

// scanAuditBeforeWriteHits mirrors scratch/txscan2/before.go's
// auditBeforeWrite: for every internal/core function, find an audit call
// (c.writeAuditEvent*/c.Log<X>, EXCLUDING c.writeAuditEventFailed and any
// c.Log<X>Denied call — both are denial/failure events, exempt by
// construction since their entire point is reporting that something did NOT
// happen) whose source position is earlier than the LAST c.storage.<write>
// call in the same function body. This is control-flow-blind, same caveat as
// scanAtomicityHits: an audit on one branch and a write on a different,
// mutually exclusive branch is flagged exactly like a true sequential case.
func scanAuditBeforeWriteHits(t *testing.T, root string) []auditBeforeWriteHit {
	t.Helper()
	var hits []auditBeforeWriteHit
	fset := token.NewFileSet()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		p := filepath.Join(root, name)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("atomicity guard: cannot parse %s: %v", p, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			recvType := atomicityExprStr(fd.Recv.List[0].Type)
			if recvType != "*KeyorixCore" && recvType != "*AnomalyDetector" {
				continue
			}
			fnName := "(" + recvType + ")." + fd.Name.Name

			type auditCall struct {
				pos  token.Pos
				name string
			}
			var audits []auditCall
			var lastWrite token.Pos
			var lastWriteName string
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				s, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "c" &&
					atomicityAuditRe.MatchString(s.Sel.Name) &&
					s.Sel.Name != "writeAuditEventFailed" && !atomicityDenialRe.MatchString(s.Sel.Name) {
					audits = append(audits, auditCall{pos: call.Pos(), name: s.Sel.Name})
				}
				if inner, ok := s.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "storage" && atomicityWriteVerbRe.MatchString(s.Sel.Name) {
					if call.Pos() > lastWrite {
						lastWrite, lastWriteName = call.Pos(), s.Sel.Name
					}
				}
				return true
			})
			if lastWrite == 0 {
				continue
			}
			for _, a := range audits {
				if a.pos < lastWrite {
					hits = append(hits, auditBeforeWriteHit{
						file: name, fn: fnName,
						auditLine: fset.Position(a.pos).Line, auditCall: a.name,
						writeLine: fset.Position(lastWrite).Line, writeCall: lastWriteName,
					})
					break // one report per function, matching scratch/txscan2/before.go
				}
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].fn < hits[j].fn })
	return hits
}

// loadAuditExemptions reads docs/atomicity-exempt.tsv the same way
// loadAtomicityExemptions does, but only rows whose function field starts
// with the "AUDIT:" prefix -- kept distinct from the write-count exemptions
// above because the SAME function can legitimately need an entry for both
// checks, for different reasons.
func loadAuditExemptions(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", path, err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			t.Fatalf("atomicity guard: %s:%d: expected 3 tab-separated fields (function, class, reason), got %d: %q", path, i+1, len(fields), line)
		}
		if after, ok := strings.CutPrefix(fields[0], "AUDIT:"); ok {
			out[after] = true
		}
	}
	return out
}

// TestAtomicityGuard_AuditBeforeWrite is Session O follow-up's
// AUDIT-BEFORE-WRITE check (scratch/txscan2): a SUCCESS audit event written
// before a later storage call in the same function claims an outcome before
// it's known -- if that later write then fails, the audit trail already
// asserted something that didn't (fully) happen. Denial/failure events are
// exempt by construction (loadAuditExemptions only loads "AUDIT:"-prefixed
// TSV rows); every other hit needs a reviewed "AUDIT:<fn>" entry explaining
// why it's safe (e.g. a false positive from a mutually exclusive branch, or
// an event describing a fact that's already true regardless of the later
// write's outcome), or the event should move after the write/commit.
func TestAtomicityGuard_AuditBeforeWrite(t *testing.T) {
	hits := scanAuditBeforeWriteHits(t, ".")
	exempt := loadAuditExemptions(t, "../../docs/atomicity-exempt.tsv")

	var unclassified []string
	for _, h := range hits {
		if !exempt[h.fn] {
			unclassified = append(unclassified, fmt.Sprintf("%s (%s): audit call %s@%d precedes storage.%s@%d",
				h.fn, h.file, h.auditCall, h.auditLine, h.writeCall, h.writeLine))
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("atomicity guard: %d function(s) have a SUCCESS audit event that precedes a later storage "+
			"write in the same function, with no reviewed \"AUDIT:<fn>\" entry in docs/atomicity-exempt.tsv. "+
			"Either move the audit call after the write/commit, or add a reviewed AUDIT:<fn> line explaining "+
			"why it's safe. Unclassified:\n  %s", len(unclassified), strings.Join(unclassified, "\n  "))
	}
}
