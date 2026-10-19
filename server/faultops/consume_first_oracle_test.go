// consume_first_oracle_test.go teaches oracle (a)'s ERROR branch the one
// state-change-on-error shape this repository has ALREADY reviewed, classified
// and machine-enforced as correct: docs/atomicity-exempt.tsv class B,
// "consume-first by design -- a single-use value is consumed BEFORE later work
// and must stay consumed even if later work fails (replay protection)".
//
// Why this is a separate file and not another knownOpenTolerances row: a
// tolerance says "a filed, not-yet-fixed finding". These are not findings. The
// functions involved carry their own `// atomicity: consume-first by design`
// marker comment, a class-B row in docs/atomicity-exempt.tsv, and a verifying
// *_FailsClosed test; internal/core/guards/atomicity_guard_test.go already fails the
// build if either stops being classified. Oracle (a) was the only mechanism in
// the repo that did not know about that ledger, so it read a deliberately
// RETAINED consumption as a partial commit -- and because the consumption
// happens before ANY faulted call, every storage method on the op reproduces
// it, which is why per-(method, nth) tolerances for this shape grow without
// ever converging (see #2549's four bulk-approve rows for the same treadmill).
//
// WHAT THIS VERIFIES. For an op with an entry below, and only on a reported
// ERROR, that the ONLY difference between this run's OWN before and after
// state is the declared consumption:
//   - consumedColumns: the named columns of the named tables, and
//   - consumedByDeletion: the named tables, and then only under a PURE ROW
//     SUBTRACTION -- rows may disappear, but a row that was ADDED or EDITED
//     makes the exemption refuse.
//
// Every other table and column must be byte-identical to this run's own
// pre-fault state. If anything else moved, the oracle still fails. That is the
// load-bearing property: it is NOT "class B functions may leave state behind",
// which would mask a genuine partial commit inside the same function.
//
// WHAT THIS DOES NOT VERIFY, stated explicitly per CLAUDE.md:
//   - Audit content. outcomeLogTables (AuditEvent/SecretAccessLog/Notification)
//     are excluded from the comparison, on the SAME reasoning the (a) SUCCESS
//     branch's onlyOutcomeLogTables already states: oracle (c) runs first and
//     would have caught a fail-open-authz cause before execution reaches here.
//     A wrong audit *message* on a consume-first error path is invisible here.
//   - Whether the consume-first design is the right design. It takes
//     docs/atomicity-exempt.tsv's class-B classification as given, and
//     TestConsumeFirstExemptions_MatchAtomicityLedger refuses any entry whose
//     function the ledger does not classify B -- so this list cannot drift
//     into blessing a function nobody reviewed, but it also does not re-derive
//     that review.
//   - The SUCCESS branch. A reported success is compared against the
//     fault-free REFERENCE run, a different question; this exemption is
//     deliberately error-branch-only.
package faultops

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

type consumeFirstExemption struct {
	// op is the opCatalog key. Checked against opCatalog by
	// TestConsumeFirstExemptions_OpsExist, so a route rename cannot leave a
	// silently-dead entry behind.
	op string
	// fn is the consuming function, spelled EXACTLY as docs/atomicity-exempt.tsv
	// spells it -- that string equality is what ties this entry to the ledger's
	// class-B classification.
	fn string
	// consumedColumns: table -> columns that carry the consumption marker and
	// may therefore differ on an error return.
	consumedColumns map[string][]string
	// consumedByDeletion: tables whose consumption is a row DELETE. Accepted
	// only under pureRowSubtraction.
	consumedByDeletion []string
	// maxRowsRemoved caps how many rows a consumedByDeletion table may lose.
	// Without it, "pure subtraction" would accept an op that deleted EVERY row
	// of the table as readily as the one row it was supposed to consume. A
	// table listed in consumedByDeletion with no cap here is unbounded, and
	// TestConsumeFirstExemptions_Documented refuses that, so the cap cannot be
	// forgotten rather than deliberately omitted.
	maxRowsRemoved map[string]int
	// why is the one-line reason, printed in the ACCEPTABLE-BY-DESIGN log line
	// so a passing run still says what it accepted and on what grounds.
	why string
}

var consumeFirstExemptions = []consumeFirstExemption{
	// #2817. DisableMFA calls requireReauth (atomicity-exempt.tsv class B, own
	// marker comment at internal/core/mfa.go's requireReauth) BEFORE its
	// SetUserMFAEnabled+DeleteMFAForUser transaction. requireReauth's
	// MarkTOTPStepUsed burns the matched TOTP time-step -- MFASecret.LastUsedStep
	// -- on c.storage, outside that transaction, which is the anti-replay
	// guarantee: a code that has been accepted once must not be accepted again
	// inside its +/-1-step window, whether or not the action it authorised went
	// on to succeed.
	//
	// consumedColumns, NOT a whole-table MFASecret exemption: a genuine partial
	// commit on this op would be SetUserMFAEnabled committing while
	// DeleteMFAForUser rolled back (or the reverse), which shows up as the
	// MFASecret ROW vanishing or User.MFAEnabled flipping -- neither of which
	// LastUsedStep's exclusion hides. Exempting the table would have masked it.
	{
		op:              "REST POST /api/v1/auth/mfa/disable",
		fn:              "(*KeyorixCore).requireReauth",
		consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
		why:             "requireReauth burned the matched TOTP time-step (MFASecret.LastUsedStep) before the disable transaction; it must stay burned so the same code cannot be replayed",
	},
	// #2814. CompleteSAML (internal/core/sso.go) is itself a class-B row
	// (docs/atomicity-exempt.tsv). ConsumeSSOLoginState burns the single-use
	// RelayState row FIRST -- a hard row DELETE -- before the assertion
	// validation and user resolution/provisioning that follow. That ordering is
	// the replay protection: the stored row is also what the InResponseTo check
	// is validated against, so leaving it live until after provisioning would
	// let a captured (RelayState, response) pair re-drive user resolution and
	// auto-provisioning rather than being refused on its second use. A
	// GetUserByUsername error inside resolveSSOUser therefore fails closed with
	// the state correctly consumed.
	//
	// consumedByDeletion rather than consumedColumns because the consume is a
	// row delete, not a column flip. The pure-subtraction requirement is what
	// makes a whole-table entry safe here without an AST check that CompleteSAML
	// never writes this table: a CreateSSOLoginState (row added) or an in-place
	// update (row edited, so its canonical JSON changes) both make the
	// exemption refuse, per-run, from the snapshot alone. maxRowsRemoved pins it
	// to the ONE row this op may consume.
	{
		op:                 "REST POST /auth/saml/{provider}/acs",
		fn:                 "(*KeyorixCore).CompleteSAML",
		consumedByDeletion: []string{"SSOLoginState"},
		maxRowsRemoved:     map[string]int{"SSOLoginState": 1},
		why:                "ConsumeSSOLoginState deleted the single-use RelayState row before assertion validation and user resolution; it must stay consumed so a captured response cannot be replayed",
	},
	// ActivateMFA and RegenerateMFARecoveryCodes are DisableMFA's siblings:
	// all three call requireReauth (class B) before their own
	// WithTransaction, so all three leave MFASecret.LastUsedStep burned when
	// that transaction fails. Found by this session's derived sweep of the
	// auth/MFA/SSO ops (ORACLE-A-1 item 4), not by a CI failure -- these are
	// the next (method, nth) pairs CI's randomized fuzz-changed would have
	// surfaced one at a time, on 7 distinct storage methods between them:
	//   /api/v1/auth/mfa/activate            ActivateMFASecret#1, CreateMFARecoveryCodes#1,
	//                                        SetUserMFAEnabled#1, WithTransaction#1
	//   /api/v1/auth/mfa/recovery-codes/...  CreateMFARecoveryCodes#1,
	//                                        DeleteMFARecoveryCodes#1, WithTransaction#1
	// all with the identical [MFASecret AuditEvent] diff. Adding them op-scoped
	// here, rather than waiting for seven separate red builds, is the whole
	// point of the op-scoped form over a per-(method, nth) tolerance row.
	//
	// ATTRIBUTION, corrected after coordinator review on this PR. An earlier
	// version of the activate entry named requireReauth, which is a class-B row
	// but performs NO consumption on this path: ActivateMFA runs with
	// user.MFAEnabled still false, so secondFactorEnrolled is false,
	// requireReauth takes its bare-password branch, and neither
	// MarkTOTPStepUsed nor ConsumeMFAStepUpGrant runs. (The harness agrees with
	// production here -- this op's Setup uses the REAL /auth/mfa/enroll
	// endpoint, not enrolMFADirect, so MFAEnabled is genuinely false.) The
	// burned LastUsedStep is ActivateMFA's OWN MarkTOTPStepUsed
	// (internal/core/mfa.go).
	//
	// That made the entry's ledger tie vacuous -- exactly the drift
	// TestConsumeFirstExemptions_MatchAtomicityLedger exists to prevent, since
	// the row it matched was real but described a different function's
	// behaviour. Fixed properly rather than by relabelling: ActivateMFA now has
	// its own reviewed class-B row in docs/atomicity-exempt.tsv, a marker
	// comment on the function, and a red/green-proved verifying test
	// (TestActivateMFA_ActivationFailureAfterConsume_FailsClosed), and fn points
	// at that row.
	{
		op:              "REST POST /api/v1/auth/mfa/activate",
		fn:              "(*KeyorixCore).ActivateMFA",
		consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
		why:             "ActivateMFA's own MarkTOTPStepUsed burned the matched enrolment-code time-step before the activation transaction; it must stay burned so a stolen enrolment code cannot be replayed",
	},
	// fn is requireReauth here (and for mfa/disable above), unlike the activate
	// entry: these two ops run with MFA already ENABLED and send a real TOTP
	// code, so requireReauth DOES take its TOTP branch and its own
	// MarkTOTPStepUsed is the consume. Verified per-op rather than assumed after
	// the activate mis-attribution -- both ops' Execute sends {"code": <TOTP>}
	// and their Setup (enrolMFADirect) sets MFAEnabled=true, matching the
	// production shape where DisableMFA/RegenerateMFARecoveryCodes
	// re-authenticate against an already-active factor.
	//
	// SCOPE OF THIS ENTRY'S GREEN, per coordinator review: with the fixture as it
	// stands on this PR's base, a green here does NOT cover the
	// zero-recovery-codes hazard (#2838) -- enrolMFADirect seeds no
	// MFARecoveryCode rows, so a partial commit that wipes the old codes without
	// writing new ones is structurally unobservable on this op, exemption or no
	// exemption. A planted class-A bug of exactly that shape SURVIVED. The
	// stacked follow-up seeds those rows and kills it; until that lands, read
	// this entry as covering the TOTP-step consumption only.
	// SCOPE OF THIS ENTRY'S GREEN. A green here used to cover LESS than it
	// looked: enrolMFADirect seeded no MFARecoveryCode rows, so a partial commit
	// that wiped the old codes without writing new ones was structurally
	// unobservable on this op, exemption or no exemption — a planted class-A bug
	// of exactly that shape SURVIVED (#2838). THIS PR seeds those rows, and the
	// same planted bug is now killed (diff [MFARecoveryCode AuditEvent
	// MFASecret] — MFARecoveryCode falls outside the declared consumption).
	//
	// So a green here now covers both the TOTP-step consumption this entry
	// declares AND the recovery-code replacement the op is named for. Stated
	// rather than assumed, because the earlier version of this comment is what
	// kept the gap visible until it could be closed.
	{
		op:              "REST POST /api/v1/auth/mfa/recovery-codes/regenerate",
		fn:              "(*KeyorixCore).requireReauth",
		consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
		why:             "requireReauth burned the matched TOTP time-step before the recovery-code replacement transaction; it must stay burned so the same code cannot be replayed",
	},
	// ORPHAN-2 (#2844 triage class B). VerifyMFAStepUp's verifyMFAStepUpCode is
	// class B in the ledger: MarkTOTPStepUsed burns the matched step before
	// CreateMFAStepUpGrant, and the step stays burned if the grant write fails,
	// panics, or lands-then-errors, so one code cannot buy two grants. Before
	// this entry the oracle knew the shape only as a per-tuple by-design row
	// (CreateMFAStepUpGrant#1/error), and the panic and effect-then-error
	// siblings failed. Now that oracle (d) consults this list too, one entry
	// covers every kind.
	//
	// Deliberately NOT added: /auth/mfa/verify. VerifyMFACredentials is class B
	// too, but no post-verdict tuple on that op is the consumption ALONE. The
	// error/effect-then-error tuples also keep the LoginAttempt slot (#2880,
	// pinned per tuple with the consumption in oracleAByDesignErrors). The one
	// shape that IS consumption-only, [MFASecret] on a post-verdict PANIC, is
	// #3048's bug (the slot was handed back), and an entry here would accept it.
	// TestConsumeFirst_NonExemptOpStillFailsTheOracle pins that.
	{
		op:              "REST POST /api/v1/auth/mfa/stepup",
		fn:              "(*KeyorixCore).verifyMFAStepUpCode",
		consumedColumns: map[string][]string{"MFASecret": {"LastUsedStep"}},
		why:             "verifyMFAStepUpCode burned the matched TOTP time-step before the step-up grant write; it must stay burned so the same code cannot be replayed for a second grant",
	},
}

// consumeFirstExemptionFor returns the entry for op, or nil.
func consumeFirstExemptionFor(op string) *consumeFirstExemption {
	for i := range consumeFirstExemptions {
		if consumeFirstExemptions[i].op == op {
			return &consumeFirstExemptions[i]
		}
	}
	return nil
}

// pureRowSubtraction reports whether after's rows are a strict multiset subset
// of before's -- the signature of a consume implemented as a row DELETE. A row
// present in after but not in before (an INSERT, or an UPDATE, since the row
// snapshot is canonical per-row JSON and an edit changes the string) makes this
// false, so a partial commit that happens to touch the same table still fails
// the oracle.
func pureRowSubtraction(before, after tableSnapshot) bool {
	if len(after.Rows) >= len(before.Rows) {
		return false
	}
	have := make(map[string]int, len(before.Rows))
	for _, r := range before.Rows {
		have[r]++
	}
	for _, r := range after.Rows {
		if have[r] == 0 {
			return false
		}
		have[r]--
	}
	return true
}

// consumeFirstAccountsForDiff reports whether the entire before->after change
// on this run is the op's declared single-use consumption and nothing else.
func consumeFirstAccountsForDiff(in oracleInput) (*consumeFirstExemption, bool) {
	e := consumeFirstExemptionFor(in.op)
	if e == nil {
		return nil, false
	}
	for _, tbl := range e.consumedByDeletion {
		before, after := in.before.Tables[tbl], in.after.Tables[tbl]
		if !pureRowSubtraction(before, after) {
			return nil, false
		}
		if removed := len(before.Rows) - len(after.Rows); removed > e.maxRowsRemoved[tbl] {
			return nil, false
		}
	}
	excluded := append(append([]string{}, outcomeLogTables...), e.consumedByDeletion...)
	if hashExcludingColumns(in.before, excluded, e.consumedColumns) !=
		hashExcludingColumns(in.after, excluded, e.consumedColumns) {
		return nil, false
	}
	return e, true
}

// atomicityLedgerClasses parses docs/atomicity-exempt.tsv into function ->
// class. Comment lines start with '#'; "AUDIT:"-prefixed rows are a different
// key namespace (TestAtomicityGuard_AuditBeforeWrite) and are skipped.
func atomicityLedgerClasses(t *testing.T) map[string]string {
	t.Helper()
	const path = "../../docs/atomicity-exempt.tsv"
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v -- the class-B ledger this exemption list is derived from must exist", path, err)
	}
	defer func() { _ = f.Close() }()
	classes := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 2 || strings.HasPrefix(cols[0], "AUDIT:") {
			continue
		}
		// Duplicate keys are rejected rather than letting the last row win: a
		// second plain row for an already-classified function would silently
		// change the class this test enforces against, which is the one way a
		// class-B oracle exemption could come to rest on a row that no longer
		// says B. See the ledger header's "JIT:" note for what to do instead.
		if prev, dup := classes[cols[0]]; dup {
			t.Fatalf("%s: duplicate row for %q (already classified %q, now %q) -- two rows for one function "+
				"silently reclassify it here; use a key namespace for the second classification",
				path, cols[0], prev, cols[1])
		}
		classes[cols[0]] = cols[1]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if len(classes) == 0 {
		t.Fatalf("%s parsed to zero rows -- the parser and the file have diverged, "+
			"which would make TestConsumeFirstExemptions_MatchAtomicityLedger vacuously green", path)
	}
	return classes
}

// TestConsumeFirstExemptions_MatchAtomicityLedger is what stops this list from
// drifting into a general carve-out: every entry must name a function that
// docs/atomicity-exempt.tsv classifies B. Reclassify or delete a row there and
// this goes red, rather than oracle (a) quietly continuing to accept state
// changes on a design nobody signed off on any more.
func TestConsumeFirstExemptions_MatchAtomicityLedger(t *testing.T) {
	classes := atomicityLedgerClasses(t)
	for _, e := range consumeFirstExemptions {
		class, ok := classes[e.fn]
		if !ok {
			t.Errorf("consumeFirstExemption for op %q names fn %q, which has no row in "+
				"docs/atomicity-exempt.tsv -- an oracle exemption may only rest on a function the "+
				"atomicity ledger has actually classified", e.op, e.fn)
			continue
		}
		if class != "B" {
			t.Errorf("consumeFirstExemption for op %q names fn %q, which docs/atomicity-exempt.tsv "+
				"classifies %q, not B (consume-first by design) -- only class B justifies retaining "+
				"state on an error return", e.op, e.fn, class)
		}
	}
}

// TestConsumeFirstExemptions_OpsExist keeps a route rename from leaving a dead
// entry that silently stops applying (and, worse, reads as still covering the
// op it names).
func TestConsumeFirstExemptions_OpsExist(t *testing.T) {
	known := make(map[string]bool, len(opCatalog))
	for _, op := range opCatalog {
		known[op.Key] = true
	}
	for _, e := range consumeFirstExemptions {
		if !known[e.op] {
			t.Errorf("consumeFirstExemption names op %q, which is not in opCatalog -- stale entry", e.op)
		}
	}
}

// TestConsumeFirstExemptions_Documented: each entry must carry a fn and a why,
// so a passing ACCEPTABLE-BY-DESIGN line always states what it accepted.
func TestConsumeFirstExemptions_Documented(t *testing.T) {
	for _, e := range consumeFirstExemptions {
		if e.fn == "" {
			t.Errorf("consumeFirstExemption for op %q has no fn", e.op)
		}
		if e.why == "" {
			t.Errorf("consumeFirstExemption for op %q has no why", e.op)
		}
		if len(e.consumedColumns) == 0 && len(e.consumedByDeletion) == 0 {
			t.Errorf("consumeFirstExemption for op %q declares no consumption at all -- it would "+
				"accept ANY unchanged-elsewhere diff, which is not what this mechanism is for", e.op)
		}
		// An uncapped consumedByDeletion table would accept "the op deleted
		// every row" as readily as "the op consumed its one token".
		for _, tbl := range e.consumedByDeletion {
			if e.maxRowsRemoved[tbl] <= 0 {
				t.Errorf("consumeFirstExemption for op %q lists %q in consumedByDeletion with no "+
					"positive maxRowsRemoved cap -- pure subtraction alone would also accept an op "+
					"that deleted the whole table", e.op, tbl)
			}
		}
	}
}

// --- calibration: red AND green on synthetic snapshots -------------------
//
// CLAUDE.md: "confirm it is green on a known-good case as well as red on a
// known-bad one -- both directions". These cases are synthetic because the
// point is the PREDICATE's discrimination, not any one op's behaviour; the
// real op's behaviour is proved by the live replay in the PR body.

func calibSnapshot(t *testing.T, mfaRows, otherRows, loginStateRows []string) dbSnapshot {
	t.Helper()
	tbl := func(name string, rows []string) tableSnapshot {
		return tableSnapshot{Table: name, Hash: strings.Join(rows, "|"), Rows: rows}
	}
	return dbSnapshot{Tables: map[string]tableSnapshot{
		"MFASecret":     tbl("MFASecret", mfaRows),
		"User":          tbl("User", otherRows),
		"SSOLoginState": tbl("SSOLoginState", loginStateRows),
		"AuditEvent":    tbl("AuditEvent", []string{"audit-anything"}),
	}}
}

func TestConsumeFirstPredicate_Calibration(t *testing.T) {
	const op = "REST POST /api/v1/auth/mfa/disable"
	// The real predicate hashes per-row JSON with the named column removed, so
	// the calibration rows have to be real JSON for rowsHashExcludingColumns to
	// strip anything.
	stepUnset := `{"ID":1,"UserID":1,"LastUsedStep":null}`
	stepBurned := `{"ID":1,"UserID":1,"LastUsedStep":57221}`
	userBefore := `{"ID":1,"MFAEnabled":true}`
	userAfter := `{"ID":1,"MFAEnabled":false}`

	t.Run("green: only the declared consumption column moved", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, []string{stepBurned}, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); !ok {
			t.Fatal("predicate refused a diff confined to MFASecret.LastUsedStep -- it must accept the " +
				"consume-first shape it exists for, or oracle (a) stays red on a correct design")
		}
	})

	t.Run("red: a second table moved too", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, []string{stepBurned}, []string{userAfter}, nil),
		}
		if e, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatalf("predicate ACCEPTED a diff that also flipped User.MFAEnabled (%+v) -- this is exactly "+
				"the genuine partial commit the exemption must not mask", e)
		}
	})

	t.Run("red: the MFASecret row vanished (a real partial commit)", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, nil, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate ACCEPTED a vanished MFASecret row -- DeleteMFAForUser committing while the " +
				"rest of the transaction rolled back must still fail the oracle")
		}
	})

	t.Run("red: unknown op gets no exemption", func(t *testing.T) {
		in := oracleInput{
			op:     "REST POST /api/v1/secrets/",
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
			after:  calibSnapshot(t, []string{stepBurned}, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate applied to an op with no entry -- it must be per-op, not global")
		}
	})
}

// TestConsumeFirstPredicate_DeletionCalibration covers the deletion-shaped
// entry (#2814, SSOLoginState). Same discipline as the column-shaped half: the
// green case must be accepted, and every nearby shape that is NOT the declared
// consumption must be refused.
func TestConsumeFirstPredicate_DeletionCalibration(t *testing.T) {
	const op = "REST POST /auth/saml/{provider}/acs"
	stepUnset := `{"ID":1,"UserID":1,"LastUsedStep":null}`
	userBefore := `{"ID":1,"MFAEnabled":true}`
	userAfter := `{"ID":1,"MFAEnabled":false}`
	stateA := `{"ID":1,"State":"relay-a"}`
	stateB := `{"ID":2,"State":"relay-b"}`

	t.Run("green: the one consumed state row was deleted", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateA, stateB}),
			after:  calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateB}),
		}
		if _, ok := consumeFirstAccountsForDiff(in); !ok {
			t.Fatal("predicate refused a diff confined to one deleted SSOLoginState row -- that is the " +
				"consume-first shape CompleteSAML's class-B classification describes")
		}
	})

	t.Run("red: a state row was ADDED, not consumed", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateA}),
			after:  calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateA, stateB}),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate ACCEPTED an ADDED SSOLoginState row -- a write to this table on the error " +
				"path is not a consumption and must still fail")
		}
	})

	t.Run("red: more rows deleted than this op may consume", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateA, stateB}),
			after:  calibSnapshot(t, []string{stepUnset}, []string{userBefore}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate ACCEPTED two deleted SSOLoginState rows where maxRowsRemoved is 1 -- " +
				"wiping other users' in-flight logins is not this op's declared consumption")
		}
	})

	t.Run("red: the consumption happened AND another table moved", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateA}),
			after:  calibSnapshot(t, []string{stepUnset}, []string{userAfter}, nil),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate ACCEPTED a diff that also changed User -- a genuine partial commit " +
				"alongside the consumption must still fail")
		}
	})

	t.Run("red: nothing was consumed but the table still differs", func(t *testing.T) {
		in := oracleInput{
			op:     op,
			before: calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateA}),
			after:  calibSnapshot(t, []string{stepUnset}, []string{userBefore}, []string{stateB}),
		}
		if _, ok := consumeFirstAccountsForDiff(in); ok {
			t.Fatal("predicate ACCEPTED a swapped SSOLoginState row (one deleted, one added) -- the row " +
				"count is unchanged, so this is not a pure consumption")
		}
	})
}

// TestPureRowSubtraction_Calibration pins the deletion-shaped half of the
// predicate independently of any exemption entry, so #2814's entry rests on a
// primitive that is red/green-proved on its own.
func TestPureRowSubtraction_Calibration(t *testing.T) {
	row := func(rows ...string) tableSnapshot { return tableSnapshot{Rows: rows} }
	cases := []struct {
		name          string
		before, after tableSnapshot
		want          bool
	}{
		{"one row deleted", row("a", "b"), row("a"), true},
		{"all rows deleted", row("a"), row(), true},
		{"nothing deleted", row("a", "b"), row("a", "b"), false},
		{"row added", row("a"), row("a", "b"), false},
		{"row edited, count unchanged", row("a", "b"), row("a", "b-edited"), false},
		{"row edited and one deleted", row("a", "b", "c"), row("a", "b-edited"), false},
		{"duplicate rows, one deleted", row("a", "a", "b"), row("a", "b"), true},
		{"duplicate rows, more than existed", row("a", "b"), row("a", "a"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pureRowSubtraction(tc.before, tc.after); got != tc.want {
				t.Errorf("pureRowSubtraction(%v, %v) = %v, want %v", tc.before.Rows, tc.after.Rows, got, tc.want)
			}
		})
	}
}
