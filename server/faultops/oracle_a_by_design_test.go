// oracle_a_by_design_test.go — #2549: the acceptable-by-design exemption
// oracle (a)'s error-reporting branch was missing, plus the staleness guard
// that would have caught four of #2549's own tolerances going dead.
//
// What #2549 asked for, and what was actually still missing
// ---------------------------------------------------------
// The issue reports that checkOracles' oracle (a) SUCCESS branch has
// onlyOutcomeLogTables (accept an AuditEvent-only diff unconditionally, safe
// because oracle (c) already ruled out the fail-open authz cause) while "the
// `default:` (error-reporting) branch has no equivalent exemption."
//
// That is no longer true: the error branch grew its own onlyOutcomeLogTables
// check. Driving #2549's two reported instances directly settles which of them
// the gap still affects, and the answer is different for each:
//
//   - BulkRejectAccessRequests / BulkApproveAccessRequests: diff vs the
//     pre-fault state is [AuditEvent] — an outcome-log table. Already accepted
//     by the error branch's onlyOutcomeLogTables, logged ACCEPTABLE-BY-DESIGN,
//     and the oracle never reaches report(). The four knownOpenTolerances that
//     cited #2549 for these were therefore DEAD — never consulted, still
//     carrying a 2026-10-17 expiry that would have produced re-filing churn for
//     a case nothing flags. They are deleted, and
//     TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance
//     pins what actually covers them so they cannot return as cargo-cult rows.
//   - VerifyMFAStepUp: diff is [MFASecret]. That is BUSINESS state, not an
//     outcome log, so no existing exemption reaches it and the tolerance was
//     genuinely load-bearing. But a tolerance is the wrong instrument: it means
//     "a filed, not-yet-fixed bug, tolerated until someone fixes it", and this
//     is not a bug — VerifyMFAStepUp's own doc comment and
//     TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed both establish
//     "consume the TOTP step first, fail closed if the grant write fails" as the
//     INTENDED design (a replayed code must not become reusable because the
//     grant write failed). Tolerating a by-design behaviour under an expiring
//     bug tolerance guarantees it is re-filed forever.
//
// So the exemption this file adds is narrow by construction and aimed at
// exactly that shape: a reported ERROR that intentionally leaves a
// business-state table mutated, where the mutation IS the security behaviour.
//
// Why not just widen onlyOutcomeLogTables, or add a tables entry to some
// existing map
// ------------------------------------------------------------------------
//   - onlyOutcomeLogTables is deliberately table-based and op-independent. It
//     is safe that way only because an outcome log is, by definition, not
//     application state. MFASecret is application state; accepting it
//     unconditionally for every op would be exactly the blanket skip #2549
//     says not to build.
//   - opScopedBestEffortTables (opScopedAcceptableByDesign) is about a
//     best-effort side effect the code is willing to LOSE. This is the
//     opposite: a mutation the code deliberately KEEPS while reporting failure.
//     Filing it there would make the next reader believe the TOTP consume is
//     discardable, which is the one thing it must not be.
//
// What this mechanism does NOT do, stated explicitly
// --------------------------------------------------
//   - It does not verify its own rows' claims. Each row cites the production
//     doc comment and the unit test that establish the design; those citations
//     are prose and this file does not re-derive them. What it does enforce is
//     that each row HAS them (TestOracleAByDesign_RowsAreFullyAttributed) and
//     that each row still matches something real
//     (TestOracleAByDesign_RowsAreLoadBearing).
//   - It only covers the error-reporting branch's business-state case. The
//     success branch and oracle (d) are untouched.
//   - A row's tables list is an exact allowlist, subset-checked. A diff with
//     even one table outside it still fails loudly.
package faultops

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// oracleAByDesignError is one reviewed exemption for oracle (a)'s
// error-reporting branch: an (op, method, kind) whose reported failure
// intentionally leaves exactly `tables` mutated.
//
// Every field is required. A row missing its design citation or its proving
// test is rejected by TestOracleAByDesign_RowsAreFullyAttributed — the point of
// the row is that someone traced the behaviour to an intentional design and
// left the evidence, not that someone silenced a failing oracle.
type oracleAByDesignError struct {
	// op is the opCatalog key. Required.
	op string
	// method is the faulted storage method. Required and never blank: a
	// wildcard would make this a per-op blanket skip, which is what #2549
	// says not to build.
	method string
	// kind is the fault kind this applies to. KindEffectThenError is
	// deliberately NOT accepted here — that shape is oracle (d)'s, which has
	// its own, differently-reasoned exclusions.
	kind faultstorage.FaultKind
	// nth, when > 0, pins the call ordinal. 0 means any.
	nth int
	// tables is the EXACT set of tables the reported failure may leave
	// diverged from the pre-fault state. Subset-checked: a diff containing
	// anything else is a different, unexplained divergence and still fails.
	// Required and non-empty.
	tables []string
	// outcomeLogs names the outcome-log tables (AuditEvent, ...) the same
	// reported failure deliberately writes ALONGSIDE tables -- e.g. the
	// auth.login_error audit event a post-verdict login fault records (#2894).
	// Kept apart from tables so tables stays business-state only (the
	// outcome-log check in TestOracleAByDesign_RowsAreFullyAttributed still
	// applies to it unchanged), and so every outcome log a row accepts is named
	// per row rather than stripped from every diff. onlyOutcomeLogTables
	// accepts an outcome-log-ONLY diff on its own; it never accepts a MIXED one,
	// which is the only case this field matters for. Optional.
	outcomeLogs []string
	// designComment names where in PRODUCTION code the intent is stated, so a
	// reader can check the claim at its source rather than trusting this row.
	// Required.
	designComment string
	// provingTest is the test that already demonstrates this behaviour is the
	// intended one. Required — without it this row is an assertion, and an
	// assertion is what a tolerance already was.
	provingTest string
	// why is the one-paragraph reason the mutation is deliberate AND safe to
	// leave in place on the error path. Required.
	why string
}

// oracleAByDesignErrors is the reviewed inventory. Adding a row is a claim
// that the divergence is intended security behaviour, with the citations to
// back it. If you are not sure, it belongs in knownOpenTolerances (a filed,
// expiring, tracked-open bug) instead — that is the honest instrument for
// "this looks wrong and nobody has fixed it yet".
var oracleAByDesignErrors = []oracleAByDesignError{
	{
		op:     "REST POST /api/v1/auth/mfa/stepup",
		method: "CreateMFAStepUpGrant",
		kind:   faultstorage.KindError,
		nth:    1,
		tables: []string{"MFASecret"},
		// #2894 review: the post-verdict denial is now audited mfa.error (it used
		// to go unaudited), the same outcome log the login rows below carry.
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/mfa_stepup.go: VerifyMFAStepUp consumes the TOTP step " +
			"(advancing MFASecret's replay window) BEFORE minting the step-up grant, and fails " +
			"closed if the grant write fails",
		provingTest: "internal/core/TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed",
		why: "The consume is not a side effect of the grant — it is the single-use enforcement. " +
			"Rolling it back when CreateMFAStepUpGrant fails would hand the caller a code that is " +
			"still valid, so a caller who can induce a storage failure could replay one TOTP code " +
			"indefinitely. The reported ERROR is correct (no grant was issued, so no elevated " +
			"action is authorized), and MFASecret's advance is the security property, not a " +
			"partial commit. Previously carried as a knownOpenTolerance citing #2549, which " +
			"mis-labelled intended behaviour as a filed-but-unfixed bug and so guaranteed " +
			"perpetual re-filing at each expiry.",
	},
	// #2880 / #2894: post-verdict faults on /auth/mfa/verify. Both are reached
	// only AFTER the TOTP code matched, so the request is charged exactly like
	// a wrong code -- lockout counter, per-IP LoginAttempt slot and a 401
	// byte-identical to a wrong code -- because doing anything cheaper for a
	// correct code is a side channel confirming correctness. Found untolerated
	// on #2894's head by LOGIN-ACCT-1 (pass on main, where the slot used to be
	// released). Pinned per method; never a wildcard.
	{
		op:          "REST POST /auth/mfa/verify",
		method:      "MarkTOTPStepUsed",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/mfa.go VerifyMFACredentials: \"the code WAS confirmed correct here -- " +
			"only the anti-replay consumption write (MarkTOTPStepUsed) failed. This must still count toward " +
			"the lockout exactly like a wrong code would\" (#2888); the error wraps " +
			"ErrMFAVerificationStorageFailure but NOT ErrMFAVerificationUnavailable, the handler's only " +
			"release condition (server/http/handlers/mfa.go)",
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/MarkTOTPStepUsed " +
			"(slot, lockout, response parity); internal/core/" +
			"TestVerifyMFALogin_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout (lockout, mfa.error audit)",
		why: "The code matched; only the anti-replay write failed, so the login is refused (the step could not " +
			"be recorded as used) and the request keeps its LoginAttempt slot like a wrong code does. Releasing " +
			"the slot here would make a correct guess cheaper than a wrong one, observable as when the per-IP " +
			"429s start (#2894). The AuditEvent is the mfa.error record that keeps the storage fault " +
			"distinguishable from a wrong code for an operator. No session, grant or step is left behind.",
	},
	{
		op:          "REST POST /auth/mfa/verify",
		method:      "CreateSession",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt", "MFASecret"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/mfa.go VerifyMFALoginPending: on a mintSession failure the consumed TOTP " +
			"step is given back with ReleaseTOTPStepIfUnchanged (#2567; last_used_step -> step-1, see its " +
			"interface doc), the attempt is counted (lc.Failed) and the error is ErrLoginPostVerdict, so " +
			"\"the per-IP login-attempt slot stays CONSUMED\" and VerifyMFA audits auth.login_error",
		provingTest: "server/http/handlers/TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode/CreateSession " +
			"(slot, lockout, response parity, no session); server/http/handlers/" +
			"TestVerifyMFA_MintFailureAfterCorrectCodeAuditsLoginError (audit); internal/core/" +
			"TestVerifyMFALogin_CreateSessionFailure_ReleasesTOTPStepForRetry (MFASecret)",
		why: "The code matched and the session write failed. No session exists, the slot stays counted exactly " +
			"as for a wrong code (#2880/#2894), and MFASecret differs only because the step release writes " +
			"last_used_step = step-1 rather than the row's pre-mark value -- which re-permits exactly this one " +
			"step so the user can retry the same code, and cannot re-open any step a later request consumed " +
			"(CAS-guarded). The AuditEvent is the auth.login_error record.",
	},
	// Same #2880 decision on REST POST /auth/webauthn/login/finish. On main this
	// tuple's diff is [LoginAttempt], absorbed by #2565's wildcard
	// knownOpenTolerance; #2894 adds the auth.login_error audit for a
	// post-verdict fault, so the diff becomes [AuditEvent LoginAttempt] and the
	// wildcard (tables [LoginAttempt]) no longer covers it. TOL-1 (#2949) pins
	// the main-side shape of this same tuple without the AuditEvent: whichever of
	// the two merges second keeps ONE row for this tuple -- this one, since it
	// is the superset -- and TestOracleAByDesign_RowsAreLoadBearing fails on the
	// narrower one if both survive.
	{
		op:          "REST POST /auth/webauthn/login/finish",
		method:      "CreateSession",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "server/http/handlers/webauthn.go FinishWebAuthnLogin releases the per-IP reservation " +
			"ONLY on core.ErrWebAuthnLoginNotEvaluated, and audits a core.ErrLoginPostVerdict failure as " +
			"auth.login_error (#2894); internal/core/webauthn.go ErrWebAuthnLoginNotEvaluated is reserved " +
			"for storage errors BEFORE any verdict on the assertion, and mintSession runs after it passed",
		provingTest: "internal/core/TestFinishWebAuthnLogin_MintFailureAfterAssertion_StillCountsTheLoginAttempt " +
			"(slot); internal/core/TestFinishWebAuthnLogin_PostVerdictFaultCostsTheSameAsAFailedAssertion " +
			"(ErrLoginPostVerdict, lockout parity)",
		why: "The WebAuthn assertion was evaluated and passed before CreateSession failed, so the request is a " +
			"genuine login attempt and keeps the IP slot it reserved -- releasing it would let an attacker " +
			"drive unlimited post-verification failures without spending budget (#2880). No session is " +
			"minted. The AuditEvent is the auth.login_error record that keeps the storage fault " +
			"distinguishable from a failed assertion for an operator.",
	},
	// #2880 (auth owner's decision: a post-verdict storage fault keeps the
	// per-IP login attempt counted), GetUserRoles half. Pinned, never a
	// wildcard: only the one post-assertion read is covered, and only for the
	// [LoginAttempt] residue. Before #2841's fix this same tuple also left an
	// MFAStepUpGrant and a login AuditEvent behind (#2807/#2841, tolerated
	// twice in knownOpenTolerances); those halves were the bug and are gone —
	// a diff naming MFAStepUpGrant or Session again is not covered by this row
	// and fails oracle (a) loudly.
	// With #2894 the failure is post-verdict (ErrLoginPostVerdict wrapping
	// ErrLoginIdentityUnavailable): answered like a failed assertion and
	// audited as auth.login_error, hence the AuditEvent outcome log.
	{
		op:          "REST POST /auth/webauthn/login/finish",
		method:      "GetUserRoles",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/webauthn.go: ErrLoginIdentityUnavailable (\"deliberately NOT " +
			"ErrWebAuthnLoginNotEvaluated: the assertion WAS evaluated and passed, so the per-IP " +
			"login-attempt reservation must stay counted\"); server/http/handlers/webauthn.go " +
			"FinishWebAuthnLogin releases the reservation only on ErrWebAuthnLoginNotEvaluated",
		provingTest: "internal/core/TestFinishWebAuthnLogin_IdentityReadFailureLeavesNoSessionOrGrant",
		why: "The WebAuthn assertion has already been evaluated and passed when the response identity " +
			"read fails, so the request is a genuine login attempt and keeps the IP slot it reserved. " +
			"Releasing it would let an attacker drive unlimited post-verification failures against an " +
			"IP without spending budget (#2880). The login itself is refused with no session, no step-up " +
			"grant and no step-up token written (#2841), so the kept LoginAttempt row is the only state " +
			"left, and it is the rate-limit enforcement, not a partial commit.",
	},
	// Same #2880 decision, the other half of the identity read (roles, then
	// permissions). #2949 (TOL-1) pins this tuple with tables [LoginAttempt]
	// only, from main's pre-#2894 shape; with #2894's auth.login_error audit the
	// diff is [AuditEvent LoginAttempt]. Whichever merges second keeps ONE row
	// for this tuple -- this one, the superset.
	{
		op:          "REST POST /auth/webauthn/login/finish",
		method:      "GetUserPermissions",
		kind:        faultstorage.KindError,
		nth:         1,
		tables:      []string{"LoginAttempt"},
		outcomeLogs: []string{"AuditEvent"},
		designComment: "internal/core/webauthn.go FinishWebAuthnLoginPending: an identity-read failure after the " +
			"assertion verified is denied via denyAfterCredentialMatched (ErrLoginPostVerdict wrapping " +
			"ErrLoginIdentityUnavailable, never ErrWebAuthnLoginNotEvaluated); server/http/handlers/webauthn.go " +
			"releases the reservation only on ErrWebAuthnLoginNotEvaluated and audits auth.login_error",
		provingTest: "internal/core/TestFinishWebAuthnLogin_PermissionsReadFailureLeavesNoSessionOrGrant",
		why: "The assertion has passed when the permissions read fails, so the request keeps the IP slot it " +
			"reserved (#2880) -- releasing it would make post-verification failures free -- and the login is " +
			"refused before any session, step-up grant or step-up token is written (#2841). The AuditEvent is " +
			"the auth.login_error record (#2894).",
	},
}

// oracleAErrorByDesign reports whether an error-reporting-branch oracle (a)
// divergence is covered by a reviewed row. Mirrors acceptableByDesign /
// opScopedAcceptableByDesign's subset semantics deliberately, so all three
// exemption mechanisms narrow a diff the same way.
func oracleAErrorByDesign(op, method string, kind faultstorage.FaultKind, nth int, diff []string) *oracleAByDesignError {
	if len(diff) == 0 {
		return nil
	}
	for i := range oracleAByDesignErrors {
		e := &oracleAByDesignErrors[i]
		if e.op != op || e.method != method || e.kind != kind {
			continue
		}
		if e.nth > 0 && e.nth != nth {
			continue
		}
		if diffSubsetOf(diff, append(append([]string{}, e.tables...), e.outcomeLogs...)) {
			return e
		}
	}
	return nil
}

// ── Guards on the mechanism itself ──────────────────────────────────────────

// TestOracleAByDesign_RowsAreFullyAttributed enforces the struct's own doc
// comment: every field is required, and the two citation fields in particular.
// A row that merely asserts "by design" is a tolerance with better branding.
func TestOracleAByDesign_RowsAreFullyAttributed(t *testing.T) {
	t.Parallel()
	for _, e := range oracleAByDesignErrors {
		label := fmt.Sprintf("%s/%s/%s", e.op, e.method, e.kind)
		if e.op == "" || e.method == "" {
			t.Errorf("oracleAByDesignError %q: op and method are both required — a blank method would make "+
				"this a per-op blanket skip, which #2549 explicitly rules out", label)
		}
		if e.nth <= 0 {
			t.Errorf("oracleAByDesignError %q: nth is %d, but oracleAErrorByDesign only compares it when "+
				"nth > 0 (`if e.nth > 0 && e.nth != nth`) — so 0 silently matches EVERY call ordinal for "+
				"this (op, method, kind). That is a wildcard wearing a specific row's clothes: the row "+
				"reads as pinned to one call site while actually exempting all of them, including ones "+
				"nobody reviewed. Name the ordinal the reviewed case actually uses (1 for the first call)",
				label, e.nth)
		}
		if e.kind == faultstorage.KindEffectThenError {
			t.Errorf("oracleAByDesignError %q: KindEffectThenError belongs to oracle (d), which has its own "+
				"exclusions and its own reasoning — this mechanism covers the error-reporting branch only", label)
		}
		if len(e.tables) == 0 {
			t.Errorf("oracleAByDesignError %q: tables is empty, which would accept ANY divergence for this "+
				"(op, method, kind) — the exact opposite of a narrow exemption", label)
		}
		for _, tb := range e.tables {
			if isOutcomeLogTable(tb) {
				t.Errorf("oracleAByDesignError %q: table %q is an outcome log, already accepted "+
					"unconditionally by onlyOutcomeLogTables — a row for it would be dead on arrival "+
					"(exactly how #2549's four bulk-op tolerances went stale)", label, tb)
			}
		}
		for _, tb := range e.outcomeLogs {
			if !isOutcomeLogTable(tb) {
				t.Errorf("oracleAByDesignError %q: outcomeLogs lists %q, which is not an outcome log — "+
					"business state belongs in tables, where the outcome-log check above applies", label, tb)
			}
		}
		if e.designComment == "" {
			t.Errorf("oracleAByDesignError %q: designComment is required — name where production code states "+
				"this intent so the claim is checkable at its source", label)
		}
		if e.provingTest == "" {
			t.Errorf("oracleAByDesignError %q: provingTest is required — the test that already demonstrates "+
				"this is intended behaviour. Without one, this row is an assertion, which is what a "+
				"knownOpenTolerance already was", label)
		}
		if len(e.why) < 80 {
			t.Errorf("oracleAByDesignError %q: why is %d chars — too short to carry a reason. State why the "+
				"mutation is deliberate AND why leaving it in place on the error path is safe",
				label, len(e.why))
		}
	}
}

// TestOracleAByDesign_RowsAreLoadBearing drives each row's own (op, method,
// nth) case and asserts the oracle really does produce the divergence the row
// exempts.
//
// This is the check whose absence let four of #2549's tolerances go dead: the
// error branch grew onlyOutcomeLogTables, those tolerances stopped being
// consulted, and nothing noticed — they sat as expiring carve-outs for a case
// nothing flagged. A row that no longer matches anything must be REMOVED, not
// left as decoration, because a reader seeing it reasonably concludes the
// oracle still flags that case.
func TestOracleAByDesign_RowsAreLoadBearing(t *testing.T) {
	for _, e := range oracleAByDesignErrors {
		e := e
		label := fmt.Sprintf("%s/%s/%s", e.op, e.method, e.kind)
		t.Run(label, func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, e.op, e.method, e.nth, e.kind)
			if outcome != driveObserved {
				// FAIL, never skip. A row whose own case could not be exercised
				// has not been shown to exempt anything, and a SKIPPED subtest
				// reads in CI exactly like one that passed its check.
				t.Fatalf("oracleAByDesignError %q: its own (op, method, nth, kind) could not be driven "+
					"(%s: %s). A row that cannot be exercised cannot be trusted — fix the row, or fix "+
					"whatever made the case unreachable", label, outcome, reason)
			}
			if in.result.Success {
				t.Fatalf("oracleAByDesignError %q: this op reported SUCCESS under its own fault, so it never "+
					"reaches the error-reporting branch this mechanism covers. Either the behaviour changed "+
					"(remove the row) or the row names the wrong case", label)
			}
			diff := diffTables(in.before, in.after)
			if len(diff) == 0 {
				t.Fatalf("oracleAByDesignError %q: no state diverged at all, so oracle (a) would not flag "+
					"this case and the row is dead. Remove it", label)
			}
			if onlyOutcomeLogTables(diff) {
				t.Fatalf("oracleAByDesignError %q: the diff %v is outcome-log-only, already accepted by "+
					"onlyOutcomeLogTables before this mechanism is consulted — the row is dead. Remove it",
					label, diff)
			}
			if got := oracleAErrorByDesign(e.op, e.method, e.kind, e.nth, diff); got == nil {
				t.Fatalf("oracleAByDesignError %q: the real diff is %v, which this row's tables %v do not "+
					"cover — either the behaviour changed or the row's table list is wrong. NOT widened "+
					"automatically: an unexplained table is a different finding", label, diff, e.tables)
			}
			t.Logf("load-bearing: %s diverges in %v, covered by the reviewed row (proving test: %s)",
				label, diff, e.provingTest)
		})
	}
}

// TestKnownOpenTolerances_AreLoadBearing is the same staleness check applied to
// knownOpenTolerances, which is where the decay #2549 exposed actually lived.
//
// It does NOT re-derive checkOracles' accept-before-report ordering. It watches
// the real decision through observeKnownOpenMatch, which matchingKnownOpen
// calls on every tolerance it actually returns. A reconstruction of that
// ordering would be a second implementation of it, and a drifted copy would
// report a LIVE tolerance as dead and invite someone to delete a real
// carve-out — the one failure mode a staleness check must not have.
//
// Scope, stated rather than implied: it drives only the entries whose (op,
// method, nth, kind) are fully specified, because a blank-method wildcard entry
// gives the driver no method to fault. Those are listed by name in
// toleranceStalenessUndrivable below so the gap is visible instead of looking
// like full coverage. Narrowing it means giving the wildcard entries a
// representative method to drive — a schema change the coordinator should
// weigh, not something to invent here.
//
// Also not covered: an entry whose fault never fires for the (method, nth) it
// names is reported as undrivable, not dead, because "the fault did not fire"
// and "the oracle no longer flags it" are different facts and only the second
// justifies deleting a row.
func TestKnownOpenTolerances_AreLoadBearing(t *testing.T) {
	c := classifyToleranceStaleness(t)
	dead, undrivable, inconclusive, revivedLive := c.dead, c.undrivable, c.inconclusive, c.revivedLive

	for _, label := range c.underspecified {
		if !toleranceStalenessUndrivable[label] {
			t.Errorf("knownOpenTolerance %q wildcards at least one of method/kind/nth, so there is no single "+
				"fault for this staleness check to arm and it cannot be driven — and it is not listed in "+
				"toleranceStalenessUndrivable. Add it there with a note, so the coverage gap is visible "+
				"rather than silent. (A wildcard row is still constrained by its mandatory non-empty "+
				"tables, enforced by TestKnownOpenTolerances_CarryIssueAndExpiry; what it is NOT covered by "+
				"is this staleness check.)", label)
		}
	}

	if len(inconclusive) > 0 {
		t.Errorf("found %d knownOpenTolerance entr(y/ies) this check could not evaluate at all — the "+
			"fault-free reference run errored or failed, Setup errored, or a snapshot failed: %v\n\n"+
			"This is a failure, not a skip: nothing was learned about those rows, so treating it as "+
			"\"nothing to report\" is exactly the silent-decay shape this check exists to catch. Fix the "+
			"harness or the op, then re-run.", len(inconclusive), inconclusive)
	}
	if len(revivedLive) > 0 {
		t.Errorf("found %d toleranceDeadPendingTriage entr(y/ies) the oracle is consulting again: %v\n\n"+
			"They are live tolerances, not dead debt. Remove them from toleranceDeadPendingTriage — a row "+
			"left in the baseline is exempt from the dead-row check forever, so the next time it really "+
			"does go dead nothing will say so.", len(revivedLive), revivedLive)
	}

	// Ratchet the other direction too: a baselined entry that came back to life
	// (or was deleted) must not sit in the baseline pretending to be debt.
	var revived []string
	for label := range toleranceDeadPendingTriage {
		stillListed := false
		for _, k := range knownOpenTolerances {
			if fmt.Sprintf("%s/%s/%s#%d", k.op, k.method, k.kind, k.nth) == label {
				stillListed = true
				break
			}
		}
		if !stillListed {
			revived = append(revived, label)
		}
	}
	sort.Strings(revived)
	if len(revived) > 0 {
		t.Errorf("found %d toleranceDeadPendingTriage entr(y/ies) whose knownOpenTolerance is gone: %v\n"+
			"The cleanup happened — remove the baseline row too, or this list outlives the debt it tracks.",
			len(revived), revived)
	}

	if len(undrivable) > 0 {
		t.Errorf("found %d knownOpenTolerance entr(y/ies) whose own (op, method, nth) could not be exercised "+
			"— the op key is stale, the storage method was renamed, or the fault never fires at that call "+
			"ordinal: %v\n"+
			"Re-triage each: a tolerance for a case the harness can no longer reach tolerates nothing, but "+
			"\"could not reach\" is NOT the same as \"no longer flagged\", so do not delete on this signal "+
			"alone.", len(undrivable), undrivable)
	}
	if len(dead) > 0 {
		t.Errorf("found %d knownOpenTolerance entr(y/ies) that no longer tolerate anything — their fault "+
			"fired, but the oracle did not report a violation for them, so matchingKnownOpen never "+
			"returned them: %v\n\n"+
			"Remove them. A dead tolerance is worse than no tolerance: it carries an expiry that produces "+
			"re-filing churn for a case nothing flags, and it tells a reader the oracle still reports that "+
			"case when it does not. This is exactly how four of #2549's own entries decayed unnoticed once "+
			"the error-reporting branch gained onlyOutcomeLogTables.\n\n"+
			"Before deleting, establish WHY each one went quiet — the fix landed, or an earlier "+
			"accept-by-design now shadows it. If it is the latter and the behaviour really is by design, "+
			"move it to oracleAByDesignErrors (this file) with its design citation and proving test rather "+
			"than just dropping it.", len(dead), dead)
	}
}

// toleranceStaleness is classifyToleranceStaleness' result: every
// knownOpenTolerance sorted into exactly one bucket.
type toleranceStaleness struct {
	// live: the oracle consulted this row — it is load-bearing.
	live []string
	// dead: its fault fired and the oracle flagged nothing, and it is NOT
	// baselined in toleranceDeadPendingTriage.
	dead []string
	// revivedLive: baselined as dead, but the oracle consulted it again.
	revivedLive []string
	// undrivable: the op key is stale, the method was renamed, or the fault
	// never fires at that ordinal.
	undrivable []string
	// inconclusive: the harness gave up before the oracle ran.
	inconclusive []string
	// underspecified: blank method and/or nth == 0, so there is nothing to
	// drive.
	underspecified []string
}

// classifyToleranceStaleness drives every fully-specified knownOpenTolerance
// once and reports which bucket each landed in.
//
// Extracted so the calibration below can assert the classification
// DISCRIMINATES, using the same code path the real check uses rather than a
// reimplementation of it. (The previous calibration was a comment on one
// baseline row — #2606, a tolerance for a bug that turned out to be fixed —
// claiming its dead verdict proved the check worked. That row is now deleted,
// as a tolerance for a fixed bug should be, so the calibration cannot live
// there; and a calibration that depends on some row happening to be stale is
// one deletion away from silently disappearing anyway.)
func classifyToleranceStaleness(t *testing.T) toleranceStaleness {
	t.Helper()
	var c toleranceStaleness
	for _, k := range knownOpenTolerances {
		label := fmt.Sprintf("%s/%s/%s#%d", k.op, k.method, k.kind, k.nth)
		// A row wildcarded in ANY dimension cannot be driven: there is no
		// single (method, nth, kind) to arm. Derived from the one shared
		// definition of "wildcarded" (#2844) rather than re-spelled here, so
		// this check and matchingKnownOpen's matching cannot disagree about
		// which rows those are.
		if len(toleranceWildcardedDimensions(k)) > 0 {
			c.underspecified = append(c.underspecified, label)
			continue
		}
		consulted := false
		target := label
		prev := observeKnownOpenMatch
		observeKnownOpenMatch = func(got *knownOpenTolerance) {
			if fmt.Sprintf("%s/%s/%s#%d", got.op, got.method, got.kind, got.nth) == target {
				consulted = true
			}
		}
		_, outcome, reason := driveFaultCase(t, k.op, k.method, k.nth, k.kind)
		observeKnownOpenMatch = prev

		_, baselined := toleranceDeadPendingTriage[label]
		switch {
		case outcome == driveNotEvaluated:
			// The harness itself gave up before the oracle ran. This used to
			// end the entire test as SKIP on the first occurrence, leaving
			// every later row unexamined — see drive_sink_test.go. It is a
			// FAILURE now: an unevaluated row is an unchecked row.
			c.inconclusive = append(c.inconclusive, label+" ("+reason+")")
		case outcome != driveObserved:
			c.undrivable = append(c.undrivable, label+" ("+outcome.String()+")")
		case consulted && baselined:
			// Ratchet in the live direction: a row baselined as dead that the
			// oracle is consulting again is no longer debt, and leaving it in
			// the baseline would make the NEXT time it dies invisible.
			c.revivedLive = append(c.revivedLive, label)
		case consulted:
			c.live = append(c.live, label)
		case !baselined:
			c.dead = append(c.dead, label)
		default:
			// Baselined and still dead — the expected steady state for a row
			// whose owning issue is still open. Not reported.
		}
	}
	sort.Strings(c.live)
	sort.Strings(c.dead)
	sort.Strings(c.revivedLive)
	sort.Strings(c.undrivable)
	sort.Strings(c.inconclusive)
	sort.Strings(c.underspecified)
	return c
}

// TestKnownToleranceStaleness_DetectsDeadAndLiveRows is the calibration for
// TestKnownOpenTolerances_AreLoadBearing: both directions, through the real
// classifier.
//
// The thing that can silently break is the `consulted` signal — it comes from
// observeKnownOpenMatch, a hook matchingKnownOpen calls. If that hook stops
// firing (renamed, removed, short-circuited by an earlier accept-by-design that
// returns before matchingKnownOpen is reached), EVERY row reads as dead and the
// check fails loudly — annoying, but not dangerous. The dangerous direction is
// the opposite: if something makes `consulted` true unconditionally, every row
// reads as load-bearing and the check passes forever while verifying nothing.
// That is the failure this test catches.
//
// Live direction: at least one REAL row must classify live. Not-live
// direction: a PLANTED known-dead row must classify dead. A stuck signal can
// satisfy only one of those.
//
// Why the not-live half is planted rather than read off the real list: it used
// to require at least one real row in a not-live bucket, which only held while
// some debt happened to be outstanding. TOL-1 cleared the last baselined dead
// row (#2548's GetMFASecret), and a calibration that depends on a bug staying
// unfixed is one cleanup away from vanishing — this file's own comment on the
// #2606 precedent says as much. The planted row is that exact real shape:
// GetMFASecret#1/error on /auth/mfa/verify fires, but its diff is [AuditEvent]
// only, accepted by onlyOutcomeLogTables before matchingKnownOpen runs, so a
// correct classifier must call it dead. Deliberately NOT asserted: which real
// rows land where — that changes every time a bug is fixed or a tolerance
// added, and pinning it would make this test a second copy of the list.
func TestKnownToleranceStaleness_DetectsDeadAndLiveRows(t *testing.T) {
	c := classifyToleranceStaleness(t)
	if len(c.live) == 0 {
		t.Errorf("the staleness classifier found NO load-bearing tolerance among %d entries. Either every "+
			"tolerance really is dead (then TestKnownOpenTolerances_AreLoadBearing is already failing and "+
			"says which), or the `consulted` signal is broken — observeKnownOpenMatch is no longer called "+
			"by matchingKnownOpen, or an earlier accept-by-design now returns before it is reached. A "+
			"classifier stuck on one answer cannot detect staleness.\n"+
			"buckets: live=%v dead=%v revivedLive=%v undrivable=%v inconclusive=%v",
			len(knownOpenTolerances), c.live, c.dead, c.revivedLive, c.undrivable, c.inconclusive)
	}

	planted := knownOpenTolerance{
		op: "REST POST /auth/mfa/verify", method: "GetMFASecret", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#calibration", expires: "2099-01-01",
		findingDoc: "TestKnownToleranceStaleness_DetectsDeadAndLiveRows planted known-dead row",
	}
	plantedLabel := fmt.Sprintf("%s/%s/%s#%d", planted.op, planted.method, planted.kind, planted.nth)
	real := knownOpenTolerances
	knownOpenTolerances = append(append([]knownOpenTolerance{}, real...), planted)
	pc := classifyToleranceStaleness(t)
	knownOpenTolerances = real

	plantedDead := false
	for _, l := range pc.dead {
		if l == plantedLabel {
			plantedDead = true
		}
	}
	if !plantedDead {
		t.Errorf("the planted known-dead row %q was NOT classified dead. Either the `consulted` signal is "+
			"stuck TRUE — the dangerous direction: this check would pass forever while verifying nothing — "+
			"or that tuple's behaviour changed so it is no longer dead (then pick another tuple whose fault "+
			"fires and whose diff the oracle accepts before matchingKnownOpen; never drop this half).\n"+
			"buckets with the plant: live=%v dead=%v undrivable=%v inconclusive=%v",
			plantedLabel, pc.live, pc.dead, pc.undrivable, pc.inconclusive)
	}
	if len(pc.live) != len(c.live) {
		t.Errorf("planting one dead row changed the real rows' live count (%d -> %d) — the classification "+
			"is not independent per row", len(c.live), len(pc.live))
	}
	t.Logf("staleness classifier discriminates: %d real rows live, planted %q classified dead=%v",
		len(c.live), plantedLabel, plantedDead)
}

// toleranceDeadPendingTriage is the ratchet baseline: knownOpenTolerances
// entries this check found already dead, each mapped to the STILL-OPEN issue
// that owns it. The check fails on a NEW dead entry, not on these — the
// inventory_ratchet_test.go idiom, so existing debt is visible with an owner
// instead of either blocking the build or being invisible.
//
// The entry condition is deliberately narrow, because a baselined row is exempt
// from the dead-row check for as long as it sits here. A row belongs here only
// when its issue is OPEN. A dead tolerance whose issue is CLOSED is not debt —
// it is a tolerance for a fixed bug, which actively hides a regression in that
// fix (the oracle would flag the behaviour coming back, and the tolerance would
// absorb it). Those get DELETED from knownOpenTolerances, not baselined:
// #2554, #2599 and #2606 were, each on three independent signals — issue
// CLOSED, the fix's own artefact present in the tree, and this check reporting
// the row dead. See each deletion note in knownOpenTolerances.
//
// What is verified for the rows below: the fault fires, the oracle reports no
// violation, and matchingKnownOpen therefore never returns them. What is NOT
// verified: WHY each went quiet — a tolerance may be dead because an earlier
// accept-by-design now shadows it, in which case the right move is to move it
// to oracleAByDesignErrors with a design citation rather than drop it. That
// per-entry call belongs to the owner of each open issue.
//
// Both ratchets fire on these rows: TestKnownOpenTolerances_AreLoadBearing
// fails if a baselined row's knownOpenTolerance is gone (stale baseline) AND if
// the oracle starts consulting it again (it is live, not debt). The check's own
// red/green calibration no longer depends on one of these rows happening to be
// a fixed bug — see TestKnownOpenToleranceStaleness_DetectsDeadAndLiveRows.
// (#2407's baseline entry — REST PUT
// /api/v1/projects/{id}/access-requests/{requestId}, CreateAccessRequestApproval,
// error, nth 1 — is GONE. Its knownOpenTolerance row no longer exists: #2415
// fixed the bug (finalizeAccessRequestApproval now runs the grant, the approval
// record and the request-state update inside one storage.WithTransaction) and
// FIX-2 deleted the row, leaving this baseline pointing at nothing. The
// stale-baseline half of the ratchet is what caught it: "found 1
// toleranceDeadPendingTriage entr(y/ies) whose knownOpenTolerance is gone". A
// baseline entry with no row behind it is pure noise — it can never go red
// again, so it only hides the fact that the exemption it names is already
// retired.)
//
// (#2548's GetMFASecret entry is GONE: TOL-1 deleted the dead row it baselined,
// so the baseline went with it. The map is empty, not deleted -- the next row
// found dead while its issue is still open belongs here.)
var toleranceDeadPendingTriage = map[string]string{}

// toleranceStalenessUndrivable names the knownOpenTolerances entries
// TestKnownOpenTolerances_AreLoadBearing cannot drive, with why. Keeping the
// list explicit is the point: an unlisted undrivable entry fails the test, so
// the uncovered set cannot grow silently.
//
// (Empty since TOL-1: the four wildcard rows that used to be listed here --
// /auth/mfa/verify and /auth/webauthn/login/finish, error and panic -- were
// deleted as dead or pinned to ReserveLoginAttempt, so every remaining row is
// fully specified and actually driven.)
var toleranceStalenessUndrivable = map[string]bool{}

// isOutcomeLogTable reports whether t is one of outcomeLogTables.
func isOutcomeLogTable(t string) bool {
	for _, o := range outcomeLogTables {
		if t == o {
			return true
		}
	}
	return false
}

// driveFaultCase runs ONE (op, method, nth, kind) case through the real harness
// and returns the oracleInput checkOraclesReporting would have seen. Shared by
// this file's staleness checks and the bulk-access-request pin below, so all of
// them observe exactly what the oracle observes rather than a reconstruction.
//
// It drives the harness through a driveSink, so the harness's own Skip/Fatal
// cannot end the CALLING test and its Errorf findings do not fail it. The
// returned driveOutcome says which of the four things happened; the caller must
// branch on it. See drive_sink_test.go for what passing the real *testing.T
// here used to cost.
func driveFaultCase(t *testing.T, op, method string, nth int, kind faultstorage.FaultKind) (oracleInput, driveOutcome, string) {
	t.Helper()
	opIdx := -1
	for i, entry := range opCatalog {
		if entry.Key == op {
			opIdx = i
			break
		}
	}
	methodIdx := -1
	for i, m := range storageInterfaceMethodNames() {
		if m == method {
			methodIdx = i
			break
		}
	}
	if opIdx < 0 || methodIdx < 0 {
		return oracleInput{}, driveNotInCatalog, fmt.Sprintf("op %q in opCatalog: %t; method %q in storage.Storage: %t",
			op, opIdx >= 0, method, methodIdx >= 0)
	}
	if nth < 1 {
		nth = 1
	}
	data := []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), fuzzKindSelector(kind)}

	var seen oracleInput
	got := false
	sink := &driveSink{t: t}
	func() {
		// driveAborted means the sink recorded the reason in notEvaluated;
		// anything else is a real panic and is re-thrown, never swallowed.
		defer func() { rethrowUnlessDriveAbort(recover()) }()
		runOneFuzzIterationReporting(t, sink, data, nil, nil, func(in oracleInput) {
			seen = in
			got = true
		})
	}()

	switch {
	case sink.notEvaluated != "":
		return oracleInput{}, driveNotEvaluated, sink.notEvaluated
	case !got:
		// The harness ran to completion without reaching the oracle: the only
		// path that does that is the armed fault never firing (NthCall beyond
		// the real call count for this method during Execute).
		return oracleInput{}, driveFaultNeverFired, fmt.Sprintf("fault %s#%d/%s never fired during %s", method, nth, kind, op)
	default:
		return seen, driveObserved, ""
	}
}

// fuzzKindSelector maps a FaultKind back to the selector byte decodeFuzzOp
// reads, so a case can be expressed in terms of the kind rather than a magic
// number. Kept adjacent to decodeFuzzOp's own mapping; a mismatch is caught by
// TestFuzzKindSelector_RoundTripsThroughDecode.
func fuzzKindSelector(kind faultstorage.FaultKind) byte {
	switch kind {
	case faultstorage.KindPanic:
		return 1
	case faultstorage.KindEffectThenError:
		return 2
	default:
		return 0
	}
}

// TestFuzzKindSelector_RoundTripsThroughDecode pins fuzzKindSelector against
// decodeFuzzOp's real mapping, so the staleness checks above cannot silently
// drive the wrong fault kind (and then report a row "dead" because it drove
// something else entirely).
func TestFuzzKindSelector_RoundTripsThroughDecode(t *testing.T) {
	t.Parallel()
	if len(opCatalog) == 0 {
		t.Skip("empty catalog")
	}
	methods := storageInterfaceMethodNames()
	if len(methods) == 0 {
		t.Skip("empty method list")
	}
	for _, kind := range []faultstorage.FaultKind{
		faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError,
	} {
		data := []byte{0, 0, 0, 0, fuzzKindSelector(kind)}
		decoded, ok := decodeFuzzOp(data)
		if !ok {
			t.Fatalf("decodeFuzzOp rejected a well-formed input for kind %s", kind)
		}
		if decoded.kind != kind {
			t.Errorf("fuzzKindSelector(%s) produced byte %d, which decodeFuzzOp reads back as %s — the "+
				"staleness checks would drive the wrong fault kind", kind, fuzzKindSelector(kind), decoded.kind)
		}
	}
}

// TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance
// pins what actually covers #2549's bulk-op instances now that their four
// tolerances are deleted: the error-reporting branch's own onlyOutcomeLogTables.
//
// Without this, a future reader hitting the same ACCEPTABLE-BY-DESIGN log line
// has no way to tell whether it is covered deliberately or by accident, and the
// natural response is to re-add a tolerance "just in case" — which is how the
// four dead ones accumulated in the first place.
func TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance(t *testing.T) {
	for _, c := range []struct{ op, method string }{
		{"REST POST /api/v1/access-requests/bulk-reject", "GetAccessRequest"},
		{"REST POST /api/v1/access-requests/bulk-approve", "GetAccessRequest"},
		{"REST POST /api/v1/access-requests/bulk-approve", "RoleSetBypassesPermissionChecks"},
		{"REST POST /api/v1/access-requests/bulk-approve", "GetRolePermissions"},
	} {
		c := c
		t.Run(strings.ReplaceAll(c.op+"/"+c.method, "/", "_"), func(t *testing.T) {
			nth := 1
			if c.method == "RoleSetBypassesPermissionChecks" {
				nth = 4 // the ordinal the deleted tolerance recorded
			}
			in, outcome, reason := driveFaultCase(t, c.op, c.method, nth, faultstorage.KindError)
			if outcome != driveObserved {
				// FAIL, not skip: these four cases are the specific thing this
				// test pins. If one of them stops being drivable, the claim
				// "onlyOutcomeLogTables covers it" is unverified, and a skip
				// would report that as covered.
				t.Fatalf("op %q / method %q (nth %d) could not be driven (%s: %s) — this test's whole "+
					"subject is what covers THESE cases, so an unevaluated one must not read as covered",
					c.op, c.method, nth, outcome, reason)
			}
			diff := diffTables(in.before, in.after)
			if len(diff) == 0 {
				t.Fatalf("no divergence at all for op %q / method %q (nth %d) — then nothing needs covering "+
					"here and this pin is stale. Remove it, or correct the case it names", c.op, c.method, nth)
			}
			if !onlyOutcomeLogTables(diff) {
				t.Fatalf("this case now diverges in %v, which is NOT outcome-log-only — the thing that "+
					"covered it after #2549 deleted its tolerance no longer applies. Re-triage before "+
					"re-adding any exemption: a business-state table here would be a real finding, not "+
					"the audit-content divergence the deleted tolerance described", diff)
			}
			t.Logf("covered by the error branch's onlyOutcomeLogTables (diff %v), no tolerance needed", diff)
		})
	}
}
