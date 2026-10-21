// owed_audit_oracle_test.go -- oracle (a)'s scoped owed-audit rule (MERGE-FIX-3482E,
// #3482; Andrei's answer to ask 3482-owed-audit-oracle-a, option (a), 2026-10-20).
//
// WHAT HAPPENS. A revocation (auditTx3RevocationOps, plus the SSO callback, whose
// IdP group reconciliation revokes memberships) runs through withOwedAuditMutation
// (internal/core/audit_owed.go, INV-CORE-revocation-audit-owed): the revocation and a
// pending_audit_events record of the audit row it owes commit in ONE transaction;
// afterwards the row is appended and the record claimed in a second transaction. If
// that second transaction fails (LogAuditEvent / ClaimPendingAuditEvent faulted), the
// request still SUCCEEDS by design ("a revocation is never blocked by the audit log",
// Andrei 2026-10-14) and the record stays queued for BackfillPendingAuditEvents. The
// final state then differs from the fault-free reference in exactly {AuditEvent
// (the row is missing), PendingAuditEvent (its record is present)}. Oracle (a) had no
// knowledge of that outcome and reported it as a partial commit (seed
// testdata/fuzz/FuzzStorageFaultOperations/5012b3d0b086d4a4).
//
// THE RULE. Oracle (a) accepts a SUCCESS whose diff against the reference is confined
// to {AuditEvent, PendingAuditEvent} only when ALL of these hold:
//
//  1. Scope. The op is in auditTx3RevocationOps, is the SSO callback / SAML ACS, or is
//     the plain secret suspend (commitOwingAudit, INV-CORE-plain-suspend-audit-owed),
//     AND the fault is on LogAuditEvent, ClaimPendingAuditEvent or WithTransaction (the
//     owing transaction or the settle transaction: refusing the latter leaves exactly a
//     refused append's outcome). Any other fault or op stays fail-closed: it never
//     reaches this rule's acceptance. It is not an input skip and not a per-op
//     oracleAByDesignErrors row (the shared tables are not edited).
//     Effect-then-error that the op REPORTS AS AN ERROR is in scope too (MERGE-FIX-3482J):
//     the owing transaction commits and reports an error, so the request fails with the
//     revocation and its record committed. Oracle (d) calls this rule first for it. The
//     same conditions apply, with two adjustments a reported error forces and nothing
//     else: the non-audit outcome logs (Notification, SecretAccessLog) and the audit
//     rows of types the op does not owe (a bulk summary row records the REPORTED
//     outcome) are left out of the comparison, as (d) leaves them out; every owed row is
//     still compared. A failed SSO/SAML login after a committed reconcile cannot equal
//     the reference (no session); owedAuditSSOPartialVerdict judges it.
//  2. The pending row is REQUIRED, not tolerated. For every audit row the faulted run
//     lacks versus the reference there is EXACTLY ONE PendingAuditEvent with the same
//     event type and payload (compared as multisets, ids and the timestamps the
//     snapshot already drops left out). Neither an audit row nor a pending row for a
//     revocation that succeeded is a violation; so is a pending row with no missing
//     audit row (a duplicate or a spurious one), an audit row the reference does not
//     write, and a pending row without the effect.
//  3. Same-transaction proof, from the state alone where the state can show it: the
//     non-audit tables equal the reference's (so the effect is exactly the reference's
//     effect), a pending or audit row accompanies it (2), so never effect-only; and a
//     pending row whose effect is missing (the other tables still equal the pre-fault
//     state although the reference changed them) is a violation, never record-only.
//     Limit, stated: when an op's catalog scenario revokes nothing visible
//     (POST /users/{id}/revoke-sessions of a user with no session) the effect is
//     state-neutral, the state cannot show that the record committed WITH it, and the
//     proof rests on 2's exact payload match plus internal/core's
//     TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost. The pending-record write
//     failing too (a fault on CreatePendingAuditEvent) is
//     OUT of this rule: the revocation still succeeds, the SECURITY log is loud and
//     the row is attempted directly (audit_owed.go: commitOwingAudit /
//     runOwedAuditMutation's collect-only run), so the final state must EQUAL the
//     reference. Anything else on that fault is a violation, never accepted here.
//  4. Convergence. After the fault is removed and BackfillPendingAuditEvents has run,
//     the final state equals the reference exactly: every audit row once, zero
//     pending rows, every other table unchanged, and the audit chain verifies. The
//     only normalisation is the backfill's own "(recorded late: ...)" description
//     suffix (it embeds the time the operation happened, which cannot equal the
//     reference's), stripped from that comparison alone, and row ids (the backfilled
//     row is appended later than the reference's).
//
// WHAT THIS RULE DOES NOT ACCEPT. The state in which the pending record AND the direct
// audit write both failed (audit_owed.go logs "NOT queued for backfill (record it by
// hand)") is a real audit-trail gap, not an outcome by design: the code documents it
// as a loud failure, and this rule does not accept it because the code documents it.
// It shows up as "neither an audit row nor a pending row" (condition 2) and is a
// violation. The fuzzer injects one fault per run, so it cannot reach that state on its
// own; owed_audit_oracle_calibration_test.go builds it explicitly.
//
// The rule is authoritative inside its scope: for an in-scope SUCCESS with a state
// difference it decides (accept or violation) and the lenient AuditEvent-only
// acceptance further down in checkOraclesReporting is never consulted, because that
// one would accept a revocation that lost its audit row without queueing it.
//
// Not covered, said explicitly: the rule judges the final state, it does not watch
// which transaction wrote what; condition 3 is inferred from the state (effect visible
// implies pending-or-audit present) plus the CreatePendingAuditEvent case, which pins
// the fallback to "equals the reference". It applies to SUCCESS only (an error branch
// is judged by the unchanged rest of oracle (a)/(d), except effect-then-error, see 1).
package faultops

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	owedAuditSSOCallbackOp = "REST GET /auth/sso/{provider}/callback"
	owedAuditAuditTable    = "AuditEvent"
	owedAuditPendingTable  = "PendingAuditEvent"
)

// owedAuditSAMLACSOp is the SAML sibling of the SSO callback: the same group/role
// reconcile (reconcileSSOGroups / reconcileSSORoles), so the same owed rows.
const owedAuditSAMLACSOp = "REST POST /auth/saml/{provider}/acs"

// owedAuditSecretSuspendOp is the plain secret suspend: the first owed-audit op
// (commitOwingAudit, INV-CORE-plain-suspend-audit-owed), older than AUDIT-TX-3 and with
// the same outcome when its audit append fails: the suspension commits with a pending
// record of secret.suspended, and the backfill writes the row (MERGE-FIX-3482J: CI input
// 7800103230, ClaimPendingAuditEvent#1). The project freeze (suspend-all) takes the same
// path per secret; its catalog scenario has no secret to suspend, so it owes nothing
// there and is not listed.
const owedAuditSecretSuspendOp = "REST POST /api/v1/secrets/{id}/suspend"

// owedAuditMoreOps are catalog ops outside auditTx3RevocationOps whose scenario also
// owes an audit row (a narrowing through runOwedAuditMutation or commitOwingAudit). Found
// by sweeping ClaimPendingAuditEvent#1..3 (all kinds) over the WHOLE opCatalog
// (MERGE-FIX-3482J): each of these left exactly the owed outcome and was reported by the
// unscoped oracle (a). TestOwedAuditOracle_EveryOwingCatalogOpIsScoped keeps the list
// complete.
var owedAuditMoreOps = []string{
	owedAuditSecretSuspendOp,
	"REST POST /api/v1/secret-access-requests/{requestId}/withdraw",
	"REST PUT /api/v1/projects/{id}/machine-identities/{machineId}",
	"REST POST /api/v1/users/{id}/require-password-reset",
	"REST DELETE /api/v1/auth/tokens/expired",
	// MERGE-FIX-3482K: a role update that adds no permission is owed (the catalog
	// scenarios keep the set and, over gRPC, change the description).
	"REST PUT /api/v1/roles/{id}",
	"GRPC keyorix.v1.RoleService.UpdateRole",
}

// owedAuditScopedOps is the rule's op scope, the single list the rule and its sweep read.
func owedAuditScopedOps() []string {
	out := append([]string{owedAuditSSOCallbackOp, owedAuditSAMLACSOp}, owedAuditMoreOps...)
	return append(out, auditTx3RevocationOps...)
}

// owedAuditRuleOp reports whether op is in the rule's scope (condition 1, op half).
func owedAuditRuleOp(op string) bool {
	return slices.Contains(owedAuditScopedOps(), op)
}

// owedAuditDecision is the rule's verdict on one oracleInput.
type owedAuditDecision struct {
	// engaged: the rule decides this input, so the lenient acceptances further down
	// in checkOraclesReporting must not.
	engaged bool
	// violation is non-empty when the input is a violation.
	violation string
	// note says what was verified when the input is accepted.
	note string
}

// owedAuditConverge removes the fault, runs BackfillPendingAuditEvents, checks the
// audit chain and returns the resulting snapshot. nil means "no backfill was run".
type owedAuditConverge func() (dbSnapshot, error)

// owedAuditConvergeFor is the real converger for the world the case ran in; nil when
// the oracle input carries no world (the rule then fails closed).
func owedAuditConvergeFor(w *faultWorld) owedAuditConverge {
	if w == nil {
		return nil
	}
	return func() (dbSnapshot, error) {
		ctx := context.Background()
		w.faulty.Arm(nil)
		if _, err := w.core.BackfillPendingAuditEvents(ctx); err != nil {
			return dbSnapshot{}, fmt.Errorf("BackfillPendingAuditEvents: %w", err)
		}
		drainAllBackgroundGoroutines()
		v, err := w.core.VerifyAuditChain(ctx)
		if err != nil {
			return dbSnapshot{}, fmt.Errorf("VerifyAuditChain: %w", err)
		}
		if !v.Valid {
			return dbSnapshot{}, fmt.Errorf("the audit chain does not verify after the backfill: first broken id=%v", v.FirstBrokenID)
		}
		return snapshotDB(w.db)
	}
}

// owedAuditDeps is what the verdict needs from the running world: the convergence step
// (condition 4) and the event types the op owes (condition 2). Either nil means "not
// available", and the rule then fails closed on the step that needs it.
type owedAuditDeps struct {
	converge  owedAuditConverge
	owedTypes func(op string) (map[string]int, error)
}

// owedAuditDepsFor is how the hook obtains the deps. The calibration swaps it for one
// that returns nothing while it DRIVES a case: the harness runs the oracle itself
// inside the drive, and a real converger would backfill the very world the calibration
// then wants to damage in its pre-backfill state.
var owedAuditDepsFor = func(w *faultWorld) owedAuditDeps {
	return owedAuditDeps{converge: owedAuditConvergeFor(w), owedTypes: owedAuditProbeFor(w)}
}

var (
	owedAuditProbeMu    sync.Mutex
	owedAuditProbeCache = map[string]map[string]int{}
)

// owedAuditProbeFor returns the probe that tells which audit rows an op OWES: it runs
// the op once, unfaulted setup, with LogAuditEvent#1 refused, and reads the event types
// of the pending records that appear. A refused first append queues every row the op
// owes (audit_owed.go: the first refusal stops the attempts, the rest stay pending), and
// nothing else, so those are exactly the revocation's own rows. A row the op writes
// best-effort (auth.sso_groups_synced, the SSO sync summary) is never pending, and
// losing it alone is the unchanged best-effort behaviour, judged by the rest of oracle
// (a), not by this rule. Cached per op for the process. A regression that made a
// revocation row non-owed would make this probe return nothing for it; that is guarded
// separately by TestOwedAuditOracle_SweepEveryScopedOp (every op's probed owed types must
// equal the hand-written owedAuditExpectedOwedTypes table) and
// TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed.
func owedAuditProbeFor(w *faultWorld) func(op string) (map[string]int, error) {
	if w == nil {
		return nil
	}
	return func(op string) (map[string]int, error) {
		owedAuditProbeMu.Lock()
		defer owedAuditProbeMu.Unlock()
		if m, ok := owedAuditProbeCache[op]; ok {
			return m, nil
		}
		var entry *operation
		for i := range opCatalog {
			if opCatalog[i].Key == op {
				entry = &opCatalog[i]
			}
		}
		if entry == nil {
			return nil, fmt.Errorf("op %q is not in opCatalog", op)
		}
		// Refuse each LogAuditEvent call in turn (1, 2, ... until the fault no longer
		// fires) and take the union of what gets queued. Refusing only the first call is
		// not enough: an op can run several owed mutations (the SSO callback removes a
		// group membership and, separately, a mapped role), the first refusal queues only
		// the rows of the mutation it hits, the first call can be a best-effort row (SAML
		// ACS: auth.sso_jit_provisioned), and the SSO role reconcile iterates a map, so
		// which call is which is not even stable between runs. A run that the refusal
		// fails (a fail-closed grant row refused) queues nothing and adds nothing.
		ctx := context.Background()
		out := map[string]int{}
		successes := 0
		// One probe run: whether the fault fired, and the pending rows' event types when
		// the op succeeded (nil otherwise). Each run gets its own subtest so its world is
		// torn down when the run ends: on Postgres every world holds a connection pool
		// and a schema until its test's Cleanup, and a union probe over every scoped op
		// built on the caller's t outlived max_connections (SQLSTATE 53300).
		probeOnce := func(nth int) (fired bool, got map[string]int, err error) {
			w.t.Run(fmt.Sprintf("owed-probe/%s/LogAuditEvent#%d", op, nth), func(t *testing.T) {
				pw := newFaultWorld(t, nil)
				var state any
				if entry.Setup != nil {
					if state, err = entry.Setup(ctx, pw); err != nil {
						err = fmt.Errorf("probe setup: %w", err)
						return
					}
				}
				drainAllBackgroundGoroutines()
				pw.faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: nth, Kind: faultstorage.KindError, Err: errFuzzInjected})
				res, xerr := entry.Execute(ctx, pw, state)
				fired = pw.faulty.Fired()
				pw.faulty.Arm(nil)
				drainAllBackgroundGoroutines()
				if xerr != nil {
					err = fmt.Errorf("probe run of %s with LogAuditEvent#%d refused: %w", op, nth, xerr)
					return
				}
				if !fired || !res.Success {
					return
				}
				snap, serr := snapshotDB(pw.db)
				if serr != nil {
					err = serr
					return
				}
				got = map[string]int{}
				for _, r := range snap.Tables[owedAuditPendingTable].Rows {
					var rec struct{ EventType string }
					if err = json.Unmarshal([]byte(r), &rec); err != nil {
						return
					}
					got[rec.EventType]++
				}
			})
			return fired, got, err
		}
		for nth := 1; ; nth++ {
			fired, got, err := probeOnce(nth)
			if err != nil {
				return nil, err
			}
			if !fired {
				break
			}
			if got == nil {
				continue
			}
			successes++
			for k, n := range got {
				out[k] = max(out[k], n)
			}
		}
		if successes == 0 {
			return nil, fmt.Errorf("probe of %s: no run with a refused LogAuditEvent succeeded, so the owed rows cannot be told", op)
		}
		owedAuditProbeCache[op] = out
		return out, nil
	}
}

// owedAuditOracle is the hook checkOraclesReporting calls first in oracle (a)'s
// success branch, and in oracle (d)'s effect-then-error branch before it reports a
// mixed state ("a" or "d" in oracle). It returns true when the rule decided the input.
func owedAuditOracle(t fuzzVerdict, oracle, label string, in oracleInput,
	report func(diff []string, format string, args ...any)) (handled bool) {
	d := owedAuditVerdict(in, owedAuditDepsFor(in.world))
	switch {
	case !d.engaged:
		return false
	case d.violation != "":
		report(diffTables(in.refAfter, in.after), "%s: ORACLE (%s) VIOLATION — owed-audit rule (INV-CORE-revocation-audit-owed): %s",
			label, oracle, d.violation)
	default:
		t.Logf("ACCEPTABLE-BY-DESIGN (owed audit, INV-CORE-revocation-audit-owed): %s: %s", label, d.note)
	}
	return true
}

// owedAuditVerdict applies the rule (see the file comment) to one input. It is pure
// except for deps, which the caller supplies so a test can say "the backfill did not
// run" or "it did the wrong thing".
func owedAuditVerdict(in oracleInput, deps owedAuditDeps) owedAuditDecision {
	// An effect-then-error fault that the op reports as an error is judged too
	// (condition 1): the owing transaction can commit and still report an error, and
	// the request then fails with the revocation and its pending record committed.
	ambiguousError := !in.result.Success && in.kind == faultstorage.KindEffectThenError
	if (!in.result.Success && !ambiguousError) || in.after.Hash == in.refAfter.Hash || !owedAuditRuleOp(in.op) {
		return owedAuditDecision{}
	}
	violation := func(format string, args ...any) owedAuditDecision {
		return owedAuditDecision{engaged: true, violation: fmt.Sprintf(format, args...)}
	}

	switch in.method {
	case "CreatePendingAuditEvent":
		if ambiguousError {
			return owedAuditDecision{} // the record and the row fail together: oracle (d) as before
		}
		// Condition 3: the pending record could not be written either. The revocation
		// still succeeds and the row is attempted directly, so the final state must
		// equal the reference. "Equal" means every table equal and the audit rows equal
		// as a multiset, row ids aside: the directly written row is appended after the
		// commit, so its id differs from the reference's, which wrote it in sequence.
		// This is the one case in which this rule accepts anything for this fault, and
		// only by comparing against the reference; no pending row may remain either.
		if diff := owedAuditNotConverged(in.after, in.refAfter, false, nil, nil); len(diff) > 0 {
			return violation("the pending-record write failed and the revocation succeeded, but the final state does not equal the "+
				"fault-free reference (%s): the audit row must then have been written directly "+
				"(audit_owed.go falls back to a collect-only run); if it was not, that is the 'NOT queued for backfill' "+
				"audit-trail gap, which is a violation, not an outcome by design", strings.Join(diff, "; "))
		}
		return owedAuditDecision{engaged: true, note: "the pending-record write failed: the revocation succeeded and its audit row was " +
			"written directly; the final state equals the reference (audit rows once each, no pending row)"}
	case "LogAuditEvent", "ClaimPendingAuditEvent", "WithTransaction":
		// WithTransaction: the settle transaction itself (the claim and the append) is
		// refused or fails, or the owing transaction commits and reports an error. Both
		// leave exactly the outcome of a refused append, and the checks below are the
		// same; a WithTransaction fault that leaves any other state is not accepted.
	default:
		return owedAuditDecision{} // condition 1: any other fault stays fail-closed
	}

	nonAuditAfter := hashExcluding(in.after, owedAuditAuditTable, owedAuditPendingTable)
	nonAuditBefore := hashExcluding(in.before, owedAuditAuditTable, owedAuditPendingTable)
	effectVisible := nonAuditAfter != nonAuditBefore

	refPending, err1 := owedAuditPendingPayloads(in.refAfter)
	gotPending, err2 := owedAuditPendingPayloads(in.after)
	if err1 != nil || err2 != nil {
		return violation("a pending audit event cannot be decoded (reference: %v; faulted run: %v): its payload cannot be checked", err1, err2)
	}
	owed := multisetMinus(gotPending, refPending)
	gone := multisetMinus(refPending, gotPending)

	// On a reported error the outcome logs other than the audit log (a notification sent
	// on success) legitimately follow the REPORTED outcome, exactly as oracle (d) treats
	// them; they are left out of the comparison with the reference and nothing else is.
	ignored := map[string]bool{}
	if ambiguousError {
		for _, tbl := range outcomeLogTables {
			if tbl != owedAuditAuditTable {
				ignored[tbl] = true
			}
		}
	}
	var otherDiff []string
	for _, tbl := range diffTables(in.refAfter, in.after) {
		if tbl != owedAuditAuditTable && tbl != owedAuditPendingTable && !ignored[tbl] {
			otherDiff = append(otherDiff, tbl)
		}
	}
	if _, sso := ssoClassCOps[in.op]; sso && ambiguousError && len(otherDiff) > 0 {
		return owedAuditSSOPartialVerdict(in, deps, owed, gone)
	}
	if len(otherDiff) > 0 {
		if len(owed) > 0 && !effectVisible {
			return violation("a pending audit event is queued but the effect is missing (the non-audit tables equal the pre-fault state, "+
				"and also differ from the reference in %v): a record without the revocation it describes", otherDiff)
		}
		return owedAuditDecision{} // not this rule's shape: the rest of oracle (a) judges it, fail-closed
	}

	refAudit, err1 := owedAuditAuditPayloads(in.refAfter, false)
	gotAudit, err2 := owedAuditAuditPayloads(in.after, false)
	if err1 != nil || err2 != nil {
		return violation("an audit event cannot be canonicalised (reference: %v; faulted run: %v)", err1, err2)
	}
	// On a reported error a best-effort audit row records the REPORTED outcome (a bulk
	// summary saying "1 failed"), which is why oracle (d) never compares AuditEvent.
	// Here only the rows the op OWES are compared, and every one of them still is.
	var keepType func(string) bool
	if ambiguousError {
		if deps.owedTypes == nil {
			return violation("the op's owed event types are unknown, so its owed rows cannot be told from outcome rows")
		}
		types, err := deps.owedTypes(in.op)
		if err != nil {
			return violation("the op's owed event types could not be established: %v", err)
		}
		keepType = func(et string) bool { return types[et] > 0 }
		refAudit, gotAudit = owedAuditKeepTypes(refAudit, keepType), owedAuditKeepTypes(gotAudit, keepType)
	}
	missing := multisetMinus(refAudit, gotAudit)
	extra := multisetMinus(gotAudit, refAudit)
	if len(missing)+len(extra)+len(owed)+len(gone) == 0 {
		return owedAuditDecision{} // differs by row ids/order only: not an owed-audit outcome
	}

	// Here every non-audit table equals the reference's, so "the effect is missing" is
	// decided above (the other-tables branch), and effectVisible only says whether the
	// reference's effect is observable in state at all: an op whose scenario revokes
	// nothing visible (revoke-sessions of a user with no session) has a state-neutral
	// effect, and condition 3 then rests on condition 2's exact payload match alone.
	var why []string
	if len(extra) > 0 {
		why = append(why, fmt.Sprintf("%d audit row(s) the fault-free reference does not write: %s", len(extra), owedAuditSummarise(extra)))
	}
	if len(gone) > 0 {
		why = append(why, fmt.Sprintf("%d pending row(s) of the reference run are gone", len(gone)))
	}
	// A missing row with no pending record is a violation only if the op OWES that row.
	// Which rows it owes comes from the probe (owedAuditProbeFor), not from the state
	// alone: state cannot tell a lost revocation row from a lost best-effort summary row.
	var bestEffortLost []string
	if lost := multisetMinus(missing, owed); len(lost) > 0 {
		if deps.owedTypes == nil {
			return violation("%d audit row(s) are missing without a pending record and the op's owed event types are unknown, "+
				"so they cannot be told from best-effort rows: %s", len(lost), owedAuditSummarise(lost))
		}
		types, err := deps.owedTypes(in.op)
		if err != nil {
			return violation("%d audit row(s) are missing without a pending record and the op's owed event types could not be "+
				"established (%v): %s", len(lost), err, owedAuditSummarise(lost))
		}
		var ownedLost []string
		for _, p := range lost {
			if types[owedAuditEventType(p)] > 0 {
				ownedLost = append(ownedLost, p)
			} else {
				bestEffortLost = append(bestEffortLost, p)
			}
		}
		if len(ownedLost) > 0 {
			why = append(why, fmt.Sprintf("%d owed audit row(s) are neither written nor queued as a pending audit event "+
				"(effect visible: %t) -- the revocation's audit trail has a gap: %s", len(ownedLost), effectVisible, owedAuditSummarise(ownedLost)))
		}
		if len(bestEffortLost) > 0 && len(owed) > 0 {
			why = append(why, fmt.Sprintf("a best-effort audit row is lost in the same run as a queued record, so the state cannot be "+
				"attributed to one refused append: %s", owedAuditSummarise(bestEffortLost)))
		}
	}
	if spurious := multisetMinus(owed, missing); len(spurious) > 0 {
		why = append(why, fmt.Sprintf("%d pending audit event(s) match no missing audit row (a duplicate or a spurious record), "+
			"so the backfill would write rows the reference does not have: %s", len(spurious), owedAuditSummarise(spurious)))
	}
	if len(why) > 0 {
		return violation("%s (missing audit rows: %d, pending audit events owed: %d)", strings.Join(why, "; "), len(missing), len(owed))
	}
	if len(bestEffortLost) > 0 && len(owed) == 0 {
		// Only plain best-effort rows are missing and nothing is queued: not an owed-audit
		// outcome. The unchanged rest of oracle (a) judges it, as it did before #3482.
		return owedAuditDecision{}
	}

	// Conditions 1-3 hold: every missing audit row has exactly one pending record with
	// the same payload and the effect is visible. Condition 4: convergence.
	if deps.converge == nil {
		return violation("the backfill was not run, so convergence to the reference state is unproven")
	}
	got, err := deps.converge()
	if err != nil {
		return violation("the backfill did not complete: %v", err)
	}
	if diff := owedAuditNotConverged(got, in.refAfter, true, ignored, keepType); len(diff) > 0 {
		return violation("after BackfillPendingAuditEvents the final state still differs from the fault-free reference: %s", strings.Join(diff, "; "))
	}
	return owedAuditDecision{
		engaged: true,
		note: fmt.Sprintf("%d audit row(s) owed, each with exactly one pending record committed alongside the effect; the backfill "+
			"converged to the reference state exactly (audit rows once each, zero pending rows, chain verifies)", len(missing)),
	}
}

// owedAuditSSOPartialVerdict judges an SSO/SAML login whose owing transaction (the IdP
// group or role reconcile, a revocation) committed and reported an error: the login
// failed after the revocation, so no session is minted and the state is a
// sub-transition of the fault-free login (SSO class C, zz_sso_class_c_oracle_test.go),
// plus the pending records of the revocation's owed rows. The state cannot equal the
// reference, so convergence is proven differently, and only this way:
//
//   - every queued record (owed) is a row the fault-free login writes (no spurious or
//     duplicated record) and no record of the reference is gone;
//   - BackfillPendingAuditEvents leaves zero pending rows, the chain verifies, and the
//     rows it appended are exactly the queued records, each once;
//   - the drained state is still accepted by SSO class C, the same judgment oracle (d)
//     applies to this login when its revocation's audit rows are written in-transaction;
//   - every membership or role the failed login removed (a UserGroup or UserRole row of
//     the pre-fault state that is gone) has an owed audit row after the drain: one row
//     of an owed type per removed row, so a revocation that committed with neither its
//     row nor its record is a violation here, which oracle (d) alone would not see.
func owedAuditSSOPartialVerdict(in oracleInput, deps owedAuditDeps, owed, gone []string) owedAuditDecision {
	removedRows := func(after dbSnapshot) int {
		n := 0
		for _, tbl := range []string{"UserGroup", "UserRole"} {
			_, rm := rowDelta(in.before.Tables[tbl].Rows, after.Tables[tbl].Rows)
			n += len(rm)
		}
		return n
	}
	if len(owed) == 0 && removedRows(in.after) == 0 {
		// No revocation committed and nothing queued: the login failed before its
		// reconcile, and oracle (d) / SSO class C judge it exactly as before.
		return owedAuditDecision{}
	}
	violation := func(format string, args ...any) owedAuditDecision {
		return owedAuditDecision{engaged: true, violation: fmt.Sprintf(format, args...)}
	}
	refAudit, err := owedAuditAuditPayloads(in.refAfter, false)
	if err != nil {
		return violation("a reference audit event cannot be canonicalised: %v", err)
	}
	if spurious := multisetMinus(owed, refAudit); len(spurious) > 0 {
		return violation("%d pending audit event(s) match no audit row of the fault-free login: %s", len(spurious), owedAuditSummarise(spurious))
	}
	if len(gone) > 0 {
		return violation("%d pending row(s) of the reference run are gone", len(gone))
	}
	if deps.converge == nil {
		return violation("the backfill was not run, so the queued rows are not proven to drain")
	}
	pre, err := owedAuditAuditPayloads(in.after, false)
	if err != nil {
		return violation("an audit event cannot be canonicalised: %v", err)
	}
	got, err := deps.converge()
	if err != nil {
		return violation("the backfill did not complete: %v", err)
	}
	if n := len(got.Tables[owedAuditPendingTable].Rows); n > 0 {
		return violation("after BackfillPendingAuditEvents %d pending audit event(s) remain", n)
	}
	post, err := owedAuditAuditPayloads(got, true)
	if err != nil {
		return violation("an audit event cannot be canonicalised after the backfill: %v", err)
	}
	written := multisetMinus(post, pre)
	if m, e := multisetMinus(owed, written), multisetMinus(written, owed); len(m)+len(e) > 0 {
		return violation("the backfill did not append exactly the queued rows: %d not written [%s], %d extra [%s]",
			len(m), owedAuditSummarise(m), len(e), owedAuditSummarise(e))
	}
	if deps.owedTypes == nil {
		return violation("the op's owed event types are unknown")
	}
	types, err := deps.owedTypes(in.op)
	if err != nil {
		return violation("the op's owed event types could not be established: %v", err)
	}
	beforeAudit, err := owedAuditAuditPayloads(in.before, false)
	if err != nil {
		return violation("a pre-fault audit event cannot be canonicalised: %v", err)
	}
	newOwedRows := owedAuditKeepTypes(multisetMinus(post, beforeAudit), func(et string) bool { return types[et] > 0 })
	removed := removedRows(got)
	if len(newOwedRows) < removed {
		return violation("the failed login removed %d membership/role row(s) but only %d owed audit row(s) exist after the drain: "+
			"a revocation committed with neither its audit row nor a pending record", removed, len(newOwedRows))
	}
	drained := in
	drained.after = got
	if !ssoClassCAccountsForDiff(drained) {
		return violation("after the backfill the failed login's state is not a sub-transition of the fault-free login's (SSO class C): %v",
			diffTables(in.refAfter, got))
	}
	return owedAuditDecision{
		engaged: true,
		note: fmt.Sprintf("failed login after a committed revocation: %d owed row(s) queued, each a row of the fault-free login; the "+
			"backfill appended exactly those, once, and the drained state is SSO class C", len(owed)),
	}
}

// owedAuditNotConverged lists how got differs from the reference: every table by hash
// except AuditEvent, which is compared as a multiset of payloads (row ids aside), and
// the ignored tables (the non-audit outcome logs of a reported error, nothing else).
// keepType, when set (a reported error), limits the AuditEvent comparison to the event
// types the op owes. stripLate removes the backfill's description suffix from got's
// audit rows (only right after a backfill).
func owedAuditNotConverged(got, ref dbSnapshot, stripLate bool, ignored map[string]bool, keepType func(string) bool) []string {
	var out []string
	names := make([]string, 0, len(ref.Tables))
	for name := range ref.Tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ignored[name] {
			continue
		}
		if name == owedAuditAuditTable {
			g, err1 := owedAuditAuditPayloads(got, stripLate)
			r, err2 := owedAuditAuditPayloads(ref, false)
			if err1 != nil || err2 != nil {
				out = append(out, fmt.Sprintf("AuditEvent cannot be canonicalised (%v; %v)", err1, err2))
				continue
			}
			if keepType != nil {
				g, r = owedAuditKeepTypes(g, keepType), owedAuditKeepTypes(r, keepType)
			}
			if m, e := multisetMinus(r, g), multisetMinus(g, r); len(m)+len(e) > 0 {
				out = append(out, fmt.Sprintf("AuditEvent: %d row(s) missing [%s], %d row(s) extra or duplicated [%s]",
					len(m), owedAuditSummarise(m), len(e), owedAuditSummarise(e)))
			}
			continue
		}
		if got.Tables[name].Hash != ref.Tables[name].Hash {
			out = append(out, fmt.Sprintf("%s differs (%d row(s) vs %d in the reference)", name, len(got.Tables[name].Rows), len(ref.Tables[name].Rows)))
		}
	}
	return out
}

// lateSuffix is the text BackfillPendingAuditEvents appends to a backfilled row's
// description (audit_owed.go); it embeds the time the operation happened.
var lateSuffix = regexp.MustCompile(` \(recorded late: it happened at \S+, when the audit log refused the write\)$`)

// embeddedTime matches an RFC3339 timestamp inside text.
var embeddedTime = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)

// snapshotTimePlaceholder replaces a timestamp inside a snapshot column's text. It is
// itself a valid RFC3339 time, so a column holding JSON (PendingAuditEvent.Event) still
// decodes into a models.AuditEvent after the replacement.
const snapshotTimePlaceholder = "1970-01-01T00:00:00Z"

// typeScopedTimeInText lists snapshot columns whose TEXT embeds a wall-clock time the
// structural time-type exclusion in canonicalRow cannot see. PendingAuditEvent.Event is
// the JSON of the audit event the operation owes, including its EventTime: without this
// every pending row differs between two worlds, which TestWorldReuseSoundness caught the
// moment the first corpus seed (5012b3d0b086d4a4) left one behind. Everything else in
// the column is still compared.
var typeScopedTimeInText = map[string][]string{
	"PendingAuditEvent": {"Event"},
}

// owedAuditCanon turns one canonical snapshot row into a comparable payload: the id is
// dropped and the columns the writer defaults on insert are made explicit. When
// stripLate is set, the backfill's description suffix is removed. RFC3339 timestamps
// embedded in Description and Diff are replaced by a placeholder: the snapshot already
// drops time-TYPED fields because two independently built worlds never share a clock
// reading, and the same holds for a time written into text (the setup row
// "setup token issued (... expires=<now+24h>)" differs by a second whenever the two
// worlds straddle a second boundary; found by FuzzOwedAuditRevocations, ~4% of replays
// of one input). The legacy oracle never compared AuditEvent content on a success, so it
// never saw this. Only the time VALUE is ignored; the text around it is compared.
func owedAuditCanon(row map[string]any, stripLate bool) (string, error) {
	delete(row, "ID")
	if row["Success"] == nil {
		row["Success"] = true // gorm default:true
	}
	if s, _ := row["ActorType"].(string); s == "" {
		row["ActorType"] = "user" // gorm default:user
	}
	if d, ok := row["Description"].(string); ok && stripLate {
		row["Description"] = lateSuffix.ReplaceAllString(d, "")
	}
	for _, col := range []string{"Description", "Diff"} {
		if d, ok := row[col].(string); ok {
			row[col] = embeddedTime.ReplaceAllString(d, "<time>")
		}
	}
	b, err := json.Marshal(row) // map keys are sorted: stable
	return string(b), err
}

func owedAuditAuditPayloads(s dbSnapshot, stripLate bool) ([]string, error) {
	var out []string
	for _, r := range s.Tables[owedAuditAuditTable].Rows {
		var m map[string]any
		if err := json.Unmarshal([]byte(r), &m); err != nil {
			return nil, err
		}
		p, err := owedAuditCanon(m, stripLate)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// owedAuditPendingPayloads decodes each PendingAuditEvent's stored audit event and
// canonicalises it exactly like an audit row, so a pending record and the audit row it
// owes compare equal (event type and payload).
func owedAuditPendingPayloads(s dbSnapshot) ([]string, error) {
	var out []string
	for _, r := range s.Tables[owedAuditPendingTable].Rows {
		var rec struct {
			Event string
		}
		if err := json.Unmarshal([]byte(r), &rec); err != nil {
			return nil, err
		}
		var ev models.AuditEvent
		if err := json.Unmarshal([]byte(rec.Event), &ev); err != nil {
			return nil, err
		}
		line, err := canonicalRow(&ev)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, err
		}
		p, err := owedAuditCanon(m, false)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// owedAuditKeepTypes returns the payloads whose event type keep accepts.
func owedAuditKeepTypes(payloads []string, keep func(string) bool) []string {
	var out []string
	for _, p := range payloads {
		if keep(owedAuditEventType(p)) {
			out = append(out, p)
		}
	}
	return out
}

// owedAuditEventType returns the event type of an audit payload.
func owedAuditEventType(payload string) string {
	var m struct{ EventType string }
	_ = json.Unmarshal([]byte(payload), &m)
	return m.EventType
}

// owedAuditSummarise names the event type and description of up to three payloads.
func owedAuditSummarise(payloads []string) string {
	var types []string
	for i, p := range payloads {
		if i == 3 {
			types = append(types, "...")
			break
		}
		var m struct{ EventType, Description string }
		_ = json.Unmarshal([]byte(p), &m)
		types = append(types, fmt.Sprintf("%s %q", m.EventType, m.Description))
	}
	return strings.Join(types, ", ")
}
