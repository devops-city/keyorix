// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// (#2834 -- compliance snapshot persisting partial counts -- is FIXED: its two
	// tolerances are gone. POST /api/v1/compliance/snapshots now fails closed on any
	// degraded sub-rollup; guarded by compliance_snapshot_fail_closed_test.go.)
	// (The third pre-existing finding from the same live runs — #2841, op="REST
	// POST /auth/webauthn/login/finish", method=GetUserRoles, kind=error, nth 1,
	// [AuditEvent LoginAttempt MFAStepUpGrant] — was tolerated here and is now
	// FIXED, so its row is gone rather than expired. Both WebAuthn login paths
	// resolve the response identity before minting the session and the ambient
	// MFAStepUpGrant, so a login that reports failure persists neither; guarded
	// by webauthn_login_no_partial_grant_test.go here and by
	// internal/core/login_identity_before_mint_test.go at the core boundary.
	// The remaining [LoginAttempt] diff is #2880's by-design post-verdict
	// accounting, pinned for GetUserRoles only in oracleAByDesignErrors — not
	// absorbed by #2565's wildcard entry, which is unchanged, not widened.)
	//
	// Fourth and LAST pre-existing finding tolerated from the same live runs,
	// also confirmed by byte-for-byte replay against unmodified origin/main.
	// Filed as #2844, which also records the thing that made me stop here: FOUR
	// distinct pre-existing oracle (a) findings surfaced in ~15 minutes of live
	// fuzzing, the committed corpus being green throughout. Per-finding
	// tolerances cannot converge at that rate, and COMMON-RULES' remedy assumes
	// roughly one such event per PR rather than a stream — so #2844 asks for a
	// batch triage of the standing backlog (#2407 #2548 #2554 #2565 #2599 #2606
	// #2834 #2841 and itself) instead of an unbounded tolerance list growing
	// inside #2549's PR. Expect CI's fuzz-changed to find a fifth; that is the
	// documented, expected outcome, not a surprise.
	//
	// (The WebAuthn register/finish DeleteSessionsForUserExcept tolerance that
	// stood here is removed: #2897 makes that purge failure observable and it is
	// now an op-scoped acceptable-by-design entry above, so the tolerance no
	// longer tolerates anything.)
	// (#2567's entry -- REST POST /auth/mfa/verify, CreateSession#1/error,
	// [MFASecret LoginAttempt] -- is gone. The "step burned, cannot retry with
	// the same code" half is fixed: VerifyMFALoginPending gives the step back
	// with ReleaseTOTPStepIfUnchanged
	// (TestVerifyMFALogin_CreateSessionFailure_ReleasesTOTPStepForRetry). What
	// remains is the by-design post-verdict shape #2894 makes deliberate (slot
	// counted, auth.login_error audited, last_used_step = step-1), now pinned in
	// oracleAByDesignErrors with its design citation and proving tests. This row
	// stopped matching once #2894 added the AuditEvent, and
	// TestKnownOpenTolerances_AreLoadBearing reported it dead.)
	// Coordinator priority (12:34Z): random pre-existing fuzz findings were
	// blocking unrelated PRs (e.g. #2556). Added here, into this PR's own
	// branch, so the hotspot file stays serialized through one PR rather than
	// several concurrent ones touching the same lines.
	//
	// (#2599's row — REST POST /api/v1/invitations, CountSetupTokensSince,
	// error, nth 1 — is GONE, not expired. The bug is fixed: a throttle count
	// that cannot be read is now its own refusal
	// (core.ErrResendThrottleUnverifiable, internal/core/invitations.go), so
	// the invitation is no longer persisted while the request reports the
	// failure. Confirmed on three independent signals before deleting: the
	// issue is CLOSED, the fix's own sentinel is present in the tree, and
	// TestKnownOpenTolerances_AreLoadBearing reports the row dead — the
	// oracle no longer flags its case at all.)
	//
	// (#2606's row — .../items/{itemId}/decide, ListProjectRoleAssignments,
	// error, nth 1 — is likewise GONE. Fixed by #2570: DecideAccessReviewItem's
	// attest path runs its reads before the claim, so the item stays pending
	// when the grant lookup errors. Same three signals: issue CLOSED, the
	// proving test present in the tree
	// (internal/core/TestDecideAccessReviewItem_AttestGrantLookupErrorLeavesItemPending),
	// and the row reported dead.)
	// ---- SESSION ORACLE-A-1, item 1: unblock the merge queue --------------
	// Two pre-existing oracle (a) error-branch findings landed on main unfixed
	// (SESSION-STALE-PR-1: both were found on PRs that touched neither code
	// path -- #2719 and #2461 -- and both merged with the fuzz leg red, so they
	// now fail UNRELATED PRs at random). Both confirmed to reproduce on
	// pristine main at 98031965 by direct replay before these entries were
	// written, so neither is caused by any open PR.
	//
	// Both are the SAME shape, and the shape is one this repo has ALREADY
	// reviewed, classified and machine-enforced as correct:
	// docs/atomicity-exempt.tsv class B, "consume-first by design: a single-use
	// value is consumed BEFORE later work and must stay consumed even if later
	// work fails (replay protection)". Both functions carry their own
	// `// atomicity: consume-first by design` marker comment and a verifying
	// *_FailsClosed test. Oracle (a)'s error branch has no knowledge of that
	// ledger, so it reads a deliberately-retained consumption as a partial
	// commit -- the same harness-oracle gap as #2549's stepup entry above, not
	// a product bug. "Fixing" either by rolling the consume back into the
	// transaction would un-consume a single-use token on a later failure,
	// which is precisely what class B and those tests forbid.
	//
	// Each entry is scoped to ONE op + ONE storage method + ONE fault kind +
	// ONE nth + the exact tables the consumption can touch: a diff that
	// includes anything else is a DIFFERENT finding and must still fail
	// loudly. Remove each when its issue is resolved (see this session's
	// report: the recommended resolution is to teach oracle (a) the class-B
	// ledger, not to change either function).
	//
	// #2817's tolerance was here and is REMOVED by this PR -- oracle (a) now
	// knows the class-B consume-first shape directly
	// (consumeFirstAccountsForDiff, consume_first_oracle_test.go), so the
	// exemption is derived from docs/atomicity-exempt.tsv rather than listed
	// as an open finding, and it covers EVERY storage method on the op rather
	// than the one method a tolerance row could name.
	//
	// #2814's tolerance was here and is REMOVED by this PR, for the same
	// reason as #2817's directly above: CompleteSAML is itself a class-B
	// consume-first row, so oracle (a) now derives the exemption from
	// docs/atomicity-exempt.tsv (consumeFirstAccountsForDiff,
	// consume_first_oracle_test.go) instead of carrying it as an open finding
	// against one named storage method.
	// (#2817's row — REST POST /api/v1/auth/mfa/disable, DeleteMFAForUser,
	// error, nth 1 — and #2814's — REST POST /auth/saml/{provider}/acs,
	// GetUserByUsername, error, nth 1 — are GONE, finishing the deletion the
	// two REMOVED notes directly above already describe. Both rows survived
	// that PR as a merge artefact: the notes landed, the rows did not get
	// dropped, so main carried a comment saying "REMOVED by this PR" sitting
	// right on top of the row it claimed to have removed. This branch's new
	// staleness guard is what surfaced it — TestKnownOpenTolerances_AreLoadBearing
	// reported both rows dead with "their fault fired, but the oracle did not
	// report a violation for them".
	//
	// Deleted rather than baselined into toleranceDeadPendingTriage, on the
	// measured reason each went quiet: the harness log shows both now accepted
	// by consumeFirstAccountsForDiff, i.e. "ACCEPTABLE-BY-DESIGN (consume-first,
	// docs/atomicity-exempt.tsv class B, (*KeyorixCore).requireReauth /
	// (*KeyorixCore).CompleteSAML)". That is a design-cited exemption derived
	// from the class-B ledger and enforced against it
	// (TestConsumeFirstExemptions_MatchAtomicityLedger), and it is STRICTLY
	// NARROWER than the rows it replaces: it requires every table and column
	// outside the op's declared single-use consumption to be byte-for-byte
	// identical to the pre-fault state, where the rows allowlisted a fixed table
	// set and nothing else. So this removes two blanket carve-outs and keeps the
	// derived one — the tolerance list shrinks, the guard does not.)
	// #2842 (ORACLE-A-1). Surfaced by CI's fuzz shard 0 + fuzz-changed on
	// #2821, whose entire diff was the two auth/MFA/SAML rows directly above
	// -- nothing in the secrets path. Confirmed to reproduce on pristine
	// origin/main by direct replay before this entry was written.
	//
	// NOT a bug: RollbackSecret (internal/core/versions.go) re-instates a
	// historical value via RotateSecret, whose storeNextSecretVersion +
	// c.storage.UpdateSecret pair is DELIBERATELY non-transactional.
	// updateSecretWithNewVersion's own doc comment
	// (internal/core/secrets_versions.go) says so, and gives the reason by
	// contrast with the UpdateSecret path it DID make transactional: for a
	// rotation the new value may already have been applied to an external
	// upstream system, and the version row is the only record of it, so
	// rolling it back would trade a loud failure for silent loss of the only
	// record of a live credential. The version row surviving the node update's
	// failure is the intended outcome.
	//
	// Deliberately a tolerance and NOT a consumeFirstExemptions entry: that
	// mechanism requires a class-B (consume-first) row in
	// docs/atomicity-exempt.tsv, enforced by
	// TestConsumeFirstExemptions_MatchAtomicityLedger, precisely so it cannot
	// become a general "state on an error path is fine" carve-out. Nothing is
	// consumed here -- the rationale is "must not roll back", a different
	// claim. #2842 asks for RotateSecret to be classified in that ledger and
	// for oracle (a) to key off the classification; remove this entry then.
	//
	// Scoping is sufficient here, and that is measured rather than assumed: a
	// DERIVED sweep of this op -- run it once unfaulted, read the real call
	// log off FaultyStorage.Calls(), then fault every (method, nth) pair the
	// op actually makes -- enumerated all 96 real pairs and found exactly ONE
	// oracle violation, the UpdateSecret#1 pair below. So unlike #2548/#2565
	// (where the write lands before any faulted call, making every method on
	// the op reproduce it and forcing a method wildcard), this one really is
	// specific to the single call that straddles the version write. No
	// wildcard needed, and no #2549-style treadmill of one new row per red
	// build expected on this op.
	registerKnownOpenTolerance("post_secrets_id_rollback_updatesecretfields_1", knownOpenTolerance{
		op: "REST POST /api/v1/secrets/{id}/rollback", method: "UpdateSecretFields", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2842", expires: "2026-10-17",
		tables:     []string{"SecretVersion"},
		findingDoc: "#2842",
	})
}
