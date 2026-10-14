// webauthn_login_no_partial_grant_test.go — #2841.
//
// A WebAuthn login whose assertion VERIFIES, and which is then reported to the
// caller as failed, must leave no session and no MFA step-up grant behind.
//
// Before this change the session half already held and the grant half did not.
// `completeLogin` (server/http/handlers/auth.go) resolves the response identity
// AFTER core has already minted the session and the grant, and on failure it
// revokes the session — but nothing revoked the grant, so an
// MFAStepUpPurposeRestrictedSecretRead grant outlived a login the caller was
// told had failed, satisfying the restricted-secret MFA gate for the rest of the
// step-up window on some later, unrelated session.
//
// Measured on the pre-fix tree with the faultops repro from #2841
// (op="REST POST /auth/webauthn/login/finish",
// fault=(GetUserRoles, NthCall=1, kind=error)):
//
//	success=false detail="HTTP 500: Login could not be completed. Please try again."
//	diff vs before     = [AuditEvent MFAStepUpGrant LoginAttempt]
//	diff vs fault-free = [Session AuditEvent]
//
// Session is absent from the vs-before diff, which is the proof the existing
// session compensation works; MFAStepUpGrant's presence there is the defect.
//
// This test asserts on the TABLE DIFF rather than on the HTTP status, because a
// partial-state bug reports the same error at every layer either way — only the
// persisted rows distinguish "nothing left behind" from "a grant survived". It
// drives the real REST handler through the real core and storage via the faultops
// harness, so it exercises the actual ordering between the fallible read and the
// writes rather than a reconstruction of it.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// webauthnLoginGrantLeakCases are the two login ops that mint an ambient
// MFAStepUpGrant. The TOTP path (VerifyMFALogin) is deliberately absent: it
// writes only the step-up TOKEN (UpsertMFAStepupToken), never a grant, so it has
// no grant to leak — verified by grepping CreateMFAStepUpGrant's call sites,
// which are these two login paths plus the two explicit step-up/reauth paths
// that are not logins at all.
//
// Only the second-factor op is in opCatalog today, so the passwordless row
// SKIPS here rather than running. That path is not uncovered — it is covered at
// the core boundary by
// TestFinishWebAuthnPasswordlessLogin_IdentityReadFailureLeavesNoSessionOrGrant
// (internal/core/login_identity_before_mint_test.go), which goes red
// without the fix. The row is kept so the coverage arrives here for free if
// opCatalog ever gains the op; the skip message names the core test so the skip
// is never mistaken for absent coverage.
var webauthnLoginGrantLeakCases = []struct {
	name   string
	op     string
	method string
}{
	{
		name:   "second-factor login",
		op:     "REST POST /auth/webauthn/login/finish",
		method: "GetUserRoles",
	},
	{
		name:   "passwordless login",
		op:     "REST POST /auth/webauthn/passwordless/finish",
		method: "GetUserRoles",
	},
}

// TestWebAuthnLogin_ReportedFailureLeavesNoSessionOrStepUpGrant is the #2841
// regression guard.
func TestWebAuthnLogin_ReportedFailureLeavesNoSessionOrStepUpGrant(t *testing.T) {
	for _, c := range webauthnLoginGrantLeakCases {
		t.Run(c.name, func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, c.op, c.method, 1, faultstorage.KindError)
			if outcome == driveNotInCatalog {
				// The ONLY tolerated non-observation. It is a structural fact
				// about opCatalog, and the path is covered at the core boundary.
				t.Skipf("op %q / method %q is not in opCatalog (%s); this path is covered at the core "+
					"boundary by internal/core/login_identity_before_mint_test.go", c.op, c.method, reason)
			}
			if outcome != driveObserved {
				t.Fatalf("op %q / method %q is IN the catalog but could not be driven (%s: %s) — a guard "+
					"that cannot reach its own case must fail, not skip", c.op, c.method, outcome, reason)
			}
			if in.result.Success {
				t.Fatalf("precondition: this fault must make the op report FAILURE, otherwise there is no "+
					"reported-failure state to check. Got success with detail %q", in.result.Detail)
			}

			left := diffTables(in.before, in.after)
			for _, table := range left {
				switch table {
				case "MFAStepUpGrant":
					t.Errorf("a login reported as FAILED left an MFAStepUpGrant behind (tables left: %v).\n"+
						"That grant satisfies the restricted-secret MFA gate for the rest of the step-up "+
						"window, on a later session the user never proved a second factor for. The "+
						"response-identity read that failed here must run BEFORE the session and grant are "+
						"written, not after — see internal/core/webauthn.go's pre-resolve step and "+
						"core.ErrLoginIdentityUnavailable.", left)
				case "Session":
					t.Errorf("a login reported as FAILED left a Session behind (tables left: %v).\n"+
						"completeLogin's existing revoke-on-failure path has stopped working.", left)
				}
			}
		})
	}
}

// TestWebAuthnLogin_SuccessfulLoginStillMintsItsStepUpGrant is the calibration
// companion, and it is the assertion that stops the fix above from being
// "delete the grant mint".
//
// The ambient MFAStepUpPurposeRestrictedSecretRead grant on a successful
// WebAuthn login is deliberate (a WebAuthn login IS proof of possessing the
// second factor, so a restricted-secret read needs no separate re-prompt), and
// its purpose separation from MFAStepUpPurposeReauth is itself the fix for an
// earlier confused-deputy bug. Removing it to make the test above pass would be
// a silent security-posture change in the other direction.
func TestWebAuthnLogin_SuccessfulLoginStillMintsItsStepUpGrant(t *testing.T) {
	for _, c := range webauthnLoginGrantLeakCases {
		t.Run(c.name, func(t *testing.T) {
			// No fault armed: drive the op clean and inspect the reference run,
			// which is the fault-free execution the oracles compare against.
			in, outcome, reason := driveFaultCase(t, c.op, c.method, 1, faultstorage.KindError)
			if outcome == driveNotInCatalog {
				t.Skipf("op %q / method %q is not in opCatalog (%s); this path is covered at the core "+
					"boundary by internal/core/login_identity_before_mint_test.go", c.op, c.method, reason)
			}
			if outcome != driveObserved {
				t.Fatalf("op %q / method %q is IN the catalog but could not be driven (%s: %s) — a "+
					"calibration that cannot reach its own case must fail, not skip", c.op, c.method, outcome, reason)
			}
			gained := diffTables(in.before, in.refAfter)
			found := false
			for _, table := range gained {
				if table == "MFAStepUpGrant" {
					found = true
				}
			}
			if !found {
				t.Errorf("a SUCCESSFUL %s did not mint an MFAStepUpGrant (tables changed: %v).\n"+
					"The #2841 fix must move the fallible identity read ahead of the writes, NOT remove the "+
					"ambient grant — that grant is deliberate (a WebAuthn login proves the second factor) "+
					"and its purpose separation from MFAStepUpPurposeReauth is itself a confused-deputy fix.",
					c.name, gained)
			}
		})
	}
}
