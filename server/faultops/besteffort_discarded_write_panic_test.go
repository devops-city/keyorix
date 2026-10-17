// besteffort_discarded_write_panic_test.go — regression pins for a post-commit
// best-effort write whose result was discarded with a bare `_ =`.
//
// `_ =` drops a returned error but not a PANIC. Each tuple below is a storage
// write that runs AFTER the operation's own commit; a panic in it escaped the
// discard, the transport's recovery turned it into a 500 / codes.Internal, and
// the caller was told an operation failed that had in fact committed:
//
//   - GRPC UserService.CreateUser, AddPasswordHistory#1/panic: the user and its
//     role grants exist ([User UserRole]) while the RPC reported Internal.
//     Found by CI's fuzz shard 2 on #2876; reproduces on origin/main.
//   - change-password, PrunePasswordHistory#1/panic: the password change is
//     committed while the request reported 500 — and the PAT/session
//     revocation that follows it in ChangePassword never ran.
//   - SAML ACS, UpdateLastLogin#1/panic: a live Session was minted while the
//     ACS reported 500 (the #2841 shape on the SSO path).
//
// The class guard is internal/besteffortguard (scan.go): a write whose own
// result is blank-discarded no longer counts as the "last write", so such a
// discard is now itself flagged when nothing checked follows it. These
// fuzz-level pins assert the EFFECT end to end, through the real harness.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestPostCommitDiscardedWritePanic_IsNotReportedAsFailure(t *testing.T) {
	cases := []struct {
		op, method string
	}{
		{op: "GRPC keyorix.v1.UserService.CreateUser", method: "AddPasswordHistory"},
		{op: "REST POST /api/v1/auth/change-password", method: "PrunePasswordHistory"},
		{op: "REST POST /api/v1/auth/change-password", method: "AddPasswordHistory"},
		{op: "REST POST /auth/saml/{provider}/acs", method: "UpdateLastLogin"},
		// #2844 sweep: resolveKeepSession's GetSession runs after the MFA
		// change has committed; its panic escaped, reported the change as
		// failed and skipped the session purge that must follow it.
		// (change-password's GetSession#1 is the auth middleware's, before
		// anything commits, so it is correctly a failure and not listed.)
		{op: "REST POST /api/v1/auth/mfa/activate", method: "GetSession"},
		{op: "REST POST /api/v1/auth/mfa/disable", method: "GetSession"},
	}
	for _, tc := range cases {
		t.Run(tc.op+"/"+tc.method, func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, tc.op, tc.method, 1, faultstorage.KindPanic)
			if outcome != driveObserved {
				t.Fatalf("could not drive %s %s#1/panic (%s: %s) — a pin that cannot run proves nothing",
					tc.op, tc.method, outcome, reason)
			}
			if !in.result.Success {
				t.Fatalf("%s: a panic in the post-commit best-effort %s was reported as a failure (%q), "+
					"but the operation had already committed. Route the call through besteffort.Run, "+
					"not a bare `_ =`", tc.op, tc.method, in.result.Detail)
			}
			checkOraclesReporting(t, in)
		})
	}
}
