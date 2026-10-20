// One file per entry; never append to a shared list. See registry_entries_test.go.
package core

func init() {
	// REAL VIOLATION, allowlisted only because the fix is in a login/MFA handler
	// owned by FIX-3277 (INVARIANT-GUARDS-1 brief: do not touch those). Reported
	// under "Needs coordinator" in SESSION-INVARIANT-GUARDS-1.md. Remove this row
	// in the commit that wraps the call in besteffort.Run (as sso.go does).
	registerBestEffortCallAllow("internal/core/mfa.go:(*KeyorixCore).requireReauth:clearLoginFailures", bestEffortCallAllowEntry{
		reason: "requireReauth (MFA re-auth gate) calls clearLoginFailures bare after the re-auth grant was consumed and the credential verified; sso.go wraps the same call in besteffort.Run: a panic in clearLoginFailures (budgetFallbackClear / UpdateLoginLockoutState) escapes requireReauth after the verdict was already accepted, so a correct re-auth is reported as a failure. Fix: besteffort.Run(ctx, \"<handler>.clearLoginFailures\", func() error { c.clearLoginFailures(ctx, user); return nil }).",
	})
}
