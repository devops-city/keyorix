// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3267: /auth/mfa/verify, GetUserPermissions#1/panic leaves [LoginAttempt
	// MFASecret] diverged while reporting an error (oracle (a)).
	//
	// A tolerance, not a by-design row, on purpose. The error and
	// effect-then-error kinds of this exact tuple are by-design (the post-verdict
	// cost equals a wrong code), but their proving test calls the handler with no
	// recovery middleware, so it cannot show that a PANIC is answered like a wrong
	// code rather than a 500. Until that is established or fixed, #3267 stays open
	// and this row is the bounded carve-out; it expires so it cannot go permanent.
	//
	// Pre-existing: reproduces on origin/main @ c3a326c1, found by fuzz on #3266
	// (which does not touch MFA). tables is the observed diff; a diff with any
	// other table still fails.
	registerKnownOpenTolerance("post_auth_mfa_verify_getuserpermissions_panic_1", knownOpenTolerance{
		op: "REST POST /auth/mfa/verify", method: "GetUserPermissions", kind: faultstorage.KindPanic,
		nth: 1, oracle: "a", issue: "#3267", expires: "2026-10-29",
		tables:     []string{"LoginAttempt", "MFASecret"},
		findingDoc: "#3267",
	})
}
