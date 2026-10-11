// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	registerKnownOpenTolerance("post_auth_mfa_verify_reserveloginattempt_1", knownOpenTolerance{
		op: "REST POST /auth/mfa/verify", method: "ReserveLoginAttempt", kind: faultstorage.KindError,
		nth: 1, oracle: "a", issue: "#2837", expires: "2026-10-17",
		tables:     []string{"LoginAttempt"},
		findingDoc: "#2837",
	})
}
