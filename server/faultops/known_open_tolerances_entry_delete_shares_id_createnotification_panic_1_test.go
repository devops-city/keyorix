// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3350. Surfaced by CI's fuzz shard 0 on #3330, whose diff touches neither
	// sharing nor notifications; confirmed to reproduce on origin/main 94d52413c
	// by direct replay (driveFaultCase with this exact tuple: HTTP 500, share
	// already revoked and audited) before this entry was written.
	//
	// RevokeShare commits the delete and the audit row, then notifies outside any
	// recovery, so a CreateNotification panic escapes as a 500 after the commit.
	// Same shape as #3075; the fix is runPostCommitNotification. Scoped to the
	// one op, method, kind and nth, and the two tables the committed revoke
	// writes. Remove when #3350 is fixed.
	registerKnownOpenTolerance("delete_shares_id_createnotification_panic_1", knownOpenTolerance{
		op: "REST DELETE /api/v1/shares/{id}", method: "CreateNotification", kind: faultstorage.KindPanic,
		nth: 1, oracle: "a", issue: "#3350", expires: "2026-11-16",
		tables:     []string{"AuditEvent", "ShareRecord"},
		findingDoc: "#3350",
	})
}
