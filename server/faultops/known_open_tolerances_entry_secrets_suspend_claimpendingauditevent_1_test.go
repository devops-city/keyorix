// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

// #3518: REST POST /api/v1/secrets/{id}/suspend, ClaimPendingAuditEvent#1/error.
// The request reports success but the run differs from the fault-free reference
// in [AuditEvent PendingAuditEvent] only. Found by fuzz-changed on #3482 and
// replayed on origin/main @ 8a626c044 (REPLAY_HEX=7800103230): it fails there too,
// so it predates AUDIT-TX-3. Scoped to that one op, method, kind and ordinal.
//
// Remove when #3518 is fixed (or moved to oracleAByDesignErrors if the owner of
// the owed-audit path decides a failed claim is meant to leave the row pending).
func init() {
	registerKnownOpenTolerance("secrets_suspend_claimpendingauditevent_1", knownOpenTolerance{
		op:         "REST POST /api/v1/secrets/{id}/suspend",
		method:     "ClaimPendingAuditEvent",
		kind:       faultstorage.KindError,
		nth:        1,
		oracle:     "a",
		issue:      "#3518",
		expires:    "2026-11-04",
		findingDoc: "#3518",
		tables:     []string{"AuditEvent", "PendingAuditEvent"},
	})
}
