package faultops

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// #3350: REST DELETE /api/v1/shares/{id} with CreateNotification#1/panic used to answer
// 500 after the revoke and its audit row had committed, and was carried by a
// knownOpenTolerance until RevokeShare's notifiers recovered a panic (INV-CORE-34).
// With the tolerance gone this pins the exact case the entry named: it must still be
// drivable (a skip would read as covered) and must now report success, with no oracle
// finding. Deleting the recover in notifySecretShareRevoked turns it red.
func TestRevokeShare_CreateNotificationPanic_ReportsSuccess_3350(t *testing.T) {
	in, outcome, reason := driveFaultCase(t, "REST DELETE /api/v1/shares/{id}", "CreateNotification", 1, faultstorage.KindPanic)
	if outcome != driveObserved {
		t.Fatalf("case could not be driven (%s: %s): the pin for #3350 would be vacuous", outcome, reason)
	}
	if !in.result.Success || strings.Contains(in.result.Detail, "HTTP 500") {
		t.Fatalf("a committed revoke must answer success when its notifier panics; got success=%t detail=%q",
			in.result.Success, in.result.Detail)
	}
}
