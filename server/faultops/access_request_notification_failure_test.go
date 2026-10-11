// access_request_notification_failure_test.go — regression pins for #3075.
//
// FuzzStorageFaultOperations found REST PUT
// /api/v1/projects/{id}/access-requests/{requestId} with
// CreateNotification#1/panic committing the approval ([AccessRequestApproval
// AuditEvent UserRole AccessRequest]) and then answering 500, because the panic
// in the post-commit notification escaped. The fix
// (core.runPostCommitNotification) recovers a notification failure (panic OR
// error), logs it at SECURITY level, audits it as "notification.failed" and
// keeps the success response.
//
// These pins assert that through the real harness, as FIXED rather than
// tolerated: every access-request op that notifies, under both kinds, must
// report SUCCESS, pass the full oracle set, and leave the notification.failed
// audit row behind. The saved corpus entry
// testdata/fuzz/FuzzStorageFaultOperations/0b2369d76a986e0e replays the
// original tuple on every plain `go test`.
package faultops

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestAccessRequestNotificationFailure_IsNotReportedAsFailure(t *testing.T) {
	// The two CREATE ops (POST /projects/{id}/access-requests, POST
	// /secret-access-requests) are not listed: this world's only admin is the
	// requester, so their fan-out has no recipient and CreateNotification is never
	// called (driveFaultCase reports "fault never fired"). Their notify step is
	// pinned in internal/core's
	// TestAccessRequestNotificationFailure_CommittedTransitionStillSucceeds.
	ops := []string{
		"REST PUT /api/v1/projects/{id}/access-requests/{requestId}", // the #3075 tuple
		"REST PUT /api/v1/secret-access-requests/{requestId}",
		"REST POST /api/v1/access-requests/bulk-approve",
		"REST POST /api/v1/access-requests/bulk-reject",
	}
	for _, op := range ops {
		for _, kind := range []faultstorage.FaultKind{faultstorage.KindPanic, faultstorage.KindError} {
			t.Run(op+"/CreateNotification#1/"+kind.String(), func(t *testing.T) {
				in, outcome, reason := driveFaultCase(t, op, "CreateNotification", 1, kind)
				if outcome != driveObserved {
					t.Fatalf("could not drive %s CreateNotification#1/%s (%s: %s) — a pin that cannot run proves nothing",
						op, kind, outcome, reason)
				}
				if !in.result.Success {
					t.Fatalf("%s: a CreateNotification %s after the access-request transition committed was reported "+
						"as a failure (%q). Run the notify step under runPostCommitNotification (#3075)",
						op, kind, in.result.Detail)
				}
				checkOraclesReporting(t, in)
				if !snapshotHasAuditEvent(in.after, "notification.failed") {
					t.Errorf("%s: the swallowed CreateNotification %s left no \"notification.failed\" audit event", op, kind)
				}
			})
		}
	}
}

// snapshotHasAuditEvent reports whether snap's AuditEvent table holds a row of
// eventType. Rows are canonical JSON, so the event_type value is matched as a
// quoted JSON string.
func snapshotHasAuditEvent(snap dbSnapshot, eventType string) bool {
	for _, row := range snap.Tables["AuditEvent"].Rows {
		if strings.Contains(row, `"`+eventType+`"`) {
			return true
		}
	}
	return false
}
