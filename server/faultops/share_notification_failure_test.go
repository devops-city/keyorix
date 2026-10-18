// share_notification_failure_test.go — regression pin for #3350.
//
// FuzzStorageFaultOperations found REST DELETE /api/v1/shares/{id} with
// CreateNotification#1/panic committing the revoke ([AuditEvent ShareRecord])
// and then answering 500, because the panic in the post-commit notification
// escaped. The share notifiers now recover it (recoverPostCommitNotifyPanic,
// the #3092 pattern), so the committed change keeps its success response. The
// create side has the same post-commit notification and is pinned too.
package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestShareNotificationFailure_IsNotReportedAsFailure(t *testing.T) {
	ops := []string{
		"REST DELETE /api/v1/shares/{id}", // the #3350 tuple
		"GRPC keyorix.v1.ShareService.RevokeShare",
		"REST POST /api/v1/secrets/{id}/share",
		"GRPC keyorix.v1.ShareService.ShareSecret",
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
					t.Fatalf("%s: a CreateNotification %s after the share change committed was reported as a failure (%q) (#3350)",
						op, kind, in.result.Detail)
				}
				checkOraclesReporting(t, in)
			})
		}
	}
}
