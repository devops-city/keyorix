// break_glass_degraded_owed_test.go -- BREAKGLASS-OWED-1 over the real router and
// gRPC: with the activation's first audit append (LogAuditEvent#1) faulted, break-
// glass activation still succeeds, and what changed is exactly an activation, its
// role grant and owed-audit records of its rows -- never an activation without
// either its audit rows or its owed records. (Before BREAKGLASS-OWED-1 it was in
// security_mutation_audit_fail_closed_test.go: refused, nothing changed.)
package faultops

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestBreakGlassActivation_AuditFailure_CommitsDegradedWithOwedRecords(t *testing.T) {
	ctx := context.Background()
	for _, key := range []string{
		"REST POST /api/v1/projects/{id}/break-glass",
		"GRPC keyorix.v1.BreakGlassService.ActivateBreakGlass",
	} {
		t.Run(key, func(t *testing.T) {
			var op *operation
			for i := range opCatalog {
				if opCatalog[i].Key == key {
					op = &opCatalog[i]
				}
			}
			require.NotNil(t, op, "op %q is not in opCatalog", key)

			w := newFaultWorld(t, nil)
			var state any
			if op.Setup != nil {
				var err error
				state, err = op.Setup(ctx, w)
				require.NoError(t, err, "setup")
			}
			drainAllBackgroundGoroutines()
			before, err := snapshotDB(w.db)
			require.NoError(t, err)

			w.faulty.Arm(&faultstorage.FaultSpec{
				Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected,
			})
			result, execErr := op.Execute(ctx, w, state)
			fired := w.faulty.Fired()
			w.faulty.Arm(nil)
			drainAllBackgroundGoroutines()

			require.True(t, fired, "%s never appended an audit row through storage -- the premise of this test is gone", key)
			require.NoError(t, execErr, "transport error")
			require.True(t, result.Success, "%s must work while the audit log refuses its rows: %s", key, result.Detail)

			after, err := snapshotDB(w.db)
			require.NoError(t, err)
			diff := diffTables(before, after)
			for _, want := range []string{"BreakGlassActivation", "UserRole", "PendingAuditEvent"} {
				require.True(t, slices.Contains(diff, want), "%s: %s must have changed (diff %v)", key, want, diff)
			}

			var acts []models.BreakGlassActivation
			require.NoError(t, w.db.Order("id").Find(&acts).Error)
			require.NotEmpty(t, acts)
			a := acts[len(acts)-1]
			require.True(t, a.Degraded, "the activation committed without its audit rows must be degraded")
			var owed []models.PendingAuditEvent
			require.NoError(t, w.db.Where("break_glass_activation_id = ?", a.ID).Order("id").Find(&owed).Error)
			require.Len(t, owed, 2, "both rows must be owed")
			var inChain int64
			require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("event_type = ? AND user_id = ?", core.EventBreakGlassActivated, a.UserID).Count(&inChain).Error)
			require.Zero(t, inChain, "the refused row is owed, not in the chain")

			n, err := w.core.BackfillPendingAuditEvents(ctx)
			require.NoError(t, err)
			require.Equal(t, 2, n)
			var settled models.BreakGlassActivation
			require.NoError(t, w.db.First(&settled, a.ID).Error)
			require.NotNil(t, settled.AuditSettledAt)
		})
	}
}
