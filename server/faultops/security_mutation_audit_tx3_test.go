// security_mutation_audit_tx3_test.go -- AUDIT-TX-3.
//
// Two router-level tests over the real HTTP/gRPC stack, the faultops side of
// internal/core's security_mutation_audit_tx3_test.go and
// revocation_owed_audit_test.go:
//
//  1. The mutations #3367's inventory listed as "not covered yet" (project and
//     environment update / restore, group create / update / restore, user
//     update / reactivate / restore, invitations, access-request create / reject,
//     config changes: notification channels, anomaly config, rotation policies,
//     risk exceptions, legal hold, alert escalation policies) commit their audit row
//     in their own transaction. With the first audit append (LogAuditEvent#1)
//     faulted the request must fail and change NOTHING, audit_events included. No
//     tolerance and no accept-by-design applies.
//
//  2. Revocations are never blocked by the audit log, and never lose their row. With
//     LogAuditEvent#1 faulted the request must still SUCCEED, the revocation must
//     have taken effect, and every audit row is either written or queued
//     (pending_audit_events): rows + pending equals what an unfaulted run writes.
//     BackfillPendingAuditEvents then writes the queued rows, once.
//
// Before AUDIT-TX-3 the first group was red (the change committed, the audit append
// ran afterwards or in the transport and its failure was only logged, so the request
// reported success) and the second was red in its last step (a refused append left
// the revocation committed with no row and nothing queued to backfill it from).
package faultops

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditTx3FailClosedOps are the catalog operations whose audit row must share the
// mutation's transaction (AUDIT-TX-3).
var auditTx3FailClosedOps = []string{
	"REST PUT /api/v1/projects/{id}",
	"REST POST /api/v1/projects/{id}/restore",
	"REST POST /api/v1/projects/{projectId}/environments/{id}/restore",
	"REST POST /api/v1/groups/",
	"GRPC keyorix.v1.GroupService.CreateGroup",
	"REST PUT /api/v1/groups/{id}",
	"GRPC keyorix.v1.GroupService.UpdateGroup",
	"REST POST /api/v1/groups/{id}/restore",
	"GRPC keyorix.v1.GroupService.RestoreGroup",
	"REST PUT /api/v1/users/{id}",
	"REST POST /api/v1/users/{id}/reactivate",
	"REST POST /api/v1/users/{id}/restore",
	"REST POST /api/v1/projects/{id}/invitations",
	"REST POST /api/v1/invitations",
	"REST POST /api/v1/projects/{id}/access-requests",
	"REST POST /api/v1/secret-access-requests",
	"REST POST /api/v1/notification-channels",
	"REST PUT /api/v1/notification-channels/{id}",
	"REST DELETE /api/v1/notification-channels/{id}",
	"REST PUT /api/v1/notification-channels/{id}/retry-policy",
	"REST PUT /api/v1/admin/anomaly-config/",
	"REST POST /api/v1/rotation-policies/",
	"REST PUT /api/v1/rotation-policies/{id}",
	"REST DELETE /api/v1/rotation-policies/{id}",
	"REST POST /api/v1/alert-escalation-policies",
	"REST PUT /api/v1/alert-escalation-policies/{id}",
	"REST DELETE /api/v1/alert-escalation-policies/{id}",
	"REST POST /api/v1/risk-exceptions",
	"REST POST /api/v1/risk-exceptions/{id}/approve",
	"REST POST /api/v1/legal-hold",
	"REST DELETE /api/v1/legal-hold",
	"REST POST /api/v1/projects/{id}/access-review/campaigns",
	"REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close",
	"REST PATCH /api/v1/projects/{id}/machine-identities/{machineId}/classification",
	"REST PATCH /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification",
	"GRPC keyorix.v1.MachineIdentityService.ClassifyMachineIdentity",
	"GRPC keyorix.v1.MachineIdentityService.ClassifyMachineToken",
}

// auditTx3RevocationOps are the catalog revocations: never blocked by the audit
// log, their rows owed (AUDIT-TX-3).
var auditTx3RevocationOps = []string{
	"REST DELETE /api/v1/user-roles/",
	"REST DELETE /api/v1/environments/{id}",
	"GRPC keyorix.v1.ProjectService.DeleteProject",
	"REST DELETE /api/v1/projects/{id}",
	"GRPC keyorix.v1.RoleService.RemoveRole",
	"REST DELETE /api/v1/groups/{id}/roles/{roleId}",
	"REST DELETE /api/v1/roles/{id}/permissions/{permissionId}",
	"REST DELETE /api/v1/roles/{id}",
	"GRPC keyorix.v1.RoleService.DeleteRole",
	"REST DELETE /api/v1/groups/{id}/members/{userId}",
	"GRPC keyorix.v1.GroupService.RemoveGroupMember",
	"REST DELETE /api/v1/groups/{id}",
	"GRPC keyorix.v1.GroupService.DeleteGroup",
	"REST DELETE /api/v1/projects/{id}/members/{userId}",
	"REST DELETE /api/v1/shares/{id}",
	"GRPC keyorix.v1.ShareService.RevokeShare",
	"REST DELETE /api/v1/secrets/{id}/acl/{aclId}",
	"GRPC keyorix.v1.SecretService.RevokeSecretACL",
	"REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}",
	"GRPC keyorix.v1.MachineIdentityService.RevokeMachineToken",
	"REST DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}",
	"GRPC keyorix.v1.MachineIdentityService.TransitionMachineIdentity",
	"REST DELETE /api/v1/auth/tokens/{id}",
	"REST DELETE /api/v1/auth/sessions/{id}",
	"REST POST /api/v1/users/{id}/revoke-sessions",
	"REST POST /api/v1/users/{id}/suspend",
	"REST DELETE /api/v1/users/{id}",
	"GRPC keyorix.v1.UserService.DeleteUser",
	"REST POST /api/v1/projects/{id}/break-glass/{activationId}/revoke",
	"GRPC keyorix.v1.BreakGlassService.RevokeBreakGlass",
	"REST DELETE /api/v1/projects/{id}/invitations/{invitationId}",
	"REST POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw",
	"REST DELETE /api/v1/risk-exceptions/{id}",
	"REST DELETE /scim/v2/Groups/{id}",
}

func catalogOp(t *testing.T, key string) *operation {
	t.Helper()
	for i := range opCatalog {
		if opCatalog[i].Key == key {
			return &opCatalog[i]
		}
	}
	require.FailNow(t, "op is not in opCatalog", key)
	return nil
}

func TestAuditTx3Mutation_AuditFailureFailsClosedChangesNothing(t *testing.T) {
	ctx := context.Background()
	for _, key := range auditTx3FailClosedOps {
		t.Run(key, func(t *testing.T) {
			op := catalogOp(t, key)
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
			fired := w.faulty.Fired() // before Arm(nil), which resets the latch
			w.faulty.Arm(nil)
			drainAllBackgroundGoroutines()

			require.True(t, fired, "%s never appended an audit row through storage -- the premise of this test is gone", key)
			require.NoError(t, execErr, "transport error")
			require.False(t, result.Success, "%s reported success although its audit row could not be written: %s", key, result.Detail)

			after, err := snapshotDB(w.db)
			require.NoError(t, err)
			require.Empty(t, diffTables(before, after),
				"%s failed its audit write but changed state anyway: the mutation committed without its audit row", key)
		})
	}
}

func auditRowCount(t *testing.T, w *faultWorld) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&models.AuditEvent{}).Count(&n).Error)
	return n
}

func pendingRowCount(t *testing.T, w *faultWorld) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&models.PendingAuditEvent{}).Count(&n).Error)
	return n
}

func TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed(t *testing.T) {
	ctx := context.Background()
	for _, key := range auditTx3RevocationOps {
		t.Run(key, func(t *testing.T) {
			op := catalogOp(t, key)

			// Reference: what an unfaulted run writes.
			ref := newFaultWorld(t, nil)
			var refState any
			if op.Setup != nil {
				var err error
				refState, err = op.Setup(ctx, ref)
				require.NoError(t, err, "setup (reference)")
			}
			drainAllBackgroundGoroutines()
			refBefore := auditRowCount(t, ref)
			refResult, err := op.Execute(ctx, ref, refState)
			require.NoError(t, err)
			require.True(t, refResult.Success, "reference run of %s failed: %s", key, refResult.Detail)
			drainAllBackgroundGoroutines()
			want := auditRowCount(t, ref) - refBefore
			require.Positive(t, want, "%s writes no audit row on success -- it does not belong in this test", key)

			// Faulted: the revocation must still succeed and take effect.
			w := newFaultWorld(t, nil)
			var state any
			if op.Setup != nil {
				state, err = op.Setup(ctx, w)
				require.NoError(t, err, "setup")
			}
			drainAllBackgroundGoroutines()
			before, err := snapshotDB(w.db)
			require.NoError(t, err)
			auditBefore, pendingBefore := auditRowCount(t, w), pendingRowCount(t, w)

			w.faulty.Arm(&faultstorage.FaultSpec{
				Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected,
			})
			result, execErr := op.Execute(ctx, w, state)
			fired := w.faulty.Fired()
			w.faulty.Arm(nil)
			drainAllBackgroundGoroutines()

			require.True(t, fired, "%s never appended an audit row through storage -- the premise of this test is gone", key)
			require.NoError(t, execErr, "transport error")
			require.True(t, result.Success, "%s was blocked by an audit-log failure: %s", key, result.Detail)

			after, err := snapshotDB(w.db)
			require.NoError(t, err)
			require.NotEmpty(t, diffTables(before, after), "%s reported success but changed nothing", key)

			rows, pending := auditRowCount(t, w)-auditBefore, pendingRowCount(t, w)-pendingBefore
			require.Equal(t, want, rows+pending,
				"%s lost an audit row: wrote %d, queued %d, an unfaulted run writes %d", key, rows, pending, want)
			require.Positive(t, pending, "%s: the refused append must leave its row queued", key)

			written, err := w.core.BackfillPendingAuditEvents(ctx)
			require.NoError(t, err)
			require.EqualValues(t, pending, written)
			require.Equal(t, want, auditRowCount(t, w)-auditBefore, "%s: the backfill must complete the trail exactly once", key)
			require.Equal(t, pendingBefore, pendingRowCount(t, w))
		})
	}
}
