// security_mutation_audit_fail_closed_test.go -- AUDIT-TX-2.
//
// Every grant-shaped security mutation (role grants, permission and role
// definition changes, group membership and group grants, shares, secret ACLs,
// machine identities and their tokens and roles, PATs, user / project /
// environment create, break-glass activation, SoD policies) commits its audit row
// in its own transaction, so a failed audit append must fail the request and
// change NOTHING. Each catalog operation below runs over the real router with
// its first audit append (LogAuditEvent#1, which the mutation now calls through
// its transaction-scoped storage) faulted, and the post-state must equal the
// pre-fault state in EVERY table, audit_events included.
//
// Stricter than oracle (a) for the same reason as
// secret_mutation_audit_fail_closed_test.go: oracle (a) accepts an error whose
// diff is confined to outcome-log tables, which would let "grant committed,
// audit row missing" through. No tolerance and no accept-by-design applies.
//
// Before AUDIT-TX-2 these were red: the grant committed, the audit append ran
// afterwards through c.storage (or in the transport), its failure was only
// logged, and the request reported success.
//
// Not listed, on purpose: revocations (role/group/permission/share/ACL/token
// removal, session and PAT revoke, user suspend/delete, break-glass revoke) keep
// their best-effort post-commit audit (Andrei 2026-10-14: a revocation is never
// blocked by the audit log), and SetUserRoles (PUT /users/{id}/roles) is a
// compensated sequence of single grants and removals, each audited on its own.
package faultops

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// securityMutationAuditOps are the catalog operations whose audit row must share
// the mutation's transaction (AUDIT-TX-2).
var securityMutationAuditOps = []string{
	"REST POST /api/v1/user-roles/",
	"GRPC keyorix.v1.RoleService.AssignRole",
	"REST POST /api/v1/projects/{id}/members",
	"REST POST /api/v1/roles/",
	"GRPC keyorix.v1.RoleService.CreateRole",
	"REST PUT /api/v1/roles/{id}",
	"GRPC keyorix.v1.RoleService.UpdateRole",
	"REST POST /api/v1/roles/{id}/permissions",
	"REST POST /api/v1/groups/{id}/roles",
	"REST POST /api/v1/groups/{id}/members",
	"GRPC keyorix.v1.GroupService.AddGroupMember",
	"REST POST /api/v1/secrets/{id}/share",
	"REST PUT /api/v1/shares/{id}",
	"GRPC keyorix.v1.ShareService.ShareSecret",
	"GRPC keyorix.v1.ShareService.UpdateSharePermission",
	"REST POST /api/v1/secrets/{id}/acl",
	"GRPC keyorix.v1.SecretService.GrantSecretACL",
	"REST POST /api/v1/projects/{id}/machine-identities",
	"GRPC keyorix.v1.MachineIdentityService.CreateMachineIdentity",
	"REST POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens",
	"GRPC keyorix.v1.MachineIdentityService.IssueMachineToken",
	"REST POST /api/v1/projects/{id}/machine-identities/{machineId}/roles",
	"REST POST /api/v1/auth/tokens",
	"REST POST /api/v1/users/",
	"GRPC keyorix.v1.UserService.CreateUser",
	"REST POST /api/v1/projects",
	"GRPC keyorix.v1.ProjectService.CreateProject",
	"REST POST /api/v1/projects/{id}/environments",
	"REST POST /api/v1/projects/{id}/break-glass",
	"GRPC keyorix.v1.BreakGlassService.ActivateBreakGlass",
	"REST POST /api/v1/sod/policies",
	"REST DELETE /api/v1/sod/policies/{id}",
}

func TestSecurityMutationAuditFailure_FailsClosedChangesNothing(t *testing.T) {
	ctx := context.Background()
	for _, key := range securityMutationAuditOps {
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
