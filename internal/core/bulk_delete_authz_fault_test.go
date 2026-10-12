// bulk_delete_authz_fault_test.go — triage for a finding reported twice,
// independently, by SESSION-AT's exploratory fuzzing (~/proj/prompts/reports/SESSION-AT.md,
// "round 3"/"round 4"): REST POST /api/v1/projects/{id}/secrets/bulk-delete,
// fault on GetUserGroupRoleIDsAt#2, flagged as an ORACLE (c) violation ("a
// fault on an authz-resolution read produced a SUCCESSFUL result instead of
// an error/deny"). Neither report traced root cause or filed a seed/fix;
// this file reproduces the underlying authorization question directly
// (bypassing the fuzz harness, which does not wire this op into its
// opCatalog at all on this branch) to determine whether a storage error
// resolving a user's GROUP-derived role can ever cause BulkDeleteSecrets to
// wrongly delete a secret that user has no OTHER path to.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// erroringGetUserGroupRoleIDsAtStorage wraps a real storage.Storage and makes
// EVERY call to GetUserGroupRoleIDsAt fail — stronger than matching the
// fuzzer's exact reported call index (#2), and conclusive either way: if
// faulting every such call still never produces a wrongful delete, no
// specific call index could either.
type erroringGetUserGroupRoleIDsAtStorage struct {
	storage.Storage
	calls *int
}

func (s *erroringGetUserGroupRoleIDsAtStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	*s.calls++
	return nil, assert.AnError
}

// ResolveUserPermissionAt (PERF-FIX-6) reads through this wrapper's own
// GetUserGroupRoleIDsAt, so Authorize still meets the fault.
func (s *erroringGetUserGroupRoleIDsAtStorage) ResolveUserPermissionAt(ctx context.Context, userID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	return storage.ComposeUserPermissionAt(ctx, s, userID, scope, permission)
}

// TestBulkDeleteSecrets_GetUserGroupRoleIDsAtFault_NeverWronglyDeletes: a user
// whose ONLY path to secrets.delete on a project is a role granted through
// GROUP membership (project_developer, assigned to a group they belong to —
// not held directly, not an admin-tier role, no ownership, no direct/ACL
// share) attempts to bulk-delete two secrets they do not own. With
// GetUserGroupRoleIDsAt faulted on every call, scopedRoleIDs/Authorize/
// AuthorizePrincipal all fail closed by their own doc comments
// (internal/core/authz.go) — this test exercises that chain end to end
// through the real HTTP-facing entry point (BulkDeleteSecrets), not just the
// unit-level Authorize call, to confirm the per-item failure is actually
// surfaced as a Failed entry and never as a silently-authorized Deleted one.
func TestBulkDeleteSecrets_GetUserGroupRoleIDsAtFault_NeverWronglyDeletes(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// user 1 is the bootstrapped admin (owns the secrets below). user 2 has
	// NO direct role, NO ownership, NO share, NO ACL — only group membership.
	member, err := st.CreateUser(ctx, foldedTestUser(t, "member", "member@example.com"))
	require.NoError(t, err)

	const projectID = uint(1)
	group, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "deleters", Description: "d"})
	require.NoError(t, err)
	require.NoError(t, c.AddUserToGroup(ctx, 1, false, member.ID, group.ID, projectID))

	devRole, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, 1, group.ID, devRole.ID, storage.Scope{ProjectID: projectID}, false))

	secret1, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "s1", ProjectID: projectID, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: c.now(), UpdatedAt: c.now(),
	})
	require.NoError(t, err)
	secret2, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "s2", ProjectID: projectID, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: c.now(), UpdatedAt: c.now(),
	})
	require.NoError(t, err)

	// Sanity check: WITHOUT any fault, the group-derived role genuinely does
	// grant delete — otherwise this test would prove nothing (a request that
	// was going to be denied anyway regardless of the fault).
	sanity, serr := c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{secret1.ID}}, projectID, "member", member.ID, "", "")
	require.NoError(t, serr)
	require.Len(t, sanity.Deleted, 1, "sanity check failed: the group-derived project_developer role must grant delete when nothing is faulted")

	calls := 0
	c.storage = &erroringGetUserGroupRoleIDsAtStorage{Storage: st, calls: &calls}

	result, err := c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{secret2.ID}}, projectID, "member", member.ID, "", "")
	require.NoError(t, err, "BulkDeleteSecrets itself must not error even when every item fails — partial-success is its documented contract")
	require.Greater(t, calls, 0, "the fault must actually have been exercised")
	assert.Empty(t, result.Deleted, "a storage error resolving the user's ONLY source of delete permission must never result in a wrongful delete")
	assert.Len(t, result.Failed, 1, "the item must be reported as failed, not silently dropped")

	// The secret must still exist, untouched, proving this isn't just a
	// reporting discrepancy (deleted for real but the response said
	// otherwise) -- the actual state matches "nothing happened."
	reloaded, rerr := st.GetSecret(ctx, secret2.ID)
	require.NoError(t, rerr, "the secret must still exist")
	assert.Equal(t, secret2.ID, reloaded.ID)
}
