package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceProjectMemberStorage makes one named storage step fail during the
// first RemoveProjectMember attempt only. Mirrors the failOnceStorage idiom
// from #2295 (auth_bootstrap_retryable_test.go): wraps storage.Storage,
// re-wraps itself across WithTransaction so the injected fault also fires on
// the transaction-scoped handle, and trips exactly once per armed instance.
func failOnceProjectMemberStorage(inner storage.Storage, failStep string, armed *bool) storage.Storage {
	trip := func(step string) error {
		if *armed && failStep == step {
			*armed = false
			return errors.New("injected fault: " + step)
		}
		return nil
	}
	return hooked(inner, &storeHooks{
		WrapTx: true,
		RemoveAllProjectRoleGrants: func(next storage.Storage, ctx context.Context, userID, projectID uint) error {
			if err := trip("RemoveAllProjectRoleGrants"); err != nil {
				return err
			}
			return next.RemoveAllProjectRoleGrants(ctx, userID, projectID)
		},
		ClearProjectSecretOwnership: func(next storage.Storage, ctx context.Context, userID, projectID uint) error {
			if err := trip("ClearProjectSecretOwnership"); err != nil {
				return err
			}
			return next.ClearProjectSecretOwnership(ctx, userID, projectID)
		},
		DeleteSecretACLsByUserAndProject: func(next storage.Storage, ctx context.Context, userID, projectID uint) error {
			if err := trip("DeleteSecretACLsByUserAndProject"); err != nil {
				return err
			}
			return next.DeleteSecretACLsByUserAndProject(ctx, userID, projectID)
		},
	})
}

// projectMemberAtomicityFixture builds: a project with one environment, a
// member (alice) holding project_viewer at the project scope, a secret alice
// OWNS in that project, and a SEPARATE secret alice holds a per-secret ACL
// grant on (owned by someone else) -- the exact three resources
// RemoveProjectMember must clear together (role grant, owner_id, ACL row).
func projectMemberAtomicityFixture(t *testing.T) (c *KeyorixCore, projectID, aliceID, actorID, ownedSecretID uint) {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	alice, err := st.CreateUser(ctx, foldedTestUser(t, "alice-pm", "alice-pm@example.com"))
	require.NoError(t, err)
	bob, err := st.CreateUser(ctx, foldedTestUser(t, "bob-pm", "bob-pm@example.com"))
	require.NoError(t, err)

	proj, err := st.CreateProject(ctx, &models.Project{Name: "atomicity-proj", Description: "d"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)

	const actor = uint(1) // the bootstrapped admin already holds "admin" globally
	require.NoError(t, c.AddProjectMember(ctx, actor, proj.ID, alice.ID, "project_viewer", false))

	owned, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "owned-by-alice", ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", IsSecret: true, Status: "active", Classification: "internal",
		OwnerID: alice.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	aclTarget, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "acl-granted-to-alice", ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", IsSecret: true, Status: "active", Classification: "internal",
		OwnerID: bob.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, st.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: aclTarget.ID, UserID: alice.ID, Permissions: `["secrets.read"]`, GrantedBy: actor,
	}))

	// Sanity: all three exist before removal.
	roles, err := st.GetUserRoleIDsExact(ctx, alice.ID, Scope{ProjectID: proj.ID})
	require.NoError(t, err)
	require.NotEmpty(t, roles)
	gotOwned, err := st.GetSecret(ctx, owned.ID)
	require.NoError(t, err)
	require.Equal(t, alice.ID, gotOwned.OwnerID)
	acl, err := st.GetSecretACL(ctx, aclTarget.ID, alice.ID)
	require.NoError(t, err)
	require.NotNil(t, acl)

	return c, proj.ID, alice.ID, actor, owned.ID
}

// TestRemoveProjectMember_PartialFailureLeavesNothingBehind is the red-proof
// for the RemoveProjectMember atomicity fix: a failure at ANY of the three
// writes (role-grant removal, owner_id clear, ACL delete) must roll back ALL
// THREE, not leave the role gone while stale secret-level access survives.
// Red before the fix: injecting a failure on ClearProjectSecretOwnership or
// DeleteSecretACLsByUserAndProject didn't even surface as an error (both were
// `_ =`), and RemoveAllProjectRoleGrants had already committed outside any
// transaction -- the member's role was gone but their owner_id/ACL access
// silently survived.
func TestRemoveProjectMember_PartialFailureLeavesNothingBehind(t *testing.T) {
	for _, step := range []string{"RemoveAllProjectRoleGrants", "ClearProjectSecretOwnership", "DeleteSecretACLsByUserAndProject"} {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			c, projectID, aliceID, actorID, ownedSecretID := projectMemberAtomicityFixture(t)
			base := c.storage
			armed := true
			c.storage = failOnceProjectMemberStorage(base, step, &armed)

			ctx := context.Background()
			err := c.RemoveProjectMember(ctx, actorID, projectID, aliceID)
			require.Error(t, err)
			require.False(t, armed, "the injected fault must actually have fired")

			// Nothing rolled forward: role grant, ownership, AND the ACL must all
			// still be exactly as they were before the call.
			roles, rerr := base.GetUserRoleIDsExact(ctx, aliceID, Scope{ProjectID: projectID})
			require.NoError(t, rerr)
			assert.NotEmpty(t, roles, "role grant must survive a partial failure at step %s", step)

			gotOwned, serr := base.GetSecret(ctx, ownedSecretID)
			require.NoError(t, serr)
			assert.Equal(t, aliceID, gotOwned.OwnerID, "secret ownership must survive a partial failure at step %s", step)

			acls, aerr := base.ListSecretACLsByUser(ctx, aliceID)
			require.NoError(t, aerr)
			assert.NotEmpty(t, acls, "ACL grant must survive a partial failure at step %s", step)

			// Retry with the fault disarmed (armed already false after tripping
			// once) must now fully succeed and clear all three.
			require.NoError(t, c.RemoveProjectMember(ctx, actorID, projectID, aliceID))
			roles, rerr = base.GetUserRoleIDsExact(ctx, aliceID, Scope{ProjectID: projectID})
			require.NoError(t, rerr)
			assert.Empty(t, roles, "retry must clear the role grant")
			acls, aerr = base.ListSecretACLsByUser(ctx, aliceID)
			require.NoError(t, aerr)
			assert.Empty(t, acls, "retry must clear the ACL grant")
		})
	}
}
