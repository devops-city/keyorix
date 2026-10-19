package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceMachineTokenStorage makes RevokeMachineIdentityCredential fail once,
// mirroring the failOnceStorage idiom from #2295.
func failOnceMachineTokenStorage(inner storage.Storage, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		RevokeMachineIdentityCredential: func(next storage.Storage, ctx context.Context, projectID, credentialID uint) error {
			if *armed {
				*armed = false
				return errors.New("injected fault: RevokeMachineIdentityCredential")
			}
			return next.RevokeMachineIdentityCredential(ctx, projectID, credentialID)
		},
	})
}

// TestIssueMachineToken_RevokeFailureRollsBackNewCredential is the red-proof for
// the IssueMachineToken atomicity fix (Session O, O2 item 3): a failure revoking
// the replaced credential must leave NEITHER change applied -- not an orphaned,
// unusable new credential (its plain token was discarded along with the error)
// plus the old credential still live. Red before the fix: CreateMachineIdentityCredential
// and RevokeMachineIdentityCredential were sequential storage calls with no
// transaction, so the new row survived a revoke failure.
func TestIssueMachineToken_RevokeFailureRollsBackNewCredential(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "mtok-proj", Description: "d"})
	require.NoError(t, err)
	machine, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: proj.ID, Name: "ci-runner", State: MachineActive,
	})
	require.NoError(t, err)

	const actor = uint(1) // bootstrapped admin
	first, err := c.IssueMachineToken(ctx, proj.ID, machine.ID, actor, IssueMachineTokenParams{Name: "first"})
	require.NoError(t, err)

	armed := true
	c.storage = failOnceMachineTokenStorage(st, &armed)

	_, err = c.IssueMachineToken(ctx, proj.ID, machine.ID, actor, IssueMachineTokenParams{
		Name: "rotated", ReplaceCredentialID: first.Credential.ID,
	})
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	creds, lerr := st.ListMachineIdentityCredentials(ctx, machine.ID)
	require.NoError(t, lerr)
	require.Len(t, creds, 1, "the failed rotation must leave exactly the original credential -- no orphaned new row")
	assert.Equal(t, first.Credential.ID, creds[0].ID)
	assert.False(t, creds[0].Revoked, "the old credential must still be active since the rotation did not complete")

	// Retry (fault already disarmed) must fully succeed.
	second, err := c.IssueMachineToken(ctx, proj.ID, machine.ID, actor, IssueMachineTokenParams{
		Name: "rotated-retry", ReplaceCredentialID: first.Credential.ID,
	})
	require.NoError(t, err)
	creds, lerr = st.ListMachineIdentityCredentials(ctx, machine.ID)
	require.NoError(t, lerr)
	require.Len(t, creds, 2)
	for _, cr := range creds {
		if cr.ID == first.Credential.ID {
			assert.True(t, cr.Revoked, "the old credential must be revoked after a successful retry")
		}
		if cr.ID == second.Credential.ID {
			assert.False(t, cr.Revoked)
		}
	}
}
