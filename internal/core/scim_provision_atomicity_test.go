package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceAssignRoleStorage makes AssignRole fail once, mirroring the
// failOnceStorage idiom from #2295.
func failOnceAssignRoleStorage(inner storage.Storage, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		AssignRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, scope storage.Scope) error {
			if *armed {
				*armed = false
				return errors.New("injected fault: AssignRole")
			}
			return next.AssignRole(ctx, userID, roleID, scope)
		},
	})
}

// TestProvisionSCIMUser_RoleAssignFailureRollsBackUser is the red-proof for
// Session O's O3 SCIM/SSO provisioning fix: a failure assigning the baseline
// role must roll back the whole user creation -- not the pre-fix bootstrap
// bug where a best-effort AssignRole failure left a SCIM-provisioned user
// created with ZERO roles, unable to do anything until an admin noticed.
func TestProvisionSCIMUser_RoleAssignFailureRollsBackUser(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	armed := true
	c.storage = failOnceAssignRoleStorage(st, &armed)

	_, err := c.ProvisionSCIMUser(ctx, 0, "newuser@example.com", "", "", "ext-1", true)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	_, ferr := st.GetUserByEmail(ctx, "newuser@example.com")
	assert.True(t, errors.Is(ferr, storage.ErrUserNotFound) || ferr != nil,
		"a failed role assignment must roll back the user row too -- no user left with zero roles")

	// Retry (fault already disarmed after tripping once above) must fully succeed.
	u, err := c.ProvisionSCIMUser(ctx, 0, "newuser@example.com", "", "", "ext-1", true)
	require.NoError(t, err)
	roles, rerr := st.GetUserRoles(ctx, u.ID)
	require.NoError(t, rerr)
	require.NotEmpty(t, roles, "a successful retry must leave the user with its baseline role")
}
