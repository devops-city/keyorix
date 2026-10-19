package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// roleScopesFailingStorage wraps a real storage and fails every
// GetUserRoleScopes call, the first read requireEqualOrGreaterAdminAuthority
// makes to resolve the target's authority. Everything else passes through.
func roleScopesFailingStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		GetUserRoleScopes: func(_ storage.Storage, ctx context.Context, userID uint) ([]storage.Scope, error) {
			return nil, errInjectedRoleScopes
		},
	})
}

var errInjectedRoleScopes = errors.New("injected: role-scope read failed")

// TestAdminRankCeiling_ResolutionFailureFailsClosed pins the fix for the
// fail-open in requireAdminRankCeilingForTarget: when the target's authority
// cannot be resolved (a storage error on the primary backend), the mutation
// must be REFUSED, not allowed. Before the fix, errCeilingResolutionFailed
// returned nil ("allow"), a branch justified only by RemoteStorage, which was
// deleted in #2162. Found by FuzzStorageFaultOperations (REPLAY_HEX=1829d438:
// gRPC DeleteUser with a fault on GetUserGroupRoleIDsAt).
func TestAdminRankCeiling_ResolutionFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	c, st := newBootstrappedCore(t)

	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username:    "ceiling-target",
		Email:       "ceiling-target@example.com",
		DisplayName: "Ceiling Target",
		Password:    "Tr1cky-Passphrase-For-Tests!",
	})
	require.NoError(t, err)

	// Control: with healthy storage, an admin acting on a normal user passes.
	require.NoError(t, c.requireAdminRankCeilingForTarget(ctx, admin.ID, target.ID, "delete"))

	// Resolution failure: refused, and not reported as "insufficient
	// authority" (the actor wasn't found wanting; we couldn't check).
	faulty := NewKeyorixCore(roleScopesFailingStorage(st))
	err = faulty.requireAdminRankCeilingForTarget(ctx, admin.ID, target.ID, "delete")
	require.Error(t, err, "a ceiling resolution failure must fail closed")
	require.ErrorIs(t, err, errCeilingResolutionFailed)
	require.ErrorIs(t, err, errInjectedRoleScopes)
	require.False(t, errors.Is(err, ErrInsufficientAdminAuthority),
		"a resolution failure must not masquerade as an authority refusal (403)")

	// End to end: the delete itself is refused and the target still exists.
	require.Error(t, faulty.DeleteUser(ctx, admin.ID, target.ID))
	still, err := st.GetUser(ctx, target.ID)
	require.NoError(t, err)
	require.Equal(t, target.ID, still.ID)
}
