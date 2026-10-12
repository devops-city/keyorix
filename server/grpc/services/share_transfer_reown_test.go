package services

// FIX-3102 over gRPC: after the secret changes hands (the transfer has no gRPC RPC; REST
// and the CLI reach core.TransferSecretOwnership, the one primitive), the secret's
// shares follow it. ShareService.ListUserShares drops them for the previous owner and
// lists them for the new one; UpdateSharePermission and RevokeShare are refused for the
// previous owner and allowed for the new one; the recipient's access is unchanged.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestShareService_TransferOwnership_ReownsShares(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	// User 3 is the new owner: a project member holding secrets.write, as a transfer target must.
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "newowner", Email: "new@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)
	oldCtx := ownerCtx()
	newCtx := authCtx(3, "newowner", "secrets.write", "secrets.read")

	// listed reports whether ListUserShares, called as userID, returns the share AS THAT
	// USER'S OWN (owner_id == userID): the recipient also sees it, as received.
	listed := func(ctx context.Context, userID uint32) bool {
		resp, err := r.svc.ListUserShares(ctx, &pb.ListUserSharesRequest{})
		require.NoError(t, err)
		for _, s := range resp.GetShares() {
			if s.GetId() == rec.GetId() && s.GetOwnerId() == userID {
				return true
			}
		}
		return false
	}
	require.True(t, listed(oldCtx, 1), "baseline: the owner lists the share")

	_, err := r.core.CheckSecretPermission(oldCtx, uint(r.secretID), 2, core.PermissionRead)
	recipientBefore := err == nil

	_, err = r.core.TransferSecretOwnership(oldCtx, uint(r.secretID), 3, 1, core.ActorTypeUser)
	require.NoError(t, err)

	// Lists.
	assert.False(t, listed(oldCtx, 1), "previous owner still lists the transferred secret's share")
	assert.True(t, listed(newCtx, 3), "new owner must list the transferred secret's share")

	// Update / revoke: refused for the previous owner, nothing changes.
	_, err = r.svc.UpdateSharePermission(oldCtx, &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "previous owner updating: %v", err)
	_, err = r.svc.RevokeShare(oldCtx, &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "previous owner revoking: %v", err)
	still, err := r.svc.ListSecretShares(newCtx, &pb.ListSecretSharesRequest{SecretId: r.secretID})
	require.NoError(t, err)
	require.Len(t, still.GetShares(), 1, "a refused revoke must leave the share")
	assert.Equal(t, "read", still.GetShares()[0].GetPermission(), "a refused update must leave the permission")

	// Recipient access unchanged.
	_, err = r.core.CheckSecretPermission(oldCtx, uint(r.secretID), 2, core.PermissionRead)
	assert.Equal(t, recipientBefore, err == nil, "the recipient's access changed by the transfer")

	// The new owner may update and then revoke.
	updated, err := r.svc.UpdateSharePermission(newCtx, &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
	require.NoError(t, err)
	assert.Equal(t, "write", updated.GetPermission())
	_, err = r.svc.RevokeShare(newCtx, &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.NoError(t, err)
	assert.False(t, listed(newCtx, 3), "a revoked share must leave the new owner's list")
}
