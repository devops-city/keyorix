// share_elevation_2941_test.go — the gRPC half of #2941: a share elevates a project
// member's access on that one secret over gRPC exactly as it does over HTTP
// (server/http/share_elevation_2941_test.go). authorizeSecretScoped used to make a
// role-only AuthorizePrincipal decision, so a project reader holding a write share
// was denied UpdateSecret here even though the core's own share check would allow it.
package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

const readerRoleID = 2

// seedProjectReader adds user 2 ("alice") as a secrets.read-only member of project 1.
func seedProjectReader(t *testing.T, r *secretTestRig) {
	t.Helper()
	require.NoError(t, r.db.Create(&models.User{ID: 2, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.Role{ID: readerRoleID, Name: "reader"}).Error)
	require.NoError(t, r.db.Create(&models.RolePermission{RoleID: readerRoleID, PermissionID: 1}).Error) // secrets.read
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 2, RoleID: readerRoleID, ProjectID: 1}).Error)
}

func TestShareElevation2941_GRPC_WriteShareLetsReaderUpdate_RevokeRemovesIt(t *testing.T) {
	r := newSecretTestRig(t)
	seedProjectReader(t, r)
	owner := authCtx(1, "owner")
	alice := authCtx(2, "alice")
	sec := r.createSecret(t, owner, "db-password", "v1")
	v := "alice-update"

	_, err := r.svc.UpdateSecret(alice, &pb.UpdateSecretRequest{Id: sec.GetId(), Value: &v})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "a reader without a share cannot update")

	share := &models.ShareRecord{SecretID: uint(sec.GetId()), OwnerID: 1, RecipientID: 2, Permission: "write"}
	require.NoError(t, r.db.Create(share).Error)
	// Through the server chain's ShareElevationAuditInterceptor: an elevated write
	// needs its recorder (#3001 follow-up, audited when performed).
	err = viaShareAudit(r.svc.core, alice, func(ctx context.Context) error {
		_, uerr := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: sec.GetId(), Value: &v})
		return uerr
	})
	require.NoError(t, err, "#2941: a write share elevates a project reader to update this secret over gRPC")

	require.NoError(t, r.db.Delete(share).Error)
	_, err = r.svc.UpdateSecret(alice, &pb.UpdateSecretRequest{Id: sec.GetId(), Value: &v})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "revoke removes the elevation")
	_, err = r.svc.GetSecret(alice, &pb.GetSecretRequest{Id: sec.GetId()})
	assert.NoError(t, err, "revoke removes exactly the elevation, not the role's read")
}

func TestShareElevation2941_GRPC_WriteShareNeverGrantsDelete(t *testing.T) {
	r := newSecretTestRig(t)
	seedProjectReader(t, r)
	sec := r.createSecret(t, authCtx(1, "owner"), "db-password", "v1")
	require.NoError(t, r.db.Create(&models.ShareRecord{
		SecretID: uint(sec.GetId()), OwnerID: 1, RecipientID: 2, Permission: "write",
	}).Error)

	_, err := r.svc.DeleteSecret(authCtx(2, "alice"), &pb.DeleteSecretRequest{Id: sec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "a share never grants secrets.delete")
}

func TestShareElevation2941_GRPC_ShareToNonMemberGrantsNothing(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "bob", Email: "bob@example.com"}).Error)
	sec := r.createSecret(t, authCtx(1, "owner"), "db-password", "v1")
	require.NoError(t, r.db.Create(&models.ShareRecord{
		SecretID: uint(sec.GetId()), OwnerID: 1, RecipientID: 3, Permission: "write",
	}).Error)

	_, err := r.svc.GetSecret(authCtx(3, "bob"), &pb.GetSecretRequest{Id: sec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "shares never apply to non-members")
}
