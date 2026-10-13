// secret_update_clear_limits_test.go — gRPC parity for REST clear_expiration /
// clear_max_reads (#3172): UpdateSecretRequest.clear_expiration and .clear_max_reads
// reach the same core path REST uses, an absent field keeps the stored value, and the
// permission model is unchanged (a clear is a lifecycle change, so a write share does
// not elevate it, exactly as over REST).
package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// limitedSecret creates a secret that has both an expiry and a read limit.
func limitedSecret(t *testing.T, r *secretTestRig, ctx context.Context, name string) (uint32, time.Time) {
	t.Helper()
	sec := r.createSecret(t, ctx, name, "v1")
	exp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	limit := int32(5)
	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: sec.GetId(), MaxReads: &limit, Expiration: timestamppb.New(exp),
	})
	require.NoError(t, err)
	got := loadSecret(t, r, sec.GetId())
	require.NotNil(t, got.MaxReads)
	require.NotNil(t, got.Expiration)
	return sec.GetId(), exp
}

func loadSecret(t *testing.T, r *secretTestRig, id uint32) models.SecretNode {
	t.Helper()
	var s models.SecretNode
	require.NoError(t, r.db.First(&s, id).Error)
	return s
}

func TestUpdateSecretGRPC_ClearFields_RemoveExpiryAndLimit(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	id, _ := limitedSecret(t, r, ctx, "clear-both")

	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: id, ClearExpiration: true, ClearMaxReads: true,
	})
	require.NoError(t, err)

	got := loadSecret(t, r, id)
	assert.Nil(t, got.Expiration, "clear_expiration must remove the expiry")
	assert.Nil(t, got.MaxReads, "clear_max_reads must remove the read limit")
}

func TestUpdateSecretGRPC_ClearEachFieldIndependently(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	idA, expA := limitedSecret(t, r, ctx, "clear-exp-only")
	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: idA, ClearExpiration: true})
	require.NoError(t, err)
	a := loadSecret(t, r, idA)
	assert.Nil(t, a.Expiration)
	require.NotNil(t, a.MaxReads, "clearing the expiry must keep the read limit")
	assert.Equal(t, 5, *a.MaxReads)
	_ = expA

	idB, expB := limitedSecret(t, r, ctx, "clear-limit-only")
	_, err = r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: idB, ClearMaxReads: true})
	require.NoError(t, err)
	b := loadSecret(t, r, idB)
	assert.Nil(t, b.MaxReads)
	require.NotNil(t, b.Expiration, "clearing the limit must keep the expiry")
	assert.True(t, expB.Equal(*b.Expiration))
}

func TestUpdateSecretGRPC_AbsentClearFields_KeepExpiryAndLimit(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	id, exp := limitedSecret(t, r, ctx, "keep-both")

	// Unrelated update (rotation) with both clear fields absent/false.
	v := "v2"
	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: id, Value: &v})
	require.NoError(t, err)

	got := loadSecret(t, r, id)
	require.NotNil(t, got.MaxReads, "absent clear_max_reads must keep the limit")
	assert.Equal(t, 5, *got.MaxReads)
	require.NotNil(t, got.Expiration, "absent clear_expiration must keep the expiry")
	assert.True(t, exp.Equal(*got.Expiration))
}

func TestUpdateSecretGRPC_ClearAndSetAreMutuallyExclusive(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	id, exp := limitedSecret(t, r, ctx, "exclusive")
	n := int32(9)

	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: id, MaxReads: &n, ClearMaxReads: true,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: id, Expiration: timestamppb.New(exp.Add(time.Hour)), ClearExpiration: true,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	got := loadSecret(t, r, id)
	require.NotNil(t, got.MaxReads)
	assert.Equal(t, 5, *got.MaxReads, "a rejected request changes nothing")
	require.NotNil(t, got.Expiration)
	assert.True(t, exp.Equal(*got.Expiration))
}

func TestUpdateSecretGRPC_ClearFields_PermissionChecksUnchanged(t *testing.T) {
	r := newSecretTestRig(t)
	seedProjectReader(t, r)
	owner := authCtx(1, "owner")
	alice := authCtx(2, "alice")
	id, exp := limitedSecret(t, r, owner, "clear-perms")

	// A reader without any share cannot clear.
	_, err := r.svc.UpdateSecret(alice, &pb.UpdateSecretRequest{Id: id, ClearMaxReads: true})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// A write share elevates plain updates only; clearing the expiry or the limit is a
	// lifecycle change and stays denied (same classification as REST).
	require.NoError(t, r.db.Create(&models.ShareRecord{
		SecretID: uint(id), OwnerID: 1, RecipientID: 2, Permission: "write",
	}).Error)
	for name, req := range map[string]*pb.UpdateSecretRequest{
		"clear_max_reads":  {Id: id, ClearMaxReads: true},
		"clear_expiration": {Id: id, ClearExpiration: true},
	} {
		err = viaShareAudit(r.svc.core, alice, func(ctx context.Context) error {
			_, uerr := r.svc.UpdateSecret(ctx, req)
			return uerr
		})
		require.Error(t, err, name)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), name)
	}

	got := loadSecret(t, r, id)
	require.NotNil(t, got.MaxReads)
	require.NotNil(t, got.Expiration)
	assert.True(t, exp.Equal(*got.Expiration))
}
