package services

// #3508: gRPC DeleteSecret reads the purge date back after the soft-delete and its
// secret.deleted audit row committed. A fault there (error or panic) must leave PurgeAt
// unset and the RPC successful, not fail a delete that already happened.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestSecretService_DeleteSecret_PurgeAtReadbackFault_DoesNotUndoCompletedDelete(t *testing.T) {
	for name, kind := range map[string]faultstorage.FaultKind{"panic": faultstorage.KindPanic, "error": faultstorage.KindError} {
		t.Run(name, func(t *testing.T) {
			r := newSecretTestRig(t)
			ctx := authCtx(1, "owner", "secrets.write", "secrets.read", "secrets.delete")
			created := r.createSecret(t, ctx, "readback-target", "v1")

			fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), nil)
			svc := NewSecretService(core.NewKeyorixCore(fs))
			fs.Arm(&faultstorage.FaultSpec{
				Method: "GetSecretIncludingDeleted", NthCall: 1, Kind: kind,
				Err: errors.New("injected GetSecretIncludingDeleted fault"),
			})

			var resp *pb.DeleteSecretResponse
			var err error
			require.NotPanics(t, func() {
				resp, err = svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: created.GetId()})
			}, "a panic in the post-commit purge-date read-back must not escape the RPC")
			require.NoError(t, err, "the delete completed, so the RPC succeeds")
			assert.Nil(t, resp.GetPurgeAt(), "purge date left unset when it could not be read back")

			var deleted, audited int64
			require.NoError(t, r.db.Raw("SELECT COUNT(*) FROM secret_nodes WHERE id = ? AND deleted_at IS NOT NULL", created.GetId()).Row().Scan(&deleted))
			assert.EqualValues(t, 1, deleted, "the secret is soft-deleted")
			require.NoError(t, r.db.Model(&models.AuditEvent{}).Where("event_type = ? AND secret_node_id = ?", "secret.deleted", created.GetId()).Count(&audited).Error)
			assert.EqualValues(t, 1, audited, "and the secret.deleted audit row is committed")
		})
	}
}
