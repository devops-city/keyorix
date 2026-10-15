package services

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ADR-112 Amendment 4 over gRPC: with storage.database.insecure_audit_skip_reads
// on, GetSecretValue still returns the value but writes no secret.read row and
// no access-log row; the create and update around it are still audited.
func TestSecretService_GetSecretValue_InsecureAuditSkipReads(t *testing.T) {
	r := newSecretTestRig(t)
	r.core.SetInsecureAuditSkipReads(true)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "token", "the-value")

	val, err := r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "the-value", val.GetValue())
	_, err = r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: created.GetId(), Value: strPtr("v2")})
	require.NoError(t, err)

	count := func(eventType string) int64 {
		var n int64
		r.db.Model(&models.AuditEvent{}).Where("event_type = ? AND secret_node_id = ?", eventType, created.GetId()).Count(&n)
		return n
	}
	require.Eventually(t, func() bool { return count("secret.created") == 1 && count("secret.updated") == 1 },
		2*time.Second, 10*time.Millisecond, "create and update must still be audited")
	assert.Zero(t, count("secret.read"))
	var logs int64
	r.db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ? AND action = ?", created.GetId(), "read").Count(&logs)
	assert.Zero(t, logs)
}
