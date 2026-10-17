package interceptors

// auth_machine_lookup_unavailable_test.go -- the credential-lookup counterpart of
// auth_machine_roles_unavailable_test.go. A FAILED machine-credential lookup
// (database down) is core.ErrAuthStorageUnavailable: over gRPC that must be
// codes.Unavailable with no strike on the peer's brute-force budget, not an
// Unauthenticated "invalid or expired token". Found by scripts/drills/disaster.sh
// (pgdown), PROD-OPS-1.

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// credentialLookupDownStorage fails the machine-credential lookup and delegates the rest.
type credentialLookupDownStorage struct{ corestorage.Storage }

func (credentialLookupDownStorage) GetMachineIdentityCredentialByHash(context.Context, string) (*models.MachineIdentityCredential, error) {
	return nil, errors.New("pq: connection reset by peer")
}

func TestAuthInterceptor_MachineCredentialLookupFault_IsUnavailableAndUnthrottled(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))

	ctxBg := context.Background()
	m, err := h.CoreService.CreateMachineIdentity(ctxBg, 2, "ci-bot-lookupdown", "service", "", "", 1, 0)
	require.NoError(t, err)
	proj2 := uint(2)
	h.AssignUserRole(t, 1, 2, &proj2)
	tok, err := h.CoreService.IssueMachineToken(ctxBg, 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok-lookupdown"})
	require.NoError(t, err)
	require.NoError(t, h.CoreService.AssignMachineRole(ctxBg, m.ID, 4, core.Scope{ProjectID: 2}, 1, false))

	faulty := core.NewKeyorixCore(credentialLookupDownStorage{Storage: h.Storage})
	const peerIP = "198.51.100.9"
	_, err = AuthInterceptor(faulty, false)(bearerCtxFromIP(tok.PlainToken, peerIP), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"a failed credential lookup is retryable infrastructure, not a verdict on the machine token")
	for i := range grpcTokenAuthFailureBurst {
		assert.True(t, recordGRPCTokenAuthFailure(peerIP),
			"budget slot %d must still be available — this was not a bad-credential attempt", i)
	}
}
