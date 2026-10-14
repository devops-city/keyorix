package interceptors

// auth_roles_unavailable_test.go — regression coverage for #1944 on the gRPC
// transport. A valid PAT whose owner's roles cannot be read (a storage fault
// in GetUserRoles, simulated by dropping the user_roles table after minting)
// must fail with a retryable codes.Unavailable — not Unauthenticated, which
// tells the client its credential is bad — and must not spend the peer IP's
// failed-auth budget.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthInterceptor_PATRoleResolutionUnavailable_IsRetryable(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	h.CreateTestUser(t, "grpc-1944", 9444)
	res, err := h.CoreService.CreateOwnPAT(context.Background(), 9444, "ci-1944", nil, nil, 0, 0, nil)
	require.NoError(t, err)

	// Token row, user row and account state all intact — only role resolution breaks.
	require.NoError(t, h.DB.Migrator().DropTable(&models.UserRole{}))

	const ip = "198.51.100.44"
	reached := false
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err = interceptor(bearerCtxFromIP(res.PlainToken, ip), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod},
		func(context.Context, any) (any, error) { reached = true; return "ok", nil })
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"a role-resolution storage failure is retryable, not a bad credential")
	assert.False(t, reached)

	for i := range grpcTokenAuthFailureBurst {
		assert.True(t, recordGRPCTokenAuthFailure(ip),
			"budget slot %d must still be available — this was not a bad-credential attempt", i)
	}
}
