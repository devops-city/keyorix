package interceptors

// auth_machine_roles_unavailable_test.go — #2748.
//
// ValidateMachineToken used to soft-fail a GetMachineRoles storage error into
// (machine, []string{}, nil): a successful-looking validation with an empty
// role list. #2748 makes it return core.ErrRoleResolutionUnavailable instead,
// matching what #1944 already did for ValidatePATToken/ValidateSessionToken.
//
// validateGRPCMachineToken, unlike the user-credential path right above it in
// auth.go, collapsed EVERY ValidateMachineToken error into grpcAuthFailure —
// an Unauthenticated status plus a strike against the peer IP's brute-force
// budget. So the core fix alone would have converted a silent wrong answer
// into a wrong-and-punitive one over gRPC: a role-lookup blip reported as
// "invalid or expired token", with the machine's egress IP throttled towards
// ResourceExhausted if its automation retried. This pins the machine path to
// the same codes.Unavailable + no-strike contract.
//
// The fault is injected by WRAPPING the real storage the token was actually
// minted through, not by mocking the whole validator: the credential lookup,
// the machine-identity read and the active-state gate all still run against
// real rows, so the test proves the roles branch specifically is what the
// status comes from.

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

// machineRolesDownStorage fails GetMachineRoles for one machine id and
// delegates everything else to the real storage underneath.
type machineRolesDownStorage struct {
	corestorage.Storage
	machineID uint
}

func (s machineRolesDownStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	if machineID == s.machineID {
		return nil, errors.New("pq: connection reset by peer")
	}
	return s.Storage.GetMachineRoles(ctx, machineID)
}

func TestAuthInterceptor_MachineRoleResolutionUnavailable_IsUnavailableAndUnthrottled(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))

	ctxBg := context.Background()
	m, err := h.CoreService.CreateMachineIdentity(ctxBg, 2, "ci-bot-rolesdown", "service", "", "", 1, 0)
	require.NoError(t, err)
	// requireMachinePrivilegeCeiling requires the minting actor (user 1) to hold
	// roles.assign at the target project scope — the seeded "admin" role (id 2)
	// bundles it. Same setup as TestAuthInterceptor_MachineTokenNetworkAllowlistOverGRPC.
	proj2 := uint(2)
	h.AssignUserRole(t, 1, 2, &proj2)
	tok, err := h.CoreService.IssueMachineToken(ctxBg, 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok-rolesdown"})
	require.NoError(t, err)
	require.NoError(t, h.CoreService.AssignMachineRole(ctxBg, m.ID, 4, core.Scope{ProjectID: 2}, 1, false))

	// Sanity: the token authenticates fine against unwrapped storage, so a
	// failure below can only come from the injected roles fault.
	_, err = AuthInterceptor(h.CoreService, false)(bearerCtxFromIP(tok.PlainToken, "198.51.100.7"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.NoError(t, err, "the machine token must authenticate normally before the fault is injected")

	faulty := core.NewKeyorixCore(machineRolesDownStorage{Storage: h.Storage, machineID: m.ID})
	const peerIP = "198.51.100.8"
	_, err = AuthInterceptor(faulty, false)(bearerCtxFromIP(tok.PlainToken, peerIP), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"a role-resolution storage failure is retryable infrastructure, not a verdict on the machine token")
	assert.NotEqual(t, codes.Unauthenticated, status.Code(err))

	// The peer's brute-force budget must be untouched: a shared NAT/egress IP
	// whose automation retries through a blip must not end up ResourceExhausted
	// once storage is healthy again.
	for i := range grpcTokenAuthFailureBurst {
		assert.True(t, recordGRPCTokenAuthFailure(peerIP),
			"budget slot %d must still be available — this was not a bad-credential attempt", i)
	}
}
