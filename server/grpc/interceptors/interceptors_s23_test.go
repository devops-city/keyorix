// interceptors_s23_test.go — fills the two remaining statement gaps in auth.go
// after the s22 sweep: the validateGRPCMachineToken error branch (line 310-312)
// and the GetUserIdentity failure branch (line 287-289).
package interceptors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// validateGRPCMachineToken — error branch (line 310-312)
//
// A token that begins with kx_machine_ but is not present in the database
// must be rejected with Unauthenticated rather than panicking or leaking an
// internal error.  The existing tests only exercise the success path.
// ---------------------------------------------------------------------------

// TestAuthInterceptor_S23_InvalidMachineTokenRejectedUnary confirms that a
// kx_machine_ token that fails ValidateMachineToken returns Unauthenticated
// over the unary interceptor.  This is the only path into validateGRPCMachineToken
// that returns an error (line 310-312).
func TestAuthInterceptor_S23_InvalidMachineTokenRejectedUnary(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))

	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("kx_machine_totally_bogus_token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"an unrecognised kx_machine_ token must yield Unauthenticated, not Internal")
}

// TestStreamAuthInterceptor_S23_InvalidMachineTokenRejected confirms the same
// error branch is reachable via the stream interceptor, which also routes
// kx_machine_ tokens through validateGRPCMachineToken.
func TestStreamAuthInterceptor_S23_InvalidMachineTokenRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: secretMethod}

	err := interceptor(nil, &fakeStream{ctx: streamBearerCtx("kx_machine_totally_bogus_token")}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"an unrecognised kx_machine_ token must yield Unauthenticated over a stream")
}

// ---------------------------------------------------------------------------
// authenticateRequest — GetUserIdentity failure branch (line 287-289)
//
// After a session token passes ValidateSessionToken and enforceGRPCAccessPolicy,
// the interceptor calls GetUserIdentity to resolve roles and permissions.  If
// the underlying storage query fails (e.g. the role_permissions table has been
// dropped), the interceptor must return codes.Internal rather than panicking or
// exposing the storage error.
//
// #1944: the fault is injected into role_permissions, NOT user_roles. A broken
// user_roles now fails ValidateSessionToken itself (GetUserRoles →
// core.ErrRoleResolutionUnavailable → codes.Unavailable, covered by
// auth_roles_unavailable_test.go) before GetUserIdentity is ever reached;
// role_permissions is read only by GetUserIdentity's permission lookup.
// ---------------------------------------------------------------------------

// TestAuthInterceptor_S23_GetUserIdentityFailureReturnsInternal exercises the
// branch at auth.go line 287-289 by deliberately corrupting the roles storage
// after a valid session has been created.  The session token passes validation;
// the subsequent identity resolution then fails because role_permissions no
// longer exists, which must produce codes.Internal.
func TestAuthInterceptor_S23_GetUserIdentityFailureReturnsInternal(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	// Create a live session for user 10001.
	mintSessionForTest(t, h, 10001, "identity-fail-user", "identity-fail-token", time.Now().Add(time.Hour))

	// Drop the role_permissions table so that GetUserPermissions (called inside
	// GetUserIdentity) returns a storage error while session validation's own
	// GetUserRoles still succeeds (#1944).  This is the only reliable way to
	// force that branch without introducing a mock core service.
	require.NoError(t, h.DB.Migrator().DropTable("role_permissions"),
		"prerequisite: drop role_permissions to trigger GetUserIdentity failure")

	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("identity-fail-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err),
		"a GetUserIdentity storage error must surface as codes.Internal, not panic or leak")
}

// TestStreamAuthInterceptor_S23_GetUserIdentityFailureReturnsInternal confirms
// the same branch is reachable via the stream interceptor.
func TestStreamAuthInterceptor_S23_GetUserIdentityFailureReturnsInternal(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	mintSessionForTest(t, h, 10002, "stream-identity-fail-user", "stream-identity-fail-token", time.Now().Add(time.Hour))

	require.NoError(t, h.DB.Migrator().DropTable("role_permissions"),
		"prerequisite: drop role_permissions to trigger GetUserIdentity failure")

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: secretMethod}

	err := interceptor(nil, &fakeStream{ctx: streamBearerCtx("stream-identity-fail-token")}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err),
		"a GetUserIdentity storage error must surface as codes.Internal over a stream")
}

// ---------------------------------------------------------------------------
// Additional GetUserContextKey and UserContext field coverage
// ---------------------------------------------------------------------------

// TestGetUserContextKey_S23_ReturnsSentinel confirms GetUserContextKey returns a
// non-zero value that can be used as a context key, consistent with s2 tests.
func TestGetUserContextKey_S23_ReturnsSentinel(t *testing.T) {
	k := GetUserContextKey()
	if k == (contextKey)("") {
		t.Error("GetUserContextKey() must return a non-empty sentinel")
	}
}

// TestUserContext_S23_MFAEnabledFieldCarried verifies the MFAEnabled field is
// populated correctly when a session token authenticates a user who has MFA set.
// This exercises the boolean expression `user.MFAEnabled || user.WebAuthnEnabled`
// (line 301) via the MFAEnabled=true arm, complementing the WebAuthn arm in s22.
func TestUserContext_S23_MFAEnabledFieldCarried(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	mintSessionForTest(t, h, 10100, "mfa-totp-user", "mfa-totp-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 10100, func(u *models.User) {
		u.MFAEnabled = true
		u.WebAuthnEnabled = false
	})

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("mfa-totp-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.True(t, user.MFAEnabled, "MFAEnabled must be true when the user has TOTP enrolled")
}

// TestUserContext_S23_BothMFAFieldsCarried verifies MFAEnabled is true when both
// MFAEnabled and WebAuthnEnabled are set — exercises the || short-circuit with
// both operands true.
func TestUserContext_S23_BothMFAFieldsCarried(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	mintSessionForTest(t, h, 10101, "mfa-both-user", "mfa-both-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 10101, func(u *models.User) {
		u.MFAEnabled = true
		u.WebAuthnEnabled = true
	})

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("mfa-both-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.True(t, user.MFAEnabled, "MFAEnabled must be true when both MFA and WebAuthn are enrolled")
}
