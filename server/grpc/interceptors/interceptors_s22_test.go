// interceptors_s22_test.go — targeted branch coverage for auth.go, logging.go,
// and related helpers: StreamAuthInterceptor, withAuditAttribution,
// enforceGRPCAccessPolicy, isPublicMethod, GetUserFromGRPCContext, and the
// LoggingInterceptor peer-present / slow-request paths.
package interceptors

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// isPublicMethod — all two entries in grpcPublicMethods
// ---------------------------------------------------------------------------

// TestIsPublicMethod_S22_AllPublicMethods verifies that every entry in
// grpcPublicMethods is recognised as public, that reflection (now
// auth-gated per r137 Sprint 1 GRPC-reflection-auth) is not, and that
// an arbitrary private method is not.
func TestIsPublicMethod_S22_AllPublicMethods(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"/grpc.health.v1.Health/Check", true},
		{"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", false},
		{"/keyorix.v1.SystemService/HealthCheck", true},
		{"/keyorix.v1.SecretService/GetSecret", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isPublicMethod(tc.method)
		if got != tc.want {
			t.Errorf("isPublicMethod(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// withAuditAttribution — nil, machine, impersonation branches
// ---------------------------------------------------------------------------

// TestWithAuditAttribution_S22_NilUserCtx confirms the nil guard returns the
// context unchanged without panicking.
func TestWithAuditAttribution_S22_NilUserCtx(t *testing.T) {
	ctx := context.Background()
	got := withAuditAttribution(ctx, nil)
	if got != ctx {
		t.Error("withAuditAttribution(nil) must return ctx unchanged")
	}
}

// TestWithAuditAttribution_S22_MachineActorTagged confirms that a machine
// UserContext causes ActorType=machine_identity to be stamped on the context.
func TestWithAuditAttribution_S22_MachineActorTagged(t *testing.T) {
	userCtx := &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: 99}
	got := withAuditAttribution(context.Background(), userCtx)
	// The actor type should now be readable from the context via core helpers.
	// We exercise the branch by verifying the context was modified (not the same
	// pointer) — a machine actor triggers the WithActorType branch.
	if got == context.Background() {
		t.Error("withAuditAttribution with machine actor must return a derived context")
	}
}

// TestWithAuditAttribution_S22_ImpersonationTagged confirms that a non-nil
// ImpersonatedBy causes the impersonation branch to execute.
func TestWithAuditAttribution_S22_ImpersonationTagged(t *testing.T) {
	adminID := uint(42)
	userCtx := &UserContext{UserID: 7, ImpersonatedBy: &adminID}
	got := withAuditAttribution(context.Background(), userCtx)
	if got == context.Background() {
		t.Error("withAuditAttribution with ImpersonatedBy must return a derived context")
	}
}

// TestWithAuditAttribution_S22_PlainUserUnmodified confirms a plain user
// (no machine, no impersonation) leaves the context pointer unchanged.
func TestWithAuditAttribution_S22_PlainUserUnmodified(t *testing.T) {
	userCtx := &UserContext{UserID: 1, Username: "alice"}
	ctx := context.Background()
	got := withAuditAttribution(ctx, userCtx)
	// No branches were taken, so the returned context must equal the input.
	if got != ctx {
		t.Error("withAuditAttribution for a plain user must return ctx unchanged")
	}
}

// ---------------------------------------------------------------------------
// enforceGRPCAccessPolicy — AccountPendingFirstLogin, WebAuthnEnabled MFA gate,
// empty-IP fail-closed
// ---------------------------------------------------------------------------

// TestEnforceGRPCAccessPolicy_S22_PendingFirstLoginDenied mirrors the
// password_reset_required test but for pending_first_login, ensuring both
// restricted account states are covered.
func TestEnforceGRPCAccessPolicy_S22_PendingFirstLoginDenied(t *testing.T) {
	user := &models.User{AccountState: core.AccountPendingFirstLogin}
	err := enforceGRPCAccessPolicy(context.Background(), user, nil, false, false)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestEnforceGRPCAccessPolicy_S22_WebAuthnSatisfiesMFAGate covers the
// user.WebAuthnEnabled=true path inside the MFA-enrolment check: a session with
// only a passkey (no TOTP) must be allowed through when requireMFA=true.
func TestEnforceGRPCAccessPolicy_S22_WebAuthnSatisfiesMFAGate(t *testing.T) {
	user := &models.User{MFAEnabled: false, WebAuthnEnabled: true}
	err := enforceGRPCAccessPolicy(context.Background(), user, nil, true /*requireMFA*/, true /*viaSession*/)
	require.NoError(t, err, "WebAuthn alone must satisfy the MFA-enrolment requirement")
}

// TestEnforceGRPCAccessPolicy_S22_PATExemptFromMFAGate covers the viaSession=false
// branch: a PAT is non-interactive and must not be blocked even when requireMFA=true
// and the owning user has no second factor.
func TestEnforceGRPCAccessPolicy_S22_PATExemptFromMFAGate(t *testing.T) {
	user := &models.User{MFAEnabled: false, WebAuthnEnabled: false}
	err := enforceGRPCAccessPolicy(context.Background(), user, nil, true /*requireMFA*/, false /*viaSession=PAT*/)
	require.NoError(t, err, "a PAT is non-interactive and exempt from the MFA-enrolment gate")
}

// TestEnforceGRPCAccessPolicy_S22_CIDRNoIP covers the fail-closed path: a PAT
// restriction with an IP allowlist must deny the request when the source IP is
// undeterminable (no peer in context → PeerIP returns "").
func TestEnforceGRPCAccessPolicy_S22_CIDRNoIP(t *testing.T) {
	restriction := &core.PATRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}}
	// No peer in context → PeerIP("") is not in any CIDR.
	err := enforceGRPCAccessPolicy(context.Background(), &models.User{}, restriction, false, false)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestEnforceGRPCAccessPolicy_S22_EmptyCIDRListSkipsCheck covers the branch
// where the restriction exists but AllowedCIDRs is empty — the IP check must be
// skipped, so a request without a peer is still allowed through.
func TestEnforceGRPCAccessPolicy_S22_EmptyCIDRListSkipsCheck(t *testing.T) {
	restriction := &core.PATRestriction{AllowedCIDRs: nil}
	err := enforceGRPCAccessPolicy(context.Background(), &models.User{}, restriction, false, false)
	require.NoError(t, err, "a restriction with no CIDRs must not block requests")
}

// ---------------------------------------------------------------------------
// GetUserFromGRPCContext — nil path
// ---------------------------------------------------------------------------

// TestGetUserFromGRPCContext_S22_NilWhenAbsent confirms the function returns nil
// (not a nil-typed non-nil interface) when the key is not present in the context.
func TestGetUserFromGRPCContext_S22_NilWhenAbsent(t *testing.T) {
	got := GetUserFromGRPCContext(context.Background())
	if got != nil {
		t.Errorf("GetUserFromGRPCContext on empty context = %v, want nil", got)
	}
}

// TestGetUserFromGRPCContext_S22_ReturnsValue confirms that a value stored
// under the package key is retrieved correctly.
func TestGetUserFromGRPCContext_S22_ReturnsValue(t *testing.T) {
	want := &UserContext{UserID: 55, Username: "test-user"}
	ctx := context.WithValue(context.Background(), userContextKey, want)
	got := GetUserFromGRPCContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, uint(55), got.UserID)
}

// ---------------------------------------------------------------------------
// LoggingInterceptor — peer-present branch + slow-request log path
// ---------------------------------------------------------------------------

// TestLoggingInterceptor_S22_WithPeer exercises the peer.FromContext branch in
// LoggingInterceptor — the "clientIP = p.Addr.String()" branch that only fires
// when the context carries a gRPC peer.
func TestLoggingInterceptor_S22_WithPeer(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 9090},
	})
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	resp, err := interceptor(ctx, "req", info,
		func(_ context.Context, req any) (any, error) {
			return "pong", nil
		})
	require.NoError(t, err)
	assert.Equal(t, "pong", resp)
}

// TestLoggingInterceptor_S22_WithPeerAndError exercises the same peer branch but
// with a handler that returns an error, covering the "ERROR" status branch.
func TestLoggingInterceptor_S22_WithPeerAndError(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 9090},
	})
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}
	handlerErr := errors.New("peer error")

	_, err := interceptor(ctx, nil, info,
		func(_ context.Context, _ any) (any, error) {
			return nil, handlerErr
		})
	require.Error(t, err)
	assert.ErrorIs(t, err, handlerErr)
}

// TestLoggingInterceptor_S22_SlowRequestBranch exercises the "SLOW gRPC REQUEST"
// log path that fires when the handler takes longer than 1 second. We use a
// handler that blocks until the context-injected deadline fires, keeping the test
// duration bounded.
func TestLoggingInterceptor_S22_SlowRequestBranch(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	// Use a context with a 1.1s deadline so the handler can sleep just over 1s,
	// triggering the slow-request log branch, without making the test hang.
	ctx, cancel := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancel()

	_, _ = interceptor(ctx, nil, info,
		func(innerCtx context.Context, _ any) (any, error) {
			// Sleep for slightly over 1 second to cross the slow-request threshold,
			// then return normally (not an error — the branch is in the logging path,
			// not the error path).
			timer := time.NewTimer(1050 * time.Millisecond)
			select {
			case <-timer.C:
			case <-innerCtx.Done():
				timer.Stop()
			}
			return "slow", nil
		})
	// The test only validates the branch is reachable without panicking; the log
	// output goes to the standard logger and is not asserted here.
}

// ---------------------------------------------------------------------------
// StreamLoggingInterceptor — peer-present branch
// ---------------------------------------------------------------------------

// TestStreamLoggingInterceptor_S22_WithPeer exercises the peer.FromContext branch
// inside StreamLoggingInterceptor (the "clientIP = p.Addr.String()" line that
// fires when stream.Context() carries a gRPC peer).
func TestStreamLoggingInterceptor_S22_WithPeer(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8080},
	})
	interceptor := StreamLoggingInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.AuditService/StreamAuditLogs"}

	err := interceptor(nil, &fakeStream{ctx: ctx}, info,
		func(_ any, _ grpc.ServerStream) error {
			return nil
		})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// StreamAuthInterceptor — full branch coverage
// ---------------------------------------------------------------------------

// streamBearerCtx returns a context carrying the given bearer token in gRPC
// incoming metadata — the same helper shape as bearerCtx but named to signal
// it is used for stream tests.
func streamBearerCtx(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

// TestStreamAuthInterceptor_S22_PublicMethodBypasses confirms that a public
// stream method (e.g. /grpc.health.v1.Health/Check) skips authentication
// entirely — the coreService is nil so any auth attempt would panic/error.
func TestStreamAuthInterceptor_S22_PublicMethodBypasses(t *testing.T) {
	interceptor := StreamAuthInterceptor(nil, false)
	info := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}

	called := false
	err := interceptor(nil, &fakeStream{ctx: context.Background()}, info,
		func(_ any, _ grpc.ServerStream) error {
			called = true
			return nil
		})
	require.NoError(t, err)
	assert.True(t, called, "handler must be called for a public stream method")
}

// TestStreamAuthInterceptor_S22_HealthCheckPublic covers the third public method
// (/keyorix.v1.SystemService/HealthCheck) via the stream interceptor.
func TestStreamAuthInterceptor_S22_HealthCheckPublic(t *testing.T) {
	interceptor := StreamAuthInterceptor(nil, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SystemService/HealthCheck"}

	err := interceptor(nil, &fakeStream{ctx: context.Background()}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.NoError(t, err)
}

// TestStreamAuthInterceptor_S22_NilCoreFailsClosed confirms that a nil core
// service causes the stream interceptor to fail closed (codes.Internal).
func TestStreamAuthInterceptor_S22_NilCoreFailsClosed(t *testing.T) {
	interceptor := StreamAuthInterceptor(nil, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	err := interceptor(nil, &fakeStream{ctx: streamBearerCtx("any")}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// TestStreamAuthInterceptor_S22_MissingMetadataRejected confirms that a stream
// with no gRPC incoming metadata is rejected with Unauthenticated.
func TestStreamAuthInterceptor_S22_MissingMetadataRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	err := interceptor(nil, &fakeStream{ctx: context.Background()}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestStreamAuthInterceptor_S22_InvalidTokenRejected confirms that an unknown
// bearer token is rejected with Unauthenticated over a stream.
func TestStreamAuthInterceptor_S22_InvalidTokenRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	err := interceptor(nil, &fakeStream{ctx: streamBearerCtx("bogus-token")}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestStreamAuthInterceptor_S22_ValidSessionPopulatesContext confirms that a
// valid session token authenticates over a stream and the wrapped stream carries
// the user context in its Context().
func TestStreamAuthInterceptor_S22_ValidSessionPopulatesContext(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 8001, "stream-user", "stream-live-token", time.Now().Add(time.Hour))

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	var capturedStreamCtx context.Context
	err := interceptor(nil, &fakeStream{ctx: streamBearerCtx("stream-live-token")}, info,
		func(_ any, s grpc.ServerStream) error {
			capturedStreamCtx = s.Context()
			return nil
		})
	require.NoError(t, err)

	user := GetUserFromGRPCContext(capturedStreamCtx)
	require.NotNil(t, user, "authenticated user must be present on the wrapped stream context")
	assert.Equal(t, uint(8001), user.UserID)
	assert.Equal(t, "stream-user", user.Username)
}

// TestStreamAuthInterceptor_S22_BlocksImpersonatedCredentialMinting mirrors the
// unary test: a credential-minting stream method must be refused while
// impersonating, returning PermissionDenied.
func TestStreamAuthInterceptor_S22_BlocksImpersonatedCredentialMinting(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	admin := uint(8100)
	target := uint(8101)
	h.CreateTestUser(t, "stream-imp-admin", admin)
	h.CreateTestUser(t, "stream-imp-target", target)
	h.AssignUserRole(t, admin, 1, nil) // super_admin — #G05 ceiling re-check
	expiry := time.Now().Add(time.Hour)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: target, SessionToken: "stream-imp-token", ExpiresAt: &expiry, ImpersonatedBy: &admin,
	})
	require.NoError(t, err)

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	const machineIssue = "/keyorix.v1.MachineIdentityService/IssueMachineToken"

	err = interceptor(nil, &fakeStream{ctx: streamBearerCtx("stream-imp-token")},
		&grpc.StreamServerInfo{FullMethod: machineIssue},
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestStreamAuthInterceptor_S22_NonCredentialMintingMethodAllowedWhileImpersonating
// confirms that a non-credential-minting stream method proceeds even during an
// impersonation session (the block is method-specific, not a blanket ban).
func TestStreamAuthInterceptor_S22_NonCredentialMintingMethodAllowedWhileImpersonating(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	admin := uint(8200)
	target := uint(8201)
	h.CreateTestUser(t, "stream-imp-admin2", admin)
	h.CreateTestUser(t, "stream-imp-target2", target)
	h.AssignUserRole(t, admin, 1, nil) // super_admin — #G05 ceiling re-check
	expiry := time.Now().Add(time.Hour)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: target, SessionToken: "stream-imp-ok-token", ExpiresAt: &expiry, ImpersonatedBy: &admin,
	})
	require.NoError(t, err)

	interceptor := StreamAuthInterceptor(h.CoreService, false)

	err = interceptor(nil, &fakeStream{ctx: streamBearerCtx("stream-imp-ok-token")},
		&grpc.StreamServerInfo{FullMethod: "/keyorix.v1.AuditService/StreamAuditLogs"},
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.NoError(t, err, "a non-credential-minting method must proceed even during impersonation")
}

// TestStreamAuthInterceptor_S22_PATAuthenticatesAndEnforcesScope confirms that a
// PAT token authenticates over a stream and its ADR-042 restriction rides the
// wrapped stream's context (same invariant as the unary path).
func TestStreamAuthInterceptor_S22_PATAuthenticatesAndEnforcesScope(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	h.CreateTestUser(t, "stream-pat-user", 8300)
	proj3 := uint(3)
	h.AssignUserRole(t, 8300, 3, &proj3) // editor in project 3

	res, err := h.CoreService.CreateOwnPAT(context.Background(), 8300, "stream-ci", nil, []string{"secrets.read"}, 3, 0, nil)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.PlainToken, "kx_pat_"))

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	var capturedStreamCtx context.Context
	err = interceptor(nil, &fakeStream{ctx: streamBearerCtx(res.PlainToken)}, info,
		func(_ any, s grpc.ServerStream) error {
			capturedStreamCtx = s.Context()
			return nil
		})
	require.NoError(t, err, "a kx_pat_ token must authenticate over a stream")

	user := GetUserFromGRPCContext(capturedStreamCtx)
	require.NotNil(t, user)
	assert.Equal(t, uint(8300), user.UserID)

	// The PAT restriction must be on the wrapped stream's context.
	readP3, err := h.CoreService.Authorize(capturedStreamCtx, 8300, "secrets.read", core.Scope{ProjectID: 3})
	require.NoError(t, err)
	assert.True(t, readP3, "in-scope read is permitted through the stream's context")

	writeP3, err := h.CoreService.Authorize(capturedStreamCtx, 8300, "secrets.write", core.Scope{ProjectID: 3})
	require.NoError(t, err)
	assert.False(t, writeP3, "write is outside the PAT's allowlist — denied through the stream's context")
}

// TestStreamAuthInterceptor_S22_MFAGateEnforcedOnStream confirms that the
// requireMFA policy is enforced over streams: a session without MFA is refused
// when requireMFA=true, and a session with MFA proceeds.
func TestStreamAuthInterceptor_S22_MFAGateEnforcedOnStream(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	mintSessionForTest(t, h, 8400, "stream-nomfa", "stream-nomfa-token", time.Now().Add(time.Hour))
	mintSessionForTest(t, h, 8401, "stream-mfa", "stream-mfa-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 8401, func(u *models.User) { u.MFAEnabled = true })

	interceptor := StreamAuthInterceptor(h.CoreService, true)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	// Session without MFA → refused.
	err := interceptor(nil, &fakeStream{ctx: streamBearerCtx("stream-nomfa-token")}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Session with MFA → allowed.
	err = interceptor(nil, &fakeStream{ctx: streamBearerCtx("stream-mfa-token")}, info,
		func(_ any, _ grpc.ServerStream) error { return nil })
	require.NoError(t, err)
}

// TestStreamAuthInterceptor_S22_MachineTokenAuthenticates confirms that a
// kx_machine_ token authenticates as a machine principal over a stream.
func TestStreamAuthInterceptor_S22_MachineTokenAuthenticates(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))

	m, err := h.CoreService.CreateMachineIdentity(context.Background(), 2, "stream-bot", "service", "", "", 1, 0)
	require.NoError(t, err)
	// requireMachinePrivilegeCeiling now requires the calling actor (user 1) to
	// hold roles.assign at the target project scope before it can mint a token —
	// grant it the seeded "admin" role (id 2, bundles roles.assign) at project 2.
	proj2stream := uint(2)
	h.AssignUserRole(t, 1, 2, &proj2stream)
	tok, err := h.CoreService.IssueMachineToken(context.Background(), 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(tok.PlainToken, "kx_machine_"))

	interceptor := StreamAuthInterceptor(h.CoreService, false)
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	var capturedStreamCtx context.Context
	err = interceptor(nil, &fakeStream{ctx: streamBearerCtx(tok.PlainToken)}, info,
		func(_ any, s grpc.ServerStream) error {
			capturedStreamCtx = s.Context()
			return nil
		})
	require.NoError(t, err, "a kx_machine_ token must authenticate over a stream")

	user := GetUserFromGRPCContext(capturedStreamCtx)
	require.NotNil(t, user)
	assert.Equal(t, core.ActorTypeMachine, user.ActorType)
	assert.Equal(t, m.ID, user.MachineIdentityID)
	assert.Equal(t, uint(0), user.UserID)
}

// ---------------------------------------------------------------------------
// AuthInterceptor — remaining unary branches
// ---------------------------------------------------------------------------

// TestAuthInterceptor_S22_HealthCheckPublicMethod confirms the third public
// method (/keyorix.v1.SystemService/HealthCheck) bypasses auth in the unary
// interceptor (the existing test covers only ServerReflectionInfo).
func TestAuthInterceptor_S22_HealthCheckPublicMethod(t *testing.T) {
	interceptor := AuthInterceptor(nil, false)
	resp, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SystemService/HealthCheck"},
		okHandler(nil))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

// TestAuthInterceptor_S22_GRPCHealthCheckPublicMethod covers the
// /grpc.health.v1.Health/Check entry (not tested by the existing suite).
func TestAuthInterceptor_S22_GRPCHealthCheckPublicMethod(t *testing.T) {
	interceptor := AuthInterceptor(nil, false)
	resp, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"},
		okHandler(nil))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

// TestAuthInterceptor_S22_PendingFirstLoginDenied extends the restricted-account
// coverage to the other restricted state (the existing test only covers
// password_reset_required).
func TestAuthInterceptor_S22_PendingFirstLoginDenied(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9500, "grpc-firstlogin", "firstlogin-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 9500, func(u *models.User) { u.AccountState = core.AccountPendingFirstLogin })

	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("firstlogin-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestAuthInterceptor_S22_WebAuthnSatisfiesMFARequirement covers the
// user.WebAuthnEnabled=true path: a session user enrolled via passkey (no TOTP)
// must be allowed through the deployment-wide MFA gate.
func TestAuthInterceptor_S22_WebAuthnSatisfiesMFARequirement(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9600, "grpc-webauthn", "webauthn-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 9600, func(u *models.User) { u.WebAuthnEnabled = true })

	interceptor := AuthInterceptor(h.CoreService, true /*requireMFA*/)
	resp, err := interceptor(bearerCtx("webauthn-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.NoError(t, err, "WebAuthn enrolment must satisfy the MFA requirement")
	assert.Equal(t, "ok", resp)
}

// TestAuthInterceptor_S22_SessionAuthFlagSet confirms the SessionAuth field is
// true for an interactive session token (false for PATs and machine tokens).
// This flag is what the service layer uses to apply per-project MFA policy.
func TestAuthInterceptor_S22_SessionAuthFlagSet(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9700, "grpc-session-flag", "session-flag-token", time.Now().Add(time.Hour))

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("session-flag-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.True(t, user.SessionAuth, "SessionAuth must be true for an interactive session token")
}

// TestAuthInterceptor_S22_PATSessionAuthFalse confirms SessionAuth is false for
// a PAT (non-interactive), distinguishing it from a session token.
func TestAuthInterceptor_S22_PATSessionAuthFalse(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	h.CreateTestUser(t, "grpc-pat-session-flag", 9800)
	res, err := h.CoreService.CreateOwnPAT(context.Background(), 9800, "ci", nil, nil, 0, 0, nil)
	require.NoError(t, err)

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err = interceptor(bearerCtx(res.PlainToken), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.False(t, user.SessionAuth, "SessionAuth must be false for a PAT (non-interactive)")
}
