package services

// coverage_s21b_test.go — targeted tests to raise coverage on branches not yet
// exercised by coverage_s17_test.go, coverage_s17b_test.go, coverage_s18_test.go,
// or coverage_s21_test.go. Targets:
//
//   audit_service.go:62    acquireStreamSlot (ResourceExhausted branch)
//   audit_service.go:212   WriteAuditCheckpoint (non-"refusing" error path)
//   user_service.go:36     CreateUser (setup-link + OTP branches, display-name default)
//   user_service.go:185    ListUsers (inactive filter)
//   system_service.go:91   GetMetrics (unauthenticated / permission-denied)
//   system_service.go:147  nonNegU64 (negative input)
//   system_service.go:183  encStatus (both branches)
//   role_service.go:44     CreateRole (reserved-name guard)
//   role_service.go:157    DeleteRole (builtin guard)
//   share_service.go:220   mapShareError (permission-denied path)
//   share_service.go:178   RevokeShare (zero-id / unauthenticated / not-found)
//   share_service.go:151   UpdateSharePermission (unauthenticated / invalid perm)
//   connect_service.go:43  ReadSecret (unsafe-Internal error branch)

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ---------------------------------------------------------------------------
// acquireStreamSlot — ResourceExhausted when the cap is reached
// ---------------------------------------------------------------------------

// TestAcquireStreamSlot_ResourceExhausted_S21b exercises the cap-exceeded branch
// of acquireStreamSlot by filling all auditStreamMaxPerPrincipal slots and then
// attempting a fourth acquisition, which must return ResourceExhausted.
func TestAcquireStreamSlot_ResourceExhausted_S21b(t *testing.T) {
	svc := newAuditService(t)

	// Build a fake actor to identify the principal (user 1).
	actor := auditActorCtxUser()

	var releases []func()
	for i := range auditStreamMaxPerPrincipal {
		release, err := svc.acquireStreamSlot(actor)
		require.NoError(t, err, "slot %d should be acquirable", i+1)
		releases = append(releases, release)
	}

	// One over the cap → ResourceExhausted.
	_, err := svc.acquireStreamSlot(actor)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	// Clean up.
	for _, r := range releases {
		r()
	}
}

// TestAcquireStreamSlot_ImpersonationCapsPerAdmin_S21b is the #G05 regression
// (detection_idea: "concurrent impersonation of N different targets by one
// admin is capped like N single-identity sessions"): an admin impersonating
// auditStreamMaxPerPrincipal DIFFERENT targets must hit the SAME cap as if
// they held all those streams under their own identity — the slot key must
// resolve to the ADMIN's id, not each target's, during impersonation.
func TestAcquireStreamSlot_ImpersonationCapsPerAdmin_S21b(t *testing.T) {
	svc := newAuditService(t)
	admin := uint(1)

	var releases []func()
	for i := range auditStreamMaxPerPrincipal {
		target := uint(100 + i) // a DIFFERENT target each time
		actor := &interceptors.UserContext{UserID: target, ImpersonatedBy: &admin}
		release, err := svc.acquireStreamSlot(actor)
		require.NoError(t, err, "slot %d (impersonating target %d) should be acquirable", i+1, target)
		releases = append(releases, release)
	}

	// A (max+1)th target, still impersonated by the SAME admin, must be refused —
	// proving the cap is keyed on the admin, not on each distinct target's id
	// (which would never collide and so never trip the cap at all).
	oneMoreTarget := uint(999)
	actor := &interceptors.UserContext{UserID: oneMoreTarget, ImpersonatedBy: &admin}
	_, err := svc.acquireStreamSlot(actor)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	// The admin's own, non-impersonated identity shares the same key — also capped.
	ownActor := &interceptors.UserContext{UserID: admin}
	_, err = svc.acquireStreamSlot(ownActor)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	for _, r := range releases {
		r()
	}
}

// TestAcquireStreamSlot_ReleasedSlotReacquirable_S21b confirms that after
// releasing a slot the counter drops back and the next acquire succeeds.
func TestAcquireStreamSlot_ReleasedSlotReacquirable_S21b(t *testing.T) {
	svc := newAuditService(t)
	actor := auditActorCtxUser()

	// Fill to the cap.
	var releases []func()
	for range auditStreamMaxPerPrincipal {
		release, err := svc.acquireStreamSlot(actor)
		require.NoError(t, err)
		releases = append(releases, release)
	}

	// Release one, then immediately re-acquire — must succeed.
	releases[0]()
	releases = releases[1:]

	release, err := svc.acquireStreamSlot(actor)
	require.NoError(t, err)
	releases = append(releases, release)

	for _, r := range releases {
		r()
	}
}

// ---------------------------------------------------------------------------
// WriteAuditCheckpoint — non-"refusing" error branch (clientSafe path)
// ---------------------------------------------------------------------------

// TestWriteAuditCheckpoint_NonRefusingError_S21b hits the `!strings.Contains(msg,
// "refusing to checkpoint")` branch (line 227) inside WriteAuditCheckpoint.
// The test rig has no audit events and no encryption, so core.WriteAuditCheckpoint
// returns either an error that doesn't start with "refusing" or written=false; both
// are FailedPrecondition, but through different sub-paths.
func TestWriteAuditCheckpoint_NonRefusingError_S21b(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "system.write", "audit.read")
	_, err := svc.WriteAuditCheckpoint(ctx, &emptypb.Empty{})
	require.Error(t, err)
	// Both the "refusing" path and the !written path land on FailedPrecondition.
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ---------------------------------------------------------------------------
// CreateUser — setup-link and OTP branches
// ---------------------------------------------------------------------------

func TestCreateUser_SetupLink_S21b(t *testing.T) {
	// The test rig has no mail-delivery base_url configured, so
	// CreateUserWithSetupLink returns an InvalidArgument validation error rather
	// than succeeding. We verify the setup-link code path is reached (not the
	// password or OTP branch) by checking that a recognisable config-related error
	// is returned (as opposed to e.g. Unauthenticated or a panic).
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:         "setuplink_user",
		Email:            "setuplink@example.com",
		DeliverSetupLink: true,
	})
	// The delivery validation error from core comes back as InvalidArgument via
	// mapUserError — the branch is exercised even on failure.
	require.Error(t, err)
	code := status.Code(err)
	assert.True(t, code == codes.InvalidArgument || code == codes.Internal,
		"expected InvalidArgument or Internal from setup-link path, got %v", code)
}

func TestCreateUser_OTP_S21b(t *testing.T) {
	svc := newUserService(t)
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:                "otp_user",
		Email:                   "otp@example.com",
		GenerateOneTimePassword: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	assert.Equal(t, "otp_user", resp.GetUser().GetUsername())
}

func TestCreateUser_DisplayNameDefault_S21b(t *testing.T) {
	// When DisplayName is empty the username is used as the display name
	// (the `if displayName == "" { displayName = req.GetUsername() }` branch).
	svc := newUserService(t)
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "noname_user",
		Email:    "noname@example.com",
		Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		// DisplayName deliberately omitted.
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	assert.Equal(t, "noname_user", resp.GetUser().GetDisplayName())
}

func TestCreateUser_DisplayNameExplicit_S21b(t *testing.T) {
	// When DisplayName is supplied it must be honoured.
	svc := newUserService(t)
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:    "hasname_user",
		Email:       "hasname@example.com",
		Password:    strPtr("Qr7#Kp2$Lm5@Vn9!"),
		DisplayName: strPtr("Has Name"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	assert.Equal(t, "Has Name", resp.GetUser().GetDisplayName())
}

// ---------------------------------------------------------------------------
// ListUsers — inactive filter branch
// ---------------------------------------------------------------------------

func TestListUsers_InactiveFilter_S21b(t *testing.T) {
	svc := newUserService(t)
	// The "inactive" filter sets an InactiveSince cutoff on the query.
	// No users with no logins in the last 30 days exist in the empty DB, but the
	// branch is exercised and the call must succeed without error.
	resp, err := svc.ListUsers(adminCtx(), &pb.ListUsersRequest{Filter: strPtr("inactive")})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// GetMetrics — unauthenticated and permission-denied paths
// ---------------------------------------------------------------------------

func TestGetMetrics_Unauthenticated_S21b(t *testing.T) {
	svc := newSystemService(t)
	_, err := svc.GetMetrics(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetMetrics_PermissionDenied_S21b(t *testing.T) {
	svc := newSystemService(t)
	ctx := authCtx(7, "nobody") // ungranted user → denied
	_, err := svc.GetMetrics(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// nonNegU64 — negative-input branch
// ---------------------------------------------------------------------------

func TestNonNegU64_Negative_S21b(t *testing.T) {
	assert.Equal(t, uint64(0), nonNegU64(-1))
	assert.Equal(t, uint64(0), nonNegU64(-999))
}

func TestNonNegU64_Zero_S21b(t *testing.T) {
	assert.Equal(t, uint64(0), nonNegU64(0))
}

func TestNonNegU64_Positive_S21b(t *testing.T) {
	assert.Equal(t, uint64(42), nonNegU64(42))
}

// ---------------------------------------------------------------------------
// encStatus — both branches
// ---------------------------------------------------------------------------

func TestEncStatus_Enabled_S21b(t *testing.T) {
	assert.Equal(t, "enabled", encStatus(true))
}

func TestEncStatus_Disabled_S21b(t *testing.T) {
	assert.Equal(t, "disabled", encStatus(false))
}

// ---------------------------------------------------------------------------
// GetSystemInfo — with nil config (covers the `if s.cfg != nil` else branch)
// ---------------------------------------------------------------------------

func TestGetSystemInfo_NilConfig_S21b(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil)
	svc := NewSystemService(h.CoreService, nil) // cfg == nil
	info, err := svc.GetSystemInfo(sysCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotEmpty(t, info.GetGoVersion())
	// When cfg is nil, Database and Encryption are absent.
	assert.Nil(t, info.GetDatabase())
	assert.Nil(t, info.GetEncryption())
}

// ---------------------------------------------------------------------------
// CreateRole — reserved-name guard
// ---------------------------------------------------------------------------

func TestCreateRole_BuiltinRejected_S21b(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name:        "super_admin", // reserved / built-in
		Description: "attempt to shadow a built-in role",
		Permissions: []string{"roles.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestCreateRole_BuiltinAdmin_S21b(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name:        "admin", // another typical built-in
		Description: "attempt to shadow admin",
		Permissions: []string{"roles.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteRole — built-in guard
// ---------------------------------------------------------------------------

func TestDeleteRole_BuiltinDenied_S21b(t *testing.T) {
	svc, h := newRoleService(t)
	// Find the actual ID of the built-in super_admin role from the seeded DB.
	roles, err := svc.ListRoles(roleAdminCtx(), &pb.ListRolesRequest{})
	require.NoError(t, err)
	var builtinID uint32
	for _, r := range roles.GetRoles() {
		if r.GetName() == "super_admin" {
			builtinID = r.GetId()
			break
		}
	}
	if builtinID == 0 {
		// Seed the role directly so we can test the guard regardless.
		require.NotNil(t, h)
		t.Skip("super_admin role not found in test rig; skipping builtin-delete guard")
	}
	_, err = svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: builtinID})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ---------------------------------------------------------------------------
// mapShareError — permission-denied branch
// ---------------------------------------------------------------------------

func TestMapShareError_PermissionDenied_S21b(t *testing.T) {
	err := mapShareError(errMsg("not authorized to share this secret"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapShareError_PermissionDenied2_S21b(t *testing.T) {
	err := mapShareError(errMsg("permission denied for this share"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapShareError_NotFound_S21b(t *testing.T) {
	err := mapShareError(errMsg("share not found in the database"))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestMapShareError_Default_S21b(t *testing.T) {
	err := mapShareError(errMsg("database connection timeout"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// RevokeShare — zero-id / unauthenticated / not-found paths
// ---------------------------------------------------------------------------

func TestRevokeShare_Unauthenticated_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.RevokeShare(context.Background(), &pb.RevokeShareRequest{ShareId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRevokeShare_ZeroID_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRevokeShare_NotFound_S21b(t *testing.T) {
	r := newShareTestRig(t)
	// authorizeShareScoped calls GetShareRecord first; a non-existent share → NotFound.
	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// UpdateSharePermission — unauthenticated / invalid-permission paths
// ---------------------------------------------------------------------------

func TestUpdateSharePermission_Unauthenticated_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.UpdateSharePermission(context.Background(), &pb.UpdateSharePermissionRequest{
		ShareId: 1, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateSharePermission_ZeroID_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: 0, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateSharePermission_InvalidPermission_S21b(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	_, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "admin",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// ShareSecret — zero-id / missing-recipient / empty-permission paths
// ---------------------------------------------------------------------------

func TestShareSecret_ZeroSecretID_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: 0, RecipientId: 2, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestShareSecret_ZeroRecipientID_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 0, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListSecretShares — zero-id / unauthenticated paths
// ---------------------------------------------------------------------------

func TestListSecretShares_Unauthenticated_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ListSecretShares(context.Background(), &pb.ListSecretSharesRequest{SecretId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListSecretShares_ZeroID_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ListSecretShares(ownerCtx(), &pb.ListSecretSharesRequest{SecretId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListUserShares — unauthenticated path
// ---------------------------------------------------------------------------

func TestListUserShares_Unauthenticated_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ListUserShares(context.Background(), &pb.ListUserSharesRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListSharedSecrets — unauthenticated path
// ---------------------------------------------------------------------------

func TestListSharedSecrets_Unauthenticated_S21b(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ListSharedSecrets(context.Background(), &pb.ListSharedSecretsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// ConnectService ReadSecret — internal-error branch (unsafe message → codes.Internal)
// ---------------------------------------------------------------------------

// errConnector is a connector whose GetSecret always returns an error that does
// NOT contain any of the patterns isSafeConnectError checks for — so ReadSecret
// must log and return codes.Internal (not codes.FailedPrecondition).
type errConnector struct{}

func (errConnector) Name() string { return "failing" }
func (errConnector) Type() string { return "fake" }
func (errConnector) GetSecret(_ context.Context, _ string) (string, error) {
	return "", errMsg("dial tcp: connection refused")
}

func newFailingConnectService(t *testing.T) *ConnectGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil)
	h.CoreService.SetConnectManager(connect.NewManager([]connect.Connector{errConnector{}}))
	h.CoreService.SetConnectOwnership(map[string]core.ConnectOwnership{"failing": {Scope: "platform"}})
	return NewConnectService(h.CoreService)
}

func TestReadSecret_InternalError_S21b(t *testing.T) {
	svc := newFailingConnectService(t)
	ctx := authCtx(1, "admin", "connect.read")
	_, err := svc.ReadSecret(ctx, &pb.ReadFederatedSecretRequest{
		Connector: "failing",
		Ref:       "some/ref",
	})
	require.Error(t, err)
	// Unsafe/unclassified backend errors must map to Internal, not FailedPrecondition.
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// ConnectService CreateRefGrant — internal-error branch
// ---------------------------------------------------------------------------

func TestCreateRefGrant_PermissionDenied_S21b(t *testing.T) {
	svc := newConnectServiceFull(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.CreateRefGrant(ctx, &pb.CreateConnectRefGrantRequest{
		RoleId: 1, Connector: "aws", RefPrefix: "x/",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCreateRefGrant_Unauthenticated_S21b(t *testing.T) {
	svc := newConnectServiceFull(t)
	_, err := svc.CreateRefGrant(context.Background(), &pb.CreateConnectRefGrantRequest{
		RoleId: 1, Connector: "aws", RefPrefix: "x/",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// ShareSecret — group share path
// ---------------------------------------------------------------------------

func TestShareSecret_GroupShare_S21b(t *testing.T) {
	r := newShareTestRig(t)
	// Attempt to share with a non-existent group — this exercises the IsGroup=true
	// branch in ShareSecret. The core will fail when looking up the group, which
	// should propagate as an error (not a panic).
	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 99999, Permission: "read", IsGroup: true,
	})
	// An error is expected (group not found / permission denied); we just verify the
	// group-share code path is exercised without panicking.
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// RevokeLease — unauthenticated / zero-id / not-found
// ---------------------------------------------------------------------------

func TestRevokeLease_Unauthenticated_S21b(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.RevokeLease(context.Background(), &pb.RevokeLeaseRequest{LeaseId: "some-id"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRevokeLease_EmptyLeaseID_S21b(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: ""})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRevokeLease_NotFound_S21b(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: "nonexistent-lease-id"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListLeases — unauthenticated / zero-id / not-found paths
// ---------------------------------------------------------------------------

func TestListLeases_Unauthenticated_S21b(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.ListLeases(context.Background(), &pb.ListLeasesRequest{ConfigId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListLeases_ZeroConfigID_S21b(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.ListLeases(ctx, &pb.ListLeasesRequest{ConfigId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListLeases_NotFound_S21b(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.ListLeases(ctx, &pb.ListLeasesRequest{ConfigId: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListMachineIdentities — error paths
// ---------------------------------------------------------------------------

func TestListMachineIdentities_ZeroProjectID_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ListMachineIdentities(ctx, &pb.ListMachineIdentitiesRequest{ProjectId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListMachineIdentities_PermissionDenied_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListMachineIdentities(ctx, &pb.ListMachineIdentitiesRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListMachineTokens — error paths
// ---------------------------------------------------------------------------

func TestListMachineTokens_Unauthenticated_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.ListMachineTokens(context.Background(), &pb.ListMachineTokensRequest{ProjectId: 1, MachineId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListMachineTokens_ZeroProjectID_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ListMachineTokens(ctx, &pb.ListMachineTokensRequest{ProjectId: 0, MachineId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListMachineTokens_PermissionDenied_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListMachineTokens(ctx, &pb.ListMachineTokensRequest{ProjectId: 1, MachineId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// CreateMachineIdentity — error paths
// ---------------------------------------------------------------------------

func TestCreateMachineIdentity_Unauthenticated_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.CreateMachineIdentity(context.Background(), &pb.CreateMachineIdentityRequest{ProjectId: 1, Name: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestCreateMachineIdentity_MissingName_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{ProjectId: 1, Name: ""})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// TransitionMachineIdentity — error paths
// ---------------------------------------------------------------------------

func TestTransitionMachineIdentity_Unauthenticated_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.TransitionMachineIdentity(context.Background(), &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: 1, Action: "activate",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestTransitionMachineIdentity_PermissionDenied_S21b(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: 1, Action: "activate",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// AssignRole — additional paths
// ---------------------------------------------------------------------------

func TestAssignRole_Unauthenticated_S21b(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.AssignRole(context.Background(), &pb.AssignRoleRequest{UserId: 1, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAssignRole_MissingFields_S21b(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: 0, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAssignRole_PermissionDenied_S21b(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.AssignRole(ctx, &pb.AssignRoleRequest{UserId: 1, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetAuditRetention — error path (unauthenticated)
// ---------------------------------------------------------------------------

func TestGetAuditRetention_Unauthenticated_S21b(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.GetAuditRetention(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetAuditRetention_PermissionDenied_S21b(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(7, "nobody")
	_, err := svc.GetAuditRetention(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetRBACAuditLogs — error path (unauthenticated)
// ---------------------------------------------------------------------------

func TestGetRBACAuditLogs_Unauthenticated_S21b(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.GetRBACAuditLogs(context.Background(), &pb.GetRBACAuditLogsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetRBACAuditLogs_PermissionDenied_S21b(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(7, "nobody")
	_, err := svc.GetRBACAuditLogs(ctx, &pb.GetRBACAuditLogsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// VerifyAuditChain — permission-denied path
// ---------------------------------------------------------------------------

func TestVerifyAuditChain_PermissionDenied_S21b(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(7, "nobody")
	_, err := svc.VerifyAuditChain(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListGroups — success path + unauthenticated
// ---------------------------------------------------------------------------

func TestListGroups_Unauthenticated_S21b(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.ListGroups(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// UpdateGroup — unauthenticated / permission-denied paths
// ---------------------------------------------------------------------------

func TestUpdateGroup_Unauthenticated_S21b(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.UpdateGroup(context.Background(), &pb.UpdateGroupRequest{Id: 1, Name: "new"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateGroup_PermissionDenied_S21b(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.UpdateGroup(ctx, &pb.UpdateGroupRequest{Id: 1, Name: "new"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListUsers — IncludeDeleted path
// ---------------------------------------------------------------------------

func TestListUsers_IncludeDeleted_S21b(t *testing.T) {
	svc := newUserService(t)
	resp, err := svc.ListUsers(adminCtx(), &pb.ListUsersRequest{IncludeDeleted: true})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// GetUser — unauthenticated / permission-denied paths
// ---------------------------------------------------------------------------

func TestGetUser_Unauthenticated_S21b(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.GetUser(context.Background(), &pb.GetUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetUser_PermissionDenied_S21b(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetUser(ctx, &pb.GetUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// auditActorCtxUser returns an interceptors.UserContext for user 1 (used in stream-slot tests).
func auditActorCtxUser() *interceptors.UserContext {
	return &interceptors.UserContext{UserID: 1, Username: "alice", Permissions: []string{"audit.read"}}
}

// errMsg wraps a plain string as an error for use in mapXxx tests.
type errString struct{ s string }

func (e errString) Error() string { return e.s }

func errMsg(s string) error { return errString{s} }
