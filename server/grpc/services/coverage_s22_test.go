package services

// coverage_s22_test.go — targeted tests to raise coverage on functions not
// exercised by any previous coverage sweep (s17, s17b, s18, s21, s21b).
//
// Targets:
//
//   break_glass_service.go:49  ListBreakGlassActivations (unauthenticated / permission-denied)
//   break_glass_service.go:69  RevokeBreakGlass          (unauthenticated / permission-denied)
//   break_glass_service.go:107 breakGlassError           (denied / expired / not-active branches)
//   project_service.go:32      mapProjectError            (already-exists / permission-denied branches)
//   project_service.go:85      GetProjectRotationOrder   (unauthenticated / permission-denied)
//   project_service.go:105     GetProjectRotationPlan    (unauthenticated / permission-denied)
//   project_service.go:170     DeleteProject             (unauthenticated / zero-id)
//   user_service.go:143        UpdateUser                (unauthenticated / zero-id / permission-denied)
//   user_service.go:168        DeleteUser                (unauthenticated / zero-id / permission-denied)
//   user_service.go:36         CreateUser                (both/setupLink+otp conflict / role-without-assign)
//   group_service.go:101       DeleteGroup               (unauthenticated / permission-denied)
//   group_service.go:115       RestoreGroup              (unauthenticated / permission-denied)
//   group_service.go:133       GetGroupMembers           (unauthenticated / permission-denied)
//   group_service.go:152       AddGroupMember            (unauthenticated / permission-denied)
//   group_service.go:166       RemoveGroupMember         (unauthenticated / permission-denied)
//   role_service.go:103        UpdateRole                (description-only update / zero-id / unauthenticated)
//   role_service.go:371        validateRoleName          (too-short / too-long)
//   role_service.go:381        validateRoleDescription   (empty / too-long)
//   role_service.go:274        GetUserRoles              (unauthenticated / permission-denied)
//   role_service.go:254        RemoveRole                (unauthenticated / zero-id / missing-fields)
//   connect_service.go:31      ListConnectors            (unauthenticated / permission-denied / success)
//   connect_service.go:74      ListRefGrants             (unauthenticated / permission-denied / success)
//   system_service.go:41       HealthCheck               (always succeeds)
//   system_service.go:51       GetSystemInfo             (with real config)
//   audit_service.go:110       GetAuditLogs              (unauthenticated / permission-denied / success)
//   audit_service.go:181       VerifyAuditChain          (unauthenticated / success)
//   conversions.go             optString / optUint / int32PtrToIntPtr / intPtrToInt32Ptr helpers

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ---------------------------------------------------------------------------
// breakGlassError — additional branches not hit by services_s2_test.go
// ---------------------------------------------------------------------------

func TestBreakGlassError_Denied_S22(t *testing.T) {
	err := breakGlassError(errBGDisabled)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestBreakGlassError_NotActive_S22(t *testing.T) {
	err := breakGlassError(errBGNotActive)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// #2905: an "expired" activation is not a distinct core refusal -- revoke
// accepts a TTL-lapsed row, and every state refusal is ErrBreakGlassNotActive --
// so the former "expired" text arm is the same FailedPrecondition sentinel.
func TestBreakGlassError_Expired_S22(t *testing.T) {
	err := breakGlassError(errBGNotActive)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestBreakGlassError_Required_S22(t *testing.T) {
	err := breakGlassError(errBGInvalidRequest)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestBreakGlassError_Invalid_S22(t *testing.T) {
	err := breakGlassError(errBGInvalidRequest)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListBreakGlassActivations — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestListBreakGlassActivations_Unauthenticated_S22(t *testing.T) {
	svc := newBreakGlassService(t)
	_, err := svc.ListBreakGlassActivations(context.Background(), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListBreakGlassActivations_PermissionDenied_S22(t *testing.T) {
	svc := newBreakGlassService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListBreakGlassActivations(ctx, &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// RevokeBreakGlass — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestRevokeBreakGlass_Unauthenticated_S22(t *testing.T) {
	svc := newBreakGlassService(t)
	_, err := svc.RevokeBreakGlass(context.Background(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRevokeBreakGlass_PermissionDenied_S22(t *testing.T) {
	svc := newBreakGlassService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RevokeBreakGlass(ctx, &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// mapProjectError — additional branches
// ---------------------------------------------------------------------------

func TestMapProjectError_AlreadyExists_S22(t *testing.T) {
	err := mapProjectError(errors.New("project with this name already exists"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestMapProjectError_PermissionDenied_S22(t *testing.T) {
	err := mapProjectError(errors.New("permission denied for this project"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapProjectError_Denied_S22(t *testing.T) {
	err := mapProjectError(errors.New("denied by policy"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapProjectError_NotFound_S22(t *testing.T) {
	err := mapProjectError(errors.New("project not found"))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestMapProjectError_Default_S22(t *testing.T) {
	err := mapProjectError(errors.New("unexpected storage failure"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetProjectRotationOrder — unauthenticated / permission-denied / zero-id
// ---------------------------------------------------------------------------

func TestGetProjectRotationOrder_Unauthenticated_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.GetProjectRotationOrder(context.Background(), &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetProjectRotationOrder_ZeroID_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProjectRotationOrder(ctx, &pb.GetProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetProjectRotationOrder_PermissionDenied_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetProjectRotationOrder(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetProjectRotationPlan — unauthenticated / permission-denied / zero-id
// ---------------------------------------------------------------------------

func TestGetProjectRotationPlan_Unauthenticated_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.GetProjectRotationPlan(context.Background(), &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetProjectRotationPlan_ZeroID_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProjectRotationPlan(ctx, &pb.GetProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetProjectRotationPlan_PermissionDenied_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetProjectRotationPlan(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteProject — unauthenticated / zero-id
// ---------------------------------------------------------------------------

func TestDeleteProject_Unauthenticated_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.DeleteProject(context.Background(), &pb.DeleteProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteProject_ZeroID_S22(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.DeleteProject(ctx, &pb.DeleteProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// UpdateUser — unauthenticated / zero-id / permission-denied
// ---------------------------------------------------------------------------

func TestUpdateUser_Unauthenticated_S22(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.UpdateUser(context.Background(), &pb.UpdateUserRequest{Id: 1, Username: strPtr("x")})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateUser_ZeroID_S22(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: 0, Username: strPtr("x")})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateUser_PermissionDenied_S22(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.UpdateUser(ctx, &pb.UpdateUserRequest{Id: 1, Username: strPtr("x")})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteUser — unauthenticated / zero-id / permission-denied
// ---------------------------------------------------------------------------

func TestDeleteUser_Unauthenticated_S22(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.DeleteUser(context.Background(), &pb.DeleteUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteUser_ZeroID_S22(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDeleteUser_PermissionDenied_S22(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteUser(ctx, &pb.DeleteUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// CreateUser — mutually-exclusive flag validation
// ---------------------------------------------------------------------------

func TestCreateUser_BothFlagsRejected_S22(t *testing.T) {
	// Both deliver_setup_link and generate_one_time_password set at once must be
	// rejected as InvalidArgument before touching any backend.
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:                "conflict_user",
		Email:                   "conflict@example.com",
		DeliverSetupLink:        true,
		GenerateOneTimePassword: true,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCreateUser_MissingUsernameOrEmail_S22(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "",
		Email:    "noname@example.com",
		Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCreateUser_PasswordRequired_S22(t *testing.T) {
	// No flags set and no password → InvalidArgument on the "password is required" branch.
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "nopw_user",
		Email:    "nopw@example.com",
		// Password deliberately omitted and neither otp nor setup-link set.
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteGroup — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestDeleteGroup_Unauthenticated_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.DeleteGroup(context.Background(), &pb.DeleteGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteGroup_PermissionDenied_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteGroup(ctx, &pb.DeleteGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// RestoreGroup — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestRestoreGroup_Unauthenticated_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.RestoreGroup(context.Background(), &pb.RestoreGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRestoreGroup_PermissionDenied_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RestoreGroup(ctx, &pb.RestoreGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetGroupMembers — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestGetGroupMembers_Unauthenticated_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.GetGroupMembers(context.Background(), &pb.GetGroupMembersRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetGroupMembers_PermissionDenied_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetGroupMembers(ctx, &pb.GetGroupMembersRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// AddGroupMember — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestAddGroupMember_Unauthenticated_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.AddGroupMember(context.Background(), &pb.GroupMemberRequest{GroupId: 1, UserId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAddGroupMember_PermissionDenied_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.AddGroupMember(ctx, &pb.GroupMemberRequest{GroupId: 1, UserId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// RemoveGroupMember — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestRemoveGroupMember_Unauthenticated_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.RemoveGroupMember(context.Background(), &pb.GroupMemberRequest{GroupId: 1, UserId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRemoveGroupMember_PermissionDenied_S22(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RemoveGroupMember(ctx, &pb.GroupMemberRequest{GroupId: 1, UserId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// validateRoleName — boundary conditions
// ---------------------------------------------------------------------------

func TestValidateRoleName_TooShort_S22(t *testing.T) {
	// roleNameMinLen is 3; a 2-char name must fail.
	err := validateRoleName("ab")
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestValidateRoleName_AtMinLength_S22(t *testing.T) {
	// Exactly at the minimum → valid.
	err := validateRoleName("abc")
	assert.NoError(t, err)
}

func TestValidateRoleName_TooLong_S22(t *testing.T) {
	// roleNameMaxLen is 50; a 51-char name must fail.
	longName := "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeef" // 51 chars
	require.Equal(t, 51, len(longName))
	err := validateRoleName(longName)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestValidateRoleName_AtMaxLength_S22(t *testing.T) {
	// Exactly at the maximum (50) → valid.
	maxName := "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeee" // 50 chars
	// Trim to exactly 50 to be safe.
	if len(maxName) > roleNameMaxLen {
		maxName = maxName[:roleNameMaxLen]
	}
	err := validateRoleName(maxName)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// validateRoleDescription — boundary conditions
// ---------------------------------------------------------------------------

func TestValidateRoleDescription_Empty_S22(t *testing.T) {
	// roleDescriptionMinLen is 1; empty string must fail.
	err := validateRoleDescription("")
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestValidateRoleDescription_TooLong_S22(t *testing.T) {
	// roleDescriptionMaxLen is 200; a 201-char description must fail.
	var longDesc string
	for range 201 {
		longDesc += "a"
	}
	err := validateRoleDescription(longDesc)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestValidateRoleDescription_Valid_S22(t *testing.T) {
	err := validateRoleDescription("a valid description")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// UpdateRole — description-only update / unauthenticated / zero-id
// ---------------------------------------------------------------------------

func TestUpdateRole_Unauthenticated_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	desc := "new desc"
	_, err := svc.UpdateRole(context.Background(), &pb.UpdateRoleRequest{Id: 1, Description: &desc})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateRole_ZeroID_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	desc := "some desc"
	_, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: 0, Description: &desc})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateRole_PermissionDenied_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	desc := "some desc"
	_, err := svc.UpdateRole(ctx, &pb.UpdateRoleRequest{Id: 1, Description: &desc})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestUpdateRole_DescriptionOnly exercises the description-update sub-path
// (req.Description != nil, len(req.GetPermissions()) == 0).
func TestUpdateRole_DescriptionOnly_S22(t *testing.T) {
	svc, h := newRoleService(t)
	perm := somePermission(t, h)

	// Create a fresh role to update.
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name:        "desc-test-role",
		Description: "original desc",
		Permissions: []string{perm},
	})
	require.NoError(t, err)

	// Update description only — permissions list is absent.
	newDesc := "updated desc"
	updated, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id:          created.GetId(),
		Description: &newDesc,
		// Permissions deliberately omitted.
	})
	require.NoError(t, err)
	assert.Equal(t, "updated desc", updated.GetDescription())
	// The original permissions must still be present.
	assert.NotEmpty(t, updated.GetPermissions())
}

// ---------------------------------------------------------------------------
// GetUserRoles — unauthenticated / permission-denied
// ---------------------------------------------------------------------------

func TestGetUserRoles_Unauthenticated_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.GetUserRoles(context.Background(), &pb.GetUserRolesRequest{UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetUserRoles_PermissionDenied_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetUserRoles(ctx, &pb.GetUserRolesRequest{UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// RemoveRole — unauthenticated / zero-id / missing-fields
// ---------------------------------------------------------------------------

func TestRemoveRole_Unauthenticated_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.RemoveRole(context.Background(), &pb.RemoveRoleRequest{UserId: 1, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRemoveRole_ZeroUserID_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: 0, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRemoveRole_ZeroRoleID_S22(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: 1, RoleId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListConnectors — unauthenticated / permission-denied / success
// ---------------------------------------------------------------------------

func TestListConnectors_Unauthenticated_S22(t *testing.T) {
	svc := newConnectServiceFull(t)
	_, err := svc.ListConnectors(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListConnectors_PermissionDenied_S22(t *testing.T) {
	svc := newConnectServiceFull(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListConnectors(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListConnectors_Success_S22(t *testing.T) {
	svc := newConnectServiceFull(t)
	resp, err := svc.ListConnectors(connAdminCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	// An empty manager produces an empty list — not an error.
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// ListRefGrants — unauthenticated / permission-denied / success
// ---------------------------------------------------------------------------

func TestListRefGrants_Unauthenticated_S22(t *testing.T) {
	svc := newConnectServiceFull(t)
	_, err := svc.ListRefGrants(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListRefGrants_PermissionDenied_S22(t *testing.T) {
	svc := newConnectServiceFull(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListRefGrants(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListRefGrants_Success_S22(t *testing.T) {
	svc := newConnectServiceFull(t)
	resp, err := svc.ListRefGrants(connAdminCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// HealthCheck — always succeeds (public endpoint)
// ---------------------------------------------------------------------------

func TestHealthCheck_S22(t *testing.T) {
	svc := newSystemService(t)
	resp, err := svc.HealthCheck(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.GetStatus())
	assert.NotEmpty(t, resp.GetVersion())
	assert.NotNil(t, resp.GetTimestamp())
}

// ---------------------------------------------------------------------------
// GetSystemInfo — with a real (non-nil) config
// ---------------------------------------------------------------------------

func TestGetSystemInfo_WithConfig_S22(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil)

	cfg := &config.Config{}
	cfg.Environment = "test"
	cfg.Storage.Type = "sqlite"
	cfg.Storage.Encryption.Enabled = true
	cfg.Server.HTTP.TLS.Enabled = false
	cfg.Server.GRPC.Enabled = true

	svc := NewSystemService(h.CoreService, cfg)
	info, err := svc.GetSystemInfo(sysCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "test", info.GetEnvironment())
	assert.NotNil(t, info.GetDatabase())
	assert.Equal(t, "sqlite", info.GetDatabase().GetType())
	assert.NotNil(t, info.GetEncryption())
	assert.Equal(t, "enabled", info.GetEncryption().GetStatus())
}

// ---------------------------------------------------------------------------
// GetAuditLogs — unauthenticated / permission-denied / success
// ---------------------------------------------------------------------------

func TestGetAuditLogs_Unauthenticated_S22(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.GetAuditLogs(context.Background(), &pb.GetAuditLogsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetAuditLogs_PermissionDenied_S22(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(7, "nobody")
	_, err := svc.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetAuditLogs_Success_S22(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "audit.read")
	resp, err := svc.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	// An empty DB yields an empty log, not an error.
	assert.GreaterOrEqual(t, resp.GetTotal(), uint32(0))
}

// TestGetAuditLogs_WithFilters exercises the optional filter fields so the
// optString / optUint / tsToTimePtr conversion helpers are exercised on a live call.
func TestGetAuditLogs_WithFilters_S22(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "audit.read")
	eventType := "secret.read"
	userID := uint32(1)
	resp, err := svc.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{
		EventType: &eventType,
		UserId:    &userID,
		Page:      1,
		PageSize:  10,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// VerifyAuditChain — unauthenticated / success
// ---------------------------------------------------------------------------

func TestVerifyAuditChain_Unauthenticated_S22(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.VerifyAuditChain(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestVerifyAuditChain_Success_S22(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "audit.read")
	resp, err := svc.VerifyAuditChain(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	// An empty chain is valid by definition.
	assert.True(t, resp.GetValid())
}

// ---------------------------------------------------------------------------
// GetAuditRetention — success path
// ---------------------------------------------------------------------------

func TestGetAuditRetention_Success_S22(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "audit.read")
	resp, err := svc.GetAuditRetention(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// Pure conversion helpers — optString / optUint / int32PtrToIntPtr / intPtrToInt32Ptr
// ---------------------------------------------------------------------------

func TestOptString_NilReturnsNil_S22(t *testing.T) {
	assert.Nil(t, optString(nil))
}

func TestOptString_EmptyStringReturnsNil_S22(t *testing.T) {
	s := ""
	assert.Nil(t, optString(&s))
}

func TestOptString_NonEmptyReturnsPointer_S22(t *testing.T) {
	s := "hello"
	got := optString(&s)
	require.NotNil(t, got)
	assert.Equal(t, "hello", *got)
}

func TestOptUint_NilReturnsNil_S22(t *testing.T) {
	assert.Nil(t, optUint(nil))
}

func TestOptUint_ZeroReturnsNil_S22(t *testing.T) {
	v := uint32(0)
	assert.Nil(t, optUint(&v))
}

func TestOptUint_NonZeroReturnsPointer_S22(t *testing.T) {
	v := uint32(42)
	got := optUint(&v)
	require.NotNil(t, got)
	assert.Equal(t, uint(42), *got)
}

func TestInt32PtrToIntPtr_Nil_S22(t *testing.T) {
	assert.Nil(t, int32PtrToIntPtr(nil))
}

func TestInt32PtrToIntPtr_Value_S22(t *testing.T) {
	v := int32(7)
	got := int32PtrToIntPtr(&v)
	require.NotNil(t, got)
	assert.Equal(t, 7, *got)
}

func TestIntPtrToInt32Ptr_Nil_S22(t *testing.T) {
	assert.Nil(t, intPtrToInt32Ptr(nil))
}

func TestIntPtrToInt32Ptr_Value_S22(t *testing.T) {
	v := 99
	got := intPtrToInt32Ptr(&v)
	require.NotNil(t, got)
	assert.Equal(t, int32(99), *got)
}
