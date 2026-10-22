package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestRoleService_AssignRole_ProjectRoleWithoutProjectIsInvalidArgument
// (#3546): the gRPC transport of the user grant refuses a project-tier role
// at the global scope with InvalidArgument (not Internal) and writes nothing;
// with a project_id the same grant succeeds at that project.
func TestRoleService_AssignRole_ProjectRoleWithoutProjectIsInvalidArgument(t *testing.T) {
	svc, h := newRoleService(t)
	ctx := context.Background()
	user := h.CreateTestUser(t, "scope-assignee", 501)
	name, err := identity.NewFoldedName("project_developer")
	require.NoError(t, err)
	role, err := h.CoreService.Storage().CreateRole(ctx, name, "ADR-021 project role")
	require.NoError(t, err)

	_, err = svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: intToU32(int(user.ID)), RoleId: intToU32(int(role.ID))})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "got %v", err)
	require.Contains(t, status.Convert(err).Message(), "role project_developer is project-scoped")
	var rows []models.UserRole
	require.NoError(t, h.DB.Where("user_id = ? AND role_id = ?", user.ID, role.ID).Find(&rows).Error)
	require.Empty(t, rows, "a refused grant must write no row")

	project := uint32(2)
	_, err = svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: intToU32(int(user.ID)), RoleId: intToU32(int(role.ID)), ProjectId: &project})
	require.NoError(t, err)
	require.NoError(t, h.DB.Where("user_id = ? AND role_id = ?", user.ID, role.ID).Find(&rows).Error)
	require.Len(t, rows, 1)
	require.EqualValues(t, 2, rows[0].ProjectID)
}
