package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"
)

// newProjectTestRig reuses the secret rig's seeded core (project 1 "default" +
// env 1 "development" + user 1 holding a global writer role with
// secrets.read/write/delete) and exposes a ProjectService over it.
func newProjectTestRig(t *testing.T) *ProjectGRPCService {
	t.Helper()
	r := newSecretTestRig(t)
	return NewProjectService(r.svc.core)
}

// newProjectTestRigWithDB also returns the rig's DB so a test can seed extra grants
// (e.g. roles.assign for the require_mfa policy gate).
func newProjectTestRigWithDB(t *testing.T) (*ProjectGRPCService, *gorm.DB) {
	t.Helper()
	r := newSecretTestRig(t)
	return NewProjectService(r.svc.core), r.db
}

func TestProjectService_CRUDAndList(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")

	// The seeded "default" project is listed.
	list, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(list.GetProjects()), 1)

	// Create → Get round-trip.
	created, err := svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: "billing", Description: "money"})
	require.NoError(t, err)
	assert.NotZero(t, created.GetId())
	assert.Equal(t, "billing", created.GetName())

	got, err := svc.GetProject(ctx, &pb.GetProjectRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "billing", got.GetName())

	// Update name/description on the writer's secrets.write gate (require_mfa is a
	// security-policy field with its own roles.assign gate, exercised separately).
	upd, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{
		Id: created.GetId(), Name: "billing-prod", Description: "money",
	})
	require.NoError(t, err)
	assert.Equal(t, "billing-prod", upd.GetName())

	// List environments of the seeded project.
	envs, err := svc.ListEnvironments(ctx, &pb.ListEnvironmentsRequest{ProjectId: 1})
	require.NoError(t, err)
	require.Len(t, envs.GetEnvironments(), 1)
	assert.Equal(t, "development", envs.GetEnvironments()[0].GetName())

	// Delete the created project.
	_, err = svc.DeleteProject(ctx, &pb.DeleteProjectRequest{Id: created.GetId()})
	require.NoError(t, err)
}

// Changing require_mfa (a per-project security control) requires roles.assign at the
// project — a plain secrets.write holder (the writer/editor persona) is refused, so a
// developer cannot silently disable the project's MFA enforcement.
func TestProjectService_UpdateRequireMFANeedsRolesAssign(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	ctx := authCtx(1, "owner") // user 1 = global writer (secrets.read/write/delete only)
	mfa := false

	// Writer (no roles.assign) → denied on the require_mfa toggle.
	_, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 1, Name: "default", RequireMfa: &mfa})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Grant the writer role roles.assign, and now the toggle is allowed.
	require.NoError(t, db.Create(&models.Permission{ID: 13, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 13}).Error)
	upd, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 1, Name: "default", RequireMfa: &mfa})
	require.NoError(t, err)
	assert.False(t, upd.GetRequireMfa())
}

func TestProjectService_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.ListProjects(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestProjectService_Unauthorized(t *testing.T) {
	svc := newProjectTestRig(t)
	// User 999 has no role grants → AuthorizePrincipal denies.
	ctx := authCtx(999, "nobody")
	_, err := svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.GetProject(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestProjectService_ListRotateOnSoftDeletedProject_GlobalGrantStillEmpty verifies
// the liveness check added to ListEnvironments / GetProjectRotationOrder /
// GetProjectRotationPlan. A caller who holds a GLOBAL (project_id=0) secrets.read
// grant passes authorizeScoped for ANY project regardless of that project's liveness
// — the deleted_at exclusion GetUserRoleIDsAt applies only to a grant whose OWN
// project_id matches the target scope, not to a project_id=0 grant, which is
// unconditional by design. Before this fix, ListEnvironmentsByProject /
// ListSecretDependenciesForProject / GenerateRotationPlan query raw project_id with
// no liveness check of their own, so such a caller got a quiet EMPTY success instead
// of NotFound for a soft-deleted project — the exact "structural gap" this fix closes
// (GetProject/UpdateProject already get NotFound for free via storage.GetProject).
func TestProjectService_ListRotateOnSoftDeletedProject_GlobalGrantStillEmpty(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)

	// Project 2: a second, later-deleted project. User 1 (the rig's seeded global
	// writer, ProjectID:0) never held a project-2-scoped grant — only the global one.
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "doomed"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "staging"}).Error)

	globalCtx := authCtx(1, "owner")

	// Sanity: before deletion, the global grant reads project 2 fine.
	envs, err := svc.ListEnvironments(globalCtx, &pb.ListEnvironmentsRequest{ProjectId: 2})
	require.NoError(t, err)
	require.Len(t, envs.GetEnvironments(), 1)

	// Soft-delete project 2 (its environment is cascaded into the same soft-delete).
	require.NoError(t, svc.core.DeleteProject(context.Background(), 0, 2, true))

	_, err = svc.ListEnvironments(globalCtx, &pb.ListEnvironmentsRequest{ProjectId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	_, err = svc.GetProjectRotationOrder(globalCtx, &pb.GetProjectRequest{Id: 2})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	_, err = svc.GetProjectRotationPlan(globalCtx, &pb.GetProjectRequest{Id: 2})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestProjectService_InvalidArgument(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProject(ctx, &pb.GetProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: ""})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
