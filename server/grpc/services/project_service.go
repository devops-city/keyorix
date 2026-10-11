package services

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// ProjectGRPCService implements pb.ProjectServiceServer, backing each RPC with the
// shared core service. It enforces the SAME permissions as the HTTP routes:
// list/get → secrets.read, create/update → secrets.write, delete → secrets.delete,
// scoped per project for per-project operations.
type ProjectGRPCService struct {
	pb.UnimplementedProjectServiceServer
	core *core.KeyorixCore
}

var _ pb.ProjectServiceServer = (*ProjectGRPCService)(nil)

// NewProjectService creates a project gRPC service backed by the shared core.
func NewProjectService(coreService *core.KeyorixCore) *ProjectGRPCService {
	return &ProjectGRPCService{core: coreService}
}

func mapProjectError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "project not found")
	case strings.Contains(msg, "already exists"):
		return status.Error(codes.AlreadyExists, "a project with this name already exists")
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		return status.Error(codes.Internal, "project operation failed")
	}
}

// ListProjects returns the projects the CALLER CAN READ, matching the HTTP route
// exactly (#2780).
//
// It used to require secrets.read at the GLOBAL scope and then return every
// project unfiltered, so a caller whose only grants are project-scoped got
// PermissionDenied here while being able to read those same projects one at a time
// through GetProject. That is the identical defect the HTTP route had, and the
// issue asked explicitly for both transports to get the same decision rather than
// a divergent one.
//
// Same narrowing as the HTTP handler: core.VisibleProjects authorizes each project
// at the project scope — the same check GetProject applies — so every project
// returned is one this caller could already fetch by id. A global reader's list is
// unchanged; a caller with no grants gets an empty list rather than
// PermissionDenied.
func (s *ProjectGRPCService) ListProjects(ctx context.Context, _ *emptypb.Empty) (*pb.ListProjectsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	// Not routed through authorizeScoped: that helper denies outright on a failed
	// check and also enforces the per-project MFA policy, neither of which fits a
	// cross-project listing (the old global gate enforced no per-project MFA either,
	// so this keeps parity with both transports' prior behaviour).
	vis, err := s.core.VisibleProjects(ctx, user.ActorKind(), user.PrincipalID(), permSecretsRead)
	if err != nil {
		return nil, status.Error(codes.Internal, "project operation failed")
	}
	projects, err := s.core.ListProjects(ctx)
	if err != nil {
		return nil, mapProjectError(err)
	}
	out := make([]*pb.Project, 0, len(projects))
	for _, p := range projects {
		if p == nil || !vis.Allows(p.ID) {
			continue
		}
		out = append(out, projectToProto(p))
	}
	return &pb.ListProjectsResponse{Projects: out}, nil
}

func (s *ProjectGRPCService) GetProject(ctx context.Context, req *pb.GetProjectRequest) (*pb.Project, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permSecretsRead, core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	project, err := s.core.GetProject(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	return projectToProto(project), nil
}

// GetProjectRotationOrder returns a safe rotation sequence for the project's secret
// dependency graph (ADR-052). Requires scoped secrets.read on the project.
func (s *ProjectGRPCService) GetProjectRotationOrder(ctx context.Context, req *pb.GetProjectRequest) (*pb.RotationOrder, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permSecretsRead, core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	// authorizeScoped only checks the caller's role binding, not whether the project
	// itself is still live: UserRole/GroupRole rows scoped to a project are deliberately
	// left in place across a soft-delete (to support RestoreProject), so a caller who
	// held a scoped grant before the project was deleted would otherwise keep passing
	// this check indefinitely. Confirm the project is live before proceeding, mirroring
	// the CreateProjectEnvironment precedent (catalog.go).
	if _, err := s.core.GetProject(ctx, uint(req.GetId())); err != nil {
		return nil, mapProjectError(err)
	}
	order, err := s.core.GetProjectRotationOrder(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	return rotationOrderToProto(order), nil
}

// GetProjectRotationPlan returns the project's automated rotation plan (ADR-053).
// Requires scoped secrets.read on the project.
func (s *ProjectGRPCService) GetProjectRotationPlan(ctx context.Context, req *pb.GetProjectRequest) (*pb.RotationPlan, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permSecretsRead, core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	// See GetProjectRotationOrder above: a scoped role binding survives project
	// soft-delete, so confirm the project is still live before proceeding.
	if _, err := s.core.GetProject(ctx, uint(req.GetId())); err != nil {
		return nil, mapProjectError(err)
	}
	plan, err := s.core.GenerateRotationPlan(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	return rotationPlanToProto(plan), nil
}

// GetDeploymentRotationPlan returns the install-wide rotation plan (ADR-053).
func (s *ProjectGRPCService) GetDeploymentRotationPlan(ctx context.Context, _ *emptypb.Empty) (*pb.DeploymentRotationPlan, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, user, permSecretsRead); err != nil {
		return nil, err
	}
	plan, err := s.core.GenerateDeploymentRotationPlan(ctx)
	if err != nil {
		return nil, mapProjectError(err)
	}
	// #G17: the response aggregates every project's own rotation plan; a
	// project that individually requires MFA must not be readable via this
	// global-scope roll-up by a session that lacks it.
	projectIDs := make([]uint, 0, len(plan.Projects))
	for _, p := range plan.Projects {
		projectIDs = append(projectIDs, p.ProjectID)
	}
	if err := enforceProjectMFAForProjects(ctx, s.core, user, projectIDs); err != nil {
		return nil, err
	}
	return deploymentRotationPlanToProto(plan), nil
}

func (s *ProjectGRPCService) CreateProject(ctx context.Context, req *pb.CreateProjectRequest) (*pb.Project, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := authorizeGlobal(ctx, s.core, user, "secrets.write"); err != nil {
		return nil, err
	}
	project, err := s.core.CreateProject(ctx, req.GetName(), req.GetDescription())
	if err != nil {
		return nil, mapProjectError(err)
	}
	s.core.LogProjectCreated(ctx, user.UserID, project.ID, project.Name)
	return projectToProto(project), nil
}

func (s *ProjectGRPCService) UpdateProject(ctx context.Context, req *pb.UpdateProjectRequest) (*pb.Project, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.write", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	var requireMFA *bool
	if req.RequireMfa != nil {
		v := req.GetRequireMfa()
		requireMFA = &v
		// require_mfa is a per-project security-policy control: changing it additionally
		// requires roles.assign at the project (parity with the HTTP handler), so a
		// non-admin secrets.write holder can't silently disable MFA enforcement.
		if err := authorizeScoped(ctx, s.core, user, "roles.assign", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
			return nil, err
		}
	}
	project, err := s.core.UpdateProject(ctx, uint(req.GetId()), req.GetName(), req.GetDescription(), requireMFA)
	if err != nil {
		return nil, mapProjectError(err)
	}
	s.core.LogProjectUpdated(ctx, user.UserID, project.ID, project.Name)
	return projectToProto(project), nil
}

func (s *ProjectGRPCService) DeleteProject(ctx context.Context, req *pb.DeleteProjectRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.delete", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	force := req.GetForce()
	projectName := ""
	if p, gerr := s.core.GetProject(ctx, uint(req.GetId())); gerr == nil && p != nil {
		projectName = p.Name
	}
	if err := s.core.DeleteProject(ctx, uint(req.GetId()), force); err != nil {
		return nil, mapProjectError(err)
	}
	s.core.LogProjectDeleted(ctx, user.UserID, uint(req.GetId()), projectName, force)
	return &emptypb.Empty{}, nil
}

func (s *ProjectGRPCService) ListEnvironments(ctx context.Context, req *pb.ListEnvironmentsRequest) (*pb.ListEnvironmentsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, permSecretsRead, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	// See GetProjectRotationOrder above: a scoped role binding survives project
	// soft-delete, so confirm the project is still live before proceeding.
	if _, err := s.core.GetProject(ctx, uint(req.GetProjectId())); err != nil {
		return nil, mapProjectError(err)
	}
	envs, err := s.core.ListEnvironmentsByProject(ctx, uint(req.GetProjectId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	out := make([]*pb.Environment, 0, len(envs))
	for _, e := range envs {
		out = append(out, environmentToProto(e))
	}
	return &pb.ListEnvironmentsResponse{Environments: out}, nil
}
