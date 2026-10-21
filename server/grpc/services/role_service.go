package services

import (
	"context"
	"errors"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Role Name/Description length bounds. #1660: these now alias
// internal/core.RoleName{Min,Max}Len/RoleDescription{Min,Max}Len — the
// shared validation layer gRPC previously had none of (this comment used to
// say so, #191) — rather than independently duplicating the numbers. Kept as
// local names since the gRPC-side error messages ("name must be between %d
// and %d characters") predate and differ in wording from HTTP's validator-
// library message, and callers below reference these short names throughout.
const (
	roleNameMinLen        = core.RoleNameMinLen
	roleNameMaxLen        = core.RoleNameMaxLen
	roleDescriptionMinLen = core.RoleDescriptionMinLen
	roleDescriptionMaxLen = core.RoleDescriptionMaxLen
)

// RoleGRPCService implements pb.RoleServiceServer, backing each RPC with the
// shared core service (role CRUD + permission wiring via storage, reads via the
// core RBAC helpers).
type RoleGRPCService struct {
	pb.UnimplementedRoleServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.RoleServiceServer = (*RoleGRPCService)(nil)

// NewRoleService creates a role gRPC service backed by the shared core.
func NewRoleService(coreService *core.KeyorixCore) *RoleGRPCService {
	return &RoleGRPCService{core: coreService}
}

// CreateRole creates a role and assigns its permission set.
func (s *RoleGRPCService) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.Role, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesWrite); err != nil {
		return nil, err
	}
	if len(req.GetPermissions()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one permission is required")
	}
	if err := validateRoleName(req.GetName()); err != nil {
		return nil, err
	}
	if err := validateRoleDescription(req.GetDescription()); err != nil {
		return nil, err
	}
	permIDs, err := s.resolvePermissionIDs(ctx, actor.UserID, req.GetPermissions())
	if err != nil {
		return nil, err
	}

	// core.CreateRole is the single place that folds the name (identity.
	// NewFoldedName — #1642), rejects reserved built-in names (#294:
	// roleSetContainsAdmin in authz.go grants a full admin bypass by NAME
	// match alone, so a caller-created row named e.g. "super_admin" would
	// function as a complete admin-bypass switch the moment it's assigned,
	// even with zero permissions of its own), runs the role-row create AND
	// the permission bundling in one transaction, and audits only after that
	// transaction commits — see its own doc comment for why (this path
	// already propagated an AssignPermissionToRole failure correctly, unlike
	// the REST side, but still left the role row committed non-atomically
	// with its permission set).
	role, perms, err := s.core.CreateRole(ctx, actor.UserID, req.GetName(), req.GetDescription(), permIDs)
	if err != nil {
		return nil, mapRoleError(err)
	}
	// Build the response from the values core.CreateRole already returned
	// (read inside the same transaction that created the role) instead of
	// issuing a fresh post-commit GetRole: a fault on that extra read used to
	// report an ERROR for a role that had, in fact, already committed
	// (#2354, oracle (a) — same class as #1969/#1996).
	return roleToProto(role, perms), nil
}

// GetRole returns a role with its permissions.
func (s *RoleGRPCService) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesRead); err != nil {
		return nil, err
	}
	return s.roleByID(ctx, uint(req.GetId()))
}

// UpdateRole updates a role's description and/or replaces its permission set.
func (s *RoleGRPCService) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.Role, error) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesWrite); err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if req.Description != nil {
		if err := validateRoleDescription(req.GetDescription()); err != nil {
			return nil, err
		}
	}

	role, _, err := s.core.GetRoleWithPermissions(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapRoleError(err)
	}
	if req.Description != nil {
		role.Description = req.GetDescription()
	}

	// A provided non-empty permission list replaces the entire set (matches
	// this endpoint's pre-existing semantics: an empty/omitted list leaves
	// permissions untouched, there is no way to clear every permission via
	// this call).
	var newPermissionIDs *[]uint
	if len(req.GetPermissions()) > 0 {
		permIDs, err := s.resolvePermissionIDs(ctx, actor.UserID, req.GetPermissions())
		if err != nil {
			return nil, err
		}
		newPermissionIDs = &permIDs
	}

	// core.UpdateRole is the single place that rejects mutating a built-in
	// role, runs the role-row update AND the permission replacement in one
	// storage transaction, and audits only after that transaction commits —
	// see its own doc comment (docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md,
	// F3a/F3b) for why this must not be split back into two separately-
	// sequenced calls the way it used to be (this gRPC path used to interleave
	// its own RemovePermissionFromRole/AssignPermissionToRole loop after a bare
	// role-row UpdateRole call, the same non-atomic shape the REST handler had).
	updated, perms, err := s.core.UpdateRole(ctx, actor.UserID, role, newPermissionIDs)
	if err != nil {
		if perr, ok := partialMutationStatus(err); ok {
			return nil, perr
		}
		return nil, mapRoleError(err)
	}
	// Same fix as CreateRole above: build from the values UpdateRole already
	// returned (read inside its own transaction) instead of a fresh
	// post-commit GetRole.
	return roleToProto(updated, perms), nil
}

// DeleteRole deletes a role.
func (s *RoleGRPCService) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesWrite); err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := s.core.DeleteRole(ctx, actor.UserID, uint(req.GetId())); err != nil {
		return nil, mapRoleError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListRoles lists roles with their permissions, paginated in memory.
func (s *RoleGRPCService) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesRead); err != nil {
		return nil, err
	}

	all, err := s.core.ListRolesWithPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list roles")
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	total := len(all)
	start := min((page-1)*pageSize, total)
	end := min(start+pageSize, total)

	out := make([]*pb.Role, 0, end-start)
	for _, rwp := range all[start:end] {
		r := rwp.Role
		out = append(out, roleToProto(&r, rwp.Permissions))
	}
	return &pb.ListRolesResponse{
		Roles:      out,
		Total:      intToU32(total),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(total, pageSize)),
	}, nil
}

// AssignRole assigns a role to a user at an optional project/environment scope.
func (s *RoleGRPCService) AssignRole(ctx context.Context, req *pb.AssignRoleRequest) (*pb.RoleAssignment, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == 0 || req.GetRoleId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}
	// Authorize roles.assign AT THE TARGET scope, not the flat global union — else a
	// project-A admin could grant roles into any project B (cross-project privesc).
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if err := authorizeScoped(ctx, s.core, actor, "roles.assign", scope); err != nil {
		return nil, err
	}
	if actor.ActorKind() == core.ActorTypeMachine {
		// A genuine, directly-authenticated machine actor requesting this
		// grant as itself (not a /system proxy relay) -- tag ctx so
		// requireGranterHoldsRolePermissions checks ITS real permissions
		// instead of unconditionally refusing. See that function's doc.
		ctx = core.WithSelfMachineGranter(ctx, actor.PrincipalID())
	}
	if err := s.core.AssignUserRole(ctx, actor.UserID, uint(req.GetUserId()), uint(req.GetRoleId()), scope, actor.ActorKind() == core.ActorTypeMachine); err != nil {
		return nil, mapRoleError(err)
	}
	return &pb.RoleAssignment{
		UserId:        req.GetUserId(),
		RoleId:        req.GetRoleId(),
		ProjectId:     req.GetProjectId(),
		EnvironmentId: req.GetEnvironmentId(),
	}, nil
}

// RemoveRole removes a role assignment from a user.
func (s *RoleGRPCService) RemoveRole(ctx context.Context, req *pb.RemoveRoleRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == 0 || req.GetRoleId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}
	// Authorize roles.assign at the target scope (see AssignRole) — not the flat union.
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if err := authorizeScoped(ctx, s.core, actor, "roles.assign", scope); err != nil {
		return nil, err
	}
	if err := s.core.RemoveUserRole(ctx, actor.UserID, uint(req.GetUserId()), uint(req.GetRoleId()), scope); err != nil {
		return nil, mapRoleError(err)
	}
	return &emptypb.Empty{}, nil
}

// GetUserRoles returns all roles assigned to a user. Calls the identical
// core.GetUserRoleAssignment the HTTP sibling RBACHandler.GetUserRoles does
// (server/http/handlers/rbac.go), which is deliberately routed behind
// permRolesAssign, not permRolesRead (server/http/router.go: GET
// /roles/user/{userId}) — a stricter permission than the roles.read that gates
// the rest of the /roles route group, because this discloses an arbitrary
// user's full role assignment (including admin-tier roles), which is
// reconnaissance for a targeted privilege-escalation attempt. Match that gate
// here (G16).
func (s *RoleGRPCService) GetUserRoles(ctx context.Context, req *pb.GetUserRolesRequest) (*pb.GetUserRolesResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, permRolesAssign); err != nil {
		return nil, err
	}
	assignment, err := s.core.GetUserRoleAssignment(ctx, uint(req.GetUserId()))
	if err != nil {
		return nil, mapRoleError(err)
	}
	roles := make([]*pb.Role, 0, len(assignment.Roles))
	for _, r := range assignment.Roles {
		roles = append(roles, roleToProto(r, nil))
	}
	return &pb.GetUserRolesResponse{
		UserId:   intToU32(int(assignment.UserID)),
		Username: assignment.Username,
		Email:    assignment.Email,
		Roles:    roles,
	}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// roleByID fetches a role with its permissions and maps it to proto.
func (s *RoleGRPCService) roleByID(ctx context.Context, id uint) (*pb.Role, error) {
	role, perms, err := s.core.GetRoleWithPermissions(ctx, id)
	if err != nil {
		return nil, mapRoleError(err)
	}
	return roleToProto(role, perms), nil
}

// resolvePermissionIDs maps permission names to IDs, rejecting unknown names, and
// requires actorID already hold every named permission (#169: CreateRole/UpdateRole
// are gated only by the narrower permRolesWrite — without this, a roles.write holder
// could bundle an arbitrary admin-tier permission into a role's DEFINITION with no
// check they hold it themselves, mirroring the same check the HTTP handler applies).
// Checked at global scope, matching how roles.write itself is gated. Validating here
// — before the caller creates/mutates anything — means a request naming even one
// unauthorized permission is rejected atomically, not partially applied.
func (s *RoleGRPCService) resolvePermissionIDs(ctx context.Context, actorID uint, names []string) ([]uint, error) {
	perms, err := s.core.Storage().ListPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to resolve permissions")
	}
	byName := make(map[string]uint, len(perms))
	for _, p := range perms {
		byName[p.Name] = p.ID
	}
	ids := make([]uint, 0, len(names))
	for _, n := range names {
		id, ok := byName[n]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown permission %q", n)
		}
		authorized, aerr := s.core.Authorize(ctx, actorID, n, core.Scope{})
		if aerr != nil {
			return nil, status.Error(codes.Internal, "failed to resolve actor authority")
		}
		if !authorized {
			return nil, status.Errorf(codes.PermissionDenied, "cannot bundle permission %q into a role: you do not hold it yourself", n)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func roleToProto(r *models.Role, perms []*models.Permission) *pb.Role {
	out := &pb.Role{
		Id:          intToU32(int(r.ID)),
		Name:        r.Name,
		Description: r.Description,
	}
	for _, p := range perms {
		out.Permissions = append(out.Permissions, permissionToProto(p))
	}
	return out
}

func permissionToProto(p *models.Permission) *pb.Permission {
	return &pb.Permission{
		Id:          intToU32(int(p.ID)),
		Name:        p.Name,
		Description: p.Description,
		Resource:    p.Resource,
		Action:      p.Action,
	}
}

// validateRoleName mirrors HTTP's CreateRoleRequest.Name `min=3,max=50` bound
// (server/http/handlers/rbac.go) so a role name accepted over gRPC is never
// shorter/longer than one accepted over HTTP (#191).
func validateRoleName(name string) error {
	if len(name) < roleNameMinLen || len(name) > roleNameMaxLen {
		return status.Errorf(codes.InvalidArgument, "name must be between %d and %d characters", roleNameMinLen, roleNameMaxLen)
	}
	return nil
}

// validateRoleDescription mirrors HTTP's Role Description `min=1,max=200`
// bound (server/http/handlers/rbac.go) for the same reason (#191).
func validateRoleDescription(description string) error {
	if len(description) < roleDescriptionMinLen || len(description) > roleDescriptionMaxLen {
		return status.Errorf(codes.InvalidArgument, "description must be between %d and %d characters", roleDescriptionMinLen, roleDescriptionMaxLen)
	}
	return nil
}

// mapRoleError translates core/storage role errors into gRPC status codes.
func mapRoleError(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "role not found")
	case strings.Contains(msg, "reserved"):
		return status.Error(codes.AlreadyExists, "this role name is reserved and cannot be created")
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "duplicate"), strings.Contains(msg, "unique"):
		return status.Error(codes.AlreadyExists, "a role with that name already exists")
	// #1660/FIX-4 (restored 2026-09-03): core.CreateRole's own validation
	// (name fold rejects control/bidi characters, length bounds) surfaces
	// here now that the RPC routes through it instead of storage directly.
	// errors.Is against core.ErrRoleValidation confirms the failure is
	// application-generated (never a storage/driver error that merely
	// happens to mention the word "validation", e.g. a constraint named
	// *_validation_*) — restoring #1668's actual precision guarantee, lost
	// 22 hours later when #1669 reverted the classification back to the
	// bare substring match as a side effect of ALSO (correctly) fixing a
	// different problem: err.Error() here wraps identity.NewFoldedName's
	// raw-input echo (%q of the caller's own string) — safe content, but
	// not a "known safe sentinel with an already-fixed string" the
	// keyorix-raw-error-to-client Semgrep gate's nosemgrep exception
	// requires, so it is NOT echoed to the client; the fixed message #1669
	// introduced is kept. The two fixes are independent: restoring
	// PRECISION here does not require reintroducing the CI-blocking MESSAGE
	// #1669 was correct to remove.
	case errors.Is(err, core.ErrRoleValidation):
		return status.Error(codes.InvalidArgument, "invalid role name or description")
	case strings.Contains(msg, "built-in"):
		return status.Error(codes.FailedPrecondition, "cannot modify a built-in role")
	default:
		return status.Error(codes.Internal, "role operation failed")
	}
}
