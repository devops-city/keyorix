package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// UserGRPCService implements pb.UserServiceServer, backing each RPC with the
// shared core service.
type UserGRPCService struct {
	pb.UnimplementedUserServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.UserServiceServer = (*UserGRPCService)(nil)

// NewUserService creates a user gRPC service backed by the shared core.
func NewUserService(coreService *core.KeyorixCore) *UserGRPCService {
	return &UserGRPCService{core: coreService}
}

// CreateUser provisions a user via one of three credential modes: a password,
// an out-of-band setup link, or a one-time password. A system role + project
// assignments may be supplied with the password mode (the atomic ADR-028 path).
func (s *UserGRPCService) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.write"); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" || req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "username and email are required")
	}

	setupLink := req.GetDeliverSetupLink()
	otp := req.GetGenerateOneTimePassword()
	if setupLink && otp {
		return nil, status.Error(codes.InvalidArgument, "choose at most one of deliver_setup_link or generate_one_time_password")
	}
	role := req.GetRole()
	assignments := toProjectAssignments(req.GetProjectAssignments())
	if (setupLink || otp) && (role != "" || len(assignments) > 0) {
		return nil, status.Error(codes.InvalidArgument, "role and project_assignments are only supported with password-based creation")
	}

	// Atomic provisioning must not let the caller hand out access they could not
	// assign directly: a system-role override requires roles.assign at global
	// scope, and each project assignment requires roles.assign at that project's
	// scope. This mirrors the HTTP CreateUser guard (handlers/users_crud.go) so
	// the cross-project privilege-escalation gate is not bypassable by switching
	// transport — a users.write holder without roles.assign cannot mint an admin
	// account over gRPC. A global admin satisfies both via admin-bypass.
	if role != "" {
		if err := authorizeScoped(ctx, s.core, actor, "roles.assign", core.Scope{}); err != nil {
			return nil, err
		}
	}
	for _, a := range assignments {
		if err := authorizeScoped(ctx, s.core, actor, "roles.assign", core.Scope{ProjectID: a.ProjectID}); err != nil {
			return nil, err
		}
	}

	displayName := req.GetDisplayName()
	if displayName == "" {
		displayName = req.GetUsername()
	}
	// AccountState is deliberately NOT taken from the client (mirrors the HTTP
	// CreateUser handler, which has no account_state field in its request body at
	// all): the field is a server-derived lifecycle state, not something a caller —
	// however privileged — should self-set at creation time. The proto still
	// declares account_state for wire compatibility, but its value is ignored here
	// so a caller cannot mint a new account already in, e.g., "active" bypassing the
	// setup-link/one-time-password flows below, which set it themselves
	// (pending_first_login / password_reset_required) when applicable.
	coreReq := &core.CreateUserRequest{
		Username:    req.GetUsername(),
		Email:       req.GetEmail(),
		DisplayName: displayName,
		Password:    req.GetPassword(),
		IsActive:    req.IsActive,
	}

	resp := &pb.CreateUserResponse{}
	var u *models.User
	switch {
	case setupLink:
		var prov *core.ProvisionSetupResult
		u, prov, err = s.core.CreateUserWithSetupLink(ctx, coreReq, actor.UserID)
		if err == nil && prov != nil {
			resp.SetupLink = optStringValue(prov.LinkForAdmin)
		}
	case otp:
		var res *core.OneTimePasswordResult
		u, res, err = s.core.CreateUserWithOneTimePassword(ctx, coreReq, actor.UserID)
		if err == nil && res != nil {
			resp.OneTimePassword = optStringValue(res.OTPValue)
			resp.OneTimePasswordExpiresAt = optStringValue(res.ExpiresAt.UTC().Format(time.RFC3339))
		}
	default:
		if req.GetPassword() == "" {
			return nil, status.Error(codes.InvalidArgument, "password is required unless deliver_setup_link or generate_one_time_password is set")
		}
		grantCtx := ctx
		if actor.ActorKind() == core.ActorTypeMachine {
			// A genuine, directly-authenticated machine actor requesting this
			// grant as itself (not a /system proxy relay) -- tag ctx so
			// requireGranterHoldsRolePermissions checks ITS real permissions
			// instead of unconditionally refusing. See that function's doc.
			grantCtx = core.WithSelfMachineGranter(ctx, actor.PrincipalID())
		}
		u, err = s.core.CreateUserWithAssignments(grantCtx, coreReq, role, assignments, actor.UserID, actor.ActorKind() == core.ActorTypeMachine)
	}
	if err != nil {
		return nil, mapUserError(err)
	}

	resp.User = s.userToProto(ctx, u)
	return resp, nil
}

// GetUser returns a user by ID.
func (s *UserGRPCService) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.read"); err != nil {
		return nil, err
	}
	u, err := s.core.GetUser(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapUserError(err)
	}
	return s.userToProto(ctx, u), nil
}

// UpdateUser updates a user's mutable fields.
func (s *UserGRPCService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.User, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.write"); err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	u, err := s.core.UpdateUser(ctx, &core.UpdateUserRequest{
		ID:          uint(req.GetId()),
		ActorID:     actor.UserID,
		Username:    req.GetUsername(),
		Email:       req.GetEmail(),
		DisplayName: req.GetDisplayName(),
		IsActive:    req.Active,
	})
	if err != nil {
		return nil, mapUserError(err)
	}
	return s.userToProto(ctx, u), nil
}

// DeleteUser soft-deletes a user.
func (s *UserGRPCService) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.delete"); err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := s.core.DeleteUser(ctx, actor.UserID, uint(req.GetId())); err != nil {
		return nil, mapUserError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListUsers lists users with filtering and pagination.
func (s *UserGRPCService) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "users.read"); err != nil {
		return nil, err
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())

	filter := &corestorage.UserFilter{
		Search:         optString(req.Search),
		IsActive:       req.IsActive,
		IncludeDeleted: req.GetIncludeDeleted(),
		Page:           page,
		PageSize:       pageSize,
	}
	// "inactive" surfaces accounts with no login in the last 30 days.
	if req.GetFilter() == "inactive" {
		cutoff := time.Now().AddDate(0, 0, -30)
		filter.InactiveSince = &cutoff
	}

	users, total, err := s.core.ListUsers(ctx, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list users")
	}

	ids := make([]uint, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	counts := s.projectCounts(ctx, ids)

	out := make([]*pb.User, 0, len(users))
	for _, u := range users {
		out = append(out, userToProtoWithCounts(u, counts[u.ID]))
	}
	return &pb.ListUsersResponse{
		Users:      out,
		Total:      i64ToU32(total),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(int(total), pageSize)),
	}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// userToProto maps a user and resolves its project-membership counts.
func (s *UserGRPCService) userToProto(ctx context.Context, u *models.User) *pb.User {
	counts := s.projectCounts(ctx, []uint{u.ID})
	return userToProtoWithCounts(u, counts[u.ID])
}

func userToProtoWithCounts(u *models.User, c corestorage.MembershipCounts) *pb.User {
	return &pb.User{
		Id:                 intToU32(int(u.ID)),
		Username:           u.Username,
		Email:              u.Email,
		DisplayName:        u.DisplayName,
		Active:             u.IsActive,
		AccountState:       u.AccountState,
		LastLoginAt:        timePtrToTs(u.LastLoginAt),
		CreatedAt:          timestamppb.New(u.CreatedAt),
		UpdatedAt:          timestamppb.New(u.UpdatedAt),
		ProjectCount:       intToU32(c.Total),
		ActiveProjectCount: intToU32(c.Active),
	}
}

// projectCounts is best-effort: on a returned error OR a panic, the counts
// are absent (zero) rather than letting either take down the whole RPC.
// Every caller of userToProto (CreateUser, UpdateUser, GetUser, ListUsers)
// reaches this AFTER its own primary write (if any) already committed --
// same "a best-effort response-enrichment failure must not report an
// already-successful operation as failed" shape as internal/core/service.go's
// emitAudit, and the same panic-masking-a-commit family as this campaign's
// other findings (docs/findings/2026-10-02-FINDING-grpc-createuser-usertoproto-projectcounts-panic-masks-commit.md):
// the returned-error case was already handled; a panic from the identical
// call had no protection at all.
func (s *UserGRPCService) projectCounts(ctx context.Context, ids []uint) map[uint]corestorage.MembershipCounts {
	if len(ids) == 0 {
		return nil
	}
	var counts map[uint]corestorage.MembershipCounts
	besteffort.Run(ctx, "grpc.UserGRPCService.projectCounts", func() error {
		c, err := s.core.ProjectMembershipCounts(ctx, ids)
		if err != nil {
			return err
		}
		counts = c
		return nil
	})
	return counts
}

func toProjectAssignments(in []*pb.ProjectAssignment) []core.ProjectAssignment {
	if len(in) == 0 {
		return nil
	}
	out := make([]core.ProjectAssignment, 0, len(in))
	for _, a := range in {
		out = append(out, core.ProjectAssignment{ProjectID: uint(a.GetProjectId()), Role: a.GetRole()})
	}
	return out
}

func optStringValue(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// mapUserError translates core user errors into gRPC status codes.
func mapUserError(err error) error {
	// S1 (CLI-split inventory #2012): checked via errors.Is, not the substring
	// switch below, so the specific permission name requireEqualOrGreaterAdminAuthority
	// wraps into the error text never reaches this function's substring matching
	// (and, via the generic messages below, never reaches the client either).
	if errors.Is(err, core.ErrInsufficientAdminAuthority) {
		return status.Error(codes.PermissionDenied, "insufficient privileges to modify this user")
	}
	if errors.Is(err, core.ErrCannotActOnSelf) {
		return status.Error(codes.FailedPrecondition, "cannot perform this action on your own account")
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "user not found")
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "duplicate"):
		return status.Error(codes.AlreadyExists, "a user with that username or email already exists")
	case strings.Contains(msg, "cannot grant this role"):
		return status.Error(codes.PermissionDenied, "insufficient privileges to assign this role") // GRPC-003: was err.Error() — leaked internal role name
	case strings.Contains(msg, "validation"), strings.Contains(msg, "required"), strings.Contains(msg, "invalid"), strings.Contains(msg, "must be"):
		return status.Error(codes.InvalidArgument, "invalid request parameters") // GRPC-003: was err.Error() — leaked password policy thresholds
	default:
		return status.Error(codes.Internal, "user operation failed")
	}
}
