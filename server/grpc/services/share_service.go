package services

import (
	"context"
	"log"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ShareGRPCService implements pb.ShareServiceServer, backing each RPC with the
// shared core service. Identity is established by the auth interceptor and read
// from the context.
type ShareGRPCService struct {
	pb.UnimplementedShareServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.ShareServiceServer = (*ShareGRPCService)(nil)

// NewShareService creates a share gRPC service backed by the shared core.
func NewShareService(coreService *core.KeyorixCore) *ShareGRPCService {
	return &ShareGRPCService{core: coreService}
}

// ShareSecret shares a secret with another user or group.
func (s *ShareGRPCService) ShareSecret(ctx context.Context, req *pb.ShareSecretRequest) (*pb.ShareRecord, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 || req.GetRecipientId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret_id and recipient_id are required")
	}
	if req.GetPermission() != "read" && req.GetPermission() != "write" {
		return nil, status.Error(codes.InvalidArgument, "permission must be 'read' or 'write'")
	}
	// Scope secrets.write to the shared secret's project (mirrors the HTTP
	// /secrets/{id}/share route), not the flat global permission set.
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsWrite, core.SecretActionShare); err != nil {
		return nil, err
	}

	var record *models.ShareRecord
	if req.GetIsGroup() {
		record, err = s.core.ShareSecretWithGroup(ctx, &core.GroupShareSecretRequest{
			SecretID:   uint(req.GetSecretId()),
			GroupID:    uint(req.GetRecipientId()),
			Permission: req.GetPermission(),
			SharedBy:   user.UserID,
			ExpiresAt:  tsToTimePtr(req.GetExpiresAt()),
		})
	} else {
		record, err = s.core.ShareSecret(ctx, &core.ShareSecretRequest{
			SecretID:    uint(req.GetSecretId()),
			RecipientID: uint(req.GetRecipientId()),
			IsGroup:     false,
			Permission:  req.GetPermission(),
			SharedBy:    user.UserID,
			ExpiresAt:   tsToTimePtr(req.GetExpiresAt()),
		})
	}
	if err != nil {
		return nil, mapShareError(err)
	}
	return shareRecordToProto(record), nil
}

// ListSecretShares lists all shares for a secret.
func (s *ShareGRPCService) ListSecretShares(ctx context.Context, req *pb.ListSecretSharesRequest) (*pb.ListSharesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsRead); err != nil {
		return nil, err
	}

	shares, err := s.core.ListSecretSharesWithPermissionCheck(ctx, uint(req.GetSecretId()), user.UserID)
	if err != nil {
		return nil, mapShareError(err)
	}
	return sharesToResponse(shares, 1, len(shares)), nil
}

// ListUserShares lists shares created by the calling user.
func (s *ShareGRPCService) ListUserShares(ctx context.Context, req *pb.ListUserSharesRequest) (*pb.ListSharesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	// Authorize through the scope/actor-aware primitive (global secrets.read), matching
	// the HTTP GET /shares gate. A flat hasPermission check ignored a PAT's scope
	// restriction, so a project-scoped (or non-read) token could list shares over gRPC
	// while HTTP correctly denied it — the #53/#54-class transport divergence, also the
	// IP-allowlist divergence ADR-066 closed.
	if err := authorizeGlobal(ctx, s.core, user, permSecretsRead); err != nil {
		return nil, err
	}

	shares, err := s.core.ListSharesByUser(ctx, user.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list user shares")
	}
	// #G17: ShareRecord only carries SecretID, so resolve each share's owning
	// project in one batched lookup before applying the same aggregate MFA
	// check GetDeploymentRotationPlan/ListSharedSecrets use — see
	// enforceProjectMFAForProjects's doc comment for why this global-scope
	// endpoint needs it despite authorizeGlobal's scope.ProjectID being 0.
	if err := enforceProjectMFAForProjects(ctx, s.core, user, s.shareProjectIDs(ctx, shares)); err != nil {
		return nil, err
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	return sharesToResponse(shares, page, pageSize), nil
}

// shareProjectIDs resolves the distinct projects the given shares' secrets
// belong to, via one batched GetSecretsByIDs lookup. A resolution failure is
// logged and treated as an empty set — enforceProjectMFAForProjects then has
// nothing to check, which is safe here because ListSharesByUser only returns
// shares the caller is independently entitled to see; the risk this closes is
// an MFA-required project's data leaking through the aggregate view, not raw
// existence, so skipping the extra step-up check on a transient lookup error
// degrades to the pre-fix behavior rather than blocking the endpoint outright.
func (s *ShareGRPCService) shareProjectIDs(ctx context.Context, shares []*models.ShareRecord) []uint {
	if len(shares) == 0 {
		return nil
	}
	secretIDSet := make(map[uint]bool, len(shares))
	secretIDs := make([]uint, 0, len(shares))
	for _, sh := range shares {
		if !secretIDSet[sh.SecretID] {
			secretIDSet[sh.SecretID] = true
			secretIDs = append(secretIDs, sh.SecretID)
		}
	}
	secrets, err := s.core.Storage().GetSecretsByIDs(ctx, secretIDs)
	if err != nil {
		log.Printf("shareProjectIDs: failed to resolve project ids for MFA check: %v", err)
		return nil
	}
	projectIDs := make([]uint, 0, len(secrets))
	for _, sec := range secrets {
		projectIDs = append(projectIDs, sec.ProjectID)
	}
	return projectIDs
}

// ListSharedSecrets lists secrets shared with the calling user.
func (s *ShareGRPCService) ListSharedSecrets(ctx context.Context, req *pb.ListSharedSecretsRequest) (*pb.ListSecretsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	// Authorize through the scope/actor-aware primitive (global secrets.read), matching
	// the HTTP GET /shared-secrets gate — a flat check let a PAT exceed its scope
	// restriction over gRPC (transport divergence; see ListUserShares).
	if err := authorizeGlobal(ctx, s.core, user, permSecretsRead); err != nil {
		return nil, err
	}

	secrets, err := s.core.ListSharedSecrets(ctx, user.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list shared secrets")
	}
	// #G17: each SecretNode already carries its own ProjectID — no extra lookup
	// needed, unlike ListUserShares' ShareRecord-based path above.
	projectIDs := make([]uint, 0, len(secrets))
	for _, sec := range secrets {
		projectIDs = append(projectIDs, sec.ProjectID)
	}
	if err := enforceProjectMFAForProjects(ctx, s.core, user, projectIDs); err != nil {
		return nil, err
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	out := make([]*pb.Secret, 0, len(secrets))
	for _, sec := range secrets {
		out = append(out, secretNodeToProto(sec))
	}
	return &pb.ListSecretsResponse{
		Secrets:     out,
		Total:       intToU32(len(out)),
		Page:        intToU32(page),
		PageSize:    intToU32(pageSize),
		TotalPages:  intToU32(totalPages(len(out), pageSize)),
		SharedCount: intToU32(len(out)),
	}, nil
}

// UpdateSharePermission changes the permission level of an existing share.
func (s *ShareGRPCService) UpdateSharePermission(ctx context.Context, req *pb.UpdateSharePermissionRequest) (*pb.ShareRecord, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetShareId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "share_id is required")
	}
	if req.GetPermission() != "read" && req.GetPermission() != "write" {
		return nil, status.Error(codes.InvalidArgument, "permission must be 'read' or 'write'")
	}
	if err := s.authorizeShareScoped(ctx, user, uint(req.GetShareId()), permSecretsWrite); err != nil {
		return nil, err
	}

	record, err := s.core.UpdateSharePermission(ctx, &core.UpdateShareRequest{
		ShareID:     uint(req.GetShareId()),
		Permission:  req.GetPermission(),
		UpdatedBy:   user.UserID,
		ExpiresAt:   tsToTimePtr(req.GetExpiresAt()),
		ClearExpiry: req.GetClearExpiry(),
	})
	if err != nil {
		return nil, mapShareError(err)
	}
	return shareRecordToProto(record), nil
}

// RevokeShare revokes a share.
func (s *ShareGRPCService) RevokeShare(ctx context.Context, req *pb.RevokeShareRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetShareId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "share_id is required")
	}
	if err := s.authorizeShareScoped(ctx, user, uint(req.GetShareId()), permSecretsWrite); err != nil {
		return nil, err
	}
	if err := s.core.RevokeShare(ctx, uint(req.GetShareId()), user.UserID); err != nil {
		return nil, mapShareError(err)
	}
	return &emptypb.Empty{}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// authorizeShareScoped resolves a share's underlying secret and checks the
// permission at that secret's project/environment — mirroring HTTP's
// ScopeFromShareParam, so mutating a specific share enforces the same scoped
// RBAC as HTTP rather than the flat global set. A missing share/secret yields
// NotFound; the downstream core call still enforces ownership.
func (s *ShareGRPCService) authorizeShareScoped(ctx context.Context, actor *interceptors.UserContext, shareID uint, perm string) error {
	share, err := s.core.Storage().GetShareRecord(ctx, shareID)
	if err != nil {
		return status.Error(codes.NotFound, "share not found")
	}
	secret, err := s.core.Storage().GetSecret(ctx, share.SecretID)
	if err != nil {
		return status.Error(codes.NotFound, "share not found")
	}
	scope := core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	if allowed, err := s.core.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions for this share")
	}
	return enforceProjectMFA(ctx, s.core, actor, scope.ProjectID)
}

// mapShareError translates core sharing errors into gRPC status codes.
func mapShareError(err error) error {
	// #2976: a typed share refusal carries a fixed, user-facing reason (owner not a
	// project member, recipient not a member, ...) — the same text HTTP returns.
	if reason, ok := core.ShareRefusalMessage(err); ok {
		return status.Error(codes.PermissionDenied, reason)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "share or secret not found")
	case strings.Contains(msg, "not authorized"), strings.Contains(msg, "permission denied"):
		return status.Error(codes.PermissionDenied, "not authorized for this share")
	case strings.Contains(msg, "expiry must be in the future"):
		// Matches REST's 400 ValidationError for the identical core error
		// (shares_crud.go) — otherwise this fell into the default Internal bucket,
		// a transport-dependent error-class divergence for a plain validation
		// failure. NOTE: core's other expiry error, "cannot update an expired
		// share record" (UpdateSharePermission on an already-expired share), is
		// deliberately left in the default Internal bucket below — REST's own
		// handler (shares_crud.go) does not special-case that message either, so
		// mapping it to InvalidArgument here would create a NEW REST/gRPC
		// divergence rather than close one.
		return status.Error(codes.InvalidArgument, "share expiry must be in the future")
	default:
		return status.Error(codes.Internal, "share operation failed")
	}
}

func shareRecordToProto(r *models.ShareRecord) *pb.ShareRecord {
	return &pb.ShareRecord{
		Id:          intToU32(int(r.ID)),
		SecretId:    intToU32(int(r.SecretID)),
		OwnerId:     intToU32(int(r.OwnerID)),
		RecipientId: intToU32(int(r.RecipientID)),
		IsGroup:     r.IsGroup,
		Permission:  r.Permission,
		CreatedAt:   timestamppb.New(r.CreatedAt),
		UpdatedAt:   timestamppb.New(r.UpdatedAt),
		ExpiresAt:   timePtrToTs(r.ExpiresAt),
	}
}

func sharesToResponse(shares []*models.ShareRecord, page, pageSize int) *pb.ListSharesResponse {
	out := make([]*pb.ShareRecord, 0, len(shares))
	for _, sh := range shares {
		out = append(out, shareRecordToProto(sh))
	}
	return &pb.ListSharesResponse{
		Shares:     out,
		Total:      intToU32(len(out)),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(len(out), pageSize)),
	}
}

// Shared pagination helpers (normalizePage / totalPages) live in conversions.go.
