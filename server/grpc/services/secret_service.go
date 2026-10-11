package services

import (
	"context"
	"errors"
	"fmt"
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

// SecretGRPCService implements pb.SecretServiceServer, backing each RPC with the
// shared core service. Authentication/identity is established by the auth
// interceptor (see interceptors.AuthInterceptor) and read from the context.
type SecretGRPCService struct {
	pb.UnimplementedSecretServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.SecretServiceServer = (*SecretGRPCService)(nil)

const errSecretIDRequired = "secret_id is required" // #nosec G101 -- error message string, not a hardcoded credential

// NewSecretService creates a secret gRPC service backed by the shared core.
func NewSecretService(coreService *core.KeyorixCore) *SecretGRPCService {
	return &SecretGRPCService{core: coreService}
}

// CreateSecret creates a new secret.
func (s *SecretGRPCService) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" || req.GetValue() == "" || req.GetProjectId() == 0 || req.GetEnvironmentId() == 0 || req.GetType() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, value, project_id, environment_id and type are required")
	}
	// Authorize secrets.write AT THE TARGET project/environment, not the flat
	// global permission set — a project-scoped writer must not create in another
	// project. Mirrors the HTTP CreateSecret handler (scope from the body).
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if allowed, err := s.core.AuthorizePrincipal(ctx, user.ActorKind(), user.PrincipalID(), permSecretsWrite, scope); err != nil || !allowed {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to create secrets in this project")
	}
	if err := enforceProjectMFA(ctx, s.core, user, scope.ProjectID); err != nil {
		return nil, err
	}

	coreReq := &core.CreateSecretRequest{
		Name:          req.GetName(),
		Value:         []byte(req.GetValue()),
		ProjectID:     uint(req.GetProjectId()),
		EnvironmentID: uint(req.GetEnvironmentId()),
		Type:          req.GetType(),
		MaxReads:      int32PtrToIntPtr(req.MaxReads),
		Expiration:    tsToTimePtr(req.GetExpiration()),
		Metadata:      req.GetMetadata(),
		Tags:          req.GetTags(),
		CreatedBy:     user.Username,
		OwnerID:       user.UserID,
	}
	// #1625 (#1573 machine-actor attribution family, Part 2 continuation
	// finding): mirrors the HTTP CreateSecret handler's identical fix --
	// OwnerMachineIdentityID exists on CreateSecretRequest and is threaded
	// through to the persisted model, but this gRPC entry point never
	// populated it, so a machine caller's secret creation over gRPC landed
	// with zero identifying information (same gap as the HTTP path, just
	// unfixed here too).
	if user.ActorType == core.ActorTypeMachine {
		coreReq.OwnerMachineIdentityID = user.MachineIdentityID
	}
	if req.ParentId != nil && req.GetParentId() != 0 {
		pID := uint(req.GetParentId())
		coreReq.ParentID = &pID
	}
	secret, err := s.core.CreateSecret(ctx, coreReq)
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the create the same way the HTTP handler does — the core method does not
	// audit internally, so without this a secret created over gRPC left no audit
	// trail. Detached + async (see GetSecretValue).
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretCreatedWithProject(auditCtx, user.UserID, secret.ID, secret.ProjectID, user.Username, secret.Name, ip, ua)
	}) // #nosec G118
	return secretNodeToProto(secret), nil
}

// GetSecret returns a secret's metadata (subject to ownership/share checks).
func (s *SecretGRPCService) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	// Machine principals (ADR-030) are already authorized above by
	// authorizeSecretScoped; the per-user owner/sharing check (and its
	// user-id requirement — a machine caller's user.UserID is always 0) does
	// not apply to them, so fetch directly. Mirrors the isMachine split the
	// HTTP handlers use (W1: this gRPC service was missing it entirely,
	// blocking every machine-token read/write/delete over gRPC).
	var secret *models.SecretNode
	if user.ActorKind() == core.ActorTypeMachine {
		secret, err = s.core.GetSecret(ctx, uint(req.GetId()))
	} else {
		secret, err = s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	}
	if err != nil {
		return nil, mapSecretError(err)
	}
	out := secretNodeToProto(secret)
	out.TotalReads = s.totalReads(ctx, secret.ID)
	return out, nil
}

// totalReads returns the secret's lifetime value-read count (core.SecretTotalReads,
// the same figure the REST API reports as total_reads), or nil when it cannot be
// computed: the field is optional, and a failed count must not fail a metadata read
// (REST/gRPC parity, #2971).
func (s *SecretGRPCService) totalReads(ctx context.Context, secretID uint) *int64 {
	n, err := s.core.SecretTotalReads(ctx, secretID)
	if err != nil {
		log.Printf("total_reads for secret %d unavailable: %v", secretID, err)
		return nil
	}
	return &n
}

// ListSecretDependencies returns a secret's direct dependencies and dependents
// (ADR-052). Requires scoped secrets.read on the secret's project/environment.
func (s *SecretGRPCService) ListSecretDependencies(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretDependencies, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	deps, err := s.core.ListSecretDependencies(ctx, user.ActorKind(), user.PrincipalID(), uint(req.GetId()))
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretDependenciesToProto(deps), nil
}

// GetSecretImpact returns the blast radius of rotating a secret — its transitive
// dependents (ADR-052). Requires scoped secrets.read.
func (s *SecretGRPCService) GetSecretImpact(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretImpact, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	impact, err := s.core.GetSecretImpact(ctx, user.ActorKind(), user.PrincipalID(), uint(req.GetId()))
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretImpactToProto(impact), nil
}

// GetSecretValue returns a secret's decrypted value (counts toward max_reads).
// version_number/read_count are not populated here — use GetSecretVersions for
// version history.
func (s *SecretGRPCService) GetSecretValue(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretValue, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	// Machine principals are already authorized above by authorizeSecretScoped;
	// the per-user owner/sharing check does not apply to them (W1 — see GetSecret).
	isMachine := user.ActorKind() == core.ActorTypeMachine

	// Resolve the name first (metadata read, no read-count side effect).
	var secret *models.SecretNode
	if isMachine {
		secret, err = s.core.GetSecret(ctx, uint(req.GetId()))
	} else {
		secret, err = s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	}
	if err != nil {
		return nil, mapSecretError(err)
	}
	var value []byte
	if isMachine {
		value, err = s.core.GetSecretValue(ctx, uint(req.GetId()))
	} else {
		value, err = s.core.GetSecretValueWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	}
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Record the read in the audit trail and secret-access log — the same call the
	// HTTP reveal handler fires. Without it, a secret read over gRPC left no
	// secret.read event and no access-log row, so the anomaly detector never saw it:
	// secrets could be exfiltrated over gRPC invisibly to both the audit trail and
	// anomaly detection. SESSION-PERF #2403 follow-up (item 3, audit-before-
	// disclosure): now synchronous and checked, matching the HTTP handler — the
	// value below is only returned AFTER its audit entry has been durably
	// committed; an audit-write failure fails the RPC instead of disclosing the
	// value. DetachedAuditContext preserves the actor-type and impersonation tags
	// the interceptor set, and (same as before) keeps the write from dying on the
	// RPC's own cancellation.
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	if auditErr := s.core.LogSecretReadWithProject(auditCtx, user.UserID, uint(req.GetId()), secret.ProjectID, user.Username, secret.Name, ip, ua); auditErr != nil {
		return nil, status.Error(codes.Internal, "failed to record audit trail")
	}
	return &pb.SecretValue{
		Id:    req.GetId(),
		Name:  secret.Name,
		Value: string(value),
	}, nil
}

// UpdateSecret updates a secret; a non-empty value rotates it to a new version.
func (s *SecretGRPCService) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsWrite); err != nil {
		return nil, err
	}

	updateReq := &core.UpdateSecretRequest{
		ID:         uint(req.GetId()),
		MaxReads:   int32PtrToIntPtr(req.MaxReads),
		Expiration: tsToTimePtr(req.GetExpiration()),
		Metadata:   req.GetMetadata(),
		Tags:       req.GetTags(),
		UpdatedBy:  user.Username,
		UserID:     user.UserID,
	}
	if v := req.GetValue(); v != "" {
		updateReq.Value = []byte(v)
	}

	// Capture pre-update metadata for the audit diff (raw fetch, no read-count side
	// effect). Best-effort: a miss just yields an empty diff — same as the HTTP path.
	oldSecret, _ := s.core.Storage().GetSecret(ctx, uint(req.GetId()))

	// Machine principals are already authorized above by authorizeSecretScoped;
	// the per-user owner/sharing check (and its user-id requirement) does not
	// apply to them (W1 — see GetSecret).
	var secret *models.SecretNode
	if user.ActorKind() == core.ActorTypeMachine {
		secret, err = s.core.UpdateSecret(ctx, updateReq)
	} else {
		secret, err = s.core.UpdateSecretWithPermissionCheck(ctx, updateReq)
	}
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the update with a before/after diff, mirroring the HTTP handler — the
	// core method does not audit internally. Detached + async (see GetSecretValue).
	diff := core.BuildSecretUpdateDiff(oldSecret, updateReq, req.GetValue() != "")
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretUpdatedWithDiff(auditCtx, user.UserID, uint(req.GetId()), secret.ProjectID, user.Username, secret.Name, ip, ua, diff)
	}) // #nosec G118
	return secretNodeToProto(secret), nil
}

// DeleteSecret deletes a secret (owner-only, enforced by core).
func (s *SecretGRPCService) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.delete"); err != nil {
		return nil, err
	}
	// Pre-fetch name + project for the audit log before the record is gone, mirroring
	// the HTTP handler. Plain, unauthorized read: authorizeSecretScoped above already
	// authorized this delete, and DeleteSecretWithPermissionCheck below authorizes it
	// again — a second *WithPermissionCheck call here bought nothing but a second
	// CheckSecretPermission storage round trip (see
	// docs/findings/2026-09-23-FINDING-redundant-authz-prefetch.md). Best-effort: a
	// miss falls back to the id.
	secretName := fmt.Sprintf("id=%d", req.GetId())
	var secretProjectID uint
	if sec, err := s.core.GetSecret(ctx, uint(req.GetId())); err == nil {
		secretName = sec.Name
		secretProjectID = sec.ProjectID
	}
	// Machine principals are already authorized above by authorizeSecretScoped;
	// the per-user owner/sharing check (and its user-id requirement) does not
	// apply to them (W1 — see GetSecret).
	if user.ActorKind() == core.ActorTypeMachine {
		err = s.core.DeleteSecret(ctx, uint(req.GetId()))
	} else {
		err = s.core.DeleteSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	}
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the delete the same way the HTTP handler does — the core method does not
	// audit internally. Detached + async (see GetSecretValue).
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretDeletedWithProject(auditCtx, user.UserID, uint(req.GetId()), secretProjectID, user.Username, secretName, ip, ua)
	}) // #nosec G118
	return &emptypb.Empty{}, nil
}

// SetSecretAutoRotate enables/disables automated rotation for a secret and sets its
// generated-value shape (ADR-046). Scoped secrets.write, mirroring the HTTP endpoint.
func (s *SecretGRPCService) SetSecretAutoRotate(ctx context.Context, req *pb.SetSecretAutoRotateRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsWrite); err != nil {
		return nil, err
	}
	if err := s.core.SetSecretAutoRotate(ctx, uint(req.GetId()), core.AutoRotateSpec{
		Enabled: req.GetEnabled(), Length: int(req.GetLength()), Charset: req.GetCharset(),
		Backend: req.GetBackend(), Ref: req.GetRef(),
	}, user.PrincipalID()); err != nil {
		return nil, mapSecretError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListSecrets lists secrets visible to the caller with sharing context.
func (s *SecretGRPCService) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	// Authorize at the requested project/environment scope (mirrors the HTTP list
	// route's ScopeFromQuery); 0/0 means global. ListSecretsWithSharingInfo then
	// filters the results to what the caller may actually see.
	listScope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if allowed, err := s.core.AuthorizePrincipal(ctx, user.ActorKind(), user.PrincipalID(), permSecretsRead, listScope); err != nil || !allowed {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to list secrets")
	}
	if err := enforceProjectMFA(ctx, s.core, user, listScope.ProjectID); err != nil {
		return nil, err
	}

	page := int(req.GetPage())
	if page < 1 {
		page = 1
	}
	pageSize := int(req.GetPageSize())
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	filter := &models.SecretListFilter{
		Search:         optString(req.Search),
		ProjectID:      optUint(req.ProjectId),
		EnvironmentID:  optUint(req.EnvironmentId),
		Type:           optString(req.Type),
		Permission:     req.GetPermission(),
		ShowOwnedOnly:  req.GetShowOwnedOnly(),
		ShowSharedOnly: req.GetShowSharedOnly(),
		Page:           page,
		PageSize:       pageSize,
		ParentID:       optUint(req.ParentId),
		FolderOnly:     req.GetFolderOnly(),
	}

	resp, err := s.core.ListSecretsWithSharingInfo(ctx, user.UserID, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list secrets")
	}

	secrets := make([]*pb.Secret, 0, len(resp.Secrets))
	for _, sec := range resp.Secrets {
		secrets = append(secrets, sharingInfoToProto(sec))
	}
	return &pb.ListSecretsResponse{
		Secrets:     secrets,
		Total:       i64ToU32(resp.Total),
		Page:        intToU32(resp.Page),
		PageSize:    intToU32(resp.PageSize),
		TotalPages:  intToU32(resp.TotalPages),
		OwnedCount:  intToU32(resp.OwnedCount),
		SharedCount: intToU32(resp.SharedCount),
	}, nil
}

// GetSecretVersions returns a secret's version history (subject to access checks).
func (s *SecretGRPCService) GetSecretVersions(ctx context.Context, req *pb.GetSecretVersionsRequest) (*pb.GetSecretVersionsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	// Machine principals are already authorized above by authorizeSecretScoped;
	// the per-user owner/sharing check (and its user-id requirement) does not
	// apply to them (W1 — see GetSecret).
	var versions []*models.SecretVersion
	if user.ActorKind() == core.ActorTypeMachine {
		versions, err = s.core.GetSecretVersions(ctx, uint(req.GetId()))
	} else {
		versions, err = s.core.GetSecretVersionsWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	}
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the listing, mirroring the HTTP handler (secrets_versions.go) —
	// without this, listing version history over gRPC left no audit event, an
	// HTTP<->gRPC audit-parity gap invisible to anomaly detection (#168). It is
	// secret.versions_listed (with an access-log row of action "versions_list",
	// which anomaly detection reads), not secret.read: no value is returned
	// (AUDIT-UX-2, #2951).
	// Plain, unauthorized read, matching the HTTP handler's own GetSecret (not
	// GetSecretWithPermissionCheck) for this exact prefetch: authorizeSecretScoped
	// above already authorized this read, and GetSecretVersionsWithPermissionCheck
	// above authorizes it again — a second *WithPermissionCheck call here bought
	// nothing but a second CheckSecretPermission storage round trip (see
	// docs/findings/2026-09-23-FINDING-redundant-authz-prefetch.md). Best-effort
	// metadata fetch: a miss just skips the audit call.
	if secret, sErr := s.core.GetSecret(ctx, uint(req.GetId())); sErr == nil && secret != nil {
		auditCtx := core.DetachedAuditContext(ctx)
		ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
		if auditErr := s.core.LogSecretVersionsListed(auditCtx, user.UserID, uint(req.GetId()), secret.ProjectID, user.Username, secret.Name, ip, ua); auditErr != nil {
			return nil, status.Error(codes.Internal, "failed to record audit trail")
		}
	}
	out := make([]*pb.SecretVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, &pb.SecretVersion{
			VersionNumber: intToU32(v.VersionNumber),
			CreatedAt:     timestamppb.New(v.CreatedAt),
			ReadCount:     intToU32(v.ReadCount),
		})
	}
	return &pb.GetSecretVersionsResponse{Versions: out, TotalReads: s.totalReads(ctx, uint(req.GetId()))}, nil
}

// GrantSecretACL grants (or updates) a per-secret ACL for a user.
// Requires secrets.manage at the secret's project scope.
func (s *SecretGRPCService) GrantSecretACL(ctx context.Context, req *pb.GrantSecretACLRequest) (*pb.SecretACLEntry, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errSecretIDRequired)
	}
	if req.GetUserId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if len(req.GetPermissions()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one permission is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsManage); err != nil {
		return nil, err
	}
	if err := s.core.GrantSecretACL(ctx, user.UserID, uint(req.GetSecretId()), uint(req.GetUserId()), req.GetPermissions()); err != nil {
		return nil, mapSecretACLError(err)
	}
	// Re-fetch so we can return the created/updated row with its ID and timestamps.
	acls, err := s.core.ListSecretACLs(ctx, uint(req.GetSecretId()))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to retrieve created ACL")
	}
	for _, a := range acls {
		if a.UserID == uint(req.GetUserId()) {
			return secretACLToProto(a), nil
		}
	}
	return nil, status.Error(codes.Internal, "ACL created but not found on re-fetch")
}

// RevokeSecretACL removes a per-secret ACL entry by its ID.
// Requires secrets.manage at the secret's project scope.
func (s *SecretGRPCService) RevokeSecretACL(ctx context.Context, req *pb.RevokeSecretACLRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errSecretIDRequired)
	}
	if req.GetAclId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "acl_id is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsManage); err != nil {
		return nil, err
	}
	if err := s.core.RevokeSecretACL(ctx, user.UserID, uint(req.GetSecretId()), uint(req.GetAclId())); err != nil {
		return nil, mapSecretACLError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListSecretACLs returns all ACL grants for a secret.
// Requires secrets.manage at the secret's project scope.
func (s *SecretGRPCService) ListSecretACLs(ctx context.Context, req *pb.ListSecretACLsRequest) (*pb.ListSecretACLsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errSecretIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsManage); err != nil {
		return nil, err
	}
	acls, err := s.core.ListSecretACLs(ctx, uint(req.GetSecretId()))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list ACLs")
	}
	entries := make([]*pb.SecretACLEntry, 0, len(acls))
	for _, a := range acls {
		entries = append(entries, secretACLToProto(a))
	}
	return &pb.ListSecretACLsResponse{Acls: entries}, nil
}

// secretACLToProto converts a models.SecretACL to its proto representation.
func secretACLToProto(a *models.SecretACL) *pb.SecretACLEntry {
	perms := core.DecodeSecretACLPerms(a.Permissions)
	return &pb.SecretACLEntry{
		Id:          uint64(a.ID),
		SecretId:    uint64(a.SecretID),
		UserId:      uint64(a.UserID),
		Permissions: perms,
		GrantedBy:   uint64(a.GrantedBy),
		CreatedAt:   a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// mapSecretACLError translates core ACL errors into gRPC status codes.
func mapSecretACLError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "ACL or secret not found")
	// "invalid"/"required" don't only match GrantSecretACL's own validation
	// messages (invalid permission, missing IDs) -- CreateOrUpdateSecretACL's
	// storage-layer failure is also routed through this classifier
	// (secret_acl.go's "%w"-wrapped ErrorStorageFailed/ErrorRetrievalFailed
	// paths), and a raw SQL/driver error can coincidentally contain either
	// word. Fixed message, not msg, so a driver error never reaches the
	// client verbatim (matches mapUserError's GRPC-003 remediation).
	case strings.Contains(msg, "invalid"), strings.Contains(msg, "required"):
		return status.Error(codes.InvalidArgument, "invalid ACL request")
	case strings.Contains(msg, "not authorized"):
		return status.Error(codes.PermissionDenied, "not authorized to manage this secret's ACLs")
	default:
		return status.Error(codes.Internal, "ACL operation failed")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// requireUser returns the authenticated user from the context or an
// Unauthenticated error. The auth interceptor populates this on every
// non-public RPC.
// authorizeSecretScoped resolves a secret's project/environment and checks the
// permission AT that scope — mirroring the HTTP RequireScopedPermission gate, so
// gRPC enforces the same scoped-RBAC model as HTTP rather than the flat, global
// permission set. Routes through the shared authorizeScopedTarget (ADR-096 §4):
// a missing secret and a found-but-unauthorized one both deny as
// PermissionDenied by default, with a genuine NotFound reserved for a caller
// who holds perm at GLOBAL scope — closing the existence oracle across every
// project/tenant boundary without silently absorbing global-scope callers'
// legitimate "doesn't exist" answer into a denial. The downstream
// *WithPermissionCheck core calls still enforce ownership/share on top of this.
func authorizeSecretScoped(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, secretID uint, perm string) error {
	secret, err := cs.Storage().GetSecret(ctx, secretID)
	if err != nil {
		return authorizeScopedTarget(ctx, cs, actor, perm, err, core.Scope{}, "secret not found")
	}
	scope := core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	return authorizeScopedTarget(ctx, cs, actor, perm, nil, scope, "")
}

// mapSecretError translates core errors into gRPC status codes.
func mapSecretError(err error) error {
	// Checked via errors.As, BEFORE the string-matching switch below: this
	// error's own message contains the substring "exceeds" (deliberately, so
	// it names the actual limit), which the switch's own
	// "exceeds"-string-matching InvalidArgument branch would otherwise catch
	// first and misreport as an unrelated invalid-rotation-configuration
	// error instead of ResourceExhausted -- exactly the collision that
	// branch's own comment already warns a future "exceeds"-containing error
	// could cause.
	var tooLarge *core.SecretValueTooLargeError
	if errors.As(err, &tooLarge) {
		return status.Error(codes.ResourceExhausted, tooLarge.Error()) // nosemgrep: keyorix-raw-error-to-client -- SecretValueTooLargeError.Error() is a fixed-format string carrying only the submitted size and configured limit (both already known to the caller), never secret content
	}
	// W3 (Session W, 2026-09-29): under sustained heavy concurrent writes to the
	// SAME secret, the version-number retry loop can legitimately exhaust — this
	// is expected contention, not a server malfunction. codes.Aborted is gRPC's
	// canonical "concurrency issue, retry the whole operation" status (matches
	// the HTTP side's 409, see secrets_crud.go's sendUpdateSecretError).
	if errors.Is(err, core.ErrSecretVersionContentionExhausted) {
		return status.Error(codes.Aborted, "high write contention on this secret; retry the request")
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "secret not found")
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "access denied"):
		return status.Error(codes.PermissionDenied, "access denied to this secret")
	case strings.Contains(msg, "already exists"):
		return status.Error(codes.AlreadyExists, "secret with this name already exists")
	// Fixed message, not msg -- these are genuinely safe caller-echo validation
	// text today (rotation_executor.go), but "exceeds" in particular is used
	// for dozens of unrelated validations across internal/core; matching a
	// coincidental substring in some future wrapped error must not turn into
	// a raw-error leak here (matches mapUserError's GRPC-003 remediation).
	case strings.Contains(msg, "unknown rotation charset"), strings.Contains(msg, "out of range"),
		strings.Contains(msg, "must be set together"), strings.Contains(msg, "unknown rotation backend"),
		strings.Contains(msg, "no rotation backends"), strings.Contains(msg, "exceeds"):
		return status.Error(codes.InvalidArgument, "invalid rotation configuration")
	default:
		return status.Error(codes.Internal, "secret operation failed")
	}
}

// Shared proto-conversion, pagination, and identity helpers live in conversions.go.
