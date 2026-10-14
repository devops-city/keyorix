// conversions.go — helpers shared across the gRPC service implementations
// (ADR Phase-2 split): caller identity, permission checks, proto<->model
// conversion, and the pagination defaults the paginated list RPCs share. These
// were previously scattered through secret_service.go / share_service.go; they
// live here so each service file holds only its own RPC methods.
package services

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/utils/safeconv"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Error sanitization ---

// clientSafe returns a generic, client-safe message in place of err's raw
// Error() text. The other RPC error-mapping helpers in this package
// (mapUserError, groupError, etc.) already do this by falling back to a
// hardcoded message on their unclassified/codes.Internal branch; clientSafe
// exists for the handful of call sites that don't go through one of those
// switches and would otherwise reflect a raw error — e.g. a storage/ORM
// failure or an upstream secret-store connector error (backlog #116) —
// straight into the gRPC status. The caller MUST still log the original err
// server-side before calling this.
func clientSafe(err error) string {
	if err == nil {
		return ""
	}
	return "an internal error occurred; please try again or contact support if the problem persists"
}

// goSafe runs fn in a detached goroutine with panic recovery. secret_service.go
// spawns "fire and forget" goroutines to audit-log secret reads/writes over
// gRPC (mirroring the HTTP handlers) so the RPC response isn't blocked on that
// I/O — but those goroutines run on the hottest secret CRUD paths and are NOT
// covered by any per-RPC recovery interceptor, which only guards the goroutine
// actually serving the RPC. A panic in a bare `go s.core.LogSecret...(...)`
// here would crash the entire process for every connected tenant (backlog
// #481, an unrecovered-coverage gap in the #243 fix, which only covered
// server/http/handlers). goSafe closes that gap: any panic in fn is recovered
// and logged instead of taking the server down. Mirrors
// server/http/handlers.goSafe / internal/core.goSafe, duplicated here because
// this package cannot import the handlers package -- all three delegate the
// actual recover/log/metric logic to besteffort.RunRecover (package
// besteffort).
// goSafeWG tracks in-flight goSafe goroutines so tests can deterministically wait
// for detached audit/side-effect writes instead of guessing with a sleep — see
// DrainBackgroundGoroutines. Mirrors server/http/handlers' identical addition.
var goSafeWG sync.WaitGroup

// DrainBackgroundGoroutines blocks until every goSafe goroutine dispatched so far
// by this package has returned. Test-only observability hook.
func DrainBackgroundGoroutines() {
	goSafeWG.Wait()
}

func goSafe(fn func()) {
	goSafeWG.Go(func() {
		defer besteffort.RunRecover("grpc.goSafe")()
		fn()
	})
}

// isSafeConnectError mirrors the HTTP handlers' connect.go allowlist: it
// reports whether msg is one of the small set of deliberately-crafted, safe
// messages core.ReadFederatedSecret / CreateConnectRefGrant /
// DeleteConnectRefGrant themselves produce. Anything else may originate from
// storage or an upstream connector (e.g. Vault) and must be sanitized.
func isSafeConnectError(msg string) bool {
	for _, marker := range []string{
		"keyorix connect is not enabled",
		"unknown connector",
		"a role is required for a connect ref-grant",
		"connector is platform-scoped",
		"is not permitted for your roles on connector",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// --- Identity & authorization ---

func requireUser(ctx context.Context) (*interceptors.UserContext, error) {
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}
	return user, nil
}

// authorizeScoped enforces perm at the given scope via core.Authorize — the same
// scope-aware path HTTP uses. This is the ONLY authorization primitive the services
// use: an earlier flat `hasPermission(user.Permissions, …)` check treated a
// permission held only at one project's scope as if held everywhere, because
// UserContext.Permissions is the FLAT union of the caller's grants across every
// scope (the #53/#54/#88/#90 flat-vs-scoped bug class). Routing through
// core.Authorize fixes that and future-proofs the PAT/machine paths.
func authorizeScoped(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, perm string, scope core.Scope) error {
	// AuthorizePrincipal is actor-aware: for a user it is identical to Authorize
	// (PAT restriction + roles + admin bypass); for a machine identity it resolves
	// machine roles with NO admin bypass. This is what makes machine tokens work
	// over gRPC (ADR-030) with the same primitive HTTP uses.
	if allowed, err := cs.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions")
	}
	return enforceProjectMFA(ctx, cs, actor, scope.ProjectID)
}

// authorizeScopedTarget is the gRPC analogue of HTTP's handleScopeResolutionError
// (server/middleware/auth.go) — ADR-096 §4 requires it back every RPC that
// resolves a scoped resource by ID. resolveErr non-nil means the resource
// fetch itself failed (no scope to check yet, so scope is ignored); nil means
// the resource was found, with scope set to its actual project/environment.
//
// Either way, a denial to a caller who lacks perm resolves to the SAME
// codes.PermissionDenied with the SAME message — a caller cannot distinguish
// "this ID doesn't exist" from "it exists but you can't touch it" from the
// response alone. The one narrow exception: a caller who holds perm at
// GLOBAL scope (core.Scope{}) gets a genuine codes.NotFound for a target that
// truly doesn't exist, exactly mirroring handleScopeResolutionError's
// errTargetNotFound branch on the HTTP side.
func authorizeScopedTarget(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, perm string, resolveErr error, scope core.Scope, notFoundMsg string) error {
	if resolveErr != nil {
		if allowed, err := cs.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, core.Scope{}); err == nil && allowed {
			return status.Error(codes.NotFound, notFoundMsg)
		}
		return status.Error(codes.PermissionDenied, "insufficient permissions")
	}
	if allowed, err := cs.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions")
	}
	return enforceProjectMFA(ctx, cs, actor, scope.ProjectID)
}

// enforceProjectMFA applies the per-project MFA policy (ADR-037) over gRPC: an
// interactive session WITHOUT a second factor is denied access to a project that
// requires MFA. It mirrors the HTTP ProjectMFABlocked gate so the policy is not
// bypassable by switching transport. Non-interactive callers (PAT / machine) are
// exempt — SessionAuth is false for them — and a global-scoped operation (project
// 0) is never gated. Called after the permission check at every project-scoped
// authorization chokepoint.
//
// #G17: fails CLOSED, matching every other primitive this file wires into
// (AuthorizePrincipal, core.Authorize) — a ProjectRequiresMFA lookup error (a
// transient storage timeout, a cancelled context) used to fall through to
// `return nil`, silently treating the caller as MFA-compliant regardless of the
// project's real policy or the session's real factor state. A "project not
// found" error is deliberately excluded from the fail-closed path: this scope
// was already permission-checked by the caller (authorizeScoped only reaches
// this line after AuthorizePrincipal allowed it), so a nonexistent project
// isn't an MFA-policy question — denying here would mask the RPC's own
// not-found handling (e.g. GetProjectRotationPlan(unknownID)) behind a
// misleading "MFA required" status instead of its real NotFound.
func enforceProjectMFA(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, projectID uint) error {
	if projectID == 0 || cs == nil || actor == nil {
		return nil
	}
	if !actor.SessionAuth || actor.MFAEnabled {
		return nil
	}
	required, err := cs.ProjectRequiresMFA(ctx, projectID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return status.Error(codes.Internal, "unable to verify project MFA policy; please try again")
	}
	if required {
		return status.Error(codes.PermissionDenied,
			"this project requires multi-factor authentication; enrol a second factor to access it")
	}
	return nil
}

// enforceProjectMFAForProjects applies enforceProjectMFA across every distinct,
// non-zero project ID in projectIDs, denying on the first one that requires MFA
// the actor's session lacks (or whose policy can't be verified).
//
// #G17: authorizeGlobal always calls enforceProjectMFA with projectID 0, which
// no-ops unconditionally — correct for genuinely install-wide data, but several
// authorizeGlobal-gated RPCs (GetDeploymentRotationPlan, ListUserShares,
// ListSharedSecrets) return content aggregated from or belonging to SPECIFIC
// projects, some of which may individually require MFA. A session-authenticated
// caller without a second factor, blocked from a single MFA-required project's
// per-project endpoint, could otherwise read that same project's data back out
// of the aggregate endpoint instead — the step-up control silently routed around
// by picking the global-scope sibling. Call this after loading the response data,
// before returning it, with every project ID the response discloses.
func enforceProjectMFAForProjects(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, projectIDs []uint) error {
	seen := make(map[uint]bool, len(projectIDs))
	for _, id := range projectIDs {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		if err := enforceProjectMFA(ctx, cs, actor, id); err != nil {
			return err
		}
	}
	return nil
}

// authorizeGlobal enforces perm at global scope (project 0) — for install-wide
// operations (user/role/system/audit management) that HTTP gates with
// RequirePermission. A grant held only at a project scope does NOT satisfy it.
func authorizeGlobal(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, perm string) error {
	return authorizeScoped(ctx, cs, actor, perm, core.Scope{})
}

// --- Pagination ---

// normalizePage applies the standard page (>=1) / page_size (1..100, default 20)
// defaults shared by most paginated list RPCs — matches the default REST's own
// handlers use for the same resources (secrets_list.go, users_list.go,
// shares_query.go, folders_handler.go). Audit's two RPCs default to 50 instead;
// see normalizePageWithDefault.
func normalizePage(page, pageSize uint32) (int, int) {
	return normalizePageWithDefault(page, pageSize, 20)
}

// normalizePageWithDefault is normalizePage with a caller-supplied default
// page_size (still capped at 1..100) — REST's own per-endpoint handlers don't
// share one hard-coded default (audit.go's two handlers default to 50, every
// other list handler defaults to 20), so the gRPC side needs the same knob to
// avoid a transport-dependent default result-set size for an identical
// unspecified-page_size request.
func normalizePageWithDefault(page, pageSize uint32, def int) (int, int) {
	p := max(int(page), 1)
	ps := int(pageSize)
	if ps < 1 || ps > 100 {
		ps = def
	}
	return p, ps
}

func totalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	return (total + pageSize - 1) / pageSize
}

// --- Proto <-> model conversion ---

func secretNodeToProto(n *models.SecretNode) *pb.Secret {
	return &pb.Secret{
		Id:            intToU32(int(n.ID)),
		Name:          n.Name,
		ProjectId:     intToU32(int(n.ProjectID)),
		EnvironmentId: intToU32(int(n.EnvironmentID)),
		Type:          n.Type,
		MaxReads:      intPtrToInt32Ptr(n.MaxReads),
		Expiration:    timePtrToTs(n.Expiration),
		Metadata:      metadataToMap(n.Metadata),
		Tags:          []string{}, // tags are not stored on the secret node
		Status:        n.Status,
		CreatedBy:     n.CreatedBy,
		OwnerId:       intToU32(int(n.OwnerID)),
		CreatedAt:     timestamppb.New(n.CreatedAt),
		UpdatedAt:     timestamppb.New(n.UpdatedAt),
		IsShared:      n.IsShared,
	}
}

func sharingInfoToProto(s *models.SecretWithSharingInfo) *pb.Secret {
	out := secretNodeToProto(s.SecretNode)
	out.ProjectName = s.ProjectName
	out.EnvironmentName = s.EnvironmentName
	out.IsShared = s.IsShared
	out.IsOwnedByUser = s.IsOwnedByUser
	out.UserPermission = s.UserPermission
	out.ShareCount = intToU32(s.ShareCount)
	return out
}

// --- Secret dependency graph (ADR-052) ---

func dependencyEdgeToProto(e core.DependencyEdge) *pb.DependencyEdge {
	return &pb.DependencyEdge{
		Id:         intToU32(int(e.ID)),
		SecretId:   intToU32(int(e.SecretID)),
		SecretName: e.SecretName,
		Note:       e.Note,
	}
}

func secretDependenciesToProto(d *core.SecretDependencies) *pb.SecretDependencies {
	out := &pb.SecretDependencies{SecretId: intToU32(int(d.SecretID))}
	for _, e := range d.DependsOn {
		out.DependsOn = append(out.DependsOn, dependencyEdgeToProto(e))
	}
	for _, e := range d.Dependents {
		out.Dependents = append(out.Dependents, dependencyEdgeToProto(e))
	}
	return out
}

func secretImpactToProto(im *core.SecretImpact) *pb.SecretImpact {
	out := &pb.SecretImpact{SecretId: intToU32(int(im.SecretID)), SecretName: im.SecretName, Truncated: im.Truncated}
	for _, a := range im.Affected {
		out.Affected = append(out.Affected, &pb.ImpactedSecret{
			SecretId:   intToU32(int(a.SecretID)),
			SecretName: a.SecretName,
			Depth:      intToI32(a.Depth), // depth is a small non-negative hop count
		})
	}
	return out
}

func rotationPlanToProto(p *core.RotationPlan) *pb.RotationPlan {
	out := &pb.RotationPlan{
		ProjectId:    intToU32(int(p.ProjectID)),
		TotalSecrets: intToI32(p.TotalSecrets),
		OverdueCount: intToI32(p.OverdueCount),
		DueSoonCount: intToI32(p.DueSoonCount),
	}
	for _, w := range p.Waves {
		pw := &pb.RotationWave{Index: intToI32(w.Index)}
		for _, s := range w.Secrets {
			after := make([]uint32, 0, len(s.AfterSecretIDs))
			for _, id := range s.AfterSecretIDs {
				after = append(after, intToU32(int(id)))
			}
			pw.Secrets = append(pw.Secrets, &pb.PlannedRotation{
				SecretId:       intToU32(int(s.SecretID)),
				SecretName:     s.SecretName,
				Status:         s.Status,
				DaysOverdue:    intToI32(s.DaysOverdue),
				RiskScore:      intToI32(s.RiskScore),
				RiskBand:       s.RiskBand,
				Urgency:        intToI32(s.Urgency),
				AutoRotate:     s.AutoRotate,
				AfterSecretIds: after,
				Reasons:        s.Reasons,
			})
		}
		out.Waves = append(out.Waves, pw)
	}
	return out
}

func deploymentRotationPlanToProto(d *core.DeploymentRotationPlan) *pb.DeploymentRotationPlan {
	out := &pb.DeploymentRotationPlan{
		ProjectsScanned:  intToI32(d.ProjectsScanned),
		ProjectsWithWork: intToI32(d.ProjectsWithWork),
		TotalSecrets:     intToI32(d.TotalSecrets),
		OverdueCount:     intToI32(d.OverdueCount),
		DueSoonCount:     intToI32(d.DueSoonCount),
	}
	for i := range d.Projects {
		out.Projects = append(out.Projects, rotationPlanToProto(&d.Projects[i]))
	}
	for _, bp := range d.BrokenProjects {
		out.BrokenProjects = append(out.BrokenProjects, &pb.BrokenRotationProject{
			ProjectId: intToU32(int(bp.ProjectID)),
			Error:     bp.Error,
		})
	}
	return out
}

func rotationOrderToProto(o *core.RotationOrder) *pb.RotationOrder {
	out := &pb.RotationOrder{ProjectId: intToU32(int(o.ProjectID))}
	for _, s := range o.Order {
		out.Order = append(out.Order, &pb.RotationStep{SecretId: intToU32(int(s.SecretID)), SecretName: s.SecretName})
	}
	return out
}

func metadataToMap(raw models.JSON) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	m := map[string]string{}
	_ = json.Unmarshal(raw, &m) // best-effort; non-string maps yield empty
	return m
}

// --- Numeric / time / optional conversions ---
// Overflow is unrealistic for IDs/counts; clamp on the off chance rather than
// failing the RPC.

func intToU32(v int) uint32 {
	x, err := safeconv.UintToUint32(uint(v))
	if err != nil || v < 0 {
		return 0
	}
	return x
}

func i64ToU32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	return intToU32(int(v))
}

// intToI32 safely narrows int → int32 (gosec G115), clamping on overflow.
func intToI32(v int) int32 {
	x, err := safeconv.IntToInt32(v)
	if err != nil {
		return 0
	}
	return x
}

func intPtrToInt32Ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v, err := safeconv.IntToInt32(*p)
	if err != nil {
		v = 0
	}
	return &v
}

func int32PtrToIntPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

func tsToTimePtr(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func timePtrToTs(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optString(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

func optUint(p *uint32) *uint {
	if p == nil || *p == 0 {
		return nil
	}
	v := uint(*p)
	return &v
}

func projectToProto(p *models.Project) *pb.Project {
	return &pb.Project{
		Id:          intToU32(int(p.ID)),
		Name:        p.Name,
		Description: p.Description,
		RequireMfa:  p.RequireMFA,
		CreatedAt:   timestamppb.New(p.CreatedAt),
		UpdatedAt:   timestamppb.New(p.UpdatedAt),
	}
}

func environmentToProto(e *models.Environment) *pb.Environment {
	return &pb.Environment{
		Id:        intToU32(int(e.ID)),
		ProjectId: intToU32(int(e.ProjectID)),
		Name:      e.Name,
		CreatedAt: timestamppb.New(e.CreatedAt),
		UpdatedAt: timestamppb.New(e.UpdatedAt),
	}
}

func machineIdentityToProto(m *models.MachineIdentity) *pb.MachineIdentity {
	return &pb.MachineIdentity{
		Id:             intToU32(int(m.ID)),
		ProjectId:      intToU32(int(m.ProjectID)),
		Name:           m.Name,
		IdentityType:   m.IdentityType,
		State:          m.State,
		Description:    m.Description,
		Classification: m.Classification,
		CreatedBy:      intToU32(int(m.CreatedBy)),
		CreatedAt:      timestamppb.New(m.CreatedAt),
		UpdatedAt:      timestamppb.New(m.UpdatedAt),
		LastSeenAt:     timePtrToTs(m.LastSeenAt),
		RevokedAt:      timePtrToTs(m.RevokedAt),
	}
}

func dynamicConfigToProto(c *models.DynamicSecretConfig) *pb.DynamicSecretConfig {
	return &pb.DynamicSecretConfig{
		Id:                intToU32(int(c.ID)),
		Name:              c.Name,
		ProjectId:         intToU32(int(c.ProjectID)),
		EnvironmentId:     intToU32(int(c.EnvironmentID)),
		BackendType:       c.BackendType,
		CreationTemplate:  c.CreationTemplate,
		DefaultTtlSeconds: intToI32(c.DefaultTTLSeconds),
		MaxTtlSeconds:     intToI32(c.MaxTTLSeconds),
		Classification:    c.Classification,
		CreatedBy:         c.CreatedBy,
		CreatedAt:         timestamppb.New(c.CreatedAt),
	}
}

func dynamicLeaseToProto(l *models.DynamicSecretLease) *pb.DynamicSecretLease {
	return &pb.DynamicSecretLease{
		LeaseId:      l.LeaseID,
		ConfigId:     intToU32(int(l.ConfigID)),
		RoleName:     l.RoleName,
		Status:       l.Status,
		RevokeReason: l.RevokeReason,
		RevokeError:  l.RevokeError,
		IssuedAt:     timestamppb.New(l.IssuedAt),
		ExpiresAt:    timestamppb.New(l.ExpiresAt),
		RevokedAt:    timePtrToTs(l.RevokedAt),
	}
}

func machineTokenToProto(c *models.MachineIdentityCredential) *pb.MachineToken {
	return &pb.MachineToken{
		Id:             intToU32(int(c.ID)),
		Name:           c.Name,
		Prefix:         c.TokenPrefix,
		LastUsedAt:     timePtrToTs(c.LastUsedAt),
		ExpiresAt:      timePtrToTs(c.ExpiresAt),
		Revoked:        c.Revoked,
		Classification: c.Classification,
		CreatedAt:      timestamppb.New(c.CreatedAt),
	}
}
