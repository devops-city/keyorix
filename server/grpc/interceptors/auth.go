package interceptors

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Token-kind prefixes — match the HTTP middleware's routing. kx_pat_ is a personal
// access token (ADR-027/042); kx_machine_ a machine-identity token (ADR-030);
// anything else is a session token.
const (
	patTokenPrefix     = "kx_pat_"
	machineTokenPrefix = "kx_machine_"
)

// UserContext represents the authenticated principal for gRPC — a human user, or
// a machine identity (ADR-030) when MachineIdentityID is set and UserID is 0.
type UserContext struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	// ActorType is "machine_identity" for a machine principal, otherwise empty
	// (treated as a user). MachineIdentityID is the machine's id for that case.
	ActorType         string `json:"actor_type,omitempty"`
	MachineIdentityID uint   `json:"machine_identity_id,omitempty"`
	// ImpersonatedBy is the initiating admin's id when this is an impersonation
	// session (nil otherwise). Resolved once in authenticateRequest and tagged onto
	// the request context by the interceptors (core.WithImpersonation) so audit
	// events written over gRPC carry the same accountability HTTP records — the
	// same definition HTTP's UserContext uses.
	ImpersonatedBy *uint `json:"impersonated_by,omitempty"`
	// SessionAuth is true only for an interactive session token — false for PATs and
	// machine tokens, which are non-interactive. MFAEnabled is true when the user has
	// any second factor (TOTP or a passkey). Together they let the service layer apply
	// the per-project MFA policy (ADR-037) the same way the HTTP ProjectMFABlocked gate
	// does, so it is not bypassable by switching transport.
	SessionAuth bool `json:"-"`
	MFAEnabled  bool `json:"-"`
	// SessionID is the authenticating session's row id (nil unless SessionAuth
	// is true) — a non-sensitive identifier, deliberately NOT the raw token or
	// its hash, so a long-lived stream's periodic re-authorization (#G18,
	// reauthorizeAuditStream) can re-verify THIS SPECIFIC session is still live
	// (core.SessionStillLive) without retaining the bearer credential itself
	// beyond the initial validation in authenticateRequest.
	SessionID *uint `json:"-"`
}

// ActorKind returns the principal's actor type ("user" or "machine_identity"),
// defaulting to user for empty contexts.
func (u *UserContext) ActorKind() string {
	if u.ActorType == core.ActorTypeMachine {
		return core.ActorTypeMachine
	}
	return core.ActorTypeUser
}

// PrincipalID returns the id to authorize against: the machine identity id for a
// machine request, otherwise the user id.
func (u *UserContext) PrincipalID() uint {
	if u.ActorType == core.ActorTypeMachine {
		return u.MachineIdentityID
	}
	return u.UserID
}

// contextKey is used for context keys to avoid collisions
type contextKey string

const (
	userContextKey contextKey = "grpc_user"
)

// AuthInterceptor returns a unary server interceptor that authenticates each
// request against a real session token via the core service. requireMFA mirrors
// the deployment-wide security.require_mfa policy so the gRPC transport enforces
// the same MFA-enrolment gate as the HTTP API.
func AuthInterceptor(coreService *core.KeyorixCore, requireMFA bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authentication for certain methods
		if isPublicMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		// Extract and validate token
		userCtx, restriction, err := authenticateRequest(ctx, coreService, requireMFA)
		if err != nil {
			return nil, err
		}

		// Mirror the HTTP BlockWhenImpersonating guard: an admin acting through an
		// impersonation session must not mint a durable credential that would outlive the
		// bounded, audited session.
		if blockedUnderImpersonation(info.FullMethod) && userCtx.ImpersonatedBy != nil {
			return nil, status.Error(codes.PermissionDenied, "this action is not permitted while impersonating")
		}

		// Add user context to request context
		newCtx := context.WithValue(ctx, userContextKey, userCtx)
		newCtx = withAuditAttribution(newCtx, userCtx)
		// Carry a PAT's least-privilege restriction (ADR-042) so core.Authorize
		// enforces it on every authorization check this RPC makes.
		if restriction != nil {
			newCtx = core.WithPATRestriction(newCtx, restriction)
		}
		// #G07: tag whether this is a genuine interactive session — see the HTTP
		// buildRequestContext's identical tag for why PATRestriction alone can't
		// distinguish an unrestricted PAT from a session.
		newCtx = core.WithSessionAuth(newCtx, userCtx.SessionAuth)
		return handler(newCtx, req)
	}
}

// StreamAuthInterceptor returns a stream server interceptor that authenticates
// each stream against a real session token via the core service. requireMFA
// mirrors the deployment-wide security.require_mfa policy (see AuthInterceptor).
func StreamAuthInterceptor(coreService *core.KeyorixCore, requireMFA bool) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip authentication for certain methods
		if isPublicMethod(info.FullMethod) {
			return handler(srv, stream)
		}

		// Extract and validate token
		userCtx, restriction, err := authenticateRequest(stream.Context(), coreService, requireMFA)
		if err != nil {
			return err
		}

		if blockedUnderImpersonation(info.FullMethod) && userCtx.ImpersonatedBy != nil {
			return status.Error(codes.PermissionDenied, "this action is not permitted while impersonating")
		}

		// Create a new stream with user context (+ audit attribution / PAT restriction).
		streamCtx := context.WithValue(stream.Context(), userContextKey, userCtx)
		streamCtx = withAuditAttribution(streamCtx, userCtx)
		if restriction != nil {
			streamCtx = core.WithPATRestriction(streamCtx, restriction)
		}
		// #G07: see AuthInterceptor's identical tag.
		streamCtx = core.WithSessionAuth(streamCtx, userCtx.SessionAuth)
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          streamCtx,
		}

		return handler(srv, wrappedStream)
	}
}

// credentialMintingMethods are the RPCs that issue a durable credential and so must be
// refused while impersonating (parity with the HTTP BlockWhenImpersonating routes). A
// token minted here would outlive the bounded, audited impersonation session with no
// impersonation attribution. Keep in sync with the HTTP routes wrapped in
// BlockWhenImpersonating. (Service-account token issuance has no gRPC surface today.)
var credentialMintingMethods = map[string]bool{
	pb.MachineIdentityService_IssueMachineToken_FullMethodName: true,
	// #G07: ActivateBreakGlass mints a durable, time-bound role grant
	// attributed to the impersonated TARGET that outlives the bounded,
	// audited impersonation session — the same class of credential-minting
	// action IssueMachineToken is blocked for; the HTTP route
	// (POST /projects/{id}/break-glass) gets the identical BlockWhenImpersonating
	// guard.
	pb.BreakGlassService_ActivateBreakGlass_FullMethodName: true,
}

// blockedUnderImpersonation reports whether fullMethod mints a durable credential that
// must not be created while impersonating.
func blockedUnderImpersonation(fullMethod string) bool {
	return credentialMintingMethods[fullMethod]
}

// wrappedServerStream wraps grpc.ServerStream to override context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context // NOSONAR
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// withAuditAttribution tags ctx so audit events written downstream over gRPC carry
// the same actor accountability the HTTP path records in buildRequestContext:
//
//   - a machine-identity request is actored as a machine (ADR-023/030) rather than
//     defaulting to "user";
//   - an impersonation session records the initiating admin (ImpersonatedBy /
//     Impersonation=true), so an admin acting through impersonation stays
//     attributable over gRPC just as on HTTP.
//
// Without this, switching transport to gRPC silently dropped both tags — machine
// actions were logged as user actions and impersonated actions lost the admin.
//
// Also tags WHICH machine (core.WithMachineActor), not just that a machine
// acted — the HTTP path has always done this (buildRequestContext), but gRPC
// never called it, so writeAuditEvent* recorded gRPC machine mutations
// without a MachineIdentityID. Audit-trail attribution only: this tag is
// deliberately NOT consulted for any authorization decision (see authz.go's
// requireGranterHoldsRolePermissions doc for why resolving a ctx-tagged
// machine's own permissions there is unsafe for /system proxy relays).
func withAuditAttribution(ctx context.Context, userCtx *UserContext) context.Context {
	if userCtx == nil {
		return ctx
	}
	if userCtx.ActorType == core.ActorTypeMachine {
		ctx = core.WithActorType(ctx, core.ActorTypeMachine)
		ctx = core.WithMachineActor(ctx, userCtx.MachineIdentityID)
	}
	if userCtx.ImpersonatedBy != nil {
		ctx = core.WithImpersonation(ctx, *userCtx.ImpersonatedBy)
	}
	return ctx
}

// grpcAuthFailure records a failed token-validation attempt against the
// caller's peer IP (mirrors HTTP's PAT-003 recordTokenAuthFailure, see
// rate_limit.go) and returns the error authenticateRequest should report:
// ResourceExhausted once that IP's failure budget is exhausted, otherwise the
// ordinary "invalid or expired token" Unauthenticated error a single bad
// request has always gotten. Deliberately NOT called for the cheap
// extraction failures above (missing metadata/header/token) — mirroring the
// HTTP precedent, only an actual validated-against-the-store failure (a real
// candidate token that was checked and rejected) consumes the budget, since
// that is the expensive, attacker-relevant case (credential brute-forcing),
// not a malformed or absent header.
//
// Called from both the unary (AuthInterceptor) and stream (StreamAuthInterceptor)
// paths via this shared function, so G41's failed-auth-hammering gap is closed
// once for both RPC styles rather than needing a chain reorder on either side.
func grpcAuthFailure(ctx context.Context) error {
	if !recordGRPCTokenAuthFailure(PeerIP(ctx)) {
		return status.Error(codes.ResourceExhausted, "too many invalid token attempts")
	}
	return status.Errorf(codes.Unauthenticated, "Invalid or expired token")
}

// authenticateRequest extracts the bearer token from the request metadata and
// validates it against the core service — the same paths the HTTP API uses. A
// kx_pat_ token authenticates as its owning user via ValidatePATToken and may
// carry a least-privilege restriction (ADR-042); anything else is a session
// token. On success it returns the authenticated user's context (id, identity,
// roles, permissions) and the PAT restriction (nil for sessions) for downstream
// authorization.
func authenticateRequest(ctx context.Context, coreService *core.KeyorixCore, requireMFA bool) (*UserContext, *core.PATRestriction, error) {
	if coreService == nil {
		// Fail closed: a server wired without a core service must not authenticate.
		return nil, nil, status.Errorf(codes.Internal, "authentication unavailable")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Missing metadata")
	}

	// Extract authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Missing authorization header")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Missing token")
	}

	// A machine-identity token (ADR-030) authenticates as a machine principal — no
	// owning user, no admin bypass downstream (AuthorizePrincipal resolves machine
	// roles). Routed by prefix, fails closed.
	if strings.HasPrefix(token, machineTokenPrefix) {
		return validateGRPCMachineToken(ctx, coreService, token)
	}

	// Validate the token (existence + expiry/revocation) and resolve the user. A
	// PAT resolves to its owner plus an optional restriction; both fail closed.
	var (
		user        *models.User
		restriction *core.PATRestriction
		patID       uint
		err         error
	)
	viaPAT := strings.HasPrefix(token, patTokenPrefix)
	if viaPAT {
		user, _, restriction, patID, err = coreService.ValidatePATToken(ctx, token)
	} else {
		user, _, err = coreService.ValidateSessionToken(ctx, token)
	}
	if err != nil {
		// #1944: a storage failure resolving the (otherwise valid) credential's
		// roles is retryable, not a bad token — answer Unavailable and don't
		// count it against the peer's brute-force budget, matching the HTTP
		// middleware's 503 for the same error.
		if errors.Is(err, core.ErrRoleResolutionUnavailable) {
			return nil, nil, status.Error(codes.Unavailable, "authentication temporarily unavailable, please retry")
		}
		return nil, nil, grpcAuthFailure(ctx)
	}

	// Session tokens: every per-session fact comes from ONE read of the session
	// row (core.ResolveSessionAuthFacts), the same one the HTTP middleware makes:
	//   - #G18: the row id (not the raw token — see UserContext.SessionID's doc
	//     comment), so a long-lived stream's periodic re-authorization re-verifies
	//     THIS SPECIFIC session, not just the owning account;
	//   - the impersonator, so audit events record the initiating admin as on HTTP
	//     and credential-minting RPCs are refused under impersonation;
	//   - #3024: whether this is a setup-only session (enforceGRPCAccountSetup).
	// Fail closed when the read fails (#3041 review): each fact restricts the
	// caller, so defaulting them would serve a setup-only or impersonation
	// session as an ordinary one. Unavailable, not a strike against the peer's
	// brute-force budget; core logs and audits the refusal.
	var (
		sessionID      *uint
		impersonatedBy *uint
		setupOnly      bool
	)
	if !viaPAT {
		facts, err := coreService.ResolveSessionAuthFacts(ctx, user.ID, token, "grpc")
		if err != nil {
			return nil, nil, status.Error(codes.Unavailable, "authentication temporarily unavailable, please retry")
		}
		id := facts.SessionID
		sessionID = &id
		impersonatedBy = facts.ImpersonatedBy
		setupOnly = facts.SetupOnly
	}

	viaSession := !viaPAT
	// Mirror the HTTP authed-group gates over gRPC so neither is bypassable by switching
	// transport (the same class of gap ADR-066 closed for the IP allowlist):
	//
	//   - PAT network allowlist (ADR-066): fail-closed on undeterminable peer IP.
	//   - Account restriction (ADR-025): a pending_first_login / password_reset_required
	//     account must change its password first. On HTTP it is confined to the
	//     change-password allowlist; gRPC has no such endpoint, so it is denied outright.
	//   - MFA enrolment (ADR-037): when the deployment mandates MFA, an interactive
	//     session without MFA is confined to the enrolment endpoints on HTTP; again gRPC
	//     has none, so deny. PATs and machine tokens are non-interactive and exempt,
	//     exactly as on HTTP — automation must not break.
	//
	// Both fail closed. viaSession is true for a session token (machine tokens already
	// returned above; a PAT carries the patTokenPrefix).
	if err := enforceGRPCAccountSetup(user, requireMFA, viaSession, setupOnly, impersonatedBy != nil); err != nil {
		return nil, nil, err
	}
	if err := enforceGRPCAccessPolicy(ctx, user, restriction, requireMFA, viaSession); err != nil {
		return nil, nil, err
	}

	// #G60: stamp last_used_at only now that the PAT's network restriction (and
	// the rest of enforceGRPCAccessPolicy) has actually been evaluated and
	// passed — touching earlier (formerly done unconditionally inside
	// ValidatePATToken) would mark a PAT as "used" even for a request just
	// rejected above for arriving from a disallowed network. No-op for a
	// non-PAT principal (patID is 0). gRPC has no auth cache, so every request
	// re-validates and this always runs on the success path.
	if viaPAT {
		coreService.TouchPATLastUsed(ctx, patID)
	}

	// Resolve roles + permissions for downstream per-method authorization.
	identity, err := coreService.GetUserIdentity(ctx, user.ID)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "failed to resolve user identity")
	}

	return &UserContext{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       identity.Roles,
		Permissions: identity.Permissions,
		// Carry the interactive-session and second-factor facts so the service layer can
		// apply the per-project MFA policy (ADR-037). viaSession is false for a PAT, which
		// stays exempt — exactly as the deployment-wide gate above and HTTP treat it.
		SessionAuth: viaSession,
		SessionID:   sessionID,
		MFAEnabled:  user.MFAEnabled || user.WebAuthnEnabled,
		// Carry the impersonation attribution so the interceptor can tag the request
		// context (core.WithImpersonation) — audit parity with HTTP.
		ImpersonatedBy: impersonatedBy,
	}, restriction, nil
}

func validateGRPCMachineToken(ctx context.Context, coreService *core.KeyorixCore, token string) (*UserContext, *core.PATRestriction, error) {
	machine, roles, restriction, credID, err := coreService.ValidateMachineToken(ctx, token)
	if err != nil {
		// #2748: a storage failure resolving the (otherwise valid) machine
		// identity's roles is retryable, not a bad token — answer Unavailable
		// and don't count it against the peer's brute-force budget, exactly as
		// the user-credential path above does for the same sentinel (#1944).
		// Without this the machine path would turn a role-lookup blip into a
		// permanent-looking 401 plus a strike against the caller's egress IP.
		if errors.Is(err, core.ErrRoleResolutionUnavailable) {
			return nil, nil, status.Error(codes.Unavailable, "authentication temporarily unavailable, please retry")
		}
		return nil, nil, grpcAuthFailure(ctx)
	}
	uc := &UserContext{
		Username:          machine.Name,
		Roles:             roles,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: machine.ID,
	}
	// Enforce machine token IP allowlist via gRPC peer IP. restriction is nil
	// unless machineRestrictionFrom found at least one CIDR (it never returns
	// a non-nil restriction with an empty AllowedCIDRs), so a non-nil check
	// alone is sufficient here — no separate length guard needed.
	if restriction != nil {
		if !core.IPInCIDRs(PeerIP(ctx), restriction.AllowedCIDRs) {
			return nil, nil, status.Errorf(codes.PermissionDenied, "token not permitted from this network")
		}
	}
	// #G60: stamp last_used_at only now that the network restriction has been
	// evaluated and passed (sibling of the same fix for the PAT path below).
	// gRPC has no auth cache, so this always runs on the success path.
	coreService.TouchMachineTokenLastUsed(ctx, credID)
	return uc, nil, nil
}

// gRPC status messages of the account-setup gate (enforceGRPCAccountSetup),
// distinct from every other interceptor message so the guard tests can tell
// this gate's refusals apart.
const (
	grpcSetupOnlyMsg     = "a setup-only session can only change the password and enrol a second factor, which are not available over gRPC: finish account setup over the REST API or the CLI"
	grpcSetupCompleteMsg = "account setup is complete: sign in again with your new password and second factor"
	grpcSetupReauthMsg   = "sign in again to finish account setup"
)

// enforceGRPCAccountSetup is the gRPC side of the HTTP EnforceAccountSetup gate
// (server/middleware, #3024). On HTTP a session owing setup steps reaches the
// union of those steps' endpoints (setupStepRoutes) plus a profile read. gRPC
// has none of those endpoints — no password-change, enrolment or profile RPC —
// so on gRPC that allowlist is empty and a setup-only session is refused every
// RPC (the guard TestEveryGRPCMethod_RefusesSetupOnlySession walks every
// registered RPC and pins the allowed set as empty). Like HTTP:
//
//   - a setup-only session that owes nothing any more is told to sign in again
//     (Unauthenticated): core revokes it when the last step completes
//     (EndSetupSessionIfComplete), and this is the backstop when that
//     revocation did not land (#3041 review: without it the surviving session
//     had full gRPC access);
//   - a setup-only session still owing a step is refused (PermissionDenied);
//   - an ordinary (non-impersonation) session owing both steps is told to sign
//     in again, which yields a setup-only session.
//
// A session owing exactly one step that is not setup-only falls through to
// enforceGRPCAccessPolicy, which refuses it as before.
func enforceGRPCAccountSetup(user *models.User, requireMFA, viaSession, setupOnly, impersonated bool) error {
	pending := core.PendingAccountSetupSteps(core.AccountRestricted(user.AccountState),
		user.MFAEnabled || user.WebAuthnEnabled, viaSession, requireMFA)
	switch {
	case setupOnly && len(pending) == 0:
		return status.Error(codes.Unauthenticated, grpcSetupCompleteMsg)
	case setupOnly:
		return status.Error(codes.PermissionDenied, grpcSetupOnlyMsg)
	case viaSession && !impersonated && len(pending) == 2:
		return status.Error(codes.Unauthenticated, grpcSetupReauthMsg)
	}
	return nil
}

func enforceGRPCAccessPolicy(ctx context.Context, user *models.User, restriction *core.PATRestriction, requireMFA, viaSession bool) error {
	if restriction != nil && len(restriction.AllowedCIDRs) > 0 {
		if !core.IPInCIDRs(PeerIP(ctx), restriction.AllowedCIDRs) {
			return status.Errorf(codes.PermissionDenied, "token not permitted from this network")
		}
	}
	if core.AccountRestricted(user.AccountState) {
		return status.Errorf(codes.PermissionDenied, "password change required before access")
	}
	if requireMFA && viaSession && !(user.MFAEnabled || user.WebAuthnEnabled) {
		return status.Errorf(codes.PermissionDenied, "multi-factor authentication enrolment required")
	}
	return nil
}

// PeerIP returns the source IP of the gRPC call from its peer (TCP) address, or "" if
// it cannot be determined (which the fail-closed allowlist check then denies). Exported
// so the service layer can stamp it on secret-access logs, matching the HTTP path.
func PeerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
		return host
	}
	return p.Addr.String()
}

// ClientUserAgent returns the gRPC client's user-agent from request metadata, or ""
// when absent. Recorded on secret-access logs alongside the peer IP, as on HTTP.
func ClientUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if ua := md.Get("user-agent"); len(ua) > 0 {
		return ua[0]
	}
	return ""
}

// isPublicMethod checks if a gRPC method is public (doesn't require authentication)
var grpcPublicMethods = []string{
	"/grpc.health.v1.Health/Check",
	"/keyorix.v1.SystemService/HealthCheck", // liveness probe — no auth
}

func isPublicMethod(method string) bool {
	return slices.Contains(grpcPublicMethods, method)
}

// GetUserFromGRPCContext extracts the user context from the gRPC request context
func GetUserFromGRPCContext(ctx context.Context) *UserContext {
	if userCtx, ok := ctx.Value(userContextKey).(*UserContext); ok {
		return userCtx
	}
	return nil
}

// GetUserContextKey returns the context key for user context (for testing)
func GetUserContextKey() contextKey {
	return userContextKey
}
