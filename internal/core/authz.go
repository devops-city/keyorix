// authz.go — Scope-aware permission enforcement (RBAC Phase 2).
//
// Authorize is the single entrypoint the HTTP middleware uses to decide whether
// a user may perform an action against a particular project/environment. It
// resolves the roles that apply at the target scope — both directly assigned and
// inherited via group membership — then checks whether any of them grants the
// permission. A user holding the admin (or super_admin) role at, or above, the
// target scope bypasses the specific-permission check: the super-user escape
// hatch. All resolution errors fail closed (deny).
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PATRestriction bounds what a request authenticated by a personal access token
// (ADR-042) may do, independent of — and intersected with — the owning user's own
// permissions. It is a least-privilege FILTER: it can only narrow a token below
// its owner, never grant the owner anything extra. The owner's live role
// resolution still runs after this check, so a restriction listing a permission
// the owner has since lost grants nothing.
type PATRestriction struct {
	// Permissions, when non-empty, is the exhaustive allowlist of permission
	// strings the token may exercise. Empty = inherit the owner's full set. An
	// entry may be an exact permission ("secrets.read"), the catch-all "*", or a
	// prefix wildcard ("secrets.*").
	Permissions []string
	// ProjectID, when non-zero, restricts the token to that project's scope;
	// any check at a different project — or at global/system scope (project 0) —
	// is denied. Zero = any scope the owner can reach.
	ProjectID uint
	// EnvironmentID, when non-zero, further restricts the token to that one
	// environment: any check whose resolved scope is a different environment — or a
	// project-level/global scope (environment 0) — is denied. Environment ids are
	// globally unique, so this confines the token to that env's project too. Zero =
	// any environment. (Secret-level checks carry the secret's environment; broader
	// project-level operations resolve environment 0 and so are denied for an
	// environment-scoped token — correct least privilege for, e.g., a staging-only
	// CI credential.)
	EnvironmentID uint
	// AllowedCIDRs, when non-empty, restricts the token to requests whose source IP falls
	// within one of the listed CIDR blocks. Enforced at the auth boundary (fail-closed: an
	// undeterminable/unparseable source IP is denied). Empty = no network restriction.
	AllowedCIDRs []string
}

// MachineTokenRestriction carries the network-level constraints a machine
// identity credential may impose. When AllowedCIDRs is non-empty, the
// request source IP must fall within one of the listed blocks; a stolen
// machine token is therefore useless from outside the allowed network.
type MachineTokenRestriction struct {
	AllowedCIDRs []string
}

// IPInCIDRs reports whether ip (a bare host like "203.0.113.7") falls within any of the
// given CIDR blocks. It is the network gate for IP-allowlisted tokens and fails CLOSED:
// an unparseable ip, an empty cidr list passed as a gate, or a malformed CIDR yields false
// (callers only invoke it when the token actually carries an allowlist).
func IPInCIDRs(ip string, cidrs []string) bool {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

// Allows reports whether this restriction permits exercising permission at scope.
// A nil restriction (no PAT, or an unrestricted PAT) is handled by the caller.
func (r *PATRestriction) Allows(permission string, scope Scope) bool {
	if r == nil {
		return true
	}
	// A project-scoped token may act ONLY within its project. A check at global
	// scope (ProjectID 0 — system-wide actions like users.read) is therefore
	// denied for a project-scoped token: it is not a system credential.
	if r.ProjectID != 0 && scope.ProjectID != r.ProjectID {
		return false
	}
	// An environment-scoped token may act ONLY within its environment; a check at a
	// different (or project-level/global) environment is denied.
	if r.EnvironmentID != 0 && scope.EnvironmentID != r.EnvironmentID {
		return false
	}
	if len(r.Permissions) == 0 {
		return true
	}
	for _, p := range r.Permissions {
		if p == "*" || p == permission {
			return true
		}
		if strings.HasSuffix(p, ".*") && strings.HasPrefix(permission, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

// patRestrictionCtxKey is the unexported context key carrying a *PATRestriction.
type patRestrictionCtxKey struct{}

// WithPATRestriction tags ctx with the restriction a personal access token
// imposes on the request. The auth middleware sets it for PAT-authenticated
// requests only; session, machine and OIDC requests never carry one. Authorize
// and AuthorizePrincipal read it back so the restriction is enforced uniformly at
// the single authorization chokepoint — every present and future authz path.
func WithPATRestriction(ctx context.Context, r *PATRestriction) context.Context {
	return context.WithValue(ctx, patRestrictionCtxKey{}, r)
}

// patRestrictionFromContext returns the PAT restriction on ctx, or nil if none.
func patRestrictionFromContext(ctx context.Context) *PATRestriction {
	r, _ := ctx.Value(patRestrictionCtxKey{}).(*PATRestriction)
	return r
}

// sessionAuthCtxKey is the unexported context key carrying whether the request
// authenticated via a genuine interactive session token.
type sessionAuthCtxKey struct{}

// WithSessionAuth tags ctx with whether the request authenticated via a real
// interactive session token — true only for a session; false for a PAT
// (restricted or not) or a machine token, which are non-interactive
// credentials. #G07: StartImpersonation reads this back, because
// patRestrictionFromContext alone can't distinguish "no restriction" from "no
// PAT at all" — an UNRESTRICTED PAT carries a nil restriction identical to a
// session's, so a check gated only on PATRestriction != nil misses it.
func WithSessionAuth(ctx context.Context, sessionAuth bool) context.Context {
	return context.WithValue(ctx, sessionAuthCtxKey{}, sessionAuth)
}

// sessionAuthFromContext reports whether ctx was tagged as a genuine
// interactive session. Defaults to true when untagged (e.g. a test or an
// internal/CLI call with no HTTP/gRPC auth layer in front of it) so this
// check only ever narrows a request the auth layer explicitly marked
// non-interactive, never a caller the auth layer never touched.
func sessionAuthFromContext(ctx context.Context) bool {
	v, ok := ctx.Value(sessionAuthCtxKey{}).(bool)
	if !ok {
		return true
	}
	return v
}

// Scope identifies the project/environment an authorization check or a role
// assignment applies to. It aliases storage.Scope so the same 0 = global
// sentinel flows from the HTTP layer through to the queries unchanged.
type Scope = storage.Scope

// adminRoleNames are roles that bypass the per-permission check at the scope
// they are assigned. A global (project 0) admin therefore bypasses everywhere;
// a project-scoped admin bypasses only within that project.
//
// "admin"/"super_admin" are the legacy single-tier super-users; "system_admin"
// and "project_admin" are the ADR-021 two-tier equivalents. A system_admin is
// expected to be assigned globally (bypasses install-wide); a project_admin is
// expected to be assigned at a project scope (bypasses within that project).
var adminRoleNames = []string{"super_admin", "admin", "system_admin", "project_admin"}

// isAdminRoleName reports whether roleName is one of the admin (permission-bypass)
// roles — a pure-string check requiring no storage lookup, for guards that already
// hold the role name.
func isAdminRoleName(roleName string) bool {
	return slices.Contains(adminRoleNames, roleName)
}

// AuthorizePrincipal reports whether a principal — a human user or a machine
// identity (ADR-030) — may exercise permission against the target scope. It is
// the actor-aware entrypoint the auth gates use; Authorize is the user-only
// wrapper kept for source compatibility. Machine principals resolve their
// permissions from machine_identity_roles and receive NO admin-role bypass: a
// machine is never a global super-user, so a leaked machine token is bounded to
// the permissions of its explicit grants. Fails closed.
func (c *KeyorixCore) AuthorizePrincipal(ctx context.Context, actorType string, principalID uint, permission string, scope Scope) (bool, error) {
	// A personal access token may carry a least-privilege restriction (ADR-042)
	// that narrows it below its owner. Enforce it first, before any role
	// resolution or admin bypass, so even a global-admin's token is bounded. Only
	// PAT-authenticated (user-actored) requests ever carry one, but the check is
	// safe on every path. Fails closed (deny) when the restriction disallows.
	if !patRestrictionFromContext(ctx).Allows(permission, scope) {
		return false, nil
	}
	if actorType == ActorTypeMachine {
		roleIDs, err := c.storage.GetMachineRoleIDsAt(ctx, principalID, scope)
		if err != nil {
			return false, err
		}
		if len(roleIDs) == 0 {
			return false, nil
		}
		return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
	}
	return c.Authorize(ctx, principalID, permission, scope)
}

// Authorize reports whether userID may exercise permission (e.g. "secrets.read")
// against the target scope. Fails closed: any resolution error returns
// (false, err).
func (c *KeyorixCore) Authorize(ctx context.Context, userID uint, permission string, scope Scope) (bool, error) {
	// PAT least-privilege filter (ADR-042) — narrows even an admin owner. Applied
	// here too (not only in AuthorizePrincipal) so direct Authorize callers and the
	// admin bypass below are equally bounded. Idempotent on the AuthorizePrincipal
	// path, which already checked it.
	if !patRestrictionFromContext(ctx).Allows(permission, scope) {
		return false, nil
	}
	roleIDs, err := c.scopedRoleIDs(ctx, userID, scope)
	if err != nil {
		return false, err
	}
	if len(roleIDs) == 0 {
		return false, nil
	}
	containsAdmin, err := c.roleSetContainsAdmin(ctx, roleIDs)
	if err != nil {
		return false, err
	}
	if containsAdmin {
		return true, nil
	}
	return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
}

// principalHasScopedPermission reports whether userID's OWN roles grant permission at
// scope, independent of any PAT restriction on the context (which belongs to the
// requesting actor, not this user). Use it to vet a THIRD party — e.g. a prospective
// secret owner — without the caller's token narrowing the result. Fails closed.
func (c *KeyorixCore) principalHasScopedPermission(ctx context.Context, userID uint, permission string, scope Scope) (bool, error) {
	roleIDs, err := c.scopedRoleIDs(ctx, userID, scope)
	if err != nil {
		return false, err
	}
	if len(roleIDs) == 0 {
		return false, nil
	}
	containsAdmin, err := c.roleSetContainsAdmin(ctx, roleIDs)
	if err != nil {
		return false, err
	}
	if containsAdmin {
		return true, nil
	}
	return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
}

// AuthorizeSecret checks whether userID may perform perm on the given secretID.
// It first checks any explicit SecretACL grant (RBAC Phase 3); if found and it covers
// perm, returns true immediately — the user need not hold a project role. Otherwise
// falls back to project-scope RBAC (Authorize at the secret's own project/environment
// scope), and finally to the share term (#2941, share_authz.go): an active share to a
// project member satisfies secrets.read (read|write share). It names no SecretAction,
// so a write share elevates nothing here; a per-secret write gate uses
// AuthorizeSecretAction. Fails closed: any resolution error returns (false, err).
func (c *KeyorixCore) AuthorizeSecret(ctx context.Context, userID, secretID uint, perm string) (bool, error) {
	d, err := c.AuthorizeSecretAction(ctx, userID, secretID, perm, "")
	return d.Allowed, err
}

// SecretDecision is the outcome of a per-secret authorization.
type SecretDecision struct {
	Allowed bool
	// ShareNotElevated: refused, and the actor holds an active share that covers perm
	// on this secret, but action is not one a share may elevate. Transports answer
	// with ShareActionNotElevatedMessage instead of a bare 403. The actor already
	// knows the secret exists (they hold a share on it), so this reveals nothing.
	ShareNotElevated bool
}

// AuthorizeSecretAction is AuthorizeSecret for a gate that names the action it
// guards: ACL, then role, then the share term, which may elevate secrets.write only
// for an allowlisted action (secretActionShareElevates). A share-made grant is
// recorded on ctx's ShareElevationRecorder and audited when the action is performed
// (noteShareElevation); the ACL or role allowing it records nothing.
func (c *KeyorixCore) AuthorizeSecretAction(ctx context.Context, userID, secretID uint, perm string, action SecretAction) (SecretDecision, error) {
	deny := SecretDecision{}
	// Resolve the secret first so we know its scope for the PAT check below.
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return deny, err
	}
	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	// PAT-SCOPE-002: a per-secret ACL grant must not let a project-scoped PAT read
	// secrets outside the token's own project/environment — check the restriction
	// against the secret's actual scope before honouring an ACL grant.
	if !patRestrictionFromContext(ctx).Allows(perm, scope) {
		return deny, nil
	}
	// Check per-secret ACL (additive grant).
	hasACL, err := c.HasSecretACL(ctx, userID, secretID, perm)
	if err != nil {
		return deny, err
	}
	if hasACL {
		return SecretDecision{Allowed: true}, nil
	}
	// Fall back to project-scope RBAC.
	allowed, err := c.Authorize(ctx, userID, perm, scope)
	if err != nil || allowed {
		return SecretDecision{Allowed: allowed}, err
	}
	// Share term (#2941): consulted only when ACL and role both said no, so the
	// share_access_elevated audit row marks exactly the actions a share made possible.
	need := shareNeedFor(perm)
	if need == PermissionNone {
		return deny, nil
	}
	grant, err := c.sharePermissionFor(ctx, userID, secretID, secret.ProjectID, need, action)
	if err != nil {
		return deny, err
	}
	if grant.Level == PermissionNone {
		deny.ShareNotElevated = c.shareCoversButNotElevated(ctx, userID, secretID, secret.ProjectID, need, action)
		return deny, nil
	}
	if !c.noteShareElevation(ctx, userID, secret, perm, action, grant) {
		return deny, nil
	}
	return SecretDecision{Allowed: true}, nil
}

// AuthorizeSecretPrincipal is the actor-aware counterpart to AuthorizeSecret,
// mirroring AuthorizePrincipal's split between human users and machine
// identities (ADR-030). It is the entrypoint the per-secret HTTP routes use
// (RequireScopedSecretPermission) so a per-secret SecretACL grant (RBAC Phase 3)
// is honored for the ~15 GET/PUT/DELETE routes gated on a specific secret ID,
// not just the ListSecrets surface.
//
// SecretACL rows are inherently user-scoped (models.SecretACL.UserID; see
// secret_acl.go's GrantSecretACL, which requires the grantee to be a project
// member — a concept that doesn't apply to machine identities). A machine
// identity's principal ID lives in an entirely separate ID space/table from
// User, so treating it as a userID for the ACL lookup would risk an accidental
// match against an unrelated human's grant purely by numeric coincidence.
// Machine/OIDC-federated principals therefore always take the existing
// role-based AuthorizePrincipal path unchanged — byte-for-byte the behavior
// before this function existed. Fails closed.
func (c *KeyorixCore) AuthorizeSecretPrincipal(ctx context.Context, actorType string, principalID, secretID uint, permission string) (bool, error) {
	if actorType != ActorTypeMachine {
		return c.AuthorizeSecret(ctx, principalID, secretID, permission)
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return false, err
	}
	return c.AuthorizeSecretPrincipalForSecret(ctx, actorType, principalID, secret, permission)
}

// AuthorizeSecretPrincipalForSecret is AuthorizeSecretPrincipal for a caller that
// has already resolved the secret (e.g. the route's own scoped-permission
// middleware), skipping the redundant storage.GetSecret fetch
// AuthorizeSecretPrincipal would otherwise do internally to compute the same
// scope (SESSION-PERF, #2403 follow-up). Identical decision logic to
// AuthorizeSecretPrincipal — that function now delegates to this one after its
// own fetch, so there is exactly one authorization-decision code path, not two
// to keep in sync.
func (c *KeyorixCore) AuthorizeSecretPrincipalForSecret(ctx context.Context, actorType string, principalID uint, secret *models.SecretNode, permission string) (bool, error) {
	d, err := c.AuthorizeSecretPrincipalForSecretAction(ctx, actorType, principalID, secret, permission, "")
	return d.Allowed, err
}

// AuthorizeSecretPrincipalForSecretAction is AuthorizeSecretPrincipalForSecret for a
// gate that names its SecretAction (every per-secret secrets.write gate does). Machine
// principals take the role-only path, as always: shares never apply to them.
func (c *KeyorixCore) AuthorizeSecretPrincipalForSecretAction(ctx context.Context, actorType string, principalID uint, secret *models.SecretNode, permission string, action SecretAction) (SecretDecision, error) {
	if actorType != ActorTypeMachine {
		return c.AuthorizeSecretAction(ctx, principalID, secret.ID, permission, action)
	}
	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	allowed, err := c.AuthorizePrincipal(ctx, actorType, principalID, permission, scope)
	return SecretDecision{Allowed: allowed}, err
}

// IsGlobalAdmin answers a SELF-CHECK: "should userID — always the ctx's own
// acting principal — be treated as an unrestricted global admin for this
// request." It must never be called with a userID other than the ctx's own
// actor; see targetHasGlobalAdminRole for that different question.
//
// A request carrying a PAT least-privilege restriction (ADR-042) is never treated
// as an unrestricted global admin: the token was deliberately scoped below its
// owner, so a caller that uses this to return unfiltered data must instead fall
// back to the scope-filtered path. Returning false here is fail-closed — the
// filtered path can only ever return a subset — and keeps the restriction honoured
// on this otherwise un-funnelled authz path (it does not flow through Authorize).
func (c *KeyorixCore) IsGlobalAdmin(ctx context.Context, userID uint) (bool, error) {
	if patRestrictionFromContext(ctx) != nil {
		return false, nil
	}
	return c.targetHasGlobalAdminRole(ctx, userID)
}

// targetHasGlobalAdminRole answers a THIRD-PARTY QUESTION: "does targetID
// currently hold a global admin-tier role" — a fact about targetID, never
// about whoever is asking. Deliberately does NOT consult
// patRestrictionFromContext(ctx): that check exists solely to stop the
// CALLER's own scoped PAT from being treated as unrestricted-admin authority
// (see IsGlobalAdmin) and is meaningless here, since the question isn't about
// the caller at all.
//
// Found 2026-09-07 (ADR conformance review, HIGH): guardLastAdminDeactivation
// and SuspendInactiveUsers both reused IsGlobalAdmin to ask this third-party
// question, so an admin acting through their own ordinary scoped PAT made
// IsGlobalAdmin's short-circuit fire on the ACTOR's restriction rather than
// the TARGET's actual role — silently reporting every target as "not an
// admin" regardless of truth, which let the last-global-admin lockout guard
// (and the inactivity-suspend admin-skip check) both no-op. Use this function
// for any "is THIS OTHER PRINCIPAL an admin" query; use IsGlobalAdmin only
// for "should THE CALLER be treated as one."
func (c *KeyorixCore) targetHasGlobalAdminRole(ctx context.Context, targetID uint) (bool, error) {
	roleIDs, err := c.scopedRoleIDs(ctx, targetID, Scope{})
	if err != nil {
		return false, err
	}
	return c.roleSetContainsAdmin(ctx, roleIDs)
}

// scopedRoleIDs returns the de-duplicated set of role IDs that apply to userID
// at the target scope, unioning direct assignments and group-inherited roles.
func (c *KeyorixCore) scopedRoleIDs(ctx context.Context, userID uint, scope Scope) ([]uint, error) {
	direct, err := c.storage.GetUserRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	viaGroups, err := c.storage.GetUserGroupRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	return dedupeUints(append(direct, viaGroups...)), nil
}

// roleSetContainsAdmin reports whether any role ID in the set has the
// structural bypasses_permission_checks flag (ADR-084). This resolves by ID
// against the flag, not by matching a fixed name list — a rename never moves
// the flag, and a newly-created role never has it regardless of what it is
// named (see models.Role.BypassesPermissionChecks's doc comment for exactly
// where it is ever written). Fails closed on a genuine resolution error: any
// storage error is returned to the caller rather than silently treated as
// "no admin role found" — #G17 (enforceProjectMFA/ProjectMFABlocked,
// server/grpc/services/conversions.go and server/middleware/auth.go) is the
// precedent this mirrors: a lookup error on a security-relevant path must not
// be indistinguishable from a legitimate negative result, or a caller can
// trigger the same lookup error to silently bypass whatever the error would
// otherwise have blocked.
func (c *KeyorixCore) roleSetContainsAdmin(ctx context.Context, roleIDs []uint) (bool, error) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- roleIDs is a principal's resolved current role set (scopedRoleIDs/GetUserRoleIDsAt), not a raw client-supplied array; every call site passes an internally-computed list
	if len(roleIDs) == 0 {
		return false, nil
	}
	return c.storage.RoleSetBypassesPermissionChecks(ctx, roleIDs)
}

// idpAutoGrantOfRoleIsEscalation reports whether an IdP-DRIVEN automatic grant of this
// role (SSO GroupRoleMap reconciliation, or SCIM/SSO group-membership conferral) must be
// REFUSED, because a self-service IdP group would otherwise become a path to
// administrative or self-propagating privilege. IdP-driven auto-grants deliberately skip
// the normal grant-ceiling (the logging-in user cannot pre-hold the role's permissions on
// their first SSO login — sso.go's reconcileSSORoles), so this predicate is the only
// backstop; before this it was inconsistent across the two surfaces (SSO checked the admin
// role NAME, SCIM checked the admin-bypass FLAG), and neither caught a custom role that
// bundled the role-granting primitive under a non-canonical name. It blocks a role that:
//   - carries the admin-bypass flag (RoleSetBypassesPermissionChecks), or
//   - is one of the canonical admin roles by name (isAdminRoleName), or
//   - grants roles.assign — the role-granting primitive. A holder of roles.assign can grant
//     roles onward (bounded by its own held permissions), so conferring it on anyone who can
//     join a self-service IdP group turns that group into a privilege pump regardless of the
//     role's name. This is the one permission whose self-service conferral is itself an
//     escalation vector.
//
// It deliberately does NOT block ordinary privileged roles (secrets read/write, system
// config, etc.): an admin who maps an IdP group to such a role is expressing intent, the
// same as granting it directly, and blocking those would break legitimate IdP-group→role
// configuration — the friction this product exists to avoid. Fails CLOSED on any lookup
// error (an inability to verify must never open the auto-grant), matching scimGroupConfersAdmin.
func (c *KeyorixCore) idpAutoGrantOfRoleIsEscalation(ctx context.Context, roleID uint, roleName string) bool {
	escalation, err := c.idpAutoGrantEscalationVerdict(ctx, roleID, roleName)
	return escalation || err != nil // fail closed: cannot verify → refuse the auto-grant
}

// idpAutoGrantEscalationVerdict is idpAutoGrantOfRoleIsEscalation with the lookup
// failure kept apart from the verdict: err != nil means NOTHING was decided. A
// caller that must tell "this role is admin-tier" from "could not find out" uses
// this one. SSO reconcile (#2910) does: the first is a counted, deliberate block,
// and the second is a reconcile error that refuses the login (#2839 condition 1).
// Either way the grant is not made.
func (c *KeyorixCore) idpAutoGrantEscalationVerdict(ctx context.Context, roleID uint, roleName string) (bool, error) {
	if isAdminRoleName(roleName) {
		return true, nil
	}
	bypass, err := c.roleSetContainsAdmin(ctx, []uint{roleID})
	if err != nil {
		return false, fmt.Errorf("resolving role %d's admin-bypass flag: %w", roleID, err)
	}
	if bypass {
		return true, nil
	}
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return false, fmt.Errorf("resolving role %d's permissions: %w", roleID, err)
	}
	for _, p := range perms {
		if p.Name == permRolesAssign {
			return true, nil
		}
	}
	return false, nil
}

// requireGlobalAdminToReinstateAdminRoles refuses to reinstate roleIDs unless
// actorID is themselves a global admin, but ONLY when roleIDs actually contains an
// admin-tier role — a non-admin role set passes untouched. Restoring a soft-deleted
// principal (a group, a project, an environment) brings back EVERY role grant it
// held atomically, in one step, with no per-role choice — unlike a single direct
// grant (requireAuthorityForRole, invitations.go), the restore may reinstate
// several roles at once, so the whole SET needs an aggregate ceiling check. Used
// by group/project/environment restore (#147/#161): a principal holding only the
// gating permission (roles.assign) — not admin authority itself — must not be able
// to resurrect an admin-conferring grant that was soft-deleted out from under them
// (e.g. an incident-response revocation), the same escalation-by-proxy shape
// requireAuthorityForRole closes for direct grants.
func (c *KeyorixCore) requireGlobalAdminToReinstateAdminRoles(ctx context.Context, actorID uint, roleIDs []uint, objectDesc string) error {
	containsAdmin, err := c.roleSetContainsAdmin(ctx, roleIDs)
	if err != nil {
		return fmt.Errorf("failed to resolve role authority: %w", err)
	}
	if !containsAdmin {
		return nil
	}
	isAdmin, err := c.IsGlobalAdmin(ctx, actorID)
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !isAdmin {
		return fmt.Errorf("only an administrator can restore a %s holding an administrative role grant", objectDesc)
	}
	return nil
}

// ceilingCacheEntry is a single cached result of requireEqualOrGreaterAdminAuthority.
type ceilingCacheEntry struct {
	err       error
	expiresAt time.Time
}

const ceilingCacheTTL = 60 * time.Second

// cachedImpersonationCeiling wraps requireStillAuthorizedToImpersonate with a
// short-lived cache (ceilingCacheTTL) so the expensive DB reads it issues are
// not repeated on every ValidateSessionToken call (IMP-001). The cache TTL is
// intentionally 2× the auth-cache window so a cache miss here never triggers
// two consecutive uncached ceiling checks within the same outer auth-cache miss.
//
// #1983 investigation, closed as NO BUG: this is an in-process TTL -- both
// entry.expiresAt (written below) and the comparison against it happen in
// THIS process, so both sides come from c.now() and, in production, retain
// Go's monotonic clock reading (time.Now(), unless something strips it).
// Go compares two monotonic-carrying times using ONLY the monotonic delta,
// which a host wall-clock step (an operator's `date -s`, an NTP correction)
// never affects -- this cache is therefore ALREADY immune to that threat,
// via the language's own guarantee, not anything this function does
// explicitly. Do NOT route this through authEffectiveNow, shareEffectiveNow,
// or a new equivalent watermark wrapper: those call .UTC() before clamping,
// which unconditionally strips the monotonic reading and REPLACES this
// existing immunity with a strictly weaker wall-clock-only comparison whose
// watermark then holds a stale verdict past its 60s TTL for as long as a
// backward step lasts -- confirmed as a real regression in two independent,
// since-closed fix attempts (#1994, #1995), neither merged. See
// impersonation_ceiling_monotonic_test.go, which pins this invariant, and
// docs/findings/2026-09-23-FINDING-impersonation-ceiling-monotonic-not-a-bug.md.
// That watermark pattern is correct for authEffectiveNow/shareEffectiveNow's
// OWN actual use (comparing against a PERSISTED instant -- a DB ExpiresAt, a
// JWT exp/iat -- that was serialized and never had a monotonic reading to
// begin with); it is the wrong tool for an in-process-only comparison like
// this one, which already has a stronger guarantee to lose.
func (c *KeyorixCore) cachedImpersonationCeiling(ctx context.Context, actorID, targetID uint) error {
	key := fmt.Sprintf("%d:%d", actorID, targetID)
	if v, ok := c.impersonationCeilingCache.Load(key); ok {
		if entry := v.(ceilingCacheEntry); c.now().Before(entry.expiresAt) {
			return entry.err
		}
	}
	err := c.requireStillAuthorizedToImpersonate(ctx, actorID, targetID)
	c.impersonationCeilingCache.Store(key, ceilingCacheEntry{err: err, expiresAt: c.now().Add(ceilingCacheTTL)})
	return err
}

// requireStillAuthorizedToImpersonate combines the two conditions that must
// continue to hold for the DURATION of an active impersonation session, not
// just at StartImpersonation's issuance-time check (#G05's detection_idea):
// the admin must still be independently granted users.impersonate — revoking
// it mid-session must end the session within one re-auth cycle, the same as
// revoking any other permission does for an ordinary session, not just block
// a NEW StartImpersonation call — and must still hold equal-or-greater
// authority than the target (the pre-existing MT-007 ceiling re-check).
// permUsersImpersonate is checked at global scope: impersonation authority is
// deployment-wide by design (StartImpersonation's target lookup is unscoped),
// mirroring the router's own RequirePermission("users.impersonate") gate.
func (c *KeyorixCore) requireStillAuthorizedToImpersonate(ctx context.Context, actorID, targetID uint) error {
	ok, err := c.Authorize(ctx, actorID, "users.impersonate", Scope{})
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !ok {
		return fmt.Errorf("impersonation authority has been revoked")
	}
	return c.requireEqualOrGreaterAdminAuthority(ctx, actorID, targetID, "impersonate")
}

// requireMachinePrivilegeCeiling refuses to hand actorType/principalID control
// over machineID — via minting it a credential, or (machineID==0) via creating
// it in the first place — when doing so would hand the actor more standing
// than their own privileges justify (MACH-001). Two branches:
//
//   - machineID's CURRENT roles already include an admin-tier role: the actor
//     must be a global admin. A machine actor can never satisfy this — ADR-030:
//     "a machine is never a global admin," so a machine holding an admin-tier
//     role itself can never mint a credential for ANOTHER admin-tier machine,
//     regardless of what that role's explicit permission bundle contains.
//   - Otherwise (machineID doesn't hold an admin-tier role today, OR
//     machineID==0 because the identity doesn't exist yet): the actor must
//     still hold roles.assign at the machine's own project scope — the SAME
//     authority the human-facing creation route (POST
//     /projects/{id}/machine-identities, RequireScopedPermission(roles.assign,
//     projectScope)) already requires. Examining only the target's CURRENT
//     roles, as this check originally did, let an actor with NO authority over
//     machine identities at all create a fresh one, mint themselves a working
//     credential for it (trivially clearing the "not admin-tier yet" branch,
//     since a brand-new identity holds no roles by construction), and reach
//     every /system route requiring only that credential — the actor's own
//     standing was never inspected in that branch at all. Minting a working
//     credential for ANY machine identity is equivalent to being able to act
//     as that machine within its project for as long as the credential lives,
//     including whatever roles it is granted later by anyone who separately
//     holds that same roles.assign authority — so the ceiling for "may this
//     actor control this identity's credential" is derived from the SAME
//     authority that already governs "may this actor bring this identity into
//     existence," not picked independently per call site.
func (c *KeyorixCore) requireMachinePrivilegeCeiling(ctx context.Context, actorType string, principalID, projectID, machineID uint) error {
	if machineID != 0 {
		roles, err := c.storage.GetMachineRoles(ctx, machineID)
		if err != nil {
			return fmt.Errorf("failed to check machine privilege ceiling: %w", err)
		}
		roleIDs := make([]uint, len(roles))
		for i, r := range roles {
			roleIDs[i] = r.ID
		}
		containsAdmin, err := c.roleSetContainsAdmin(ctx, roleIDs)
		if err != nil {
			return fmt.Errorf("failed to check machine privilege ceiling: %w", err)
		}
		if containsAdmin {
			isAdmin := false
			if actorType != ActorTypeMachine {
				var err error
				isAdmin, err = c.IsGlobalAdmin(ctx, principalID)
				if err != nil {
					return fmt.Errorf("failed to verify actor authority: %w", err)
				}
			}
			if !isAdmin {
				return fmt.Errorf("%w: issuing a token for a machine identity that holds administrative roles requires administrative authority", ErrMachinePrivilegeCeilingDenied)
			}
			return nil
		}
	}
	allowed, err := c.AuthorizePrincipal(ctx, actorType, principalID, permRolesAssign, Scope{ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("failed to verify actor authority: %w", err)
	}
	if !allowed {
		return fmt.Errorf("%w: creating a machine identity, or minting a credential for one, requires roles.assign at the project scope", ErrMachinePrivilegeCeilingDenied)
	}
	return nil
}

// RequireMachinePrivilegeCeiling is requireMachinePrivilegeCeiling's exported
// form, originally for callers outside internal/core that needed the SAME
// MACH-001 check IssueMachineToken already runs — CreateMachineIdentityCredentialProxy
// and CreateMachineIdentityProxy, both since deleted along with the rest of the
// RemoteStorage-sync proxy tree (ADR-108 Phase 6, #2162/#2171). Zero non-test
// callers remain today -- another candidate for the same follow-up cleanup
// pass as the plaintextValue/plaintextPassword variadics in
// internal/core/storage/interface.go, not removed here.
func (c *KeyorixCore) RequireMachinePrivilegeCeiling(ctx context.Context, actorType string, principalID, projectID, machineID uint) error {
	return c.requireMachinePrivilegeCeiling(ctx, actorType, principalID, projectID, machineID)
}

// requireEqualOrGreaterAdminAuthority refuses when targetID holds, at any scope
// (global OR project-scoped, direct OR group-inherited), a permission actorID
// does not ALSO effectively hold at that same scope. Unlike the single-scope
// IsGlobalAdmin check, this discovers and checks EVERY scope the target actually
// holds a grant at (via GetUserRoleScopes), so a target who is a project-scoped
// project_admin — never itself flagged "global admin" — is still compared
// correctly. Used by impersonation's admin-rank-ceiling check (#165/#G05): the
// action string only customizes the error message (e.g. "impersonate").
//
// #G05: this compares the target's actual bundled PERMISSIONS against what the
// actor can actually exercise (via c.Authorize, which resolves the admin-role-
// name bypass and broader-scope grants exactly like every other authorization
// decision) — not role-NAME membership in the fixed adminRoleNames list. The old
// role-name check silently no-op'd for any target whose admin-tier role was
// defined under a different name (a custom "SecOps" role bundling roles.assign +
// system.write, say): roleSetContainsAdmin(target) would return false, skipping
// the ceiling entirely, letting a lower-privileged actor impersonate a de-facto
// admin uncontested. Comparing actual permissions closes that regardless of what
// the role bundling them is named. This mirrors requireGranterHoldsRolePermissions'
// established pattern (the role-GRANT ceiling) applied here to impersonation.
//
// S1 sweep (CLI-split inventory #2012) found the OPPOSITE gap in the same
// function: a target holding a genuine BypassesPermissionChecks role (ADR-084
// — "system_admin"/"super_admin", the canonical shape a real deployment's
// admin role takes) typically carries NO explicit RolePermission rows at all —
// a bypass role's whole point is not needing them enumerated. Before this,
// targetPerms resolved EMPTY for such a target, the permission-comparison loop
// below iterated zero times, and this function returned nil (allowed) for
// EVERY actor, including one holding nothing but users.write — a
// users.write-only principal could modify/delete/restore/deactivate/revoke the
// credentials of, or mint a fresh setup token for, the install's actual
// highest-privileged admin. Confirmed via a real-server, real-attacker-role
// red test (TestUpdateUser_UsersWriteHolderCannotRewriteHigherPrivilegedTarget_RealServer)
// before this was added. #G05's permission-comparison and this bypass check
// are complementary, not competing: #G05 catches a custom role with real
// admin-equivalent permissions but no bypass flag; this catches a canonical
// bypass role with the flag but no enumerated permissions. Neither alone is
// sufficient — both are checked.
func (c *KeyorixCore) requireEqualOrGreaterAdminAuthority(ctx context.Context, actorID, targetID uint, action string) error {
	scopes, err := c.storage.GetUserRoleScopes(ctx, targetID)
	if err != nil {
		return fmt.Errorf("%w: failed to resolve target authority: %w", errCeilingResolutionFailed, err)
	}
	for _, scope := range scopes {
		targetRoleIDs, err := c.scopedRoleIDs(ctx, targetID, scope)
		if err != nil {
			return fmt.Errorf("%w: failed to resolve target authority: %w", errCeilingResolutionFailed, err)
		}
		targetBypasses, err := c.roleSetContainsAdmin(ctx, targetRoleIDs)
		if err != nil {
			return fmt.Errorf("%w: failed to resolve target authority: %w", errCeilingResolutionFailed, err)
		}
		if targetBypasses {
			actorRoleIDs, err := c.scopedRoleIDs(ctx, actorID, scope)
			if err != nil {
				return fmt.Errorf("%w: failed to resolve actor authority: %w", errCeilingResolutionFailed, err)
			}
			actorBypasses, err := c.roleSetContainsAdmin(ctx, actorRoleIDs)
			if err != nil {
				return fmt.Errorf("%w: failed to resolve actor authority: %w", errCeilingResolutionFailed, err)
			}
			if !actorBypasses {
				return fmt.Errorf("cannot %s a user holding an administrator role, which you do not also hold", action)
			}
			continue
		}
		targetPerms := make(map[string]bool)
		for _, roleID := range targetRoleIDs {
			perms, err := c.rolePermissionNameSet(ctx, roleID)
			if err != nil {
				return fmt.Errorf("%w: failed to resolve target authority: %w", errCeilingResolutionFailed, err)
			}
			for p := range perms {
				targetPerms[p] = true
			}
		}
		for permName := range targetPerms {
			ok, aerr := c.Authorize(ctx, actorID, permName, scope)
			if aerr != nil {
				return fmt.Errorf("%w: failed to resolve actor authority: %w", errCeilingResolutionFailed, aerr)
			}
			if !ok {
				return fmt.Errorf("cannot %s a user holding permission %q, which you do not also hold", action, permName)
			}
		}
	}
	return nil
}

// requireAdminRankCeilingForTarget is the shared entry point every
// human-facing mutation of ANOTHER user's account (UpdateUser, DeleteUser,
// RestoreUser, SuspendUser/ReactivateUser/RequirePasswordReset,
// RevokeUserSessions, ResendAccountSetupLink) calls before proceeding.
//
// Exactly ONE exemption: actorID == targetID (a self-action). You always
// have equal authority to yourself; each caller that needs a DIFFERENT
// self-action rule (e.g. UpdateUser's self-deactivation refusal) enforces
// that separately, before or instead of calling this.
//
// actorID == 0 is deliberately NOT exempted, even though it is the
// established codebase convention for "no human actor" (DeleteUser's actorID
// doc; the inactivity-suspend sweep passes 0 explicitly). #actor-sentinel:
// an HTTP/gRPC request authenticated as a MACHINE identity also resolves to
// UserID/actorID 0 (catalog.go's actorID(r), users_active_transition_proxy.go's
// humanActorID) -- there is no way to distinguish "genuinely no actor" from
// "a machine caller" from a bare uint alone. Exempting 0 outright would let
// a machine identity holding users.write bypass this ceiling entirely
// (caught by actor_sentinel_completeness_test.go during this fix's own
// development, not assumed safe). Instead actorID 0 flows into
// requireEqualOrGreaterAdminAuthority normally, which fails closed exactly
// like the already-fixed /system active-transition proxy's own
// humanActorID==0 case: refused against a target holding ANY permission,
// passed through only for a target holding none — the same outcome an
// ordinary unprivileged human actor gets, not a bypass. The
// inactivity-suspend sweep (actorID 0) already excludes global admins
// itself before reaching this point; this ceiling additionally refuses it
// against any OTHER privileged target it did not already exclude — a
// stricter, more conservative sweep than before, not a functional
// regression a security fix should accept weakening instead.
//
// Every other actor must hold, at every scope, every permission the target
// already holds — requireEqualOrGreaterAdminAuthority, the SAME admin-rank
// ceiling impersonation and the /system active-transition proxy
// (UpdateUserIfActiveStateMatchesProxy) already enforce. A refusal is
// audited (Success=false, EventAdminRankCeilingRefused) — ADR-102's
// "alerting on anomalous activity" detection position depends on refusals
// actually being recorded, not just returned to the caller. The returned
// error wraps ErrInsufficientAdminAuthority (errors.Is) so HTTP/gRPC mapping
// can pick the right status code without parsing message text or leaking
// the specific permission name to the client.
//
// S1, CLI-split inventory #2012: PUT /api/v1/users/{id} was the one route in
// this family with NO ceiling at all (core.UpdateUser took no actor
// parameter whatsoever); the sweep found every sibling in this list had the
// SAME gap — each called requireUserCredentialsRevokeAuthority-equivalent
// "users.write" checks (enforced at the HTTP layer) but never this ceiling.
// errCeilingResolutionFailed marks a requireEqualOrGreaterAdminAuthority
// failure caused by the backend being unable to answer the question at all
// (a storage/role-resolution error), as opposed to a genuine ceiling
// REFUSAL (the actor was asked and found wanting). requireAdminRankCeilingForTarget
// refuses both (fail closed); only the returned error differs, so a resolution
// failure surfaces as a retryable server error rather than a 403.
var errCeilingResolutionFailed = errors.New("ceiling resolution failed")

func (c *KeyorixCore) requireAdminRankCeilingForTarget(ctx context.Context, actorID, targetID uint, action string) error {
	if actorID == targetID {
		return nil
	}
	err := c.requireEqualOrGreaterAdminAuthority(ctx, actorID, targetID, action)
	if err == nil {
		return nil
	}
	if errors.Is(err, errCeilingResolutionFailed) {
		// FAIL CLOSED. This branch used to return nil ("allow") on the grounds
		// that only storage.type: remote (RemoteStorage, CLI client mode) could
		// ever reach it. RemoteStorage was deleted in #2162 (ADR-108), so the
		// only way here now is a real storage error on the primary backend (a
		// DB blip, a timeout, a bug in a role-resolution read) -- exactly the
		// window in which we cannot verify the actor outranks the target.
		// Refuse, and return an error that is NOT ErrInsufficientAdminAuthority:
		// the caller didn't lack authority, we couldn't check it, so this
		// surfaces as a retryable server error, not a 403. It is logged rather
		// than written as an audit event: like any other storage error it is an
		// infrastructure failure, not an authorization decision, and an error
		// path must leave no persisted state behind (FuzzStorageFaultOperations
		// oracle (a)). Found by that fuzzer (REPLAY_HEX=1829d438: gRPC
		// DeleteUser, fault on GetUserGroupRoleIDsAt).
		log.Printf("Keyorix: refusing to %s user %d for actor %d: could not verify admin authority: %v",
			action, targetID, actorID, err)
		return fmt.Errorf("could not verify admin authority to %s user %d: %w", action, targetID, err)
	}
	aid := actorID
	c.writeAuditEventFailed(ctx, EventAdminRankCeilingRefused, &aid, nil, "",
		fmt.Sprintf("actor %d refused: insufficient admin authority to %s user %d", actorID, action, targetID))
	return fmt.Errorf("%w: %w", ErrInsufficientAdminAuthority, err)
}

// selfMachineGranterCtxKey is the unexported context key carrying a machine
// identity ID that authenticated the CURRENT request itself and is
// requesting a grant on its own behalf -- distinct from audit_context.go's
// WithMachineActor/machineActorFromContext, which is set for EVERY
// machine-authenticated request (including /system proxy relays) purely
// for audit-trail attribution and is deliberately never consulted for an
// authorization decision. See requireGranterHoldsRolePermissions's doc for
// why the distinction matters: a /system proxy relay's authenticating node
// credential must never have ITS OWN permissions treated as authorizing an
// operation relayed on behalf of an unidentified downstream actor.
type selfMachineGranterCtxKey struct{}

// WithSelfMachineGranter tags ctx with machineID as a genuine, directly
// (non-proxy) authenticated machine actor requesting a grant AS ITSELF.
// Call this ONLY from a direct HTTP/gRPC handler that authenticated a real
// machine token for the CURRENT request and is about to call a core method
// that may reach requireGranterHoldsRolePermissions with actorIsMachine
// true -- NEVER from a /system proxy handler, which by construction cannot
// know the real downstream actor's identity. A zero machineID is a no-op
// (mirrors WithMachineActor/WithImpersonation).
func WithSelfMachineGranter(ctx context.Context, machineID uint) context.Context {
	if machineID == 0 {
		return ctx
	}
	return context.WithValue(ctx, selfMachineGranterCtxKey{}, machineID)
}

// selfMachineGranterFromContext returns the tagged machine identity ID and
// whether ctx carries one.
func selfMachineGranterFromContext(ctx context.Context) (uint, bool) {
	machineID, ok := ctx.Value(selfMachineGranterCtxKey{}).(uint)
	return machineID, ok && machineID != 0
}

// systemProxyRelayCtxKey marks a WithSelfMachineGranter tag that was set by a
// /system proxy handler (WithSystemProxyMachineGranter) rather than by a
// direct machine-facing handler.
type systemProxyRelayCtxKey struct{}

// WithSystemProxyMachineGranter is the /system-proxy counterpart of
// WithSelfMachineGranter (PR #1979 CI fix). The F6 sweep's roles.assign
// baseline made every relayed grant fail closed unless the proxy tagged the
// machine caller, so the /system proxies tag it -- but a /system call is,
// at the auth layer, indistinguishable from a NODE CREDENTIAL relaying on
// behalf of an unidentified downstream actor, and node credentials
// legitimately hold admin-tier roles (server/http/integration_test.go's
// createNodeToken). Letting such a credential's OWN permissions authorize an
// admin-tier grant is exactly the self-authorization requireGranterHoldsRole-
// Permissions' doc warns against (G80/#1529/#1578 guard tests). So this tag
// resolves permissions against the machine like WithSelfMachineGranter, but
// requireGranterHoldsRolePermissionsNoBaseline additionally refuses ANY
// admin-tier role (canonical admin name, or a bundle roleIsAdminTier
// classifies as administrative, #1685) for it. Non-admin grants relay as
// before; admin-tier grants over a relay fail closed, as they did on main.
// A zero machineID is a no-op.
func WithSystemProxyMachineGranter(ctx context.Context, machineID uint) context.Context {
	if machineID == 0 {
		return ctx
	}
	return context.WithValue(WithSelfMachineGranter(ctx, machineID), systemProxyRelayCtxKey{}, true)
}

// isSystemProxyRelayGrant reports whether ctx's machine-granter tag came from
// WithSystemProxyMachineGranter.
func isSystemProxyRelayGrant(ctx context.Context) bool {
	relay, _ := ctx.Value(systemProxyRelayCtxKey{}).(bool)
	return relay
}

// requireGranterHoldsRolePermissions refuses to GRANT roleID at scope unless the
// actor already holds, at that scope or broader, EVERY permission bundled into the
// role — the admin-rank-ceiling check on the GRANT step (#93/#107/#141), distinct
// from and complementary to #169's check on role DEFINITION. #169 only stops a
// roles.write holder from bundling a permission they don't hold into a role's
// definition; it does nothing to stop a roles.assign holder from GRANTING an
// already-defined, already-permission-rich role — including a pre-existing/seeded
// builtin like "editor" — to a third party (or to themselves) without holding any
// of its bundled permissions. c.Authorize already includes the admin-role bypass
// and resolves a broader (e.g. global) grant the actor holds at a narrower target
// scope, so a genuine admin, or an actor who already holds every bundled
// permission at an equal-or-broader scope, is unaffected.
//
// actorID 0 is the established "system" pseudo-actor for genuinely non-attacker-
// reachable callers (the local CLI's AssignRoleToUser); skipped exactly like
// #169's analogous check on AssignPermissionToRole. actorIsMachine distinguishes
// that true local/absent case from a machine-credential-authenticated caller,
// which also produces actorID==0 (server/middleware/auth.go: "UserID is 0" for
// ANY machine token) but is NOT the trusted pseudo-actor this exemption was
// written for -- #1542: AssignRoleWithExpiryProxy called storage.AssignRoleWithExpiry
// directly, bypassing this check (and every other core ceiling) entirely for
// ANY system.write holder, human or machine. Routing that proxy through
// AssignUserRoleWithExpiry (which calls this) closes that, but only if this
// exemption also stops treating a real machine actor as the trusted case.
// actorIsMachine is threaded through for the routes this fix targets;
// existing callers not part of that fix pass false unchanged (see #1545 for
// the broader sibling instances of this same exemption elsewhere -- not
// fixed here, tracked separately).
//
// Part 2 regression audit (adversarial review run 2) first attempted and
// REVERTED a blanket fix here, then landed this narrower one. Every caller
// passes actorID==0 for a machine-authenticated granter (server
// middleware's UserID==0-for-any-machine-token convention), so a naive
// c.Authorize(ctx, actorID=0, ...) always denies -- a false-refusal
// regression, not an escalation. The FIRST fix attempt resolved the real
// granting machine's ID from ctx via the general-purpose WithMachineActor
// tag (set for EVERY machine-authenticated request, audit-trail purposes)
// and checked ITS permissions via AuthorizePrincipal. That was unsafe:
// several of this function's callers were /system proxy handlers (since
// deleted along with RemoteStorage, ADR-108) relaying a raw storage call with
// NO real acting-user identity at all (actorID==0 by construction, e.g. the
// former RemoteStorage.AddUserToGroup) -- the only "machine"
// WithMachineActor's tag can resolve there is the NODE CREDENTIAL's own
// machine identity, which integration tests deliberately grant admin-tier
// roles for legitimate node-trust reasons ("no role, including admin,
// grants node status" -- server/http/integration_test.go's createNodeToken).
// A node credential is, at the auth layer, structurally indistinguishable
// from any other machine token -- resolving and using its own permissions
// here let ANY node credential self-authorize an admin-tier grant it was
// merely relaying on behalf of an unidentified downstream actor -- see
// TestSystemProxyRelayGranter_RefusesAdminTierRoles (authz_system_proxy_relay_
// ceiling_test.go) and its Invitation/Membership/group-service siblings.
//
// This fix instead checks a SEPARATE, narrowly-scoped context tag,
// selfMachineGranterFromContext (WithSelfMachineGranter), that is ONLY set
// by DIRECT (non-proxy) HTTP/gRPC handlers immediately before they call
// into a core method that reaches this function -- a machine genuinely
// authenticating and requesting a grant AS ITSELF. No /system proxy
// handler ever sets it (grep for WithSelfMachineGranter finds only direct
// handlers and gRPC services), so a relayed call's ctx never carries it,
// and the machine-actor branch below falls through to the same fail-closed
// refusal the pre-fix code always gave -- never worse than before, and
// correct (not merely "no worse") for the direct-call case the tag DOES
// cover. Adding a tag call at a handler is purely additive: a direct entry
// point this pass didn't get to simply keeps failing closed, exactly as
// before -- there is no way to reach fail-open by omission.
func (c *KeyorixCore) requireGranterHoldsRolePermissions(ctx context.Context, actorID, roleID uint, scope Scope, actorIsMachine bool) error {
	if actorID == 0 && !actorIsMachine {
		return nil
	}
	selfMachineID, isSelfMachineGrant := uint(0), false
	if actorIsMachine {
		selfMachineID, isSelfMachineGrant = selfMachineGranterFromContext(ctx)
	}

	// Baseline (F6 sweep, 2026-09-22): granting ANY role requires roles.assign
	// at scope, independent of what that role happens to bundle. Without this,
	// a role that bundles ZERO permissions -- a legal, ordinary role, not an
	// edge case -- made the per-permission loop below vacuously succeed for
	// ANY caller at ANY scope: zero permissions means zero loop iterations,
	// so "you hold every permission this role bundles" was trivially true of
	// nobody in particular. Every caller of this function already documents
	// itself as gating a role GRANT (AssignRoleToGroup, AssignMachineRole,
	// AssignUserRoleWithExpiry, CreateInvitationProxy/CreateMembershipProxy's
	// escalation-by-proxy checks, ...) and assumes the actor separately holds
	// roles.assign -- this makes that assumption load-bearing here instead of
	// silently absent whenever the role's own bundle happens to be empty.
	//
	// Exception: CreateUserWithAssignments' MANDATORY, caller-non-discretionary
	// system_viewer default (never an explicit ask) intentionally calls
	// requireGranterHoldsRolePermissionsNoBaseline instead of this function --
	// see that call site's own comment for why the roles.assign baseline does
	// not apply there.
	if ok, aerr := checkGranterHoldsPermission(ctx, c, actorID, "roles.assign", scope, actorIsMachine, isSelfMachineGrant, selfMachineID); aerr != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", aerr)
	} else if !ok {
		return fmt.Errorf("cannot grant this role: you do not hold permission %q yourself", "roles.assign")
	}

	return c.requireGranterHoldsRolePermissionsNoBaseline(ctx, actorID, roleID, scope, actorIsMachine)
}

// requireGranterHoldsRolePermissionsNoBaseline is requireGranterHoldsRolePermissions'
// per-permission loop WITHOUT the roles.assign baseline check -- the actor must
// still hold every permission the role bundles, but is not additionally required
// to hold roles.assign itself. Reserved for the one call site where that
// distinction is correct: CreateUserWithAssignments' mandatory default
// system_viewer grant, which mirrors plain CreateUser's own unconditional,
// zero-ceiling auto-assign (users.go) -- "create a plain user" has always been
// gated by users.write alone, not roles.assign, and every OTHER caller of the
// escalation-by-proxy check in this codebase represents a genuinely
// discretionary role grant the actor is choosing to make, which this one does
// not. Do not reach for this function for a new call site without the same
// "mandatory, non-discretionary, caller didn't ask for this specific role"
// justification -- every other case should call requireGranterHoldsRolePermissions.
func (c *KeyorixCore) requireGranterHoldsRolePermissionsNoBaseline(ctx context.Context, actorID, roleID uint, scope Scope, actorIsMachine bool) error {
	if actorID == 0 && !actorIsMachine {
		return nil
	}
	selfMachineID, isSelfMachineGrant := uint(0), false
	if actorIsMachine {
		selfMachineID, isSelfMachineGrant = selfMachineGranterFromContext(ctx)
	}
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to resolve role permissions: %w", err)
	}
	// A /system relay never grants an admin-tier role on the strength of the
	// relaying credential's own authority -- see WithSystemProxyMachineGranter.
	if isSelfMachineGrant && isSystemProxyRelayGrant(ctx) {
		role, rerr := c.storage.GetRole(ctx, roleID)
		if rerr != nil {
			return fmt.Errorf("failed to resolve role: %w", rerr)
		}
		if isAdminRoleName(role.Name) || roleIsAdminTier(perms) {
			return fmt.Errorf("cannot grant this role: an admin-tier role cannot be granted through a /system relay credential")
		}
	}
	for _, p := range perms {
		ok, aerr := checkGranterHoldsPermission(ctx, c, actorID, p.Name, scope, actorIsMachine, isSelfMachineGrant, selfMachineID)
		if aerr != nil {
			return fmt.Errorf("failed to resolve actor authority: %w", aerr)
		}
		if !ok {
			return fmt.Errorf("cannot grant this role: you do not hold permission %q yourself", p.Name)
		}
	}
	return nil
}

// checkGranterHoldsPermission resolves whether the granting actor holds
// permName at scope, using the SAME actor-resolution rules
// requireGranterHoldsRolePermissions has always applied: a genuinely
// self-authenticated machine granter (isSelfMachineGrant) is checked against
// its OWN permissions; any other machine actor (a /system proxy relay, or any
// call site that never tagged itself via WithSelfMachineGranter) fails
// closed; a human actor is checked via c.Authorize.
func checkGranterHoldsPermission(ctx context.Context, c *KeyorixCore, actorID uint, permName string, scope Scope, actorIsMachine, isSelfMachineGrant bool, selfMachineID uint) (bool, error) {
	switch {
	case isSelfMachineGrant:
		return c.AuthorizePrincipal(ctx, ActorTypeMachine, selfMachineID, permName, scope)
	case actorIsMachine:
		// actorIsMachine but ctx carries no WithSelfMachineGranter tag: a
		// /system proxy relay (or any call site not yet updated to tag
		// itself) -- fail closed exactly as before this fix.
		return false, nil
	default:
		return c.Authorize(ctx, actorID, permName, scope)
	}
}

// groupHoldsGlobalAdminRole reports whether groupID carries a LIVE global-scope
// (project 0, environment 0) grant of any role in adminIDs, per the pre-fetched
// assignments — the cheap relevance check every group-path last-admin guard (#107)
// runs first: a mutation touching a group with no admin-tier grant at all can
// never strand the install, so there is nothing to compute or refuse.
func groupHoldsGlobalAdminRole(assignments []storage.RoleAssignment, adminIDs map[uint]bool, groupID uint) bool {
	for _, a := range assignments {
		if a.PrincipalType == "group" && a.PrincipalID == groupID && adminIDs[a.RoleID] {
			return true
		}
	}
	return false
}

// resolveGlobalAdminHolders expands the given global-scope assignments (both
// direct user grants and group grants, the latter to their live members) into the
// set of user IDs who hold admin-tier authority, after applying the optional
// exclusions. Backs the group-path last-admin guards (#107): unlike
// guardLastGlobalAdmin's simpler "does another assignment ROW exist" check
// (sufficient when the removal itself deletes the admin-conferring row), removing
// a single user from a group leaves the group's own role grant row intact — only
// that one member's DERIVED authority disappears — so the check must expand group
// grants to their actual live members, not just count rows.
//
//   - excludeAssignment, when non-nil, drops every assignment row it matches:
//     the one (group, role) grant being removed (RemoveRoleFromGroup), or every
//     row belonging to a group being deleted (DeleteGroup).
//   - excludeMember, when non-nil, drops one specific (groupID, userID) member
//     expansion while leaving the group's grant — and its OTHER members' derived
//     authority — intact (RemoveUserFromGroup).
//
// Any storage error is returned, never swallowed: silently under-counting here
// only makes the guard MORE likely to refuse (fail closed), but silently mis-
// resolving a group's membership on a real error could do the opposite.
//
// #G03: a role/group ASSIGNMENT row surviving is not the same as the holder
// actually being usable as a fallback admin — deactivating (SCIM/DeleteUser/
// SuspendUser) never removes the UserRole/GroupRole grant, only the user's
// IsActive flag or deleted_at. Without filtering by current active status, this
// function could report a just-deactivated (or already-deleted) user as "another
// admin survives" purely because their stale grant row is still there —
// letting the LAST two admins each be deactivated one after another (or
// concurrently), not just the intended "one may go, one must remain."
func (c *KeyorixCore) resolveGlobalAdminHolders(ctx context.Context, adminIDs map[uint]bool, assignments []storage.RoleAssignment, excludeAssignment func(storage.RoleAssignment) bool, excludeMember func(groupID, userID uint) bool) (map[uint]bool, error) {
	holders := make(map[uint]bool)
	for _, a := range assignments {
		if !adminIDs[a.RoleID] {
			continue
		}
		if excludeAssignment != nil && excludeAssignment(a) {
			continue
		}
		switch a.PrincipalType {
		case "user":
			holders[a.PrincipalID] = true
		case "group":
			if err := c.resolveGroupAdminMembers(ctx, a.PrincipalID, excludeMember, holders); err != nil {
				return nil, err
			}
		}
	}
	return c.filterActiveHolders(ctx, holders)
}

// filterActiveHolders drops every holder whose account is no longer usable as a
// fallback admin (soft-deleted, IsActive=false, or a login-blocked
// account_state such as suspended) — see resolveGlobalAdminHolders'
// #G03 doc comment above for why a surviving grant ROW is not sufficient on its own.
func (c *KeyorixCore) filterActiveHolders(ctx context.Context, holders map[uint]bool) (map[uint]bool, error) {
	for id := range holders {
		user, err := c.storage.GetUser(ctx, id)
		if err != nil {
			if isNotFound(err) {
				// Soft-deleted: GetUser's default scope excludes it — this holder no
				// longer counts, but is not itself an error.
				delete(holders, id)
				continue
			}
			return nil, err
		}
		// #2658: a suspended/deprovisioned admin keeps IsActive=true (setAccountState
		// changes only account_state) but cannot log in, so it is no fallback admin
		// either. Same predicate the storage-level RemoveGlobalAdminRoleGuarded check
		// applies (store.GlobalAdminLiveAccountStates).
		if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
			delete(holders, id)
		}
	}
	return holders, nil
}

// resolveGroupAdminMembers expands groupID's membership into holders, but ONLY
// members whose own UserGroup row is global (project_id=0) — resolveGlobalAdminHolders
// is always resolving GLOBAL-scope role assignments, so a member whose
// membership in this group is itself scoped to one project does not derive
// GLOBAL admin authority from it (#G01: ListGroupMembers ignored this scope
// entirely, over-counting global admin holders and letting the true last
// global admin be removed because a project-scoped member was miscounted as a
// backup).
func (c *KeyorixCore) resolveGroupAdminMembers(ctx context.Context, groupID uint, excludeMember func(groupID, userID uint) bool, holders map[uint]bool) error {
	members, merr := c.storage.ListGroupMembersAt(ctx, groupID, Scope{})
	if merr != nil {
		return fmt.Errorf("failed to resolve group %d membership: %w", groupID, merr)
	}
	for _, m := range members {
		if excludeMember != nil && excludeMember(groupID, m.ID) {
			continue
		}
		holders[m.ID] = true
	}
	return nil
}

// guardLastGlobalAdminGroupRole is guardLastGlobalAdmin's group-role-removal
// counterpart (#107): refuses to remove roleID from groupID at the global scope
// when doing so would leave the install with zero global admin-tier holders.
func (c *KeyorixCore) guardLastGlobalAdminGroupRole(ctx context.Context, groupID, roleID uint, scope Scope) error {
	if scope.ProjectID != 0 || scope.EnvironmentID != 0 {
		return nil // not the global scope — project admins are recoverable
	}
	adminIDs, err := c.adminBypassRoleIDSet(ctx)
	if err != nil {
		return err // #2496: fail closed — "can't tell" must not read as "not an admin role"
	}
	if !adminIDs[roleID] {
		return nil // not removing an install-admin role
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, func(a storage.RoleAssignment) bool {
		return a.PrincipalType == "group" && a.PrincipalID == groupID && a.RoleID == roleID
	}, nil)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return fmt.Errorf("refusing to remove role %d from group %d: the install would be left with no install administrator at the global scope and no one able to manage users, roles, or settings", roleID, groupID)
	}
	return nil
}

// guardLastGlobalAdminGroupDelete is guardLastGlobalAdmin's group-deletion
// counterpart (#107): refuses to delete groupID when it holds a global admin-tier
// role and doing so would leave the install with zero admin-tier holders —
// deleting a group cascades to remove EVERY role grant it holds, not just one. A
// group with no admin-tier grant at all is never blocked, regardless of the
// install's overall admin count.
func (c *KeyorixCore) guardLastGlobalAdminGroupDelete(ctx context.Context, groupID uint) error {
	adminIDs, err := c.adminBypassRoleIDSet(ctx)
	if err != nil {
		return err // #2496: fail closed
	}
	if len(adminIDs) == 0 {
		return nil // no install-admin role seeded — nothing to guard
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	if !groupHoldsGlobalAdminRole(assignments, adminIDs, groupID) {
		return nil // this group carries no admin-tier grant — irrelevant to the guard
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, func(a storage.RoleAssignment) bool {
		return a.PrincipalType == "group" && a.PrincipalID == groupID
	}, nil)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return fmt.Errorf("refusing to delete group %d: it holds the install's last administrative role grant, and deleting it would leave no install administrator at the global scope", groupID)
	}
	return nil
}

// guardLastGlobalAdminMembership is guardLastGlobalAdmin's group-membership-
// removal counterpart (#107): refuses to remove userID from groupID when the
// group's admin-tier grant is userID's only remaining route to global admin-tier
// authority and no other user holds one either. The group's grant row survives
// this removal, so — unlike the other two guards — this can't be answered by
// excluding an assignment row; it must exclude just this one member's derived
// authority via this one group. A group with no admin-tier grant at all is never
// blocked, regardless of the install's overall admin count.
func (c *KeyorixCore) guardLastGlobalAdminMembership(ctx context.Context, userID, groupID uint) error {
	adminIDs, err := c.adminBypassRoleIDSet(ctx)
	if err != nil {
		return err // #2496: fail closed
	}
	if len(adminIDs) == 0 {
		return nil // no install-admin role seeded — nothing to guard
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	if !groupHoldsGlobalAdminRole(assignments, adminIDs, groupID) {
		return nil // this group carries no admin-tier grant — irrelevant to the guard
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, nil, func(gID, uID uint) bool {
		return gID == groupID && uID == userID
	})
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		// Wraps storage.ErrWouldStrandLastAdmin -- the sentinel the direct-grant
		// guard (RemoveGlobalAdminRoleGuarded) already returns -- so a caller can
		// tell THIS refusal from a storage failure by errors.Is. SSO reconcile
		// does (#2903): it is what selects the last-admin audit event and message.
		return fmt.Errorf("refusing to remove user %d from group %d: they may be the install's last administrator via this group's role grant, and removing them would leave no install administrator at the global scope: %w", userID, groupID, storage.ErrWouldStrandLastAdmin)
	}
	return nil
}

// GetReadableScopes returns every (project, environment) scope at which the
// calling principal (identified by principalID, resolved as a user or a machine
// identity per actorTypeFromContext(ctx) — see the doc on CheckSecretPermission's
// userID param for the same ctx-derived-actor-type convention) holds the given
// permission, directly or via group membership (users only — machine identities
// have no group concept). It is used by ListSecrets to enumerate the scopes a
// project-scoped reader can access when no explicit project_id/environment_id
// filter is provided and the caller lacks a global grant. The global scope
// ({0,0}) is deliberately excluded — callers check that first and fall back here
// only when the global check fails.
//
// G33: this originally called the user-only c.storage.GetUserRoleScopes +
// c.Authorize unconditionally, so a machine identity holding a ListSecrets-
// relevant permission ONLY at a project scope (no global grant) was resolved to
// zero readable scopes here — the same "helper written for humans, never updated
// for machines" shape as connect.go's actorRoleIDs and dashboard.go's
// GetDashboardStats. Machine identities now resolve their project-scoped grants
// via GetMachineRoleScopes + AuthorizePrincipal instead.
//
// PAT restrictions are honoured: a PAT that is itself narrowed to one project
// will receive at most that project's scopes from this function.
//
// Any storage error is returned unchanged; the caller fails closed (returns an
// empty list to the user rather than a 500).
func (c *KeyorixCore) GetReadableScopes(ctx context.Context, principalID uint, permission string) ([]Scope, error) {
	actorType := actorTypeFromContext(ctx)
	var allScopes []Scope
	var err error
	if actorType == ActorTypeMachine {
		allScopes, err = c.storage.GetMachineRoleScopes(ctx, principalID)
	} else {
		allScopes, err = c.storage.GetUserRoleScopes(ctx, principalID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate user scopes: %w", err)
	}

	var result []Scope
	for _, scope := range allScopes {
		if scope.ProjectID == 0 {
			// Global scope handled by caller; skip.
			continue
		}
		ok, aerr := c.AuthorizePrincipal(ctx, actorType, principalID, permission, scope)
		if aerr != nil {
			// Fail closed: skip scopes we cannot evaluate. Logged (not just silently
			// skipped) — a persistently-failing authorization check for one scope would
			// otherwise look identical to a caller who is legitimately ungranted there.
			log.Printf("GetReadableScopes: authorization check failed, skipping scope (actor_type=%s principal_id=%d permission=%s project_id=%d environment_id=%d): %v",
				actorType, principalID, permission, scope.ProjectID, scope.EnvironmentID, aerr)
			continue
		}
		if ok {
			result = append(result, scope)
		}
	}
	return result, nil
}

// dedupeUints returns ids with duplicates removed, preserving first-seen order.
func dedupeUints(ids []uint) []uint {
	if len(ids) <= 1 {
		return ids
	}
	seen := make(map[uint]struct{}, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
