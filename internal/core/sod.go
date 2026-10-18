// sod.go — separation of duties (ISO 27001 A.5.3 / SOX). A SoD policy names two
// permissions that one principal must not hold together (a "toxic combination",
// e.g. "approve access requests" AND "administer secrets"). DetectSoDViolations
// finds the users who effectively hold both sides of any policy. Policies are
// managed by admins (system.write); detection + listing need system.read. The
// violations feed the compliance posture/evidence and the web.
package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrSoDValidation, ErrSoDPermissionDenied, and ErrSoDNotFound classify
// CreateSoDPolicy/DeleteSoDPolicy failures for server/http/handlers/sod.go to
// match via errors.Is, rather than the substring text match it used to do
// against these functions' i18n-prefixed messages (e.g.
// strings.Contains(msg, "permission denied")). That match only worked because
// every shipped locale left the underlying translation key (ErrorValidation/
// ErrorPermissionDenied) untranslated -- the first deployment whose locale
// translates it would silently fall through to the handler's generic 500
// default instead of the correct 400/403.
var (
	ErrSoDValidation       = errors.New("sod validation")
	ErrSoDPermissionDenied = errors.New("sod permission denied")
	ErrSoDNotFound         = errors.New("sod policy not found")
)

// sodClassifiedError tags err as matching target for errors.Is, without
// target's own text ever appearing in Error() -- same shape as FIX-4's
// roleValidationError (internal/core/rbac_roles.go).
type sodClassifiedError struct {
	err    error
	target error
}

func (e *sodClassifiedError) Error() string        { return e.err.Error() }
func (e *sodClassifiedError) Unwrap() error        { return e.err }
func (e *sodClassifiedError) Is(target error) bool { return target == e.target }

func wrapSoDValidation(err error) error {
	return &sodClassifiedError{err: err, target: ErrSoDValidation}
}
func wrapSoDPermissionDenied(err error) error {
	return &sodClassifiedError{err: err, target: ErrSoDPermissionDenied}
}
func wrapSoDNotFound(err error) error { return &sodClassifiedError{err: err, target: ErrSoDNotFound} }

// SoD audit event types. Create/Delete denial paths below reuse these SAME
// constants (Success=false via writeAuditEventFailed distinguishes a denied
// attempt from a successful one) — the established convention this file's own
// PlaceLegalHold/LiftLegalHold precedent uses, not a separate "_denied" event
// type per action.
const (
	EventSoDPolicyCreated         = "sod.policy_created"          // #nosec G101 -- audit event type, not a credential
	EventSoDPolicyDeleted         = "sod.policy_deleted"          // #nosec G101 -- audit event type, not a credential
	EventSoDPreExistingViolations = "sod.pre_existing_violations" // #nosec G101 -- audit event type, not a credential
)

// SoDViolation is one principal (human user or machine identity) that effectively
// holds both permissions a policy forbids together.
type SoDViolation struct {
	PolicyID   uint   `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	// PrincipalType is "user" or "machine". UserID/Username carry the principal's id
	// and label for either kind (the JSON keys stay user_* for backward compatibility).
	PrincipalType string `json:"principal_type"`
	UserID        uint   `json:"user_id"`
	Username      string `json:"username"`
	Email         string `json:"email,omitempty"`
	PermissionA   string `json:"permission_a"`
	PermissionB   string `json:"permission_b"`
	// Detail explains a non-obvious basis for the violation, e.g. that the principal
	// holds both sides only by virtue of an admin permission-bypass role.
	Detail string `json:"detail,omitempty"`
	// Reference is the stable, matchable identifier for this specific violation
	// (policy + principal) — copy it verbatim into a "sod"-category risk
	// exception's Reference field to have that exception suppress THIS violation,
	// and only this one, from the compliance posture (#170).
	Reference string `json:"reference"`
}

// sodViolationReference builds the stable per-(policy, principal) reference a
// governed risk exception matches against to suppress this specific violation.
func sodViolationReference(policyID uint, principalType string, principalID uint) string {
	return fmt.Sprintf("sod:policy:%d:%s:%d", policyID, principalType, principalID)
}

// SoDViolationsReport is the result of a full separation-of-duties scan: every
// violation found, plus a signal for whether the scan is complete. #420: a user
// whose effective permissions could not be read was previously silently skipped
// (`continue`, no logging, no signal) — if that user actually held a toxic
// permission combination, the violation was silently never reported, exactly the
// fail-open shape already fixed elsewhere (CompliancePosture.degrade,
// AccessReviewReport.degrade, SecretAccessorsResult.degrade). Degraded +
// DegradedReasons make the gap detectable instead.
type SoDViolationsReport struct {
	Violations []SoDViolation `json:"violations"`
	// Degraded is true when at least one principal's permissions could not be read,
	// so the scan may be missing a violation for that principal.
	Degraded bool `json:"degraded"`
	// DegradedReasons names each principal whose permissions failed to resolve,
	// with the underlying error.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
}

// degrade records that a principal's permissions could not be evaluated for SoD
// violations: it flips Degraded and appends a human-readable reason, mirroring
// AccessReviewReport.degrade (access_review.go).
func (r *SoDViolationsReport) degrade(area string, err error) {
	r.Degraded = true
	r.DegradedReasons = append(r.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// CreateSoDPolicy defines a toxic-combination rule. The two permissions must be
// present and distinct. actorID is the creating admin.
//
// #1529: actorID used to be threaded through ONLY for audit attribution, with
// no authority check at all -- any system.write holder (the route's own gate;
// this is also reachable via the /system proxy, where "any caller" widens to
// include a bare node credential, actorID==0) could unilaterally define a new
// deployment-wide governance control. Defining a toxic-permission-pair rule is
// a policy-SETTING action with no existing object to compare a "creator" against
// (unlike delete/revoke below), so it mirrors PlaceLegalHold's admin-tier gate,
// not LiftLegalHold's creator-or-admin one. A denied attempt is itself audited,
// distinctly from a successful create -- confirmed via CI: no test asserted a
// non-admin could create a policy, so this was an oversight, not a documented
// design choice.
func (c *KeyorixCore) CreateSoDPolicy(ctx context.Context, actorID uint, name, description, permA, permB string) (*models.SoDPolicy, error) {
	name = strings.TrimSpace(name)
	permA = strings.TrimSpace(permA)
	permB = strings.TrimSpace(permB)
	if name == "" {
		return nil, wrapSoDValidation(fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a policy name is required"))
	}
	if permA == "" || permB == "" {
		return nil, wrapSoDValidation(fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "two permissions are required"))
	}
	if permA == permB {
		return nil, wrapSoDValidation(fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the two permissions must be different"))
	}
	// #1529 authority check runs AFTER field validation (mirrors PlaceLegalHold's
	// own order: cheap input checks before a DB-backed authority resolution) --
	// see this function's doc comment above for the full reasoning.
	adminRole, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if adminRole == "" {
		c.writeAuditEventFailed(ctx, EventSoDPolicyCreated, actorPtr(actorID), nil, "",
			fmt.Sprintf("SoD policy create DENIED: actor %d is not an admin-tier principal", actorID))
		return nil, wrapSoDPermissionDenied(fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
			"only an admin-tier principal may define a SoD policy"))
	}
	// AUDIT-TX-2: the policy and its sod_policy.created row commit in ONE
	// transaction.
	var policy *models.SoDPolicy
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var err error
		if policy, err = tx.CreateSoDPolicy(ctx, &models.SoDPolicy{
			Name: name, Description: description, PermissionA: permA, PermissionB: permB,
			CreatedBy: actorID, CreatedAt: c.now(),
		}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.writeAuditEventFullOn(ctx, tgt, EventSoDPolicyCreated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("created SoD policy %d (%q): %s + %s", policy.ID, name, permA, permB))
		return nil
	}); err != nil {
		return nil, err
	}

	// SOD-001: scan for principals that already hold both sides of the new policy.
	// Violations are recorded via audit events so operators are immediately alerted;
	// they do not prevent creation (the policy is already persisted above).
	if report, scanErr := c.scanPolicyViolations(ctx, policy); scanErr == nil && len(report.Violations) > 0 {
		c.writeAuditEvent(ctx, EventSoDPreExistingViolations, actorPtr(actorID), nil,
			fmt.Sprintf("new SoD policy %d (%q) has %d pre-existing violation(s); run DetectSoDViolations to enumerate them", policy.ID, name, len(report.Violations)))
	}

	return policy, nil
}

// ListSoDPolicies returns all separation-of-duties policies.
func (c *KeyorixCore) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return policies, nil
}

// DeleteSoDPolicy retires a policy. actorID is the acting admin.
//
// #1529: same gap as CreateSoDPolicy above, but retiring an EXISTING policy has
// a natural "creator" to compare against (unlike defining a new one), so this
// mirrors LiftLegalHold's creator-or-admin precedent exactly: only the
// principal who originally created the policy, or a global-admin-tier
// principal, may delete it. A denied attempt is itself audited.
//
// FIX-6 (adversarial review run 2): the authority check used to run AFTER the
// existence lookup, and returned that lookup's error verbatim on failure --
// so a caller holding the deliberately-broad system.write (this route's own
// gate; see this file's own doc comment) but no creator/admin-tier standing
// could tell "policy id doesn't exist" (404, from GetSoDPolicy's own error)
// apart from "policy id exists but isn't mine" (403, from the check below): a
// reliable ID-enumeration oracle. Fixed per ADR-096's 403-for-both
// convention, already the house standard for exactly this shape
// (server/middleware/auth.go's handleScopeResolutionError): a real 404 is
// safe ONLY for a caller already authorized at global admin-tier -- the SAME
// standing that would grant access to this resource had it existed, mirroring
// handleScopeResolutionError's own "authorized at global scope" condition --
// since an admin-tier caller can already see/delete every policy regardless
// of which id this is. Every other caller gets the IDENTICAL
// ErrSoDPermissionDenied response whether the id is missing or just not
// theirs -- same status, same message, same error classification -- closing
// the oracle rather than merely renaming it.
func (c *KeyorixCore) DeleteSoDPolicy(ctx context.Context, actorID, id uint) error {
	adminRole, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	isAdminTier := adminRole != ""

	policy, err := c.storage.GetSoDPolicy(ctx, id)
	if err != nil {
		if isAdminTier && errors.Is(err, storage.ErrSoDPolicyNotFound) {
			return wrapSoDNotFound(err)
		}
		if errors.Is(err, storage.ErrSoDPolicyNotFound) {
			// Non-admin caller: collapse "doesn't exist" into the identical
			// denial a non-owning caller gets for an EXISTING policy below --
			// see this function's doc comment.
			c.writeAuditEventFailed(ctx, EventSoDPolicyDeleted, actorPtr(actorID), nil, "",
				fmt.Sprintf("SoD policy %d delete DENIED: actor %d is not an admin-tier principal (policy lookup found no match)", id, actorID))
			return wrapSoDPermissionDenied(fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
				"only the creating admin or an admin-tier principal may delete this SoD policy"))
		}
		return err
	}

	if actorID != policy.CreatedBy && !isAdminTier {
		c.writeAuditEventFailed(ctx, EventSoDPolicyDeleted, actorPtr(actorID), nil, "",
			fmt.Sprintf("SoD policy %d delete DENIED: actor %d is neither the creator (%d) nor an admin-tier principal", id, actorID, policy.CreatedBy))
		return wrapSoDPermissionDenied(fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
			"only the creating admin or an admin-tier principal may delete this SoD policy"))
	}
	// AUDIT-TX-2: deleting a policy loosens a preventive control (it removes no
	// one's access), so it fails closed on audit like a grant: the delete and its
	// sod_policy.deleted row commit together.
	return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.DeleteSoDPolicy(ctx, id); err != nil {
			return err
		}
		c.writeAuditEventFullOn(ctx, tgt, EventSoDPolicyDeleted, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("deleted SoD policy %d", id))
		return nil
	})
}

// DetectSoDViolations evaluates every policy against every active principal's
// effective permissions and returns each that holds both sides of a policy. Empty
// when there are no policies. It covers BOTH human users (paged, no silent cap) and
// machine identities — automation principals hold roles and are authorized too, so
// omitting them would leave the control blind to a whole class of actor. The
// returned report's Degraded/DegradedReasons signal when a principal's permissions
// could not be read, rather than silently reading as "scanned, no violation" (#420).
func (c *KeyorixCore) DetectSoDViolations(ctx context.Context) (*SoDViolationsReport, error) {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	report := &SoDViolationsReport{Violations: []SoDViolation{}}
	if len(policies) == 0 {
		return report, nil
	}

	const pageSize = 500
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		c.appendUserSoDViolations(ctx, report, users, policies)
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}

	c.machineSoDViolations(ctx, report, policies)
	return report, nil
}

// scanPolicyViolations runs DetectSoDViolations scoped to a single policy.
// Used by CreateSoDPolicy to detect pre-existing violators without re-scanning
// every existing policy on every creation.
func (c *KeyorixCore) scanPolicyViolations(ctx context.Context, policy *models.SoDPolicy) (*SoDViolationsReport, error) {
	policies := []*models.SoDPolicy{policy}
	report := &SoDViolationsReport{Violations: []SoDViolation{}}
	const pageSize = 500
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return nil, err
		}
		c.appendUserSoDViolations(ctx, report, users, policies)
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	c.machineSoDViolations(ctx, report, policies)
	return report, nil
}

// userSoDViolations returns the policy violations a single user holds. A user whose
// role set includes an admin permission-bypass role effectively holds EVERY
// permission — Authorize short-circuits on it before ever consulting role_permissions
// — so such a user violates every policy, even though their explicit role_permissions
// rows may name only one side (or neither). Missing that made the SoD control blind to
// exactly the most-privileged principals it exists to police. For a non-admin, the
// appendUserSoDViolations iterates a page of users and adds any violations to
// the report. Inactive users are skipped. Permission-resolution errors degrade
// the report rather than abort the scan (#420).
func (c *KeyorixCore) appendUserSoDViolations(ctx context.Context, report *SoDViolationsReport, users []*models.User, policies []*models.SoDPolicy) {
	for _, u := range users {
		if !u.IsActive {
			continue
		}
		uv, err := c.userSoDViolations(ctx, u, policies)
		if err != nil {
			report.degrade(fmt.Sprintf("user_permissions:user=%d", u.ID), err)
			continue
		}
		report.Violations = append(report.Violations, uv...)
	}
}

// held-set unions direct and group-inherited permissions (mirroring Authorize).
//
// #420: an error resolving the user's permissions is returned to the caller rather
// than silently swallowed — the user genuinely can't be scanned without the data, but
// the caller (DetectSoDViolations) must record that the scan is incomplete instead of
// looking clean.
func (c *KeyorixCore) userSoDViolations(ctx context.Context, u *models.User, policies []*models.SoDPolicy) ([]SoDViolation, error) {
	adminRole, err := c.isGlobalAdminRoleName(ctx, u.ID)
	if err != nil {
		// Same #420 precedent as the permission-resolution error below: degrade the
		// scan, don't silently resolve an unconfirmed admin status to "not admin."
		return nil, err
	}
	if adminRole != "" {
		out := make([]SoDViolation, 0, len(policies))
		detail := fmt.Sprintf("holds all permissions via admin role %q", adminRole)
		for _, pol := range policies {
			out = append(out, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "user", UserID: u.ID, Username: u.Username, Email: u.Email,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Detail:    detail,
				Reference: sodViolationReference(pol.ID, "user", u.ID),
			})
		}
		return out, nil
	}

	held, err := c.userHeldPermissionSet(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var out []SoDViolation
	for _, pol := range policies {
		if held[pol.PermissionA] && held[pol.PermissionB] {
			out = append(out, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "user", UserID: u.ID, Username: u.Username, Email: u.Email,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Reference: sodViolationReference(pol.ID, "user", u.ID),
			})
		}
	}
	return out, nil
}

// userHeldPermissionSet returns the set of permission names userID holds via
// DIRECT role assignments and GROUP-inherited roles — NOT the admin-bypass
// (callers that need bypass-awareness check adminRoleName separately, exactly as
// userSoDViolations already does above). Shared by the periodic scan
// (userSoDViolations) and the grant-time preventive check (requireNoSoDViolation
// and friends, #419) so both compute "what does this principal effectively hold"
// identically — one policy-matching rule, not two.
func (c *KeyorixCore) userHeldPermissionSet(ctx context.Context, userID uint) (map[string]bool, error) {
	perms, err := c.storage.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	groupPerms, err := c.storage.GetUserGroupPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool, len(perms)+len(groupPerms))
	for _, p := range perms {
		held[p.Name] = true
	}
	for _, p := range groupPerms {
		held[p.Name] = true
	}
	return held, nil
}

// machineSoDViolations scans active machine identities, appending any violations
// found directly onto report.Violations. Machines resolve permissions from
// machine_identity_roles and receive NO admin-role bypass (a leaked machine token
// is bounded to its explicit grants), so the held-set is just the union of its
// roles' permissions.
//
// #492: sibling of userSoDViolations/#420 — every sub-check error here was
// previously silently discarded (ListAllMachineIdentities returning nil,
// GetMachineRoles/RoleSetHasPermission folded into a bare `continue`), so a
// machine identity that actually held a toxic combination could be dropped from
// the scan while the report still looked clean. Each failure now flips
// report.Degraded via report.degrade, named for the machine (and policy, for the
// permission checks) that couldn't be evaluated, instead of looking clean.
func (c *KeyorixCore) machineSoDViolations(ctx context.Context, report *SoDViolationsReport, policies []*models.SoDPolicy) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	machines, err := c.storage.ListAllMachineIdentities(ctx)
	if err != nil {
		report.degrade("machine_identities", err)
		return
	}
	for _, m := range machines {
		if m.State != "active" {
			continue
		}
		roles, err := c.storage.GetMachineRoles(ctx, m.ID)
		if err != nil {
			report.degrade(fmt.Sprintf("machine_roles:machine=%d", m.ID), err)
			continue
		}
		if len(roles) == 0 {
			continue
		}
		roleIDs := make([]uint, 0, len(roles))
		for _, r := range roles {
			roleIDs = append(roleIDs, r.ID)
		}
		for _, pol := range policies {
			hasA, err := c.storage.RoleSetHasPermission(ctx, roleIDs, pol.PermissionA)
			if err != nil {
				report.degrade(fmt.Sprintf("machine_permission:machine=%d:policy=%d", m.ID, pol.ID), err)
				continue
			}
			if !hasA {
				continue
			}
			hasB, err := c.storage.RoleSetHasPermission(ctx, roleIDs, pol.PermissionB)
			if err != nil {
				report.degrade(fmt.Sprintf("machine_permission:machine=%d:policy=%d", m.ID, pol.ID), err)
				continue
			}
			if !hasB {
				continue
			}
			report.Violations = append(report.Violations, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "machine", UserID: m.ID, Username: m.Name,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Reference: sodViolationReference(pol.ID, "machine", m.ID),
			})
		}
	}
}

// isGlobalAdminRoleName returns the name of an admin (permission-bypass) role
// the user holds at GLOBAL SCOPE specifically (ProjectID 0) — direct or
// group-inherited — or "" if none, and a non-nil error if the user's admin
// status at global scope could not be determined at all.
//
// Fails closed on a genuine resolution error (docs/findings/2026-10-02-FINDING-
// sod-policy-create-getrole-error-misread-as-not-admin.md): a scopedRoleIDs or
// GetRole storage error is returned to the caller rather than silently treated
// as "" — the same outcome a role set that genuinely contains no admin role
// produces. Every caller must distinguish "confirmed not admin-tier" (safe to
// deny, and to audit the denial as a real denial) from "could not confirm"
// (an infrastructure failure, not a verdict on the actor) — mirrors
// roleSetContainsAdmin's own documented precedent one file over
// (internal/core/authz.go): "a lookup error on a security-relevant path must
// not be indistinguishable from a legitimate negative result, or a caller can
// trigger the same lookup error to silently bypass whatever the error would
// otherwise have blocked" (here, to silently trigger a false admin-tier
// DENIAL instead — fail-closed either way, just the other failure direction).
//
// #G01: this replaces the former adminRoleName, which checked the role NAME
// only and ignored the grant's own scope — so a role named like an admin role
// but granted (directly, or via a group's role grant, or via the user's own
// group MEMBERSHIP) at a single project was wrongly treated as install-wide
// admin-bypass authority everywhere it was checked (legal-hold placement/lift,
// the SoD preventive gate's admin-bypass exemption). A project-scoped admin
// does not hold "all permissions" the way a true global admin does, so it must
// not exempt a principal from a deployment-wide control or a deployment-wide
// SoD policy. scopedRoleIDs(ctx, userID, Scope{}) — the same primitive
// requireAdminAuthorityAt already uses for its own scope-aware admin check —
// unions direct (GetUserRoleIDsAt) and group-inherited (GetUserGroupRoleIDsAt)
// roles, and BOTH of those storage queries already correctly filter to
// project_id=0 rows (and, for the group-inherited case, ALSO require the
// user's own group membership to be project_id=0) when called with the global
// scope — so this call is scope-correct for free, reusing already-tested code.
func (c *KeyorixCore) isGlobalAdminRoleName(ctx context.Context, userID uint) (string, error) {
	ids, err := c.scopedRoleIDs(ctx, userID, Scope{})
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		role, rerr := c.storage.GetRole(ctx, id)
		if rerr != nil {
			if storage.IsRoleNotFound(rerr) {
				// A dangling user-role/group-role row pointing at a since-deleted
				// role (the orphan class AT4's guard #2380 exists for) is "not
				// this role," not a resolution failure to fail closed on -- a
				// role that no longer exists cannot confer admin-bypass either
				// way, and blocking every SoD/legal-hold/risk-exception/
				// license-expiry check for this user forever over a stale
				// reference has no security benefit, only an availability cost.
				continue
			}
			return "", rerr
		}
		if isAdminRoleName(role.Name) {
			return role.Name, nil
		}
	}
	return "", nil
}

// actorPtr returns a *uint for an actor id (nil when 0/unauthenticated).
func actorPtr(id uint) *uint {
	if id == 0 {
		return nil
	}
	a := id
	return &a
}

// ── Preventive gate (#419) ───────────────────────────────────────────────────
//
// DetectSoDViolations above is a purely periodic/on-demand DETECTIVE control — it
// only catches a toxic-permission overlap when someone runs it (a scheduled
// digest or an on-demand call). Combined with this codebase's JIT/time-bound
// role grants (UserRole.ExpiresAt and friends), a toxic overlap that both STARTS
// and FULLY EXPIRES between two scans is genuinely exercisable through the live
// Authorize() path — real access is granted and can be used during that window —
// but never appears in any SoD violation report: a timing-based evasion of the
// control, concretely constructible by arranging two overlapping short-lived
// grants.
//
// The functions below are the PREVENTIVE counterpart. Called from every direct
// role-grant choke point, before a new grant lands, they reuse the exact same
// policy-matching rule the periodic scan uses (sodPolicyNewlyCompletedBy) to ask
// a narrower, single-principal (or single-grant-set) question — "would THIS
// grant, together with what the principal ALREADY holds, complete a policy that
// isn't already complete?" — and BLOCK the grant if so (fail closed, matching
// this codebase's established posture for every other grant-time ceiling check:
// requireGranterHoldsRolePermissions, requireAuthorityForRole).
//
// Deliberately out of scope below: a principal who ALREADY holds (or is being
// granted) an admin permission-bypass role (isAdminRoleName). An admin holds
// every permission and so trivially "violates" every SoD policy the instant one
// is defined — exactly the case userSoDViolations' own admin-bypass branch flags
// on the periodic scan. Applying that same rule as a hard PREVENTIVE block would
// refuse ALL further admin-role provisioning the moment any SoD policy exists —
// an availability regression far outside what this fix is meant to close.
// Admin-role grants are separately, adequately gated by their own
// escalation-by-proxy ceiling (requireAuthorityForRole/requireAdminAuthorityAt:
// only an existing admin may grant one).
//
// Also deliberately NOT wired into break_glass.go's self-service emergency
// activation: break-glass is documented as "Deliberately un-gated by RBAC — the
// whole point is access the user does NOT already have", and a false-positive
// SoD block during a genuine incident would be a severe, unacceptable failure
// mode for the control that exists to remediate incidents. See
// assignUserRoleWithExpirySkipSoD (jit_access.go) for the carve-out, which
// mirrors the SAME reasoning this codebase already applies to the ceiling check
// AssignUserRoleWithExpiry also (deliberately) skips.

// sodPolicyNewlyCompletedBy returns the first policy in policies that becomes
// satisfied (both permission sides held) once adding is unioned into held, but
// was NOT already satisfied by held alone — i.e. a violation this specific
// change would newly create, not one that already existed. nil when nothing
// newly completes. The one shared predicate every preventive check below (and,
// via userSoDViolations, the periodic scan) evaluates a policy with.
func sodPolicyNewlyCompletedBy(policies []*models.SoDPolicy, held, adding map[string]bool) *models.SoDPolicy {
	for _, pol := range policies {
		if held[pol.PermissionA] && held[pol.PermissionB] {
			continue // already violated before this change — not created by it
		}
		hasA := held[pol.PermissionA] || adding[pol.PermissionA]
		hasB := held[pol.PermissionB] || adding[pol.PermissionB]
		if hasA && hasB {
			return pol
		}
	}
	return nil
}

// rolePermissionNameSet returns the permission names roleID's role_permissions
// rows carry.
func (c *KeyorixCore) rolePermissionNameSet(ctx context.Context, roleID uint) (map[string]bool, error) {
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(perms))
	for _, p := range perms {
		set[p.Name] = true
	}
	return set, nil
}

// sodBlockedErr formats the blocking error a preventive check returns when a
// grant would newly complete pol.
func sodBlockedErr(pol *models.SoDPolicy, detail string) error {
	return fmt.Errorf("cannot %s: it would create a separation-of-duties violation with policy %q (%s + %s)",
		detail, pol.Name, pol.PermissionA, pol.PermissionB)
}

// requireNoSoDViolation is the preventive gate for a DIRECT user role grant: it
// blocks granting roleID to userID if doing so would newly complete an SoD
// policy given userID's OTHER current permissions (direct + group,
// scope-agnostic — SoD policies are principal-level, exactly like the periodic
// scan, not scope-restricted; a user must never hold both sides ANYWHERE, not
// merely "not in the same project"). This is the choke point AssignUserRole and
// AssignUserRoleWithExpiry both call.
func (c *KeyorixCore) requireNoSoDViolation(ctx context.Context, userID, roleID uint) error {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	adminRole, err := c.isGlobalAdminRoleName(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if adminRole != "" {
		return nil // already holds admin-bypass — see package doc above
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if isAdminRoleName(role.Name) {
		return nil // granting admin-bypass — see package doc above
	}
	adding, err := c.rolePermissionNameSet(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(adding) == 0 {
		return nil
	}
	held, err := c.userHeldPermissionSet(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
		return sodBlockedErr(pol, "grant this role")
	}
	return nil
}

// groupGrantSoDContext resolves everything requireGroupGrantNoSoDViolation
// needs to know BEFORE the caller decides whether it's even worth listing
// group membership and acquiring a lock per member (withGroupMemberSoDLocks,
// rbac_management.go — issue #1780): the policy set and roleID's own
// permission set, plus needed=false for every early-out
// requireGroupGrantNoSoDViolation used to apply internally (no policies
// configured at all, roleID is itself admin-bypass, or roleID grants no
// permissions) — cases where no member's held-permission set could possibly
// matter. Splitting this out means a deployment with no SoD policies (the
// common case) never pays for a ListGroupMembers call or a single member
// lock on every group-role grant; the member-lock dance only runs when a
// policy could genuinely be affected.
func (c *KeyorixCore) groupGrantSoDContext(ctx context.Context, roleID uint) (policies []*models.SoDPolicy, adding map[string]bool, needed bool, err error) {
	policies, err = c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil, nil, false, nil
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if isAdminRoleName(role.Name) {
		return nil, nil, false, nil
	}
	adding, err = c.rolePermissionNameSet(ctx, roleID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(adding) == 0 {
		return nil, nil, false, nil
	}
	return policies, adding, true, nil
}

// requireGroupGrantNoSoDViolation is requireNoSoDViolation's GROUP-grant
// counterpart: a role assigned to a group is inherited by every member, so it
// can complete a policy for a member exactly as a direct grant would. Checks
// each active, non-admin-bypass member (a group's membership is a small,
// bounded set — unlike DetectSoDViolations' full-deployment scan — so this
// stays cheap even run synchronously on every group-role assignment). A member
// who already holds admin-bypass is skipped, not treated as a block (see
// package doc above).
//
// members is the caller's ALREADY-FETCHED membership snapshot (see
// withGroupMemberSoDLocks, rbac_management.go), not re-listed here —
// issue #1780: this function used to list membership itself, but the caller
// needs that exact same list to know which members' sodGrantLockKey("user", ...)
// locks to hold for the duration of the check-then-write (otherwise a
// concurrent direct grant to a member reads this function's pre-grant state
// as clean and commits before this function's own caller writes the group
// grant — the two operations never serialize against each other at all,
// since they use different lock keys). Passing the same snapshot through
// guarantees the locks taken and the members checked are identical.
//
// policies/adding come from groupGrantSoDContext, called by the caller BEFORE
// it decides whether to acquire member locks at all — this function no
// longer re-derives them (or re-applies their early-outs) itself.
func (c *KeyorixCore) requireGroupGrantNoSoDViolation(ctx context.Context, members []*models.User, policies []*models.SoDPolicy, adding map[string]bool) error { // nosemgrep: keyorix-unbounded-bulk-slice-param -- members is withGroupMemberSoDLocks's own ListGroupMembers(ctx, groupID) result (that group's actual membership), not a raw client-supplied array in one request
	for _, m := range members {
		if !m.IsActive {
			continue
		}
		adminRole, err := c.isGlobalAdminRoleName(ctx, m.ID)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		if adminRole != "" {
			continue
		}
		held, err := c.userHeldPermissionSet(ctx, m.ID)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
			return fmt.Errorf("cannot assign this role to the group: it would create a separation-of-duties violation for member %d with policy %q (%s + %s)",
				m.ID, pol.Name, pol.PermissionA, pol.PermissionB)
		}
	}
	return nil
}

// requireMachineGrantNoSoDViolation is requireNoSoDViolation's machine-identity
// counterpart: a machine holds permissions only through its explicit role
// grants (machineSoDViolations — no admin-bypass ever applies to a machine, a
// leaked token is bounded to its explicit grants), so "held" is simply the
// union of its OTHER current roles' permissions.
func (c *KeyorixCore) requireMachineGrantNoSoDViolation(ctx context.Context, machineID, roleID uint) error {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if isAdminRoleName(role.Name) {
		return nil
	}
	adding, err := c.rolePermissionNameSet(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(adding) == 0 {
		return nil
	}
	roles, err := c.storage.GetMachineRoles(ctx, machineID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	held := make(map[string]bool)
	for _, r := range roles {
		perms, err := c.rolePermissionNameSet(ctx, r.ID)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		for name := range perms {
			held[name] = true
		}
	}
	if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
		return sodBlockedErr(pol, "assign this role")
	}
	return nil
}

// requireGrantSetNoSoDViolation is requireNoSoDViolation's counterpart for a set
// of roles granted ATOMICALLY to one principal with NO prior grants — e.g.
// CreateUserWithAssignments minting a brand-new user's system role plus project
// assignments in one call, where there is no user ID yet to look up existing
// permissions against, so every role in the set is evaluated together instead.
// Any role in the set that is itself admin-bypass exempts the whole set (see
// package doc above).
func (c *KeyorixCore) requireGrantSetNoSoDViolation(ctx context.Context, roleIDs []uint) error { // nosemgrep: keyorix-unbounded-bulk-slice-param -- roleIDs derives from CreateUserWithAssignments's assignments param, which enforces maxUserCreateAssignments before calling this
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	held := make(map[string]bool)
	for _, rid := range roleIDs {
		role, err := c.storage.GetRole(ctx, rid)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		if isAdminRoleName(role.Name) {
			return nil
		}
		perms, err := c.rolePermissionNameSet(ctx, rid)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		for name := range perms {
			held[name] = true
		}
	}
	if pol := sodPolicyNewlyCompletedBy(policies, map[string]bool{}, held); pol != nil {
		return fmt.Errorf("cannot create user: the combined role assignments would create a separation-of-duties violation with policy %q (%s + %s)",
			pol.Name, pol.PermissionA, pol.PermissionB)
	}
	return nil
}

// requireGroupJoinNoSoDViolation is requireNoSoDViolation's GROUP-JOIN
// counterpart (AUTHZ-007 / #G05): joining a group confers EVERY role the
// group holds at once, so the permissions a new member gains are a SET
// landing atomically — not a sequence of independent single-role grants. A
// per-role loop, where each iteration re-queries the user's CURRENT held
// permissions fresh from storage, structurally cannot see a violation that
// only exists because two of the group's OWN roles combine with each other:
// neither role's individual permission set, checked against what the user
// held BEFORE this join, ever includes the other new role's permissions in
// the same pass. (Confirmed empirically: two roles X and Y granted together
// by one group, {X, Y} a forbidden policy pair, held by neither the user nor
// either role alone, sailed straight through the old per-grant
// requireNoSoDViolation loop.)
//
// This mirrors requireGrantSetNoSoDViolation's "evaluate the whole set
// together" shape, but — unlike that function, which is for a brand-new
// principal with NO prior grants to weigh against — this principal already
// exists, so "held" starts from their actual current permissions
// (userHeldPermissionSet, exactly as requireNoSoDViolation uses), and
// "adding" is the union of every permission ALL of the group's role grants
// would confer, checked together in one pass. Any role in the set that is
// itself admin-bypass exempts the whole join (see package doc above — a
// member who would gain admin-bypass through this join trivially "violates"
// every policy already, same carve-out requireGrantSetNoSoDViolation makes).
func (c *KeyorixCore) requireGroupJoinNoSoDViolation(ctx context.Context, userID uint, grants []storage.RoleAssignment) error {
	// A group with no role grants confers nothing, so there is nothing to
	// evaluate — return before touching storage at all. This matches the old
	// per-role loop's behavior (an empty grants slice meant its body, and thus
	// every storage call inside it, never ran) and keeps a plain, role-less
	// group join working in callers/tests that never provision the
	// sod_policies table.
	if len(grants) == 0 {
		return nil
	}
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	adminRole, err := c.isGlobalAdminRoleName(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if adminRole != "" {
		return nil // already holds admin-bypass — see package doc above
	}
	adding := make(map[string]bool)
	for _, g := range grants {
		role, err := c.storage.GetRole(ctx, g.RoleID)
		if err != nil {
			continue // mirrors validateGroupJoinRoles' existing "skip roles whose definition cannot be loaded"
		}
		if isAdminRoleName(role.Name) {
			return nil // this join grants admin-bypass — see package doc above
		}
		perms, err := c.rolePermissionNameSet(ctx, g.RoleID)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		for name := range perms {
			adding[name] = true
		}
	}
	if len(adding) == 0 {
		return nil
	}
	held, err := c.userHeldPermissionSet(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
		return sodBlockedErr(pol, "join this group")
	}
	return nil
}
