// invitations.go — project invitations + access requests (ADR-024).
//
// Two related onboarding flows:
//
//   - Invitations: an admin invites an email to a project with an intended role.
//     State: pending → accepted / revoked / expired. The email/setup-link
//     consumption (accept) is implemented in setup_consume.go
//     (completeInvitationAccept); this tracks the pending invite so it can be
//     listed, revoked, and aged out.
//   - Access requests: a user asks for a role in a project. State: pending →
//     approved / rejected / withdrawn / expired. Approval grants the (possibly
//     adjusted) role at the project scope. No auto-approval.
//
// Every transition is audited. TTLs: invitations 14 days, access requests 7 days.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Invitation states.
const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationRevoked  = "revoked"
	InvitationExpired  = "expired"
)

// Access request states.
const (
	AccessRequestPending   = "pending"
	AccessRequestApproved  = "approved"
	AccessRequestRejected  = "rejected"
	AccessRequestWithdrawn = "withdrawn"
	AccessRequestExpired   = "expired"
)

// TTLs (ADR-024).
const (
	invitationTTL    = 14 * 24 * time.Hour
	accessRequestTTL = 7 * 24 * time.Hour

	eventInvitationRaceRevokeFailed = "invitation.accept_race_revoke_failed" // #nosec G101 -- audit event type, not a credential
)

// ── Invitations ────────────────────────────────────────────────────────────

// requireAuthorityForRole (REMOVED, FIX-1): used to refuse a role GRANT only
// when the role's NAME matched the fixed canonical admin-tier list
// (super_admin/admin/system_admin/project_admin), doing nothing for any other
// role regardless of what permissions it actually bundled. A custom role
// bundling real permissions under a non-canonical name passed this check
// unconditionally on 9 entry points (AssignRoleToGroup, AssignGroupRoleWithExpiry,
// AssignMachineRole, AddUserToGroup, CreateUserWithAssignments, InviteToProject/
// InviteGlobal, ApproveAccessRequestWithExpiry, TransitionMembership, plus the
// /system proxy re-derivations), letting a low-privilege actor mint an
// arbitrary permission-rich role via any of them. All 9 (plus the proxy layer)
// now call requireGranterHoldsRolePermissions instead — the same mechanism
// AssignUserRole/AssignUserRoleWithExpiry already used, deriving the ceiling
// from the role's real bundled permissions, not its name.

// RequireAdminAuthorityAt exports requireAdminAuthorityAt for the /system proxy
// layer (server/http/handlers), which cannot call unexported KeyorixCore methods
// across the package boundary. Used to re-derive, at the hub, the SAME ceiling
// InviteToProject/InviteGlobal/ApproveSecretAccessRequest/DeleteSoDPolicy-shaped
// core methods already enforce locally on a downstream node before relaying a
// state change here -- the #1542 shape, closed the same way
// TransitionMachineIdentityStateProxy's core.IsValidMachineTransition
// re-derivation was.
func (c *KeyorixCore) RequireAdminAuthorityAt(ctx context.Context, actorID, projectID uint) error {
	return c.requireAdminAuthorityAt(ctx, actorID, projectID)
}

// RequireGranterHoldsRolePermissions exports requireGranterHoldsRolePermissions
// for the /system proxy layer, for the same reason as RequireAdminAuthorityAt
// above -- re-deriving, at the hub, the escalation-by-proxy grant ceiling a
// matching core method already enforces locally on a downstream node before
// relaying a state change here.
func (c *KeyorixCore) RequireGranterHoldsRolePermissions(ctx context.Context, actorID, roleID uint, scope Scope, actorIsMachine bool) error {
	return c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine)
}

// requireAdminAuthorityAt refuses unless actorID holds an admin role (adminRoleNames)
// directly assigned at the given project scope (0 = global). The shared primitive
// behind requireAuthorityForRole (gating a role GRANT) and any other action that
// carries equivalent risk without being a role grant per se — e.g. binding a
// rotation backend to a secret (#90): the backend often carries org-wide admin
// credentials, so the same escalation-by-proxy ceiling applies.
func (c *KeyorixCore) requireAdminAuthorityAt(ctx context.Context, actorID, projectID uint) error {
	ids, err := c.scopedRoleIDs(ctx, actorID, storage.Scope{ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	containsAdmin, err := c.roleSetContainsAdmin(ctx, ids)
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !containsAdmin {
		return fmt.Errorf("admin authority is required")
	}
	return nil
}

// buildProjectInvite validates email/role/the inviter's escalation-by-proxy
// ceiling and constructs (but does NOT persist) the ProjectInvitation row for
// InviteToProject/InviteToProjectWithLink -- split out so the WithLink variant
// can run every check up front, before anything is written, and only then
// decide whether the actual create needs to be atomic with a setup-token mint
// (#2444 coordinator follow-up).
// Returns the possibly-WithSelfMachineGranter-tagged ctx too: the tag is
// applied AFTER GetRoleByName (matching this function's pre-refactor order
// exactly, which existing mocked tests assert on precisely), so the caller
// must use the RETURNED ctx, not its own original one, for anything after
// this call (persistInvitation's audit closure, provisionInvitationSetupLink).
func (c *KeyorixCore) buildProjectInvite(ctx context.Context, projectID uint, email, role string, invitedBy, invitedByMachineID uint) (context.Context, *models.ProjectInvitation, error) {
	if projectID == 0 || email == "" || role == "" {
		return ctx, nil, fmt.Errorf("project ID, email, and role are required")
	}
	if !c.domainAllowed(email) {
		return ctx, nil, fmt.Errorf("email domain is not on the allowlist")
	}
	inviteRole, err := c.storage.GetRoleByName(ctx, role)
	if err != nil {
		return ctx, nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	if invitedByMachineID != 0 {
		ctx = WithSelfMachineGranter(ctx, invitedByMachineID)
	}
	// Escalation-by-proxy guard: the inviter must already hold every permission the
	// invited role bundles (parallel to the access-request ceiling), not merely an
	// admin-tier role name.
	if err := c.requireGranterHoldsRolePermissions(ctx, invitedBy, inviteRole.ID, Scope{ProjectID: projectID}, invitedByMachineID != 0); err != nil {
		return ctx, nil, err
	}
	now := c.now()
	expires := now.Add(invitationTTL)
	return ctx, &models.ProjectInvitation{
		ProjectID:                  projectID,
		Email:                      email,
		Role:                       role,
		State:                      InvitationPending,
		InvitedBy:                  invitedBy,
		InvitedByMachineIdentityID: invitedByMachineID,
		// Snapshot the install validation mode (ADR-022) so acceptance honours the
		// mode in force at invite time, not whatever it changes to later.
		ValidationModeAtInvite: c.validationMode(),
		ExpiresAt:              &expires,
		CreatedAt:              now,
	}, nil
}

// persistInvitation commits inv (built by buildProjectInvite/buildGlobalInvite,
// not yet persisted) and runs auditFn with the committed row. Shared by the
// standalone InviteToProject/InviteGlobal and by provisionInvitationSetupLink's
// benign early-exit paths (base_url unset, throttled) below, which must keep
// creating the invitation immediately and unconditionally -- those are
// config/rate-limit conditions, not storage faults, so there is nothing to
// roll back and the existing "caller can resend" contract stays intact. A
// throttle whose count query FAILED (ErrResendThrottleUnverifiable) is a
// storage fault, not a rate-limit verdict, and does not take this path (#2599).
func (c *KeyorixCore) persistInvitation(ctx context.Context, inv *models.ProjectInvitation, auditFn func(*models.ProjectInvitation)) (*models.ProjectInvitation, error) {
	created, err := c.storage.CreateProjectInvitation(ctx, inv)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}
	auditFn(created)
	return created, nil
}

// createInvitationWithSetupTokenAtomically commits inv and mints its setup
// token (supersede+create) in ONE outer transaction (#2444 coordinator
// follow-up): a genuine storage fault in the mint step must roll the
// invitation insert back too, not leave an orphan pending invitation with no
// working link and no superseded-token side effect that could also block a
// resend via a duplicate-pending check. mintSetupTokenOn's own WithTransaction
// nests as a SAVEPOINT inside this one (see its doc comment), so the two
// writes genuinely commit or roll back together. Neither inv's nor the
// token's audit event is written here -- both happen only once this whole
// transaction has actually committed (see provisionInvitationSetupLink).
// invCtx (possibly WithSelfMachineGranter-tagged, see buildProjectInvite/
// buildGlobalInvite) is used ONLY for the invitation insert, matching
// pre-refactor behavior exactly; the mint step keeps using the caller's
// original, untagged ctx (the same one IssueSetupToken was always called
// with from this flow).
func (c *KeyorixCore) createInvitationWithSetupTokenAtomically(ctx, invCtx context.Context, inv *models.ProjectInvitation, req IssueSetupTokenRequest) (*models.ProjectInvitation, *IssueSetupTokenResult, error) {
	var created *models.ProjectInvitation
	var issued *IssueSetupTokenResult
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		var cerr error
		created, cerr = tx.CreateProjectInvitation(invCtx, inv)
		if cerr != nil {
			return cerr
		}
		req.InvitationID = &created.ID
		issued, cerr = c.mintSetupTokenOn(ctx, tx, req)
		return cerr
	})
	if err != nil {
		// mintSetupTokenOn already wraps a genuine mint-step failure with
		// ErrSetupTokenIssuanceFailed; a CreateProjectInvitation failure (rarer,
		// e.g. a storage error on the insert itself) reaches here unwrapped --
		// wrap it the same way, since either case means the SAME thing to every
		// caller: nothing committed, fail closed.
		if !errors.Is(err, ErrSetupTokenIssuanceFailed) {
			err = fmt.Errorf("%w: %w", ErrSetupTokenIssuanceFailed, err)
		}
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return created, issued, nil
}

// provisionInvitationSetupLink is InviteToProjectWithLink/InviteGlobalWithLink's
// shared body: it mirrors provisionSetupLink's base_url/throttle/deliver
// sequence, but creates inv together with the setup token's supersede+create
// as one atomic unit via createInvitationWithSetupTokenAtomically (#2444
// coordinator follow-up) instead of minting against an already-committed
// invitation. inv must not be persisted yet (callers build it via
// buildProjectInvite/buildGlobalInvite, which also return invCtx -- pass that
// through here unchanged; every OTHER step keeps using the plain ctx callers
// already passed to provisionSetupLink/IssueSetupToken pre-refactor). The
// base_url-unset and throttled cases are UNCHANGED from before this fix:
// neither is a storage fault, the invitation is still created and committed
// immediately via persistInvitation, and the caller can fix config/wait and
// resend -- only the actual mint attempt needs atomicity with the invitation
// insert. The one throttle outcome that is NOT benign is a failed count query
// (ErrResendThrottleUnverifiable): that is a storage fault like a failed mint,
// so it persists nothing and returns a nil invitation (#2599). Before, it
// committed the invitation with no setup token and the HTTP layer reported 201
// -- a state no fault-free run reaches. The throttle still fails closed: no
// link is issued either way.
func (c *KeyorixCore) provisionInvitationSetupLink(ctx, invCtx context.Context, inv *models.ProjectInvitation, auditFn func(*models.ProjectInvitation), req IssueSetupTokenRequest, displayName, assignmentSummary string) (*models.ProjectInvitation, *ProvisionSetupResult, error) {
	if c.setupBaseURL == "" {
		created, err := c.persistInvitation(invCtx, inv, auditFn)
		if err != nil {
			return nil, nil, err
		}
		return created, nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrSetupBaseURLRequired)
	}

	c.setupResendMu.Lock()
	if err := c.checkResendThrottle(ctx, req.Purpose, req.SubjectEmail); err != nil {
		c.setupResendMu.Unlock()
		if errors.Is(err, ErrResendThrottleUnverifiable) {
			return nil, nil, err
		}
		created, cerr := c.persistInvitation(invCtx, inv, auditFn)
		if cerr != nil {
			return nil, nil, cerr
		}
		return created, nil, err
	}
	created, issued, err := c.createInvitationWithSetupTokenAtomically(ctx, invCtx, inv, req)
	c.setupResendMu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	auditFn(created)
	c.auditSetupTokenIssued(ctx, req, issued.Token)

	prov, err := c.deliverSetupLink(ctx, issued, req, displayName, assignmentSummary)
	if err != nil {
		return created, nil, err
	}
	return created, prov, nil
}

// InviteToProject creates a pending invitation for an email to a project with an
// intended role. It snapshots the current validation mode and sets a 14-day TTL.
func (c *KeyorixCore) InviteToProject(ctx context.Context, projectID uint, email, role string, invitedBy, invitedByMachineID uint) (*models.ProjectInvitation, error) {
	ctx, inv, err := c.buildProjectInvite(ctx, projectID, email, role, invitedBy, invitedByMachineID)
	if err != nil {
		return nil, err
	}
	return c.persistInvitation(ctx, inv, func(*models.ProjectInvitation) {
		c.auditProjectScoped(ctx, "invitation.created", invitedBy, projectID,
			fmt.Sprintf("invited %s to project %d as %s", email, projectID, role))
	})
}

// InviteToProjectWithLink creates an invitation and provisions its accept link
// (ADR-028): an invitation_accept setup token bound to the invitation, delivered via
// the configured channel. Returns the invitation and the delivery outcome. If
// provisioning fails (e.g. base_url unset, or the resend throttle below), the
// invitation still exists and is returned with a nil result and the error, so the
// caller can resend rather than losing the invite. A storage fault (the mint
// step, or the throttle's own count query) instead persists nothing and returns
// a nil invitation (#2444, #2599).
//
// The link provisioning is throttled per (purpose, email) via
// provisionSetupLinkThrottled — the same control ResendInvitationLink uses (#183) —
// rather than the unthrottled provisionSetupLink an earlier version called directly.
// Without this, a principal holding only project-scoped roles.assign could loop-call
// this endpoint for the same target email to fire unbounded real SMTP sends from the
// operator's mail relay (#345); reusing the existing (purpose, email) key rather than
// adding an actor or per-invitation dimension keeps initial invites and resends of the
// same target subject to one combined rate, matching how ResendInvitationLink already
// treats every pending invite to the same email as one throttled subject.
//
// The SEPARATE pre-issuance supersede (IssueSetupToken's "kill the old link" step) is,
// unlike the throttle above, scoped to THIS project via SupersedeProjectID
// (CORE-INVITATIONS-003): without it, any admin holding roles.assign in some unrelated
// project B could invite the same target email to project B and, as a side effect,
// silently invalidate project A's still-pending invite link — a cross-project
// interference project B's admin has no authority to cause and no visibility into.
// Scoping the supersede (but deliberately NOT the throttle, which stays per (purpose,
// email) globally — see above) preserves the SMTP-abuse ceiling while eliminating that
// cross-project side effect. A genuine same-project resend/re-invite still supersedes
// the prior pending invite for that project, exactly as before.
func (c *KeyorixCore) InviteToProjectWithLink(ctx context.Context, projectID uint, email, role string, invitedBy, invitedByMachineID uint) (*models.ProjectInvitation, *ProvisionSetupResult, error) {
	invCtx, inv, err := c.buildProjectInvite(ctx, projectID, email, role, invitedBy, invitedByMachineID)
	if err != nil {
		return nil, nil, err
	}
	auditFn := func(*models.ProjectInvitation) {
		c.auditProjectScoped(invCtx, "invitation.created", invitedBy, projectID,
			fmt.Sprintf("invited %s to project %d as %s", email, projectID, role))
	}
	return c.provisionInvitationSetupLink(ctx, invCtx, inv, auditFn, IssueSetupTokenRequest{
		Purpose:                    SetupPurposeInvitationAccept,
		SubjectEmail:               email,
		CreatedBy:                  invitedBy,
		CreatedByMachineIdentityID: invitedByMachineID,
		SupersedeProjectID:         &projectID,
	}, "", fmt.Sprintf("%s on project %d", role, projectID))
}

// InviteGlobal creates a non-project-scoped invitation (ProjectID 0) that, on
// accept, grants a system role plus a set of project assignments in one go — the
// invitation analogue of CreateUserWithAssignments (ADR-024/028). The system role
// and every assignment (project + role) are validated and deduped up front, so
// acceptance can't later fail on an unknown role or project. The per-project
// grants are snapshotted as JSON on the invitation.
func (c *KeyorixCore) InviteGlobal(ctx context.Context, email, systemRole string, assignments []ProjectAssignment, invitedBy, invitedByMachineID uint) (*models.ProjectInvitation, error) {
	ctx, inv, sysRole, clean, err := c.buildGlobalInvite(ctx, email, systemRole, assignments, invitedBy, invitedByMachineID)
	if err != nil {
		return nil, err
	}
	return c.persistInvitation(ctx, inv, func(*models.ProjectInvitation) {
		c.auditProjectScoped(ctx, "invitation.created", invitedBy, 0,
			fmt.Sprintf("invited %s globally as %s with %d project assignment(s)", email, sysRole, len(clean)))
	})
}

// buildGlobalInvite validates email/system role/every project assignment's
// escalation-by-proxy ceiling and constructs (but does NOT persist) the
// ProjectInvitation row for InviteGlobal/InviteGlobalWithLink -- split out for
// the same reason as buildProjectInvite above (#2444 coordinator follow-up).
// Returns the possibly-WithSelfMachineGranter-tagged ctx too, for the same
// reason as buildProjectInvite: the tag is applied AFTER the sysRole lookup
// (matching this function's pre-refactor order, which existing mocked tests
// assert on precisely), so the caller must use the RETURNED ctx afterward.
func (c *KeyorixCore) buildGlobalInvite(ctx context.Context, email, systemRole string, assignments []ProjectAssignment, invitedBy, invitedByMachineID uint) (outCtx context.Context, inv *models.ProjectInvitation, sysRole string, clean []ProjectAssignment, err error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	if email == "" {
		return ctx, nil, "", nil, fmt.Errorf("email is required")
	}
	if !c.domainAllowed(email) {
		return ctx, nil, "", nil, fmt.Errorf("email domain is not on the allowlist")
	}
	sysRole = systemRole
	if sysRole == "" {
		sysRole = "system_viewer"
	}
	sysRoleModel, err := c.storage.GetRoleByName(ctx, sysRole)
	if err != nil {
		return ctx, nil, "", nil, fmt.Errorf("unknown role %q (system): %w", sysRole, err)
	}
	if invitedByMachineID != 0 {
		ctx = WithSelfMachineGranter(ctx, invitedByMachineID)
	}
	// Escalation-by-proxy guard (#231), mirroring InviteToProject: a global system
	// role is the most powerful grant this flow can mint, so it needs the ceiling
	// check applied everywhere else — the inviter's real bundled permissions, not
	// just the role's name — at global scope (projectID 0).
	//
	// F6 sweep (2026-09-22): requireGranterHoldsRolePermissions's roles.assign
	// BASELINE deliberately does not apply when systemRole was left empty --
	// see CreateUserWithAssignments' identical comment (users.go) for the full
	// reasoning: a mandatory, non-discretionary default (here, system_viewer)
	// mirrors plain CreateUser's own unconditional auto-assign and is gated by
	// users.write alone, same as this test file's own documented invariant
	// ("inviting the default baseline (no role) is still allowed").
	if systemRole == "" {
		if err := c.requireGranterHoldsRolePermissionsNoBaseline(ctx, invitedBy, sysRoleModel.ID, Scope{}, invitedByMachineID != 0); err != nil {
			return ctx, nil, "", nil, err
		}
	} else if err := c.requireGranterHoldsRolePermissions(ctx, invitedBy, sysRoleModel.ID, Scope{}, invitedByMachineID != 0); err != nil {
		return ctx, nil, "", nil, err
	}

	// Validate + dedup assignments before persisting anything.
	seen := map[uint]bool{}
	clean = make([]ProjectAssignment, 0, len(assignments))
	for _, a := range assignments {
		if a.ProjectID == 0 || a.Role == "" {
			return ctx, nil, "", nil, fmt.Errorf("each project assignment needs a project_id and a role")
		}
		if seen[a.ProjectID] {
			continue
		}
		seen[a.ProjectID] = true
		if _, err := c.storage.GetProject(ctx, a.ProjectID); err != nil {
			return ctx, nil, "", nil, fmt.Errorf("unknown project %d: %w", a.ProjectID, err)
		}
		assignRole, err := c.storage.GetRoleByName(ctx, a.Role)
		if err != nil {
			return ctx, nil, "", nil, fmt.Errorf("unknown role %q: %w", a.Role, err)
		}
		// Same ceiling check InviteToProject applies to its own role parameter —
		// without this, a non-admin roles.assign holder could bundle a
		// permission-rich project assignment into an otherwise-innocuous global
		// invite.
		if err := c.requireGranterHoldsRolePermissions(ctx, invitedBy, assignRole.ID, Scope{ProjectID: a.ProjectID}, invitedByMachineID != 0); err != nil {
			return ctx, nil, "", nil, err
		}
		clean = append(clean, ProjectAssignment{ProjectID: a.ProjectID, Role: a.Role})
	}
	assignJSON := ""
	if len(clean) > 0 {
		b, err := json.Marshal(clean)
		if err != nil {
			return ctx, nil, "", nil, fmt.Errorf("failed to encode assignments: %w", err)
		}
		assignJSON = string(b)
	}

	now := c.now()
	expires := now.Add(invitationTTL)
	inv = &models.ProjectInvitation{
		ProjectID:                  0, // global
		Email:                      email,
		Role:                       "",
		State:                      InvitationPending,
		InvitedBy:                  invitedBy,
		InvitedByMachineIdentityID: invitedByMachineID,
		SystemRole:                 sysRole,
		AssignmentsJSON:            assignJSON,
		ValidationModeAtInvite:     c.validationMode(),
		ExpiresAt:                  &expires,
		CreatedAt:                  now,
	}
	return ctx, inv, sysRole, clean, nil
}

// InviteGlobalWithLink creates a global invitation and provisions its accept link
// (ADR-028), mirroring InviteToProjectWithLink. A nil result with a non-nil error
// and a non-nil invitation means the invite exists but the link couldn't be
// delivered (e.g. base_url unset, or the resend throttle) — the caller can resend.
// Throttled per (purpose, email) via provisionSetupLinkThrottled for the same reason
// as InviteToProjectWithLink (#345): the users.write-gated global-invite endpoint is
// otherwise an equally loop-callable unbounded-SMTP vector.
//
// Unlike InviteToProjectWithLink, SupersedeProjectID is intentionally left nil: a
// global invite (ProjectID 0) has no single project to scope the pre-issuance
// supersede to, so it keeps the original (purpose, email)-only scope — it still
// supersedes a prior pending global invite to the same address, and, as before, a
// prior PROJECT-scoped invite to that address (there is no narrower boundary to draw
// here; CORE-INVITATIONS-003 is specifically about project-vs-project interference).
func (c *KeyorixCore) InviteGlobalWithLink(ctx context.Context, email, systemRole string, assignments []ProjectAssignment, invitedBy, invitedByMachineID uint) (*models.ProjectInvitation, *ProvisionSetupResult, error) {
	invCtx, inv, sysRole, clean, err := c.buildGlobalInvite(ctx, email, systemRole, assignments, invitedBy, invitedByMachineID)
	if err != nil {
		return nil, nil, err
	}
	auditFn := func(*models.ProjectInvitation) {
		c.auditProjectScoped(invCtx, "invitation.created", invitedBy, 0,
			fmt.Sprintf("invited %s globally as %s with %d project assignment(s)", email, sysRole, len(clean)))
	}
	return c.provisionInvitationSetupLink(ctx, invCtx, inv, auditFn, IssueSetupTokenRequest{
		Purpose:                    SetupPurposeInvitationAccept,
		SubjectEmail:               email,
		CreatedBy:                  invitedBy,
		CreatedByMachineIdentityID: invitedByMachineID,
	}, "", fmt.Sprintf("%s + %d project assignment(s)", sysRole, len(assignments)))
}

// applyInvitationGrants materializes an invitation's role grants onto a freshly
// created (accepting) user. A global invite (ADR-024) grants its system role plus
// each project assignment from AssignmentsJSON; a project-scoped invite grants the
// single project role. Everything was validated at invite time, so a failure here
// is a storage error (leaving the invitation pending/resendable), not bad input.
func (c *KeyorixCore) applyInvitationGrants(ctx context.Context, inv *models.ProjectInvitation, userID uint) error { // NOSONAR -- cognitive complexity 22, suppress go:S3776
	// A genuine machine inviter (not a /system proxy relay) -- tag ctx so the
	// requireGranterHoldsRolePermissions calls reached via AssignUserRole/
	// inviteMemberWithMode below check ITS real permissions instead of
	// unconditionally refusing. This ctx is freshly built by the accept-time
	// caller (completeInvitationAccept), so it does not already carry the tag
	// InviteToProject/InviteGlobal set at invite time.
	if inv.InvitedByMachineIdentityID != 0 {
		ctx = WithSelfMachineGranter(ctx, inv.InvitedByMachineIdentityID)
	}
	// Global invite: system role + multi-project assignments.
	if inv.SystemRole != "" || inv.AssignmentsJSON != "" {
		if inv.SystemRole != "" {
			role, err := c.storage.GetRoleByName(ctx, inv.SystemRole)
			if err != nil {
				return fmt.Errorf("unknown system role %q: %w", inv.SystemRole, err)
			}
			// Routed through the audited wrapper — this is the moment of privilege
			// grant for a global invitation (up to and including super_admin), which
			// previously left zero trace of any kind (#299). Attributed to the inviter,
			// consistent with the per-project assignment grants below.
			if err := c.AssignUserRole(ctx, inv.InvitedBy, userID, role.ID, Scope{ProjectID: 0}, inv.InvitedByMachineIdentityID != 0); err != nil {
				return fmt.Errorf("failed to grant system role: %w", err)
			}
		}
		if inv.AssignmentsJSON != "" {
			var assignments []ProjectAssignment
			if err := json.Unmarshal([]byte(inv.AssignmentsJSON), &assignments); err != nil {
				return fmt.Errorf("failed to decode assignments: %w", err)
			}
			for _, a := range assignments {
				if _, err := c.inviteMemberWithMode(ctx, a.ProjectID, userID, a.Role, inv.InvitedBy, inv.InvitedByMachineIdentityID, inv.ValidationModeAtInvite, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	// Project-scoped invite: single project membership.
	_, err := c.inviteMemberWithMode(ctx, inv.ProjectID, userID, inv.Role, inv.InvitedBy, inv.InvitedByMachineIdentityID, inv.ValidationModeAtInvite, false)
	return err
}

// revokeInvitationGrants best-effort undoes applyInvitationGrants for userID. Used
// exclusively by completeInvitationAccept when it discovers, only after granting,
// that the invitation was concurrently revoked (#412): the conditional
// UpdateProjectInvitation write that would flip the row to accepted lost the race,
// so whatever was just granted must not be left standing behind an invitation that
// no longer reads as accepted. actorID 0 attributes the reversal to the system
// (mirroring applyInvitationGrants' own actorID-0-eligible AssignUserRole/
// inviteMemberWithMode calls), and every removal is independently best-effort — a
// failure on one project assignment must not stop the others from being reverted.
// Errors are audited, not returned or retried: the caller is already on a fail-closed
// path and a partial rollback is strictly better than leaving every grant live.
func (c *KeyorixCore) revokeInvitationGrants(ctx context.Context, inv *models.ProjectInvitation, userID uint) {
	if inv.SystemRole != "" || inv.AssignmentsJSON != "" {
		c.revokeSystemRoleGrant(ctx, inv, userID)
		c.revokeAssignmentGrants(ctx, inv, userID)
		return
	}
	// Project-scoped invite: revert the single project membership/role.
	if err := c.RemoveProjectMember(ctx, 0, inv.ProjectID, userID); err != nil {
		c.auditProjectScopedFailed(ctx, eventInvitationRaceRevokeFailed, userID, inv.ProjectID,
			fmt.Sprintf("failed to revert project role %q granted to user %d by invitation %d: %v — MANUAL CLEANUP REQUIRED", inv.Role, userID, inv.ID, err))
	}
}

func (c *KeyorixCore) revokeSystemRoleGrant(ctx context.Context, inv *models.ProjectInvitation, userID uint) {
	if inv.SystemRole == "" {
		return
	}
	role, err := c.storage.GetRoleByName(ctx, inv.SystemRole)
	if err != nil {
		return
	}
	if err := c.RemoveUserRole(ctx, 0, userID, role.ID, Scope{ProjectID: 0}); err != nil {
		c.auditProjectScopedFailed(ctx, eventInvitationRaceRevokeFailed, userID, 0,
			fmt.Sprintf("failed to revert system role %q granted to user %d by invitation %d: %v — MANUAL CLEANUP REQUIRED", inv.SystemRole, userID, inv.ID, err))
	}
}

func (c *KeyorixCore) revokeAssignmentGrants(ctx context.Context, inv *models.ProjectInvitation, userID uint) {
	if inv.AssignmentsJSON == "" {
		return
	}
	var assignments []ProjectAssignment
	if err := json.Unmarshal([]byte(inv.AssignmentsJSON), &assignments); err != nil {
		return
	}
	for _, a := range assignments {
		if err := c.RemoveProjectMember(ctx, 0, a.ProjectID, userID); err != nil {
			c.auditProjectScopedFailed(ctx, eventInvitationRaceRevokeFailed, userID, a.ProjectID,
				fmt.Sprintf("failed to revert project assignment %q granted to user %d by invitation %d: %v — MANUAL CLEANUP REQUIRED", a.Role, userID, inv.ID, err))
		}
	}
}

// ResendInvitationLink reissues the accept link for a still-pending invitation
// (superseding the prior token) and re-delivers it. Throttled per ADR-028. The
// caller is already verified to be authorized within projectID (below), and the
// supersede itself is scoped to that same project (CORE-INVITATIONS-003) — a resend
// here can only ever kill this project's own prior link for the address.
func (c *KeyorixCore) ResendInvitationLink(ctx context.Context, projectID, invitationID, actorID uint) (*ProvisionSetupResult, error) {
	inv, err := c.storage.GetProjectInvitation(ctx, invitationID)
	if err != nil {
		return nil, fmt.Errorf("invitation not found")
	}
	// The caller is authorized within projectID; an invitation in another project
	// must not be resendable through it (cross-project guard).
	if inv.ProjectID != projectID {
		return nil, fmt.Errorf("invitation not found")
	}
	// Lazy-expire an overdue invite so a resend can't revive a dead one. Best-effort:
	// if the conditional write loses to a concurrent transition (accept/revoke), that
	// transition is authoritative and the state check below still refuses the resend.
	if inv.State == InvitationPending && inv.ExpiresAt != nil && c.now().After(*inv.ExpiresAt) {
		inv.State = InvitationExpired
		_, _ = c.storage.UpdateProjectInvitation(ctx, inv)
	}
	if inv.State != InvitationPending {
		return nil, fmt.Errorf("only a pending invitation can be resent (state is %s)", inv.State)
	}
	return c.provisionSetupLinkThrottled(ctx, IssueSetupTokenRequest{
		Purpose:            SetupPurposeInvitationAccept,
		SubjectEmail:       inv.Email,
		InvitationID:       &inv.ID,
		CreatedBy:          actorID,
		SupersedeProjectID: &inv.ProjectID,
	}, "", fmt.Sprintf("%s on project %d", inv.Role, inv.ProjectID))
}

// ListProjectInvitations returns a project's invitations, marking any pending
// invite past its TTL as expired (lazily, on read).
func (c *KeyorixCore) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	rows, err := c.storage.ListProjectInvitations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	for _, inv := range rows {
		if inv.State == InvitationPending && inv.ExpiresAt != nil && now.After(*inv.ExpiresAt) {
			inv.State = InvitationExpired
			// Best-effort: if a concurrent accept/revoke already resolved this
			// invitation, that transition is authoritative — the conditional write
			// no-ops here rather than clobbering it, but the row we return this
			// call is still fine to display with the intended lazy-expiry state.
			_, _ = c.storage.UpdateProjectInvitation(ctx, inv)
		}
	}
	return rows, nil
}

// RevokeInvitation cancels a pending invitation.
func (c *KeyorixCore) RevokeInvitation(ctx context.Context, projectID, invitationID, actorID uint) error {
	inv, err := c.storage.GetProjectInvitation(ctx, invitationID)
	if err != nil {
		return fmt.Errorf("invitation not found")
	}
	if inv.ProjectID != projectID {
		return fmt.Errorf("invitation not found")
	}
	if inv.State != InvitationPending {
		return fmt.Errorf("only a pending invitation can be revoked (state is %s)", inv.State)
	}
	now := c.now()
	inv.State = InvitationRevoked
	inv.RevokedAt = &now
	ok, err := c.storage.UpdateProjectInvitation(ctx, inv)
	if err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}
	if !ok {
		// The invitation stopped being pending between the read above and this
		// write — most likely a concurrent accept (completeInvitationAccept) won
		// the race. Refuse rather than silently reporting success while the
		// invitation (and whatever it granted) is left untouched (#412).
		return fmt.Errorf("invitation is no longer pending (it was concurrently accepted or resolved)")
	}
	c.auditProjectScoped(ctx, "invitation.revoked", actorID, inv.ProjectID,
		fmt.Sprintf("revoked invitation %d (%s)", inv.ID, inv.Email))
	return nil
}

// StaleInvitations returns pending invitations older than the cutoff.
func (c *KeyorixCore) StaleInvitations(ctx context.Context, projectID uint, olderThan time.Duration) ([]*models.ProjectInvitation, error) {
	rows, err := c.storage.ListProjectInvitations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	cutoff := c.now().Add(-olderThan)
	var stale []*models.ProjectInvitation
	for _, inv := range rows {
		if inv.State == InvitationPending && inv.CreatedAt.Before(cutoff) {
			stale = append(stale, inv)
		}
	}
	return stale, nil
}

// ── Access requests ──────────────────────────────────────────────────────────

// RequestProjectAccess creates a pending access request for a user to a project.
func (c *KeyorixCore) RequestProjectAccess(ctx context.Context, projectID, userID uint, suggestedRole, reason string) (*models.AccessRequest, error) {
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("project and user IDs are required")
	}
	if suggestedRole != "" {
		if _, err := c.storage.GetRoleByName(ctx, suggestedRole); err != nil {
			return nil, fmt.Errorf("unknown role %q: %w", suggestedRole, err)
		}
	}
	// The target project must exist and be live — GetProject's default soft-delete scope
	// excludes a deleted project, so this also refuses a request against one that has been
	// soft-deleted (#371). Otherwise a request can sit pending against a project an admin
	// believes is gone, waiting to be approved (and go live) whenever it's restored.
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("project %d not found: %w", projectID, err)
	}
	// #G82: refuse a second pending PROJECT-ROLE request for the SAME (user,
	// project) pair — without this, any authenticated user could call this
	// endpoint in a tight loop and flood the project with an unbounded number
	// of pending AccessRequest rows, each firing its own admin notification
	// (notifyAccessRequested below). Scoped to e.SecretID == nil: a
	// SECRET-scoped request (RequestSecretAccess, classification_gate.go)
	// shares the same (UserID, ProjectID) shape but is a semantically
	// different request the user may legitimately have pending at the same
	// time as a project-role request. ListAccessRequests lazily expires stale
	// pending rows on read, so this check is never blocked by a request
	// that's actually expired.
	existing, err := c.storage.ListAccessRequests(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing access requests: %w", err)
	}
	for _, e := range existing {
		if e.UserID == userID && e.State == AccessRequestPending && e.SecretID == nil {
			return nil, fmt.Errorf("you already have a pending access request for this project")
		}
	}
	now := c.now()
	expires := now.Add(accessRequestTTL)
	req := &models.AccessRequest{
		ProjectID:     projectID,
		UserID:        userID,
		SuggestedRole: suggestedRole,
		State:         AccessRequestPending,
		Reason:        reason,
		ExpiresAt:     &expires,
		CreatedAt:     now,
	}
	created, err := c.storage.CreateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.created", userID, projectID,
		fmt.Sprintf("user %d requested %s access to project %d", userID, suggestedRole, projectID))
	c.runPostCommitNotification(ctx, "access_request.created", userID, created, func() error {
		return c.notifyAccessRequested(ctx, created)
	})
	return created, nil
}

// ListAccessRequests returns a project's access requests, expiring stale pending
// ones lazily on read.
func (c *KeyorixCore) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	rows, err := c.storage.ListAccessRequests(ctx, projectID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	required := c.requiredApprovals()
	for _, req := range rows {
		if req.State == AccessRequestPending && req.ExpiresAt != nil && now.After(*req.ExpiresAt) {
			req.State = AccessRequestExpired
			// Best-effort lazy expiry: a concurrent approve/reject/withdraw that
			// already resolved this request wins and the conditional write no-ops.
			_, _ = c.storage.UpdateAccessRequest(ctx, req)
		}
		// Annotate the dual-control progress for a pending request.
		if req.State == AccessRequestPending {
			req.RequiredApprovals = required
			if approvals, err := c.storage.ListAccessRequestApprovals(ctx, req.ID); err == nil {
				req.ApprovalsReceived = len(approvals)
			}
		}
	}
	return rows, nil
}

// ApproveAccessRequest, a 4-argument convenience wrapper that hardcoded
// approverMachineID=0, was DELETED in #2495. It is deliberately not replaced.
//
// Hardcoding 0 means "there is no acting machine identity", and that is not a
// safe default on this path: a machine caller's approverID is also 0 (ADR-030 —
// a machine identity has no UserID), so the pair (approverID=0,
// approverMachineID=0) is exactly the unauthenticated/system pseudo-actor that
// requireGranterHoldsRolePermissions exempts from the escalation-by-proxy
// ceiling. A machine approver routed through that wrapper was therefore reported
// to the ceiling as trusted-system and skipped it entirely. The bulk
// approve/reject path (bulk_access_requests.go) did exactly that, which is the
// defect #2495 closes.
//
// Call ApproveAccessRequestWithExpiry directly and state the machine identity
// (0 for a genuine human approver) at the call site, so the claim is visible
// where it is made rather than buried in a wrapper.

// SetDualControlPolicy sets the N-of-M approval threshold for access requests
// (A.5.3). <=1 = single approval (the default).
func (c *KeyorixCore) SetDualControlPolicy(requiredApprovals int) {
	c.dualControlRequiredApprovals = requiredApprovals
}

// requiredApprovals returns the dual-control threshold (minimum 1).
func (c *KeyorixCore) requiredApprovals() int {
	if c.dualControlRequiredApprovals > 1 {
		return c.dualControlRequiredApprovals
	}
	return 1
}

// ApproveAccessRequestWithExpiry records an approver's sign-off on a pending request
// and, once the dual-control threshold of K distinct approvers (none the requester)
// is reached, grants the role — TIME-BOUND when grantTTL > 0 (JIT). Below the
// threshold the request stays pending and the returned request carries the M-of-K
// progress. When K is 1 (the default) the first approval grants immediately.
func (c *KeyorixCore) ApproveAccessRequestWithExpiry(ctx context.Context, projectID, requestID, approverID, approverMachineID uint, grantedRole string, grantTTL time.Duration) (*models.AccessRequest, error) {
	// #G04-HA: the read-approvals-decide-record sequence must be serialized per
	// REQUEST across every replica, not merely within this process. What #1646
	// established still holds and is not re-litigated here: two racing
	// THRESHOLD-CROSSING approvals cannot double-grant (UserRole's composite
	// primary key makes the loser's AssignUserRole INSERT fail outright, and the
	// grant deliberately precedes CreateAccessRequestApproval), and one approver
	// cannot inflate the count by racing themselves (models.AccessRequestApproval's
	// ux_access_request_approver unique index). Neither constraint covers a pair of
	// DISTINCT approvers that straddles the K-th approval: both read the same
	// below-threshold count, both take recordPartialApproval, and — being distinct
	// approvers granting no role — collide with neither constraint. The request is
	// then left pending holding K valid approvals, needing a (K+1)-th approver that
	// policy never asked for, and nothing ever reconciles it: the only sweep over
	// pending requests expires them at their TTL. A 2-of-N request approved by
	// exactly two people at the same instant lapses instead of granting.
	//
	// It fails CLOSED, never open — approval rows are unique per approver and the
	// finalizing caller is by construction not already among them, so the distinct
	// approver count at finalize is always len(approvals)+1 >= K. The cost is
	// availability (a legitimately-approved break-glass grant that never lands) and
	// audit fidelity (both racers emit the same "approval M of K" ordinal, and the
	// K-th is never recorded) — the latter directly undercutting the ISO 27001
	// A.5.3 / SOX evidence this threshold exists to produce.
	//
	// WithNamedLock is #1646's own general-purpose primitive rather than a bespoke
	// one: a Postgres advisory lock keyed per request, and a process mutex on
	// SQLite where there is no cross-replica concern. Keying on the request (not a
	// single global mutex, as dualControlApprovalMu was) also lets approvals of
	// DIFFERENT requests proceed concurrently, which the mutex it replaces did not.
	var approved *models.AccessRequest
	if err := c.storage.WithNamedLock(ctx, dualControlLockKey(requestID), func(ctx context.Context) error {
		// fn receives the lock-marked ctx and MUST thread it onward: the grant path
		// below reaches AssignUserRole, which takes its own WithNamedLock on
		// sodGrantLockKey. Passing a closed-over ctx instead would drop the
		// reentrancy marker (see store.namedLockHeldCtxKey).
		res, err := c.approveAccessRequestWithExpiryLocked(ctx, projectID, requestID, approverID, approverMachineID, grantedRole, grantTTL)
		if err != nil {
			return err
		}
		approved = res
		return nil
	}); err != nil {
		return nil, err
	}
	return approved, nil
}

// dualControlLockKey names the per-request lock serializing an access request's
// M-of-K approval sequence across replicas. Mirrors sodGrantLockKey's convention
// (rbac_management.go): a stable, collision-free string per protected subject.
func dualControlLockKey(requestID uint) string {
	return fmt.Sprintf("dual-control-approval:request:%d", requestID)
}

// approveAccessRequestWithExpiryLocked is ApproveAccessRequestWithExpiry's body,
// running under the per-request named lock its caller holds. ctx is the
// lock-marked context and must be used for every downstream call.
func (c *KeyorixCore) approveAccessRequestWithExpiryLocked(ctx context.Context, projectID, requestID, approverID, approverMachineID uint, grantedRole string, grantTTL time.Duration) (*models.AccessRequest, error) {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("access request not found")
	}
	// The approver is authorized within projectID; a request belonging to another
	// project must not be approvable through it, or the role grant would land in a
	// project the caller has no rights over (cross-project privilege escalation).
	if req.ProjectID != projectID {
		return nil, fmt.Errorf("access request not found")
	}
	if req.State != AccessRequestPending {
		return nil, fmt.Errorf("only a pending request can be approved (state is %s)", req.State)
	}
	// The target project must still be live at approval time (#371) — DeleteProject never
	// touches access_requests, so a request can otherwise sit pending across a project
	// soft-delete and be approved afterward, producing a role grant scoped to a
	// nonexistent project that goes live again — against potentially-stale intent — the
	// moment the project is later restored, with no re-review of whether the original
	// approval still makes sense. GetProject's default soft-delete scope makes this check
	// double as the soft-delete check.
	if _, err := c.storage.GetProject(ctx, req.ProjectID); err != nil {
		return nil, fmt.Errorf("cannot approve: project %d no longer exists", req.ProjectID)
	}
	// Enforce the request's own TTL here, not only on the list path. GetAccessRequest
	// returns the stored record verbatim, so a request whose expiry has passed is still
	// State==pending until something reconciles it — approving it would grant access on a
	// stale request that should have lapsed. Expire it lazily and refuse.
	if req.ExpiresAt != nil {
		// #1653: refuse a now that looks earlier than one this process has
		// already legitimately observed for an access-request approval --
		// shared with ApproveSecretAccessRequest's identical check
		// (classification_gate.go); see
		// checkAccessRequestApprovalClockNotRegressed's doc comment there.
		if err := c.checkAccessRequestApprovalClockNotRegressed(c.now()); err != nil {
			return nil, err
		}
		if c.now().After(*req.ExpiresAt) {
			req.State = AccessRequestExpired
			// Best-effort: if a concurrent approve/reject/withdraw already resolved this
			// request, the "has expired" refusal below still stands — no role was
			// granted on this path, so there's nothing to unwind either way.
			_, _ = c.storage.UpdateAccessRequest(ctx, req)
			return nil, fmt.Errorf("access request has expired")
		}
	}
	if grantTTL < 0 {
		return nil, fmt.Errorf("grant TTL must not be negative")
	}
	// Maker ≠ checker: a requester cannot approve their own request.
	if approverID == req.UserID {
		return nil, fmt.Errorf("a requester cannot approve their own access request")
	}
	// Determine the role to grant. Under multi-party control (K>1) the role is LOCKED to
	// the request's suggested_role — the value every approver reviews. A per-approver
	// override would let the threshold-crossing approver substitute a higher role than
	// the other K-1 approvers consented to (a dual-control escalation). Single-control
	// (K=1) keeps the approve-with-a-different-role override, where one approver is the
	// whole decision anyway.
	required := c.requiredApprovals()
	role, err := resolveApprovalRole(req, grantedRole, required)
	if err != nil {
		return nil, err
	}
	roleModel, err := c.storage.GetRoleByName(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	// Privilege ceiling: an approver may not grant a role unless they themselves
	// hold every permission it bundles (escalation-by-proxy guard), not merely an
	// admin-tier role name.
	if approverMachineID != 0 {
		ctx = WithSelfMachineGranter(ctx, approverMachineID)
	}
	if err := c.requireGranterHoldsRolePermissions(ctx, approverID, roleModel.ID, Scope{ProjectID: req.ProjectID}, approverMachineID != 0); err != nil {
		return nil, err
	}
	// One sign-off per distinct approver.
	approvals, err := c.storage.ListAccessRequestApprovals(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to read approvals: %w", err)
	}
	if hasAlreadyApproved(approvals, approverID, approverMachineID) {
		return nil, fmt.Errorf("you have already approved this request")
	}
	received := len(approvals) + 1
	// Below the threshold: record the approval, stay pending, notify, return progress.
	if received < required {
		return c.recordPartialApproval(ctx, req, requestID, approverID, approverMachineID, received, required)
	}
	// Threshold reached — grant the role and finalize.
	return c.finalizeAccessRequestApproval(ctx, req, approverID, approverMachineID, roleModel, grantTTL, received, required)
}

// resolveApprovalRole determines the role string to grant for an approval, enforcing
// the dual-control lock when required > 1.
func resolveApprovalRole(req *models.AccessRequest, grantedRole string, required int) (string, error) {
	role := grantedRole
	if role == "" {
		role = req.SuggestedRole
	}
	if required > 1 {
		if req.SuggestedRole == "" {
			return "", fmt.Errorf("a %d-of-N access request must specify the role at request time", required)
		}
		if grantedRole != "" && grantedRole != req.SuggestedRole {
			return "", fmt.Errorf("under %d-of-N approval the granted role is fixed to the requested role %q and cannot be changed by an approver", required, req.SuggestedRole)
		}
		role = req.SuggestedRole
	}
	if role == "" {
		return "", fmt.Errorf("a role to grant is required")
	}
	return role, nil
}

// hasAlreadyApproved reports whether the (approverID, approverMachineID) principal
// already appears in the existing approvals. #1573: approverID alone is 0 for
// EVERY machine caller (ADR-030, no UserID), so comparing only ApproverID would
// treat any two distinct machine approvers as the same approver — the second,
// genuinely different machine's legitimate sign-off would be rejected as a
// duplicate, making a K>=2 threshold unreachable via machine approvers.
// approverMachineID is 0 for a human approver, so the tuple comparison reduces
// to the original ApproverID-only check for the human case unchanged.
func hasAlreadyApproved(approvals []*models.AccessRequestApproval, approverID, approverMachineID uint) bool {
	for _, a := range approvals {
		if a.ApproverID == approverID && a.ApproverMachineIdentityID == approverMachineID {
			return true
		}
	}
	return false
}

// recordPartialApproval handles the below-threshold path: records the approval, stays
// pending, notifies, and returns progress annotations on the request.
func (c *KeyorixCore) recordPartialApproval(ctx context.Context, req *models.AccessRequest, requestID, approverID, approverMachineID uint, received, required int) (*models.AccessRequest, error) {
	if err := c.storage.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: requestID, ApproverID: approverID, ApproverMachineIdentityID: approverMachineID, CreatedAt: c.now(),
	}); err != nil {
		return nil, fmt.Errorf("failed to record approval: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.approval_recorded", approverID, req.ProjectID,
		fmt.Sprintf("approval %d of %d recorded for access request %d", received, required, req.ID))
	c.runPostCommitNotification(ctx, "access_request.approval_recorded", approverID, req, func() error {
		return c.notifyApprovalProgress(ctx, req, received, required)
	})
	req.ApprovalsReceived = received
	req.RequiredApprovals = required
	return req, nil
}

// finalizeAccessRequestApproval handles the threshold-reached path: grants the role,
// records the approval, and updates the request state atomically. On a concurrent
// write race (!ok) nothing is granted at all — the whole sequence rolls back.
//
// The grant, the approval record, and the request-state update all run inside ONE
// storage.WithTransaction, instead of granting first and compensating with a
// separate RemoveUserRole call if a later step fails (the pre-fix shape, PR #2306).
// Compensating-after-the-fact had two real costs this closes: (1) a window existed,
// between the grant's own commit and the compensating revert's commit, where the
// role was genuinely, visibly granted — anything reading UserRole state in that
// window (an auth check, a token mint) saw an over-grant that was about to be
// un-done; true atomicity removes that window entirely, not just shortens it. (2) a
// CreateAccessRequestApproval storage error reverted correctly but still left a new
// "approval_race_reverted" AuditEvent behind — the operation's only observable
// effect for a reported failure — which FuzzStorageFaultOperations' oracle (a)
// flags as "reported an ERROR but logical state changed anyway" (found via
// REST PUT /api/v1/projects/{id}/access-requests/{requestId}, fault
// CreateAccessRequestApproval#1/error, GH #2407). A clean rollback has no such
// side effect: a reported failure now means PRECISELY "nothing happened," matching
// every other mutating call's own error contract.
//
// Mirrors the SoD-grant locking AssignUserRole/AssignUserRoleWithExpiry use
// (#1646, sodGrantLockKey): the lock must still span the SoD check and the write
// so a concurrent grant cannot slip in between them, but the write itself needs to
// also cover CreateAccessRequestApproval/UpdateAccessRequest atomically — grant
// ceiling + SoD check stay as plain reads immediately before the lock/transaction
// (same timing the two functions above already use), the lock is taken once, and
// the transaction opens INSIDE it (pg_advisory_lock is session-scoped, independent
// of transaction boundaries, so nesting a transaction inside an already-held
// named lock is the same safe shape WithNamedLock's own call sites already rely
// on elsewhere).
func (c *KeyorixCore) finalizeAccessRequestApproval(ctx context.Context, req *models.AccessRequest, approverID, approverMachineID uint, roleModel *models.Role, grantTTL time.Duration, received, required int) (*models.AccessRequest, error) {
	now := c.now()
	scope := storage.Scope{ProjectID: req.ProjectID}
	grantDesc := roleModel.Name
	var expiresAt time.Time
	if grantTTL > 0 {
		expiresAt = now.Add(grantTTL)
		grantDesc = fmt.Sprintf("%s until %s (TTL %s)", roleModel.Name, expiresAt.UTC().Format(time.RFC3339), grantTTL)
	}
	// Same two gates AssignUserRole(WithExpiry) apply, run once here up front: the
	// escalation-by-proxy grant ceiling (#93/#107/#141) and (inside the lock below)
	// the #419 separation-of-duties preventive check.
	if err := c.requireGranterHoldsRolePermissions(ctx, approverID, roleModel.ID, scope, approverMachineID != 0); err != nil {
		return nil, fmt.Errorf("failed to grant role: %w", err)
	}

	raceLost := false
	err := c.storage.WithNamedLock(ctx, sodGrantLockKey("user", req.UserID), func(ctx context.Context) error {
		if err := c.requireNoSoDViolation(ctx, req.UserID, roleModel.ID); err != nil {
			return err
		}
		// AUDIT-TX-2: the grant's role.assigned row and the access_request.approved
		// row are the last statements of the same transaction.
		return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
			if grantTTL > 0 {
				if err := tx.AssignRoleWithExpiry(ctx, req.UserID, roleModel.ID, scope, expiresAt); err != nil {
					return fmt.Errorf("failed to grant role: %w", err)
				}
			} else if err := tx.AssignRole(ctx, req.UserID, roleModel.ID, scope); err != nil {
				return fmt.Errorf("failed to grant role: %w", err)
			}
			if err := tx.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
				RequestID: req.ID, ApproverID: approverID, ApproverMachineIdentityID: approverMachineID, CreatedAt: now,
			}); err != nil {
				return fmt.Errorf("failed to record approval: %w", err)
			}
			req.State = AccessRequestApproved
			req.GrantedRole = roleModel.Name
			req.ResolvedBy = approverID
			req.ResolvedByMachineIdentityID = approverMachineID
			req.ResolvedAt = &now
			ok, err := tx.UpdateAccessRequest(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to update access request: %w", err)
			}
			if !ok {
				// The request stopped being pending between the read in
				// approveAccessRequestWithExpiryLocked and this write — most likely a
				// concurrent WithdrawAccessRequest/RejectAccessRequest (neither takes
				// this request's dualControlLockKey lock) won the race. Returning an
				// error here rolls back the grant and the approval record together —
				// nothing to revert afterward, since nothing committed.
				raceLost = true
				return fmt.Errorf("access request was concurrently withdrawn or resolved")
			}
			c.LogRoleAssignedOn(ctx, tgt, approverID, req.UserID, roleModel.ID, scope)
			c.auditProjectScopedOn(ctx, tgt, "access_request.approved", approverID, req.ProjectID,
				fmt.Sprintf("approved access request %d for user %d as %s (%d approval(s))", req.ID, req.UserID, grantDesc, received))
			return nil
		})
	})
	if err != nil {
		if raceLost {
			return nil, fmt.Errorf("access request was concurrently withdrawn or resolved; no role was granted")
		}
		return nil, err
	}

	// Notify only once the transaction (grant + audit rows) has committed.
	c.runPostCommitNotification(ctx, "access_request.approved", approverID, req, func() error {
		return c.notifyAccessResolved(ctx, req, true)
	})
	req.ApprovalsReceived = received
	req.RequiredApprovals = required
	return req, nil
}

// notifyApprovalProgress alerts the project's approvers that a request needs more
// sign-offs (best-effort). It returns every failure for runPostCommitNotification
// to record; whoever WAS resolved is still notified.
func (c *KeyorixCore) notifyApprovalProgress(ctx context.Context, req *models.AccessRequest, received, required int) error {
	var errs []error
	recipients, rerr := c.projectAdminRecipients(ctx, req.ProjectID) // partial result still notified (best-effort)
	if rerr != nil {
		errs = append(errs, fmt.Errorf("resolve project %d admins (%d resolved), some admins may not be notified: %w", req.ProjectID, len(recipients), rerr))
	}
	pid := req.ProjectID
	label := c.projectLabel(ctx, req.ProjectID)
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	msg := fmt.Sprintf("Access request %d for %s has %d of %d approvals — another approver is needed.", req.ID, label, received, required)
	for _, uid := range recipients {
		if uid == req.UserID {
			continue
		}
		errs = append(errs, c.notifyChecked(ctx, uid, NotificationAccessRequested, "Access request needs another approval", msg, &pid, link, models.NotificationSeverityNone))
	}
	return errors.Join(errs...)
}

// RejectAccessRequest rejects a pending request with a reason.
func (c *KeyorixCore) RejectAccessRequest(ctx context.Context, projectID, requestID, approverID, approverMachineID uint, reason string) (*models.AccessRequest, error) {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("access request not found")
	}
	if req.ProjectID != projectID {
		return nil, fmt.Errorf("access request not found")
	}
	if req.State != AccessRequestPending {
		return nil, fmt.Errorf("only a pending request can be rejected (state is %s)", req.State)
	}
	now := c.now()
	req.State = AccessRequestRejected
	req.Reason = reason
	req.ResolvedBy = approverID
	req.ResolvedByMachineIdentityID = approverMachineID
	req.ResolvedAt = &now
	ok, err := c.storage.UpdateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update access request: %w", err)
	}
	if !ok {
		// The request stopped being pending between the read above and this write —
		// e.g. a concurrent approval already granted the role and moved it to
		// approved. Refuse rather than silently reporting a rejection that never
		// took effect (#277's TOCTOU pattern, applied here too).
		return nil, fmt.Errorf("access request is no longer pending (it was concurrently approved or resolved)")
	}
	c.auditProjectScoped(ctx, "access_request.rejected", approverID, req.ProjectID,
		fmt.Sprintf("rejected access request %d for user %d", req.ID, req.UserID))
	c.runPostCommitNotification(ctx, "access_request.rejected", approverID, req, func() error {
		return c.notifyAccessResolved(ctx, req, false)
	})
	return req, nil
}

// WithdrawAccessRequest lets the requester cancel their own pending request.
// #G14: a nonexistent requestID and one that exists but belongs to another
// user both yield the SAME "access request not found" error — a distinct "not
// your access request" message would let a caller enumerate which request IDs
// exist (and are owned by someone else) purely from the response shape.
func (c *KeyorixCore) WithdrawAccessRequest(ctx context.Context, requestID, userID uint) error {
	notFound := fmt.Errorf("access request not found")
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return notFound
	}
	if req.UserID != userID {
		return notFound
	}
	if req.State != AccessRequestPending {
		return fmt.Errorf("only a pending request can be withdrawn (state is %s)", req.State)
	}
	now := c.now()
	req.State = AccessRequestWithdrawn
	req.ResolvedAt = &now
	ok, err := c.storage.UpdateAccessRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
	}
	if !ok {
		// The request stopped being pending between the read above and this write —
		// e.g. a concurrent approval already granted the role and moved it to
		// approved. Refuse rather than silently reporting a withdrawal that never
		// took effect while a role grant is live behind it (#277).
		return fmt.Errorf("access request is no longer pending (it was concurrently approved or resolved)")
	}
	c.auditProjectScoped(ctx, "access_request.withdrawn", userID, req.ProjectID,
		fmt.Sprintf("withdrew access request %d", req.ID))
	return nil
}

// auditProjectScoped writes a project-scoped audit event with an actor.
func (c *KeyorixCore) auditProjectScoped(ctx context.Context, eventType string, actorID, projectID uint, description string) {
	c.auditProjectScopedOn(ctx, c.auditNow(), eventType, actorID, projectID, description)
}

// auditProjectScopedOn is auditProjectScoped against an explicit audit target.
func (c *KeyorixCore) auditProjectScopedOn(ctx context.Context, tgt auditTarget, eventType string, actorID, projectID uint, description string) {
	aid, pid := actorID, projectID
	c.writeAuditEventFullOn(ctx, tgt, eventType, &aid, nil, &pid, "", description)
}

// auditProjectScopedFailed is auditProjectScoped for an event that records a
// failure: stored with Success=false (#3363).
func (c *KeyorixCore) auditProjectScopedFailed(ctx context.Context, eventType string, actorID, projectID uint, description string) {
	aid, pid := actorID, projectID
	c.writeAuditEventFailedFull(ctx, eventType, &aid, nil, &pid, "", description)
}
