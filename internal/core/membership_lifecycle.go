// membership_lifecycle.go — project membership onboarding state machine (ADR-022).
//
// A ProjectMembership tracks a user's onboarding into a project, separate from
// the role grant (user_roles). The lifecycle is a 5-state machine:
//
//	invited → identity_verified → provisioned → active   (revoked is terminal,
//	                                                       reachable from any
//	                                                       non-terminal state)
//
// The actual project role is granted (via AssignRole) only when a membership
// reaches `active`, and removed when it is revoked. An install's validation mode
// controls how much of the chain a new invite must traverse:
//
//	open      — self-serve: an invite lands directly in `active`.
//	allowlist — an admin steps the membership through each state explicitly.
//	idp       — IdP-resolved users skip invited/identity_verified (provisioned),
//	            others start at `invited`.
//
// Every transition writes a discrete audit event. Email/setup-link delivery
// (ADR-024) and inviter notifications are separate follow-ups.
package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Membership states.
const (
	MembershipInvited          = "invited"
	MembershipIdentityVerified = "identity_verified"
	MembershipProvisioned      = "provisioned"
	MembershipActive           = "active"
	MembershipRevoked          = "revoked"
)

// Validation modes (install-level).
const (
	ValidationModeOpen      = "open"
	ValidationModeAllowlist = "allowlist"
	ValidationModeIDP       = "idp"
)

// membershipTransitions lists the allowed next states for each state. revoked is
// terminal (no outgoing transitions); every non-terminal state may go to revoked.
var membershipTransitions = map[string][]string{
	MembershipInvited:          {MembershipIdentityVerified, MembershipRevoked},
	MembershipIdentityVerified: {MembershipProvisioned, MembershipRevoked},
	MembershipProvisioned:      {MembershipActive, MembershipRevoked},
	MembershipActive:           {MembershipRevoked},
	MembershipRevoked:          {},
}

// membershipStamps is a ProjectMembership's pair of lifecycle timestamps,
// snapshotted before a transition so a failed side effect can restore the row
// exactly as it was (#2800). Both fields are nullable and a nil here means
// "that event has not happened", which is itself part of what must be restored
// — so this is a value carrying two pointers, not two separately-optional
// arguments that a caller could forget to pass.
type membershipStamps struct {
	ActivatedAt *time.Time
	RevokedAt   *time.Time
}

// canTransition reports whether a membership may move from → to.
func canTransition(from, to string) bool {
	return slices.Contains(membershipTransitions[from], to)
}

// SetMembershipValidationMode overrides the install validation mode (default
// ValidationModeAllowlist). The server calls this at startup from config.
func (c *KeyorixCore) SetMembershipValidationMode(mode string) {
	switch mode {
	case ValidationModeOpen, ValidationModeAllowlist, ValidationModeIDP:
		c.membershipValidationMode = mode
	}
}

// SetMembershipDomainAllowlist restricts InviteToProject/InviteGlobal to these
// email domains (ADR-022). Empty = no restriction. The server calls this at
// startup from config.
func (c *KeyorixCore) SetMembershipDomainAllowlist(domains []string) {
	c.membershipDomainAllowlist = domains
}

// domainAllowed reports whether email's domain passes the configured
// allowlist. An empty allowlist means no restriction (default, backward
// compatible).
//
// #G46: this used to extract the domain via strings.LastIndex(email, "@"),
// which silently accepts a malformed multi-'@' address like
// "attacker@evil.com@allowed.com" and reports its trailing segment as the
// domain — a parser-differential risk if any downstream mail/identity
// consumer of the same raw email string parses '@' differently (e.g. takes
// the FIRST '@' as the local-part boundary). Requiring exactly one '@' closes
// that gap: a malformed address is rejected outright instead of having its
// domain guessed.
func (c *KeyorixCore) domainAllowed(email string) bool {
	if len(c.membershipDomainAllowlist) == 0 {
		return true
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	domain = strings.ToLower(domain)
	for _, d := range c.membershipDomainAllowlist {
		if strings.ToLower(d) == domain {
			return true
		}
	}
	return false
}

// domainAllowedForUser is domainAllowed for the userID-keyed onboarding paths
// (InviteMember, AddProjectMember, SetProjectMemberRole) — every place that
// grants a project-scope role directly by user ID rather than by email, and
// so doesn't otherwise pass through InviteToProject/InviteGlobal's check.
func (c *KeyorixCore) domainAllowedForUser(ctx context.Context, userID uint) error {
	if len(c.membershipDomainAllowlist) == 0 {
		return nil
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !c.domainAllowed(user.Email) {
		return fmt.Errorf("email domain is not on the allowlist")
	}
	return nil
}

func (c *KeyorixCore) validationMode() string {
	if c.membershipValidationMode == "" {
		return ValidationModeAllowlist
	}
	return c.membershipValidationMode
}

// InviteMember starts a membership for userID in projectID with the given
// intended role. The initial state depends on the install validation mode (and,
// for idp, whether the user is IdP-resolved). Rejects a duplicate non-revoked
// membership. When the mode lands the membership directly in `active`, the role
// grant is applied immediately.
func (c *KeyorixCore) InviteMember(ctx context.Context, projectID, userID uint, role string, invitedBy, invitedByMachineID uint, idpResolved bool) (*models.ProjectMembership, error) {
	return c.inviteMemberWithMode(ctx, projectID, userID, role, invitedBy, invitedByMachineID, c.validationMode(), idpResolved)
}

// inviteMemberWithMode is InviteMember with an explicit validation mode, so the
// invitation-accept flow (ADR-024/ADR-028) can honour the mode snapshotted at invite
// time rather than the install's current mode. InviteMember passes the current mode.
func (c *KeyorixCore) inviteMemberWithMode(ctx context.Context, projectID, userID uint, role string, invitedBy, invitedByMachineID uint, mode string, idpResolved bool) (*models.ProjectMembership, error) {
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("project and user IDs are required")
	}
	if role == "" {
		return nil, fmt.Errorf("a project role is required")
	}
	inviteMemberRole, err := c.storage.GetRoleByName(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	if err := c.domainAllowedForUser(ctx, userID); err != nil {
		return nil, err
	}
	// The parent project must be live. GetProject is soft-delete-scoped, so this refuses
	// onboarding into a soft-deleted project — otherwise accepting an invitation that was
	// outstanding when the project was deleted would re-establish a membership/role grant
	// that silently resurrects on a later RestoreProject (the restore-into-deleted-parent
	// class). It also covers the per-assignment grants applied at invite-accept.
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("project %d not found or deleted", projectID)
	}
	// Escalation-by-proxy guard: onboarding a member requires the inviter to already
	// hold every permission the role bundles (parallel to the access-request
	// approval ceiling), not merely an admin-tier role name. idpResolved invites
	// still pass through here.
	//
	// F6 sweep (2026-09-22): requireGranterHoldsRolePermissions now also checks a
	// roles.assign BASELINE before this per-role check -- for a genuine machine
	// inviter (invitedByMachineID != 0), that baseline can only resolve against
	// the machine's OWN real permissions if ctx is tagged via
	// WithSelfMachineGranter first (mirrors InviteToProject's identical, already-
	// existing tagging, invitations.go); without it, checkGranterHoldsPermission's
	// actorIsMachine branch fails closed unconditionally, which would make it
	// impossible for ANY machine inviter -- however genuinely permissioned -- to
	// ever pass.
	if invitedByMachineID != 0 {
		ctx = WithSelfMachineGranter(ctx, invitedByMachineID)
	}
	// #2659: everything from the ceiling check through the create (committing
	// `active` in open mode) and the role grant runs under membershipLockKey,
	// the key TransitionMembership also takes around its state CAS and
	// grant/removal side effect. Without it, a revoke on another replica
	// landing between the `active` create and the grant found no grant to
	// remove, reported success, and the grant then landed on a `revoked`
	// membership.
	var out *models.ProjectMembership
	err = c.storage.WithNamedLock(ctx, membershipLockKey(projectID, userID), func(ctx context.Context) error {
		if err := c.requireGranterHoldsRolePermissions(ctx, invitedBy, inviteMemberRole.ID, Scope{ProjectID: projectID}, invitedByMachineID != 0); err != nil {
			return err
		}
		// One active onboarding per (project, user).
		if existing, err := c.storage.GetActiveProjectMembership(ctx, projectID, userID); err == nil && existing != nil {
			return fmt.Errorf("user already has a %s membership in this project", existing.State)
		}

		now := c.now()
		initial := initialMembershipStateForMode(mode, idpResolved)
		m := &models.ProjectMembership{
			ProjectID:                  projectID,
			UserID:                     userID,
			Role:                       role,
			State:                      initial,
			InvitedBy:                  invitedBy,
			InvitedByMachineIdentityID: invitedByMachineID,
			InvitedAt:                  now,
			UpdatedAt:                  now,
		}
		if initial == MembershipActive {
			t := now
			m.ActivatedAt = &t
		}
		created, err := c.storage.CreateProjectMembership(ctx, m)
		if err != nil {
			// #309: the "no active membership" read above races with a concurrent invite for
			// the same (project, user) — both can pass it before either commits. The DB-level
			// partial unique index (uniq_project_memberships_active) catches the loser's Create
			// and CreateProjectMembership wraps it in ErrDuplicateActiveMembership; surface the
			// same clean "already has a membership" error the winner's sequential check would
			// have produced, instead of a raw constraint-violation message or an orphaned row.
			return wrapCreateMembershipError(err)
		}

		c.logMembershipEvent(ctx, "membership.invited", created, invitedBy)
		// If the mode put us straight into active, grant the role now.
		if created.State == MembershipActive {
			if err := c.AddProjectMember(ctx, invitedBy, projectID, userID, role, invitedByMachineID != 0); err != nil {
				// #309: created just committed as `active` above; if the role grant that's
				// supposed to back it fails (e.g. the composite user_roles primary key
				// rejects a grant that already exists via some other, independent path —
				// the DB-level uniq_project_memberships_active index only dedupes
				// ProjectMembership rows, not user_roles grants), leaving that row standing
				// would report a failure to the caller while a live active-looking
				// membership with no grant behind it persists in ListProjectMemberships/
				// ListUserProjectMemberships indefinitely. There's no earlier state to fall
				// back to (this row didn't exist before this call), so revert straight to
				// revoked.
				// #2800: this row did not exist before this call, so there is
				// no earlier state to restore — the revert IS a genuine
				// terminal revocation. Say so explicitly (never activated,
				// revoked now) instead of leaving revertFailedActivation to
				// infer timestamps from the target state.
				revokedAt := c.now()
				c.revertFailedActivation(ctx, created, MembershipRevoked,
					membershipStamps{ActivatedAt: nil, RevokedAt: &revokedAt})
				return fmt.Errorf("failed to grant role on activation: %w", err)
			}
			c.logMembershipEvent(ctx, "membership.activated", created, invitedBy)
		}
		out = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func wrapCreateMembershipError(err error) error {
	if errors.Is(err, storage.ErrDuplicateActiveMembership) {
		return fmt.Errorf("user already has a membership in this project")
	}
	return fmt.Errorf("failed to create membership: %w", err)
}

// initialMembershipStateForMode resolves the starting state for a new invite under
// an explicit validation mode. An empty/unknown mode falls back to allowlist.
func initialMembershipStateForMode(mode string, idpResolved bool) string {
	switch mode {
	case ValidationModeOpen:
		return MembershipActive
	case ValidationModeIDP:
		if idpResolved {
			return MembershipProvisioned // skip invited/identity_verified
		}
		return MembershipInvited
	default: // allowlist (and empty/unknown)
		return MembershipInvited
	}
}

// TransitionMembership advances a membership to the next state, enforcing the
// state machine. Reaching `active` grants the project role; `revoked` removes it.
// actorID is the user performing the transition (for the audit trail).
// actorIsMachine distinguishes a machine-credential-authenticated caller (also
// actorID==0) from the true actorID==0 system pseudo-actor.
func (c *KeyorixCore) TransitionMembership(ctx context.Context, projectID, membershipID uint, to string, actorID uint, actorIsMachine bool) (*models.ProjectMembership, error) {
	m, err := c.storage.GetProjectMembership(ctx, membershipID)
	if err != nil {
		return nil, fmt.Errorf("membership not found")
	}
	// The caller is authorized within projectID; a membership in another project
	// must not be reachable through it (cross-project guard).
	if m.ProjectID != projectID {
		return nil, fmt.Errorf("membership not found")
	}
	// #2657: re-read under membershipLockKey (project and user are immutable,
	// so the unlocked read above names the right key) and run the state CAS
	// together with its grant/removal side effect under the lock, which
	// inviteMemberWithMode also takes. Without it, a revoke on another replica
	// landing between activation's CAS and its grant found no grant to remove,
	// reported success, and the grant then landed on a `revoked` membership.
	err = c.storage.WithNamedLock(ctx, membershipLockKey(m.ProjectID, m.UserID), func(ctx context.Context) error {
		var err error
		m, err = c.storage.GetProjectMembership(ctx, membershipID)
		if err != nil {
			return fmt.Errorf("membership not found")
		}
		if m.ProjectID != projectID {
			return fmt.Errorf("membership not found")
		}
		if !canTransition(m.State, to) {
			return fmt.Errorf("cannot transition membership from %s to %s", m.State, to)
		}
		// F6 sweep (2026-09-22): this used to be checked ONLY inside the
		// MembershipActive branch below -- every OTHER legal transition
		// (membershipTransitions: e.g. active->revoked, provisioned->revoked,
		// identity_verified->provisioned) reached storage with ZERO
		// caller-authority check, gated only by the state-machine legality guard
		// above and the cross-project ID-match guard, which refuses a
		// MISMATCHED project_id but never required the caller hold anything on
		// the matching one. The human-facing PUT
		// /projects/{id}/memberships/{membershipId} route requires roles.assign
		// unconditionally, for every target state -- require it here too, before
		// ANY transition, not only activation.
		selfMachineID, isSelfMachineGrant := uint(0), false
		if actorIsMachine {
			selfMachineID, isSelfMachineGrant = selfMachineGranterFromContext(ctx)
		}
		if ok, aerr := checkGranterHoldsPermission(ctx, c, actorID, "roles.assign", Scope{ProjectID: m.ProjectID}, actorIsMachine, isSelfMachineGrant, selfMachineID); aerr != nil {
			return fmt.Errorf("failed to resolve actor authority: %w", aerr)
		} else if !ok {
			return ErrMembershipAuthorityRequired
		}
		// Activating a membership grants its role, so the ADDITIONAL
		// escalation-by-proxy ceiling applies on top of the baseline above: the
		// actor must already hold every permission the membership's role bundles
		// to activate it, not merely roles.assign.
		if to == MembershipActive {
			activateRole, err := c.storage.GetRoleByName(ctx, m.Role)
			if err != nil {
				return fmt.Errorf("unknown role %q: %w", m.Role, err)
			}
			if err := c.requireGranterHoldsRolePermissions(ctx, actorID, activateRole.ID, Scope{ProjectID: m.ProjectID}, actorIsMachine); err != nil {
				return err
			}
		}

		prevState := m.State
		// #2800: snapshot the row's lifecycle timestamps BEFORE this transition
		// stamps its own, so a failed side effect can put the row back exactly
		// as it was rather than reconstructing timestamps from the target state
		// (which got them wrong — see revertFailedActivation).
		prevStamps := membershipStamps{ActivatedAt: m.ActivatedAt, RevokedAt: m.RevokedAt}
		now := c.now()
		m.State = to
		m.UpdatedAt = now
		switch to {
		case MembershipActive:
			m.ActivatedAt = &now
		case MembershipRevoked:
			m.RevokedAt = &now
		}
		// #G42: a blind UpdateProjectMembership (full-row Save) here would race a
		// concurrent TransitionMembership call on the same membership — m was
		// read above via GetProjectMembership with no lock, so a concurrent
		// transition landing between that read and this write would be silently
		// reverted (or, if this write lands first, silently clobbered). Route
		// through the conditional write gated on the state this call actually
		// observed (prevState).
		matched, err := c.storage.TransitionProjectMembershipState(ctx, m, prevState)
		if err != nil {
			return fmt.Errorf("failed to update membership: %w", err)
		}
		if !matched {
			return fmt.Errorf("membership %d: %w", membershipID, ErrMembershipStateConflict)
		}

		// Side effects on the role grant.
		switch to {
		case MembershipActive:
			if err := c.AddProjectMember(ctx, actorID, m.ProjectID, m.UserID, m.Role, actorIsMachine); err != nil {
				// #309: m just committed as `active` above; if the role grant fails, revert
				// to the state m held before this transition (not straight to revoked) —
				// unlike inviteMemberWithMode's straight-to-active create, this row already
				// existed in a legitimate pending state, so a failed activation attempt
				// should leave it retriable rather than terminally revoked. See
				// revertFailedActivation.
				c.revertFailedActivation(ctx, m, prevState, prevStamps)
				return fmt.Errorf("failed to grant role on activation: %w", err)
			}
		case MembershipRevoked:
			if err := c.RemoveProjectMember(ctx, actorID, m.ProjectID, m.UserID); err != nil && !errors.Is(err, ErrNotProjectMember) {
				// #G54: a security-relevant refusal (guardLastProjectAdmin: this user is
				// the project's last roles.assign holder) or a real storage failure must
				// not be silently swallowed — the membership row was just committed as
				// `revoked` above, but if the underlying role grant removal was
				// REFUSED, the user still holds full access via that live grant while
				// ListProjectMemberships and friends report them as removed. Revert the
				// membership back to its pre-transition state and surface the error,
				// same as the activation-failure handling above. ErrNotProjectMember
				// (no grant existed to remove — already gone via some other path) is
				// the one genuinely benign case and is still ignored.
				c.revertFailedActivation(ctx, m, prevState, prevStamps)
				return fmt.Errorf("failed to remove role grant on revocation: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	c.logMembershipEvent(ctx, "membership."+transitionVerb(to), m, actorID)
	if to == MembershipActive {
		c.notifyMembershipActivated(ctx, m)
	}
	return m, nil
}

// membershipLockKey is the WithNamedLock key serializing every write that
// moves a (project, user) membership into or out of `active` together with its
// role-grant side effect (#2657, #2659): TransitionMembership and
// inviteMemberWithMode. It is always taken before AddProjectMember's
// sodGrantLockKey and RemoveProjectMember's projectAdminGuardLockKey, and no
// holder of either of those calls back into a membership write, so the order
// cannot invert.
func membershipLockKey(projectID, userID uint) string {
	return fmt.Sprintf("project-membership:%d:%d", projectID, userID)
}

// (helpers below)

// transitionVerb maps a target state to the audit event suffix.
func transitionVerb(to string) string {
	switch to {
	case MembershipIdentityVerified:
		return "identity_verified"
	case MembershipProvisioned:
		return "provisioned"
	case MembershipActive:
		return "activated"
	case MembershipRevoked:
		return "revoked"
	default:
		return to
	}
}

// ListProjectMemberships returns all membership rows for a project.
func (c *KeyorixCore) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	return c.storage.ListProjectMemberships(ctx, projectID)
}

// StaleInvites returns memberships still in `invited` state older than the cutoff
// (ADR-022 stale-invite warnings; default surfaced at >7 days).
func (c *KeyorixCore) StaleInvites(ctx context.Context, olderThan time.Duration) ([]*models.ProjectMembership, error) {
	before := c.now().Add(-olderThan)
	return c.storage.ListStaleInvitedMemberships(ctx, before)
}

// (#2781) ListUserProjectMemberships — the per-user "which projects is this user in"
// read off this journal — is deliberately gone. It was the second, non-equivalent
// definition of project membership, and it answered "none" for every user on an
// install whose members were added through POST /projects/{id}/members. Ask
// ListProjectMembershipsForUser (project_membership_definition.go) instead; it reads
// this journal only for the lifecycle STATE annotation.
// guards/project_membership_definition_guard_test.go fails the build if a second definition
// reappears.

// logMembershipEvent writes an audit event for a membership transition.
func (c *KeyorixCore) logMembershipEvent(ctx context.Context, eventType string, m *models.ProjectMembership, actorID uint) {
	aid, pid := actorID, m.ProjectID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, &pid, "",
		fmt.Sprintf("membership %d for user %d in project %d → %s", m.ID, m.UserID, m.ProjectID, m.State))
}

// revertFailedActivation reverts a ProjectMembership row that was just persisted as
// `active` back to a non-active state, after the role grant that's supposed to back
// that `active` row failed (#309). Without this, a caller-visible error ("failed to
// grant role on activation") would still leave a live state=active row behind —
// ListProjectMemberships/ListUserProjectMemberships would keep reporting the user as
// an active project member indefinitely, with no role grant behind it and no way to
// revoke a grant that was never made. This can happen without any TOCTOU: the
// uniq_project_memberships_active partial index only dedupes ProjectMembership rows,
// not user_roles grants, so a role already held via an independent path (a direct
// /user-roles grant, another membership's activation, etc.) still makes
// AssignRole's composite primary key reject this grant after the row committed.
//
// toState is the state to fall back to: inviteMemberWithMode has no earlier state to
// return to (the row didn't exist before this call) and passes MembershipRevoked;
// TransitionMembership passes the membership's own pre-transition state, so a
// legitimate retry of the activation is still possible.
//
// stamps is what the row's ActivatedAt/RevokedAt must read afterwards, supplied by
// the caller rather than inferred here.
//
// #2800: this used to derive them from toState — `RevokedAt = now` when reverting
// to revoked, `ActivatedAt = nil` otherwise — which is wrong for the
// revocation-failure path (:404). There, TransitionMembership has already stamped
// `RevokedAt = now` for the revoke that then failed, and toState is the row's
// pre-transition `active`. The old branch took the else arm: it cleared
// ActivatedAt and left the failed revoke's RevokedAt standing, so the row read
// `active` / never-activated / revoked-at-T — three mutually contradictory facts,
// and a member who looks revoked to anything reading RevokedAt while actually
// holding their role. The target state cannot tell you what the timestamps were;
// only the pre-transition row can, so the caller snapshots it (prevStamps) and
// passes it in. Guard: TestRevertFailedActivation_RestoresPreTransitionTimestamps.
//
// Best-effort and mirrors revokeInvitationGrants (invitations.go): m is already on a
// path that's about to return an error to its caller, so a failure to revert is
// audited (flagged for manual cleanup) rather than returned or retried — a partial
// revert is strictly better than silently leaving the active row standing.
func (c *KeyorixCore) revertFailedActivation(ctx context.Context, m *models.ProjectMembership, toState string, stamps membershipStamps) {
	// #G42: m.State is still MembershipActive here (TransitionMembership's own
	// write above just committed it) — capture that as fromState so this
	// revert's write only matches if nothing else has touched the row since,
	// same as TransitionMembership's own conditional write.
	fromState := m.State
	m.State = toState
	m.UpdatedAt = c.now()
	m.ActivatedAt = stamps.ActivatedAt
	m.RevokedAt = stamps.RevokedAt
	matched, err := c.storage.TransitionProjectMembershipState(ctx, m, fromState)
	if err == nil && !matched {
		err = fmt.Errorf("%w", ErrMembershipStateConflict)
	}
	if err != nil {
		c.auditProjectScoped(ctx, "membership.activation_race_revert_failed", m.UserID, m.ProjectID,
			fmt.Sprintf("failed to revert orphaned active membership %d for user %d in project %d (state %s) after a role-grant failure: %v — MANUAL CLEANUP REQUIRED",
				m.ID, m.UserID, m.ProjectID, toState, err))
		return
	}
	c.logMembershipEvent(ctx, "membership.activation_reverted", m, 0)
}
