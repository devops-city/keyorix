// impersonation.go — admin impersonation sessions and their audit trail.
//
// An admin starts impersonation of a target user; Keyorix issues a SEPARATE,
// short-lived session for the target user that records the initiating admin
// (Session.ImpersonatedBy). The admin's own session is left untouched, so the
// frontend swaps to the impersonation token and can swap back to the admin
// token without re-authentication ("Return to Admin").
//
// Discrete impersonation.start / impersonation.end events bracket the session.
// The end event reports duration and the count of actions taken while
// impersonating. Every action in between is tagged impersonation=true via the
// context propagation in audit_context.go.
package core

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// impersonationSessionTTL bounds how long an impersonation session is valid.
// Shorter than a normal 24h session — impersonation is a privileged, audited act.
const impersonationSessionTTL = 1 * time.Hour

// EventImpersonationStart / EventImpersonationEnd are the discrete bracket events.
// EventImpersonationStartFailed is the failure counterpart of
// EventImpersonationStart, following this codebase's `<domain>.<action>_failed`
// convention for auditing a refused/blocked attempt alongside its success event
// (e.g. auth.login_failed alongside auth.login, secret.rotate_failed alongside
// secret.rotated) — see writeImpersonationDeniedEvent.
const (
	EventImpersonationStart       = "impersonation.start"
	EventImpersonationEnd         = "impersonation.end"
	EventImpersonationStartFailed = "impersonation.start_failed"
)

// StartImpersonation issues an impersonation session for targetID initiated by
// adminID and logs an impersonation.start event. Returns the new session (whose
// token the caller should hand back to the admin's client) and the target user.
func (c *KeyorixCore) StartImpersonation(ctx context.Context, adminID, targetID uint, ip string) (*models.Session, *models.User, error) {
	if adminID == targetID {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("user %d attempted to impersonate themselves", adminID))
		return nil, nil, fmt.Errorf("cannot impersonate yourself")
	}
	// A request authenticated with a least-privilege PAT (ADR-042) must not LAUNDER that
	// restriction through impersonation: the impersonation session is a plain session
	// carrying no restriction, so it would act as the target with the target's FULL
	// permissions — escaping the bound the PAT deliberately imposed. Refuse, mirroring
	// IsGlobalAdmin's fail-closed convention for the PAT restriction.
	if patRestrictionFromContext(ctx) != nil {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("user %d attempted to impersonate user %d using a restricted access token", adminID, targetID))
		return nil, nil, fmt.Errorf("a restricted access token may not start impersonation")
	}
	// #G07: the check above only catches a RESTRICTED PAT — patRestrictionFromContext
	// returns nil for BOTH a session and an UNRESTRICTED PAT (or a machine token),
	// which look identical from that helper's perspective (see its own doc comment:
	// "or nil for sessions / unrestricted PATs"). Impersonation is an interactive
	// admin action, not something an API credential should ever be able to trigger,
	// restricted or not — sessionAuthFromContext distinguishes the two.
	if !sessionAuthFromContext(ctx) {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("user %d attempted to impersonate user %d using a non-interactive credential", adminID, targetID))
		return nil, nil, fmt.Errorf("impersonation requires an interactive session, not an API credential")
	}
	admin, err := c.storage.GetUser(ctx, adminID)
	if err != nil {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("impersonation attempt refused: acting admin user %d not found", adminID))
		return nil, nil, fmt.Errorf("admin not found")
	}
	target, err := c.storage.GetUser(ctx, targetID)
	if err != nil {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("%s attempted to impersonate user %d, but the target was not found", admin.Username, targetID))
		return nil, nil, fmt.Errorf("target user not found")
	}
	// Don't mint a session for a target who cannot log in: it would be dead on arrival
	// (ValidateSessionToken rejects blocked/inactive accounts on every request) and would
	// only produce a misleading impersonation.start audit event.
	if !target.IsActive || AccountLoginBlocked(target.ID, target.AccountState) {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("%s attempted to impersonate %s, but the target is suspended or inactive", admin.Username, target.Username))
		return nil, nil, fmt.Errorf("cannot impersonate a suspended or inactive user")
	}
	// Admin-rank-ceiling check (#165): the impersonator must already hold authority
	// equal to or greater than the target's, at EVERY scope the target holds it —
	// not just the global scope a plain IsGlobalAdmin(target) check would catch.
	// Without this, a principal holding only users.impersonate (a permission that
	// by CONVENTION only global admins hold, but nothing enforces that as an
	// invariant) could impersonate an actual admin — global OR project-scoped,
	// direct OR group-inherited — then use that session to grant their own real
	// account admin via the ordinary role-assignment endpoints; the privilege
	// persists after the impersonation session ends. Today users.impersonate is
	// satisfiable only by global admins by convention, so for the common case this
	// check is a no-op; it keeps impersonation from escalating if that permission
	// is ever delegated to a lower-privileged (sub-admin) role, or if the target is
	// merely a project-scoped project_admin the older global-only check never saw.
	if err := c.requireEqualOrGreaterAdminAuthority(ctx, adminID, targetID, "impersonate"); err != nil {
		c.writeImpersonationDeniedEvent(ctx, adminID, &targetID, ip,
			fmt.Sprintf("%s attempted to impersonate %s but was refused by the admin-rank ceiling: %v", admin.Username, target.Username, err))
		return nil, nil, err
	}
	// The ceiling check above runs once here at start, but is NOT only a
	// point-in-time check (MT-007): ValidateSessionToken re-runs
	// ReauthorizeImpersonation on every request against this session, and
	// StreamAuditLogs' dedicated re-auth ticker (#108, audit_service.go) does
	// the same for long-lived gRPC streams — both catch either side's authority
	// changing (the target elevated, or the admin demoted/suspended) DURING an
	// active session, cached at ceilingCacheTTL (60s) to bound the added cost.
	token, err := generateSecureToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	now := c.now()
	expiresAt := now.Add(impersonationSessionTTL)
	session := &models.Session{
		UserID:                 target.ID,
		SessionToken:           token,
		ImpersonatedBy:         &adminID,
		ImpersonationStartedAt: &now,
		LastSeenAt:             &now,
		ExpiresAt:              &expiresAt,
	}
	created, err := c.createImpersonationSession(ctx, session, ip)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create impersonation session: %w", err)
	}
	c.writeImpersonationEvent(ctx, EventImpersonationStart, adminID, targetID, ip,
		fmt.Sprintf("%s started impersonating %s", admin.Username, target.Username), "")
	return created, target, nil
}

// createImpersonationSession is createSession for StartImpersonation. A panic
// in the insert comes back as an error wrapping ErrLoginWritePanicked (#3277
// follow-up), so the handler answers it exactly like the insert's error ("Failed
// to start impersonation") instead of the Recovery 500. createSession has
// already deleted a row that landed, and no token is returned, so no
// impersonation session survives the failure.
func (c *KeyorixCore) createImpersonationSession(ctx context.Context, session *models.Session, ip string) (created *models.Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: impersonation session write for user %d panicked; refusing it like its error: %v\n%s",
				session.UserID, r, debug.Stack())
			created, err = nil, fmt.Errorf("%w: impersonation session write: %v", ErrLoginWritePanicked, r)
		}
	}()
	return c.createSession(ctx, session, ip, "impersonation start")
}

// EndImpersonation terminates the impersonation session identified by token,
// logging an impersonation.end event with the session duration and the number
// of actions taken while impersonating. The token must belong to an
// impersonation session. Returns the admin ID that was impersonating (i.e.
// the ended session's ImpersonatedBy) so the caller can bind any "restore my
// own session" step to that SAME admin, rather than trusting whatever session
// token happens to be sitting in a client-supplied cookie (see
// admin_impersonation.go's End). Restoring the admin's own session is
// otherwise a caller (HTTP handler) concern — End stashes the admin's token in
// a second cookie at Start and reads it back here, rather than this core
// layer trying to recall a plaintext token it never retains (session tokens
// are stored only as a hash, see local_auth.go's hashSessionToken).
func (c *KeyorixCore) EndImpersonation(ctx context.Context, token string) (uint, error) {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return 0, fmt.Errorf("session not found")
	}
	if session.ImpersonatedBy == nil {
		return 0, fmt.Errorf("not an impersonation session")
	}
	adminID := *session.ImpersonatedBy
	targetID := session.UserID

	start := c.now()
	if session.ImpersonationStartedAt != nil {
		start = *session.ImpersonationStartedAt
	}
	duration := c.now().Sub(start)
	actions, _ := c.storage.CountImpersonatedActions(ctx, targetID, adminID, start)

	// #G60: delete the session BEFORE writing the impersonation.end audit event.
	// The event below asserts the session ended, so it must not be recorded
	// unless the delete actually succeeded — otherwise a failed delete leaves an
	// audit trail claiming the impersonation session ended when it's still live
	// and usable. Mirrors StartImpersonation, which likewise only writes
	// impersonation.start after CreateSession has already succeeded. No
	// dedicated "failed" event is written on error here — matching this
	// package's existing convention (e.g. RevokeMachineToken, RevokeUserSessions)
	// of a plain error return when a state-changing storage call fails
	// mid-operation, reserving the explicit failed-audit-event helper for
	// pre-mutation authorization denials instead.
	if err := c.storage.DeleteSession(ctx, session.ID); err != nil {
		return 0, fmt.Errorf("failed to end impersonation session: %w", err)
	}

	diff := fmt.Sprintf(`{"duration_seconds":%d,"action_count":%d}`, int64(duration.Seconds()), actions)
	desc := fmt.Sprintf("impersonation ended after %s (%d action(s))", duration.Round(time.Second), actions)
	c.writeImpersonationEvent(ctx, EventImpersonationEnd, adminID, targetID, session.IPAddress, desc, diff)

	return adminID, nil
}

// ReauthorizeImpersonation re-verifies an ACTIVE impersonation session's admin
// side: that adminID's account is still active, and that adminID still holds
// equal-or-greater authority than targetID (MT-007/#G05) — the same ceiling
// StartImpersonation checked at issuance, re-run for a long-lived credential
// that authenticates once and is not re-validated by the ordinary per-request
// path. ValidateSessionToken calls this on every request against an
// impersonation session; StreamAuditLogs' dedicated re-auth ticker
// (server/grpc/services/audit_service.go, #108) calls it too, since a gRPC
// stream's own auth happens once at open. Cached via cachedImpersonationCeiling
// (IMP-001, 60s) so neither caller repeats the underlying DB reads on every
// invocation.
func (c *KeyorixCore) ReauthorizeImpersonation(ctx context.Context, adminID, targetID uint) error {
	admin, err := c.storage.GetUser(ctx, adminID)
	if err != nil {
		return fmt.Errorf("impersonating account not found")
	}
	if !admin.IsActive || AccountLoginBlocked(admin.ID, admin.AccountState) {
		return fmt.Errorf("impersonating account is not active")
	}
	if err := c.cachedImpersonationCeiling(ctx, adminID, targetID); err != nil {
		return fmt.Errorf("impersonation ceiling exceeded — target's authority now exceeds impersonator's: %w", err)
	}
	return nil
}

// SessionImpersonator returns the initiating admin ID if token belongs to an
// impersonation session, or nil otherwise. Used by the auth middleware to tag
// the request context so downstream audit events are marked impersonated.
func (c *KeyorixCore) SessionImpersonator(ctx context.Context, token string) *uint {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil
	}
	return session.ImpersonatedBy
}

// writeImpersonationEvent records an audit event with explicit impersonation
// attribution (ImpersonatedBy = admin, ActingAs = target, Impersonation = true).
func (c *KeyorixCore) writeImpersonationEvent(ctx context.Context, eventType string, adminID, targetID uint, ip, description, diff string) {
	t := true
	ab, ta := adminID, targetID
	event := &models.AuditEvent{
		EventType:      eventType,
		UserID:         &ta,
		IPAddress:      ip,
		Description:    description,
		Success:        &t,
		EventTime:      time.Now(),
		Diff:           diff,
		ImpersonatedBy: &ab,
		ActingAs:       &ta,
		Impersonation:  true,
	}
	c.emitAudit(ctx, event)
}

// writeImpersonationDeniedEvent records a REFUSED impersonation attempt
// (Success=false) — the failure counterpart of writeImpersonationEvent,
// following this codebase's dedicated `<domain>.<action>_failed` convention
// for auditing failures alongside successes (auth.login_failed alongside
// auth.login, secret.rotate_failed alongside secret.rotated). Without this,
// StartImpersonation's error returns (self-impersonation, a restricted-PAT
// or non-interactive caller, a suspended target, or — critically — the
// admin-rank-ceiling denial from #165/#G05) are invisible to security
// monitoring: a defender investigating suspicious activity would see only
// successful impersonations, never a blocked privilege-escalation attempt.
// targetID is still recorded even when the target account itself could not
// be resolved, so a probe against a non-existent user ID is not lost either.
func (c *KeyorixCore) writeImpersonationDeniedEvent(ctx context.Context, adminID uint, targetID *uint, ip, description string) {
	f := false
	ab := adminID
	event := &models.AuditEvent{
		EventType:      EventImpersonationStartFailed,
		UserID:         &ab,
		IPAddress:      ip,
		Description:    description,
		Success:        &f,
		EventTime:      time.Now(),
		ImpersonatedBy: &ab,
		ActingAs:       targetID,
		Impersonation:  true,
	}
	c.emitAudit(ctx, event)
}
