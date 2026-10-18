// notifications.go — in-app notifications (ADR-024).
//
// Notifications are addressed to a single user and surfaced via the header bell.
// Emission is best-effort: a delivery failure never blocks the action that
// triggered it (same contract as audit emission). In addition to the in-app row,
// notify() fans each event out to a configured external channel when a
// recipientNotificationSink is wired.
//
// #391: every event this file emits (secret shared, share revoked, ownership
// transferred, access requested, anomaly alert, break-glass activation, …) is
// addressed to exactly one user — the recipient this file already computed. It is
// dispatched to recipientNotificationSink, NOT the deployment-wide broadcast
// notificationSink (used elsewhere for the compliance digest / rotation-failure
// summaries): chat (Slack/Teams) and generic webhook channels are one fixed
// destination an operator configures, with no per-user identity mapping to target a
// specific recipient, so handing them a per-user event would broadcast it to
// everyone with channel visibility regardless of project membership or secret
// access. Only recipient-addressable channels (email) are wired into
// recipientNotificationSink; see SetRecipientNotificationSink and server/main.go.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Notification types.
const (
	NotificationMembershipActivated        = "membership.activated"
	NotificationAccessRequested            = "access_request.created"
	NotificationAccessApproved             = "access_request.approved"
	NotificationAccessRejected             = "access_request.rejected"
	NotificationSecretShared               = "secret.shared"
	NotificationSecretShareRevoked         = "secret.share_revoked"
	NotificationSecretOwnershipTransferred = "secret.ownership_transferred"
	// NotificationPATExpiredUsed fires when an expired PAT is presented at the
	// auth boundary, so the owner knows to revoke or replace it.
	NotificationPATExpiredUsed = "pat.expired_used"
)

// approverRoleNames are the project/system roles whose holders can approve access
// requests — the recipients of a "new request" notification.
var approverRoleNames = map[string]struct{}{
	"project_admin": {}, "system_admin": {}, "admin": {}, "super_admin": {},
}

// isApproverRole reports whether holders of roleName can approve access requests.
func isApproverRole(roleName string) bool {
	_, ok := approverRoleNames[roleName]
	return ok
}

// projectAdminRecipients resolves "the project's admins" for every notifier that
// addresses them (#2955, NOTIFY-1): the project's own approver-role members PLUS
// every ACTIVE holder of an install-wide admin-bypass role -- directly or through
// a group. Reading ListProjectMembers alone matches user_roles.project_id exactly,
// so the install's global admin (the usual admin on a fresh install, who holds no
// project-scoped row) was never considered and received nothing. A global admin
// has admin authority on every project (requireAdminAuthorityAt), so they may
// see anything a project admin may and are a project admin for alerting purposes.
//
// Every candidate -- approver-role project members AND install-wide admins -- is
// vetted the same way: a deleted user, a deactivated one, or one whose login is
// blocked (AccountLoginBlocked: suspended, deprovisioned, blank/unrecognised
// state) is dropped, because nothing about the subject (secret names, anomaly
// detail) may reach someone whose account is off. Admin-group members count only
// through a GLOBAL (project_id=0) membership.
//
// Every notifier that notifies project admins MUST resolve them here -- the
// guard in notify_recipients_guard_test.go fails any notify*/remind* function
// that reads ListProjectMembers directly. Callers that must skip someone (the
// requester of their own access request) filter the result.
//
// Returns each user once, in ascending ID order. On a partial failure it returns
// the recipients it did resolve together with the error, so the caller can still
// alert them and report the gap loudly (#166).
func (c *KeyorixCore) projectAdminRecipients(ctx context.Context, projectID uint) ([]uint, error) {
	// candidates: every user who might be a recipient. ONE vetting rule (an active
	// account whose login is not blocked) is applied to all of them below.
	candidates := map[uint]struct{}{}
	var errs []error

	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		errs = append(errs, fmt.Errorf("list project %d members: %w", projectID, err))
	}
	for _, m := range members {
		if isApproverRole(m.RoleName) {
			candidates[m.UserID] = struct{}{}
		}
	}

	adminRoleIDs, err := c.adminBypassRoleIDSlice(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("resolve install-wide admins: %w", err))
	} else if assignments, aerr := c.storage.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs); aerr != nil {
		// Read-only use outside any transaction: the Postgres row lock it takes is
		// released immediately, and a stale read here only costs one alert.
		errs = append(errs, fmt.Errorf("list install-wide admin grants: %w", aerr))
	} else {
		for _, a := range assignments {
			switch a.PrincipalType {
			case "user":
				candidates[a.PrincipalID] = struct{}{}
			case "group":
				// The assignment is GLOBAL, so only members whose own membership is
				// global (user_groups.project_id=0) inherit it. ListGroupMembers
				// ignores that scope: a member scoped to another project would be
				// told about every project (same rule as resolveGroupAdminMembers).
				gm, gerr := c.storage.ListGroupMembersAt(ctx, a.PrincipalID, corestorage.Scope{})
				if gerr != nil {
					errs = append(errs, fmt.Errorf("list members of admin group %d: %w", a.PrincipalID, gerr))
					continue
				}
				for _, u := range gm {
					candidates[u.ID] = struct{}{}
				}
			}
		}
	}

	var ids []uint
	for uid := range candidates {
		u, uerr := c.storage.GetUser(ctx, uid)
		switch {
		case uerr != nil && corestorage.IsUserNotFound(uerr):
			continue // deleted: not a recipient, not a failure
		case uerr != nil:
			errs = append(errs, fmt.Errorf("vet recipient %d: %w", uid, uerr))
		case u != nil && u.IsActive && !AccountLoginBlocked(u.ID, u.AccountState):
			ids = append(ids, uid)
		}
	}
	slices.Sort(ids)
	return ids, errors.Join(errs...)
}

// notify creates one in-app notification, best-effort (errors are swallowed so a
// failed insert can't roll back the triggering action).
func (c *KeyorixCore) notify(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string) {
	c.notifyWithSeverity(ctx, userID, nType, title, message, projectID, link, models.NotificationSeverityNone)
}

// notifyWithSeverity is notify plus a recorded NotificationSeverity (#250):
// reminder schedulers (expiry/rotation/license) use this so a later recheck can
// compare a newly computed severity against what's recorded here on the
// standing unread reminder — see upgradeReminder. Notification types that don't
// participate in escalation-aware dedup should keep using plain notify(), which
// records NotificationSeverityNone.
//
// #488: a failed CreateNotification — including the benign duplicate-skip a
// concurrent reminder run hits against the unread-reminder dedup index — must not
// still fire an out-of-band delivery for a row that was never actually persisted,
// or the race this index closes at the DB layer would still duplicate the
// user-visible email/webhook. Mirrors upgradeReminder's identical guard (#482).
func (c *KeyorixCore) notifyWithSeverity(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string, severity models.NotificationSeverity) { // NOSONAR -- domain-driven parameter count
	_ = c.notifyChecked(ctx, userID, nType, title, message, projectID, link, severity)
}

// recoverPostCommitNotifyPanic is deferred by a notifier that runs AFTER its
// primary write has committed and keeps no failure record of its own (#3092):
// it recovers a PANIC from the insert or the out-of-band dispatch and logs it at
// SECURITY level, so the committed write is never reported as an error. A
// CreateNotification ERROR is already swallowed by notify; this closes the panic
// half. Deliberately not folded into notify itself: break-glass relies on the
// panic reaching notifyBreakGlassAdmins' own recover to audit it.
func recoverPostCommitNotifyPanic(nType string, userID uint) {
	if r := recover(); r != nil {
		log.Printf("SECURITY: WARN: %s notification for user %d panicked (best-effort, primary operation already committed): %v", nType, userID, r)
	}
}

// notifyChecked is notifyWithSeverity that RETURNS the CreateNotification error
// instead of swallowing it, for a caller that has to record the failure: the
// access-request notifiers, run under runPostCommitNotification (#3075). It does
// not recover a panic; runPostCommitNotification does.
func (c *KeyorixCore) notifyChecked(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string, severity models.NotificationSeverity) error { // NOSONAR -- domain-driven parameter count
	if userID == 0 {
		return nil
	}
	if _, err := c.storage.CreateNotification(ctx, &models.Notification{
		UserID:    userID,
		ProjectID: projectID,
		Type:      nType,
		Title:     title,
		Message:   message,
		Link:      link,
		Severity:  severity,
		CreatedAt: c.now(),
	}); err != nil {
		return fmt.Errorf("notify user %d (%s): %w", userID, nType, err)
	}
	c.dispatchNotification(ctx, userID, nType, title, message, projectID, link)
	return nil
}

// runPostCommitNotification runs notifyFn, a notification step that follows an
// access-request transition which has ALREADY committed, so nothing notifyFn does
// can turn that committed transition into a reported failure (#3075, the #2880
// rule: once the decision is durable, the response reports it).
//
// The bug it closes: FuzzStorageFaultOperations found PUT
// /projects/{id}/access-requests/{requestId} with CreateNotification#1/panic
// granting the role, approving the request and writing its audit row, then
// answering 500 because the panic escaped the notify step. A CreateNotification
// ERROR was already swallowed, but silently -- nobody could tell an approver was
// never told.
//
// A returned error or a panic anywhere in notifyFn (recipient resolution, the
// project label lookup, CreateNotification, the email sink) is recovered, logged
// at SECURITY level with the step, actor, project and access request, and
// recorded as one "notification.failed" audit event in the request's project.
// The audit write recovers its own panic (writeAuditEventDiffOn, #2561).
func (c *KeyorixCore) runPostCommitNotification(ctx context.Context, step string, actorID uint, req *models.AccessRequest, notifyFn func() error) {
	var failure error
	func() {
		defer func() {
			if r := recover(); r != nil {
				failure = fmt.Errorf("panic: %v", r)
			}
		}()
		failure = notifyFn()
	}()
	if failure == nil {
		return
	}
	log.Printf("SECURITY: WARN: %s: notification for access request %d (project %d, actor %d) failed after the transition committed; the transition stands: %v",
		step, req.ID, req.ProjectID, actorID, failure)
	c.auditProjectScopedFailed(ctx, auditNotificationFailed, actorID, req.ProjectID,
		fmt.Sprintf("%s: notification for access request %d was not delivered: %v", step, req.ID, failure))
}

// upgradeReminder overwrites Title/Message/Severity on an existing unread
// standing reminder notification in place and persists it (#250). Used when a
// recheck finds a strictly more severe state than what the notification was
// last created/updated with, so the escalation reaches the user without
// piling up a second unread notification of the same (user, type, project).
// Returns whether the update succeeded (best-effort — a storage failure here
// just means the stale reminder stands until the next tick).
//
// #482: an escalation must also re-fire the out-of-band channel exactly like a
// fresh notification does, or a Warning-level reminder silently escalating to
// Critical (e.g. "expiring soon" → "now expired") would update the DB row but
// never re-send the email/webhook that made the state change visible in the
// first place. dispatchNotification is only called after the DB update
// succeeds, mirroring notifyWithSeverity's create path.
func (c *KeyorixCore) upgradeReminder(ctx context.Context, n *models.Notification, title, message string, severity models.NotificationSeverity) bool {
	n.Title, n.Message, n.Severity = title, message, severity
	if c.storage.UpdateNotification(ctx, n) != nil {
		return false
	}
	c.dispatchNotification(ctx, n.UserID, n.Type, title, message, n.ProjectID, n.Link)
	return true
}

// dispatchNotification fans a per-user notification out to the recipient-addressable
// external channel (email), resolving the recipient's email best-effort. A no-op
// when no such sink is wired; the sink itself is non-blocking, so this never delays
// the caller.
//
// This deliberately uses recipientNotificationSink, not the deployment-wide
// notificationSink — see the package comment and #391.
func (c *KeyorixCore) dispatchNotification(ctx context.Context, userID uint, nType, title, message string, projectID *uint, link string) {
	if c.recipientNotificationSink == nil {
		return
	}
	ev := NotificationEvent{
		UserID:    userID,
		Type:      nType,
		Title:     title,
		Message:   message,
		ProjectID: projectID,
		Link:      link,
	}
	if u, err := c.storage.GetUser(ctx, userID); err == nil && u != nil {
		ev.Email = u.Email
	}
	c.recipientNotificationSink.Deliver(ev)
}

// projectLabel returns a human label for a project ("Payments" or "#3").
func (c *KeyorixCore) projectLabel(ctx context.Context, projectID uint) string {
	if p, err := c.storage.GetProject(ctx, projectID); err == nil && p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("#%d", projectID)
}

// notifyMembershipActivated tells the inviter their invitee is now active.
func (c *KeyorixCore) notifyMembershipActivated(ctx context.Context, m *models.ProjectMembership) {
	if m.InvitedBy == 0 || m.InvitedBy == m.UserID {
		return // self-serve activation: nobody distinct to notify.
	}
	pid := m.ProjectID
	link := fmt.Sprintf("/projects/%d", m.ProjectID)
	c.notify(ctx, m.InvitedBy, NotificationMembershipActivated,
		"Member activated",
		fmt.Sprintf("User %d is now an active member of %s.", m.UserID, c.projectLabel(ctx, m.ProjectID)),
		&pid, link)
}

// notifyAccessRequested fans a new-request notification out to the project's
// admins (projectAdminRecipients: approver-role members + install-wide admins).
// It returns every failure (a partial recipient resolution, a failed
// CreateNotification) for runPostCommitNotification to record; whoever WAS
// resolved is still notified.
func (c *KeyorixCore) notifyAccessRequested(ctx context.Context, req *models.AccessRequest) error {
	var errs []error
	recipients, rerr := c.projectAdminRecipients(ctx, req.ProjectID) // partial result still notified (best-effort)
	if rerr != nil {
		errs = append(errs, fmt.Errorf("resolve project %d admins (%d resolved), some admins may not be notified: %w", req.ProjectID, len(recipients), rerr))
	}
	pid := req.ProjectID
	label := c.projectLabel(ctx, req.ProjectID)
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	for _, uid := range recipients {
		if uid == req.UserID {
			continue // don't notify the requester of their own request.
		}
		errs = append(errs, c.notifyChecked(ctx, uid, NotificationAccessRequested,
			"New access request",
			fmt.Sprintf("User %d requested %s access to %s.", req.UserID, req.SuggestedRole, label),
			&pid, link, models.NotificationSeverityNone))
	}
	return errors.Join(errs...)
}

// notifyAccessResolved tells the requester their request was approved/rejected.
// Run it under runPostCommitNotification, which records a returned error.
func (c *KeyorixCore) notifyAccessResolved(ctx context.Context, req *models.AccessRequest, approved bool) error {
	pid := req.ProjectID
	label := c.projectLabel(ctx, req.ProjectID)
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	if approved {
		return c.notifyChecked(ctx, req.UserID, NotificationAccessApproved,
			"Access request approved",
			fmt.Sprintf("Your request for access to %s was approved as %s.", label, req.GrantedRole),
			&pid, link, models.NotificationSeverityNone)
	}
	return c.notifyChecked(ctx, req.UserID, NotificationAccessRejected,
		"Access request rejected",
		fmt.Sprintf("Your request for access to %s was rejected.", label),
		&pid, link, models.NotificationSeverityNone)
}

// notifySecretShared tells a recipient a secret was shared with them directly. Self-
// shares are skipped. Best-effort — failure never blocks the share.
func (c *KeyorixCore) notifySecretShared(ctx context.Context, secret *models.SecretNode, recipientID, sharedBy uint, permission string) {
	defer recoverPostCommitNotifyPanic(NotificationSecretShared, recipientID)
	if secret == nil || recipientID == 0 || recipientID == sharedBy {
		return
	}
	var pid *uint
	if secret.ProjectID != 0 {
		p := secret.ProjectID
		pid = &p
	}
	c.notify(ctx, recipientID, NotificationSecretShared,
		"Secret shared with you",
		fmt.Sprintf("You were granted %s access to secret %q.", permission, secret.Name),
		pid, fmt.Sprintf("/secrets/%d", secret.ID))
}

// notifyGroupSecretShared fans the "shared with you" notification out to every member
// of a group a secret was shared with (excluding the sharer). Best-effort — a member
// lookup failure just means no fan-out.
func (c *KeyorixCore) notifyGroupSecretShared(ctx context.Context, secret *models.SecretNode, groupID, sharedBy uint, permission string) {
	defer recoverPostCommitNotifyPanic(NotificationSecretShared, groupID)
	if secret == nil {
		return
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return
	}
	for _, m := range members {
		c.notifySecretShared(ctx, secret, m.ID, sharedBy, permission)
	}
}

// notifySecretShareRevoked tells a recipient their access to a secret was revoked.
// Direct shares only (a group share has no single user); skips the actor revoking
// their own share. Best-effort.
func (c *KeyorixCore) notifySecretShareRevoked(ctx context.Context, secret *models.SecretNode, recipientID, revokedBy uint) {
	defer recoverPostCommitNotifyPanic(NotificationSecretShareRevoked, recipientID)
	if secret == nil || recipientID == 0 || recipientID == revokedBy {
		return
	}
	var pid *uint
	if secret.ProjectID != 0 {
		p := secret.ProjectID
		pid = &p
	}
	c.notify(ctx, recipientID, NotificationSecretShareRevoked,
		"Secret access revoked",
		fmt.Sprintf("Your access to secret %q was revoked.", secret.Name),
		pid, fmt.Sprintf("/secrets/%d", secret.ID))
}

// notifyGroupSecretShareRevoked fans the revoke notification out to every member of a
// group whose share was revoked (excluding the actor). Best-effort.
func (c *KeyorixCore) notifyGroupSecretShareRevoked(ctx context.Context, secret *models.SecretNode, groupID, revokedBy uint) {
	defer recoverPostCommitNotifyPanic(NotificationSecretShareRevoked, groupID)
	if secret == nil {
		return
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return
	}
	for _, m := range members {
		c.notifySecretShareRevoked(ctx, secret, m.ID, revokedBy)
	}
}

// notifySecretOwnershipTransferred tells a user they are now the owner of a secret.
// Skipped when the actor transferred it to themselves. Best-effort.
func (c *KeyorixCore) notifySecretOwnershipTransferred(ctx context.Context, secret *models.SecretNode, newOwnerID, actorID uint) {
	if secret == nil || newOwnerID == 0 || newOwnerID == actorID {
		return
	}
	var pid *uint
	if secret.ProjectID != 0 {
		p := secret.ProjectID
		pid = &p
	}
	defer recoverPostCommitNotifyPanic(NotificationSecretOwnershipTransferred, newOwnerID)
	c.notify(ctx, newOwnerID, NotificationSecretOwnershipTransferred,
		"You are now a secret owner",
		fmt.Sprintf("You were made the owner of secret %q.", secret.Name),
		pid, fmt.Sprintf("/secrets/%d", secret.ID))
}

// notifySecretsReassigned tells a new owner that a batch of secrets was re-homed to
// them (bulk offboarding) — one summary instead of one-per-secret. Best-effort.
func (c *KeyorixCore) notifySecretsReassigned(ctx context.Context, newOwnerID, actorID, projectID uint, count int) {
	if newOwnerID == 0 || newOwnerID == actorID || count == 0 {
		return
	}
	var pid *uint
	if projectID != 0 {
		p := projectID
		pid = &p
	}
	defer recoverPostCommitNotifyPanic(NotificationSecretOwnershipTransferred, newOwnerID)
	c.notify(ctx, newOwnerID, NotificationSecretOwnershipTransferred,
		"Secrets reassigned to you",
		fmt.Sprintf("%d secret(s) in %s were reassigned to you.", count, c.projectLabel(ctx, projectID)),
		pid, fmt.Sprintf("/projects/%d", projectID))
}

// ── Self-scoped reads/writes (the authenticated user) ───────────────────────

// ListNotifications returns the user's notifications, newest first.
//
// A request authenticated by a restricted PAT sees only the notifications its
// restriction allows (patAllowsNotification, PAT-GUARD-1): a notification names
// project resources, and this feed is self-scoped, so no Authorize call ever
// narrows it. The narrowing is done in the query (patNotificationScope), so limit
// counts visible rows: a restricted token gets up to limit of the rows it can see,
// however many newer rows it cannot.
func (c *KeyorixCore) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	if patRestrictionFromContext(ctx) == nil {
		return c.storage.ListNotifications(ctx, userID, unreadOnly, limit)
	}
	scope, ok := patNotificationScope(ctx)
	if !ok {
		return []*models.Notification{}, nil
	}
	rows, err := c.storage.ListScopedNotifications(ctx, userID, scope, unreadOnly, limit)
	if err != nil {
		return nil, err
	}
	// Defence in depth: the scope is exact (see patNotificationScope), so this drops
	// nothing; if the two ever disagree, the row is hidden, never shown.
	visible := make([]*models.Notification, 0, len(rows))
	for _, n := range rows {
		if patAllowsNotification(ctx, n) {
			visible = append(visible, n)
		}
	}
	return visible, nil
}

// UnreadNotificationCount returns how many unread notifications the user has —
// for a restricted PAT, how many of the ones it can see, so the badge count and
// the list agree.
func (c *KeyorixCore) UnreadNotificationCount(ctx context.Context, userID uint) (int64, error) {
	if patRestrictionFromContext(ctx) == nil {
		return c.storage.CountUnreadNotifications(ctx, userID)
	}
	scope, ok := patNotificationScope(ctx)
	if !ok {
		return 0, nil
	}
	return c.storage.CountUnreadScopedNotifications(ctx, userID, scope)
}

// MarkNotificationRead marks one of the user's notifications read (ownership-checked).
// A restricted PAT gets the same not-found for a notification it cannot see as for
// one that does not exist.
func (c *KeyorixCore) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	if patRestrictionFromContext(ctx) == nil {
		return c.storage.MarkNotificationRead(ctx, id, userID)
	}
	scope, ok := patNotificationScope(ctx)
	if !ok {
		// The storage layer's own wording for "no such (id, user) row".
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return c.storage.MarkScopedNotificationRead(ctx, id, userID, scope)
}

// MarkAllNotificationsRead marks all of the user's notifications read — for a
// restricted PAT, all of the ones it can see (one UPDATE, so all or none).
func (c *KeyorixCore) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	if patRestrictionFromContext(ctx) == nil {
		return c.storage.MarkAllNotificationsRead(ctx, userID)
	}
	scope, ok := patNotificationScope(ctx)
	if !ok {
		return nil
	}
	return c.storage.MarkAllScopedNotificationsRead(ctx, userID, scope)
}

// auditNotificationFailed is the audit event type recorded when a notification
// that follows an already-committed operation could not be created (#3075).
const auditNotificationFailed = "notification.failed"
