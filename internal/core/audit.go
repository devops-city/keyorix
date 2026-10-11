package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RBAC audit event types. Role assignments/removals are written to the shared
// audit_events table and surfaced together by ListRBACAuditLogs.
const (
	EventRoleAssigned      = "role.assigned"
	EventRoleRemoved       = "role.removed"
	EventRoleExpired       = "role.expired"        // #nosec G101 -- audit event type, not a credential
	EventRoleGroupAssigned = "role.group_assigned" // #nosec G101 -- audit event type, not a credential
	EventRoleGroupRemoved  = "role.group_removed"  // #nosec G101 -- audit event type, not a credential
	EventPermissionAdded   = "permission.assigned" // #nosec G101 -- audit event type, not a credential
	EventPermissionRemoved = "permission.removed"  // #nosec G101 -- audit event type, not a credential
	// Role-definition lifecycle (the role itself, not an assignment of it).
	EventRoleCreated = "role.created"
	EventRoleUpdated = "role.updated"
	EventRoleDeleted = "role.deleted"
	// Group membership: adding/removing a member confers/revokes every role the
	// group holds — the same blast radius as a direct role grant/removal, so these
	// land in the RBAC audit trail alongside role.assigned/role.removed (#233).
	EventGroupMemberAdded   = "group.member_added"
	EventGroupMemberRemoved = "group.member_removed"
)

// rbacAuditEventTypes is the set of event types that make up the RBAC audit log.
var rbacAuditEventTypes = []string{
	EventRoleAssigned, EventRoleRemoved, EventRoleExpired,
	EventRoleGroupAssigned, EventRoleGroupRemoved,
	EventPermissionAdded, EventPermissionRemoved,
	EventRoleCreated, EventRoleUpdated, EventRoleDeleted,
	EventGroupMemberAdded, EventGroupMemberRemoved,
}

// reasonBuiltinRoleTarget is a fixed reason= token appended to a
// permission.assigned/permission.removed event's Description when the target
// role is a built-in (IsBuiltinRole) — #1500. Reuses ADR-082 §H's convention
// (docs/adr-082-connect-connector-tenant-scoping.md): a closed-set free-text
// token at a consistent position in Description, so an operator can learn
// something the API response itself doesn't distinguish (here: whether the
// permission change just landed on a built-in role's authorization
// baseline). ADR-044 already establishes that this stays PERMITTED, not
// refused — ONLY the visibility changes; see the call sites in
// rbac_management.go for the full reasoning. Unlike §H's Connect events,
// this event ALSO carries the same signal as a structured field
// (rbacAuditDetail.BuiltinRoleTarget below) because rbacAuditDetail already
// existed here — §H used free text only because no structured field was
// available for Connect events at the time, and named the day a structured
// column exists as the point this would become "parse-and-backfill, not a
// rewrite"; rbacAuditDetail's JSON Diff is exactly that column already, so
// there is no reason to wait.
const reasonBuiltinRoleTarget = "builtin_role_target"

// reasonBaselineRoleBackfill is the reason= token for a role.assigned event
// issued by ReconcileUserBaselineRoles (user_baseline_role_reconcile.go) — the
// startup sweep that grants system_viewer to any user missing it, repairing
// an install bootstrapped before #2188 fixed the seeding-order bug that made
// every fresh install (any backend) miss the grant on its first user. Same
// free-text-token-in-Description convention as reasonBuiltinRoleTarget
// (ADR-082 §H), paired with the structured BaselineRoleBackfill field below.
const reasonBaselineRoleBackfill = "baseline_role_backfill"

// rbacAuditDetail is the structured payload stored in an RBAC event's Diff field,
// carrying the target/role/scope that the generic AuditEvent row cannot.
type rbacAuditDetail struct {
	TargetUserID uint `json:"target_user_id,omitempty"`
	GroupID      uint `json:"group_id,omitempty"`
	RoleID       uint `json:"role_id"`
	PermissionID uint `json:"permission_id,omitempty"`
	// BuiltinRoleTarget is true when RoleID identifies a built-in role
	// (IsBuiltinRole) — #1500. Set only by logPermissionChange today; see
	// reasonBuiltinRoleTarget above for the parallel Description token.
	BuiltinRoleTarget bool `json:"builtin_role_target,omitempty"`
	// BaselineRoleBackfill is true when this grant was issued by the startup
	// baseline-role reconcile rather than an ordinary role-assignment path —
	// see reasonBaselineRoleBackfill above.
	BaselineRoleBackfill bool `json:"baseline_role_backfill,omitempty"`
	ProjectID            uint `json:"project_id,omitempty"`
	EnvironmentID        uint `json:"environment_id,omitempty"`
}

// LogRoleAssigned / LogRoleRemoved record an RBAC change. actorID is the user who
// made the change (0 = no authenticated principal, e.g. a local CLI invocation);
// the target/role/scope are captured in the event's structured diff.
func (c *KeyorixCore) LogRoleAssigned(ctx context.Context, actorID, targetUserID, roleID uint, scope Scope) {
	c.logRoleChange(ctx, EventRoleAssigned, "assigned to", actorID, targetUserID, roleID, scope, false)
}

func (c *KeyorixCore) LogRoleRemoved(ctx context.Context, actorID, targetUserID, roleID uint, scope Scope) {
	c.LogRoleRemovedOn(ctx, c.auditNow(), actorID, targetUserID, roleID, scope)
}

// LogRoleRemovedOn is LogRoleRemoved against an explicit audit target
// (audit_target.go) — used by the access-review revoke path, which writes this
// event inside the same transaction as the removal it describes.
func (c *KeyorixCore) LogRoleRemovedOn(ctx context.Context, tgt auditTarget, actorID, targetUserID, roleID uint, scope Scope) {
	c.logRoleChangeOn(ctx, tgt, EventRoleRemoved, "removed from", actorID, targetUserID, roleID, scope, false)
}

// LogRoleAssignedBackfill records a role grant issued by the startup baseline-
// role reconcile (ReconcileUserBaselineRoles) — same event type and shape as
// LogRoleAssigned, tagged reason=baseline_role_backfill (Description) and
// BaselineRoleBackfill=true (structured Diff) so an operator reading the audit
// trail can tell "the system repaired this on startup" apart from an ordinary
// role.assigned grant.
func (c *KeyorixCore) LogRoleAssignedBackfill(ctx context.Context, actorID, targetUserID, roleID uint, scope Scope) {
	c.logRoleChange(ctx, EventRoleAssigned, "assigned to", actorID, targetUserID, roleID, scope, true)
}

func (c *KeyorixCore) logRoleChange(ctx context.Context, eventType, verb string, actorID, targetUserID, roleID uint, scope Scope, baselineBackfill bool) {
	c.logRoleChangeOn(ctx, c.auditNow(), eventType, verb, actorID, targetUserID, roleID, scope, baselineBackfill)
}

// logRoleChangeOn is logRoleChange against an explicit audit target. ONE body,
// two entry points.
func (c *KeyorixCore) logRoleChangeOn(ctx context.Context, tgt auditTarget, eventType, verb string, actorID, targetUserID, roleID uint, scope Scope, baselineBackfill bool) {
	desc := fmt.Sprintf("%s %s %s", c.auditRef(ctx, tgt.st, auditKindRole, roleID), verb, c.auditRef(ctx, tgt.st, auditKindUser, targetUserID))
	if baselineBackfill {
		desc = fmt.Sprintf("%s reason=%s", desc, reasonBaselineRoleBackfill)
	}
	c.writeRBACAuditOn(ctx, tgt, eventType, desc, actorID, scope, rbacAuditDetail{
		TargetUserID:         targetUserID,
		RoleID:               roleID,
		BaselineRoleBackfill: baselineBackfill,
		ProjectID:            scope.ProjectID,
		EnvironmentID:        scope.EnvironmentID,
	})
}

// LogGroupRoleAssigned / LogGroupRoleRemoved record a role granted to / removed
// from a group. See LogRoleAssigned for actorID semantics.
func (c *KeyorixCore) LogGroupRoleAssigned(ctx context.Context, actorID, groupID, roleID uint, scope Scope) {
	c.logGroupRoleChange(ctx, EventRoleGroupAssigned, "assigned to group", actorID, groupID, roleID, scope)
}

func (c *KeyorixCore) LogGroupRoleRemoved(ctx context.Context, actorID, groupID, roleID uint, scope Scope) {
	c.LogGroupRoleRemovedOn(ctx, c.auditNow(), actorID, groupID, roleID, scope)
}

// LogGroupRoleRemovedOn is LogGroupRoleRemoved against an explicit audit target
// (audit_target.go) — the group-grant counterpart of LogRoleRemovedOn.
func (c *KeyorixCore) LogGroupRoleRemovedOn(ctx context.Context, tgt auditTarget, actorID, groupID, roleID uint, scope Scope) {
	c.logGroupRoleChangeOn(ctx, tgt, EventRoleGroupRemoved, "removed from group", actorID, groupID, roleID, scope)
}

func (c *KeyorixCore) logGroupRoleChange(ctx context.Context, eventType, verb string, actorID, groupID, roleID uint, scope Scope) {
	c.logGroupRoleChangeOn(ctx, c.auditNow(), eventType, verb, actorID, groupID, roleID, scope)
}

// logGroupRoleChangeOn is logGroupRoleChange against an explicit audit target.
// ONE body, two entry points.
func (c *KeyorixCore) logGroupRoleChangeOn(ctx context.Context, tgt auditTarget, eventType, verb string, actorID, groupID, roleID uint, scope Scope) {
	desc := fmt.Sprintf("%s %s %s", c.auditRef(ctx, tgt.st, auditKindRole, roleID), verb, c.auditRefTail(ctx, tgt.st, auditKindGroup, groupID))
	c.writeRBACAuditOn(ctx, tgt, eventType, desc, actorID, scope, rbacAuditDetail{
		GroupID:       groupID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
	})
}

// LogGroupMemberAdded / LogGroupMemberRemoved record a user being added to / removed
// from a group. Because membership confers every role the group holds, this is a
// role-grant-equivalent action and lands in the RBAC audit trail (#233). See
// LogRoleAssigned for actorID semantics.
func (c *KeyorixCore) LogGroupMemberAdded(ctx context.Context, actorID, userID, groupID uint) {
	c.logGroupMemberChange(ctx, EventGroupMemberAdded, "added to group", actorID, userID, groupID)
}

func (c *KeyorixCore) LogGroupMemberRemoved(ctx context.Context, actorID, userID, groupID uint) {
	c.logGroupMemberChange(ctx, EventGroupMemberRemoved, "removed from group", actorID, userID, groupID)
}

func (c *KeyorixCore) logGroupMemberChange(ctx context.Context, eventType, verb string, actorID, userID, groupID uint) {
	desc := fmt.Sprintf("%s %s %s", c.auditRef(ctx, c.storage, auditKindUser, userID), verb, c.auditRefTail(ctx, c.storage, auditKindGroup, groupID))
	c.writeRBACAudit(ctx, eventType, desc, actorID, Scope{}, rbacAuditDetail{
		TargetUserID: userID,
		GroupID:      groupID,
	})
}

// LogPermissionAssigned / LogPermissionRemoved record a permission granted to /
// removed from a role. See LogRoleAssigned for actorID semantics. builtinTarget
// is true when roleID identifies a built-in role (IsBuiltinRole) — #1500; it
// does not change whether the event is written, only what it carries (see
// reasonBuiltinRoleTarget).
func (c *KeyorixCore) LogPermissionAssigned(ctx context.Context, actorID, roleID, permissionID uint, builtinTarget bool) {
	c.logPermissionChange(ctx, EventPermissionAdded, "granted to role", actorID, roleID, permissionID, builtinTarget)
}

func (c *KeyorixCore) LogPermissionRemoved(ctx context.Context, actorID, roleID, permissionID uint, builtinTarget bool) {
	c.logPermissionChange(ctx, EventPermissionRemoved, "removed from role", actorID, roleID, permissionID, builtinTarget)
}

func (c *KeyorixCore) logPermissionChange(ctx context.Context, eventType, verb string, actorID, roleID, permissionID uint, builtinTarget bool) {
	desc := fmt.Sprintf("permission %d %s %d", permissionID, verb, roleID)
	if builtinTarget {
		desc = fmt.Sprintf("%s reason=%s", desc, reasonBuiltinRoleTarget)
	}
	c.writeRBACAudit(ctx, eventType, desc, actorID, Scope{}, rbacAuditDetail{
		RoleID:            roleID,
		PermissionID:      permissionID,
		BuiltinRoleTarget: builtinTarget,
	})
}

// LogRoleCreated / LogRoleUpdated / LogRoleDeleted record a change to a role
// DEFINITION (distinct from assigning a role to a principal). Role definitions are
// global, so no scope. actorID is the admin who made the change (0 = no
// authenticated principal). They surface in the RBAC audit log alongside grants.
func (c *KeyorixCore) LogRoleCreated(ctx context.Context, actorID, roleID uint, name string) {
	c.logRoleDefinitionChange(ctx, EventRoleCreated, "created", actorID, roleID, name)
}

func (c *KeyorixCore) LogRoleUpdated(ctx context.Context, actorID, roleID uint, name string) {
	c.logRoleDefinitionChange(ctx, EventRoleUpdated, "updated", actorID, roleID, name)
}

// LogRoleDeleted records a role deletion. counts is DeleteRole's cascade
// result (PR #2357 review) -- the user/group/machine assignment rows that
// were silently dropped along with the role, surfaced here so the audit
// trail shows who lost a grant row, not just that the role itself is gone.
func (c *KeyorixCore) LogRoleDeleted(ctx context.Context, actorID, roleID uint, name string, counts storage.RoleDeleteCascadeCounts) {
	desc := fmt.Sprintf("role %q (id %d) deleted", name, roleID)
	if counts.UserAssignments > 0 || counts.GroupAssignments > 0 || counts.MachineAssignments > 0 {
		desc += fmt.Sprintf(" (removed %d user / %d group / %d machine assignment(s))",
			counts.UserAssignments, counts.GroupAssignments, counts.MachineAssignments)
	}
	c.writeRBACAudit(ctx, EventRoleDeleted, desc, actorID, Scope{}, rbacAuditDetail{RoleID: roleID})
}

// LogRoleUpdateDenied / LogRoleDeleteDenied record a DENIED attempt to update
// or delete a role -- #1503: UpdateRole/DeleteRole refuse a built-in role
// (core.IsBuiltinRole) on both transports (server/http/handlers/rbac.go,
// server/grpc/services/role_service.go), but until now that refusal left no
// audit trail at all, unlike every other RBAC/Connect deny path. Callable
// from either handler package since writeAuditEventFailed itself is
// unexported. Reuses EventRoleUpdated/EventRoleDeleted rather than minting a
// "_denied" event type per action -- Success=false already distinguishes a
// denied attempt from a completed one, the same convention CreateSoDPolicy/
// PlaceLegalHold established (see sod.go's package-level comment).
func (c *KeyorixCore) LogRoleUpdateDenied(ctx context.Context, actorID, roleID uint, name, reason string) {
	c.writeAuditEventFailed(ctx, EventRoleUpdated, actorPtr(actorID), nil, "",
		fmt.Sprintf("role update DENIED for %q (id %d): %s", name, roleID, reason))
}

func (c *KeyorixCore) LogRoleDeleteDenied(ctx context.Context, actorID, roleID uint, name, reason string) {
	c.writeAuditEventFailed(ctx, EventRoleDeleted, actorPtr(actorID), nil, "",
		fmt.Sprintf("role delete DENIED for %q (id %d): %s", name, roleID, reason))
}

func (c *KeyorixCore) logRoleDefinitionChange(ctx context.Context, eventType, verb string, actorID, roleID uint, name string) {
	desc := fmt.Sprintf("role %q (id %d) %s", name, roleID, verb)
	c.writeRBACAudit(ctx, eventType, desc, actorID, Scope{}, rbacAuditDetail{RoleID: roleID})
}

// writeRBACAudit is the shared writer for RBAC audit events: actor as UserID,
// scope's project as ProjectID, and the structured detail in the diff.
func (c *KeyorixCore) writeRBACAudit(ctx context.Context, eventType, desc string, actorID uint, scope Scope, detail rbacAuditDetail) {
	c.writeRBACAuditOn(ctx, c.auditNow(), eventType, desc, actorID, scope, detail)
}

// writeRBACAuditOn is writeRBACAudit against an explicit audit target — see
// audit_target.go for why a transaction-scoped caller needs one. ONE body, two
// entry points: writeRBACAudit is the auditNow() case.
func (c *KeyorixCore) writeRBACAuditOn(ctx context.Context, tgt auditTarget, eventType, desc string, actorID uint, scope Scope, detail rbacAuditDetail) {
	encoded, _ := json.Marshal(detail)
	var actor *uint
	if actorID != 0 {
		a := actorID
		actor = &a
	}
	var projectID *uint
	if scope.ProjectID != 0 {
		p := scope.ProjectID
		projectID = &p
	}
	c.writeAuditEventDiffOn(ctx, tgt, eventType, actor, nil, projectID, "", desc, string(encoded))
}

// writeAuditEvent persists an audit_events row (basic — no project/IP context).
func (c *KeyorixCore) writeAuditEvent(ctx context.Context, eventType string, userID *uint, secretID *uint, description string) {
	c.writeAuditEventFull(ctx, eventType, userID, secretID, nil, "", description)
}

// writeAuditEventFull persists an audit_events row with full NIS2/DORA context.
// Returns whether it actually persisted (see emitAudit's own doc comment) --
// every pre-#2406 caller ignores it, source-compatible and behavior-unchanged.
func (c *KeyorixCore) writeAuditEventFull(ctx context.Context, eventType string, userID *uint, secretID *uint, projectID *uint, ip string, description string) bool {
	return c.writeAuditEventFullOn(ctx, c.auditNow(), eventType, userID, secretID, projectID, ip, description)
}

// writeAuditEventFullOn is writeAuditEventFull against an explicit audit target
// (audit_target.go). ONE body, two entry points. A pure one-line delegation --
// writeAuditEventDiffOn (below) is where the actual construction/panic risk
// lives and where the #2561 recover is, so this needs none of its own.
func (c *KeyorixCore) writeAuditEventFullOn(ctx context.Context, tgt auditTarget, eventType string, userID *uint, secretID *uint, projectID *uint, ip string, description string) bool {
	return c.writeAuditEventDiffOn(ctx, tgt, eventType, userID, secretID, projectID, ip, description, "")
}

// writeAuditEventDiff is writeAuditEventFull plus a structured before/after diff.
// It also stamps impersonation attribution when the context carries an
// impersonation tag (set by the auth middleware), so every action taken inside
// an impersonation session is consistently marked with impersonation=true.
func (c *KeyorixCore) writeAuditEventDiff(ctx context.Context, eventType string, userID *uint, secretID *uint, projectID *uint, ip string, description string, diff string) bool { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	return c.writeAuditEventDiffOn(ctx, c.auditNow(), eventType, userID, secretID, projectID, ip, description, diff)
}

// writeAuditEventDiffOn is writeAuditEventDiff against an explicit audit target
// (audit_target.go). ONE body, two entry points.
//
// Recovers its own panic (#2561). emitAuditOn already does, but its recover
// only begins once control REACHES it: this function BUILDS the AuditEvent
// (sanitizeAuditText, withClientOriginNote, actorTypeFromContext,
// impersonatorFromContext) before calling emitAuditOn, so a panic in any of
// those -- or in this wrapper's own frame -- would still escape to a caller
// that has already committed its write, which is exactly the "panic masks an
// already-committed write" class QA-1 found 12+ times. 42 post-commit call
// sites in this package discard this function's bool (via writeAuditEventFull/
// writeAuditEventDiff), so the window was real, if narrow. Closing it here
// (rather than recording it as a reviewed exemption in
// docs/besteffort-exempt.tsv) makes the safety DERIVABLE by
// internal/besteffortguard's panicSafetyIndex, which reads this defer out of
// the source -- and a derived fact goes red if someone deletes it, where an
// exemption row would have kept pardoning the call sites.
func (c *KeyorixCore) writeAuditEventDiffOn(ctx context.Context, tgt auditTarget, eventType string, userID *uint, secretID *uint, projectID *uint, ip string, description string, diff string) (persisted bool) { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: writeAuditEventDiffOn panicked building/emitting audit event %q (best-effort, primary operation already succeeded): %v", eventType, r)
			persisted = false
		}
	}()
	t := true
	event := &models.AuditEvent{
		EventType:    eventType,
		UserID:       userID,
		SecretNodeID: secretID,
		ProjectID:    projectID,
		IPAddress:    ip,
		Description:  withClientOriginNote(ctx, sanitizeAuditText(description)),
		Success:      &t,
		EventTime:    time.Now(),
		Diff:         diff,
		ActorType:    actorTypeFromContext(ctx),
	}
	if adminID, ok := impersonatorFromContext(ctx); ok {
		a := adminID
		event.ImpersonatedBy = &a
		event.ActingAs = userID
		event.Impersonation = true
	}
	return c.emitAuditOn(ctx, tgt, event)
}

// writeAuditEventFailed persists a failed audit event (Success=false), with
// project context — added for ADR-082 branch 3, whose Connect deny-path events
// need both Success=false and a populated ProjectID (the connector's owning
// project), which no prior helper supported simultaneously.
func (c *KeyorixCore) writeAuditEventFailed(ctx context.Context, eventType string, userID *uint, projectID *uint, ip string, description string) {
	f := false
	event := &models.AuditEvent{
		EventType:   eventType,
		UserID:      userID,
		ProjectID:   projectID,
		IPAddress:   ip,
		Description: sanitizeAuditText(description),
		Success:     &f,
		EventTime:   time.Now(),
		ActorType:   actorTypeFromContext(ctx),
	}
	// #G23: stamp impersonation attribution the same way the success-path
	// writer (writeAuditEventDiff) does — a failed action taken inside an
	// impersonation session must be attributable to the impersonating admin
	// too, not just the userID it was attempted as.
	if adminID, ok := impersonatorFromContext(ctx); ok {
		a := adminID
		event.ImpersonatedBy = &a
		event.ActingAs = userID
		event.Impersonation = true
	}
	c.emitAudit(ctx, event)
}

// sanitizeAuditText strips control characters (CR/LF, ANSI/C1 escapes, NUL, etc.) from a
// string headed for an audit Description, so a crafted secret name or username can't inject
// a forged audit line or smuggle terminal-control sequences into a CLI audit viewer. The
// audit chain hashes the Description, so cleaning it also keeps the persisted, tamper-
// evident content faithful. A tab is normalized to a space; other controls are dropped.
func sanitizeAuditText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1 // drop
		}
		return r
	}, s)
}

// writeAccessLog persists a secret_access_logs row. A failure here is a gap in the
// secret-access trail, so it is surfaced loudly rather than silently discarded —
// mirroring emitAudit's handling of a failed audit_events write. A panic from the
// storage call is recovered the same way (best-effort, not a reason to report the
// CALLER's already-committed primary mutation as failed) — found by
// FuzzStorageFaultOperations on REST PATCH /api/v1/secrets/{id}/classification:
// a panic here propagated past the point where the classification change (and its
// own audit event) had already committed, reporting an already-successful request
// as an error. Same shape, same fix, as #2408 (projectCounts) and #2416
// (EnforceSessionLimit).
func (c *KeyorixCore) writeAccessLog(ctx context.Context, secretID uint, accessedBy, action, ip, ua string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: writeAccessLog panicked persisting secret access log (secret=%d action=%q accessedBy=%q, best-effort, primary operation already succeeded): %v",
				secretID, action, accessedBy, r)
		}
	}()
	entry := &models.SecretAccessLog{
		SecretNodeID: secretID,
		AccessedBy:   accessedBy,
		AccessTime:   time.Now(),
		Action:       action,
		IPAddress:    ip,
		UserAgent:    ua,
	}
	if err := c.storage.CreateSecretAccessLog(ctx, entry); err != nil {
		log.Printf("SECURITY: failed to persist secret access log (secret=%d action=%q accessedBy=%q): %v",
			secretID, action, accessedBy, err)
	}
}

// LogSecretRead writes audit_events + secret_access_logs for a secret read.
func (c *KeyorixCore) LogSecretRead(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.read", &uid, &sid,
		fmt.Sprintf("User %s read secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "read", ip, ua)
}

// LogSecretReadWithProject writes audit_events + secret_access_logs including
// project context, as ONE atomic unit, and BLOCKS until both are durably
// committed (SESSION-PERF, #2403 follow-up, item 3 — audit-before-disclosure).
// Returns an error if the write fails; the caller must treat that as "do not
// disclose the value" (fail closed), never return the value and discard the
// error. Unlike LogSecretCreated/LogSecretUpdated/etc. (still fire-and-forget
// via writeAuditEventFull+writeAccessLog as two independent best-effort
// writes, unchanged), this is the one audit-logging call in this file a
// caller is required to wait on and check — because it is the only one that
// gates a value disclosure the client hasn't seen yet when this runs.
func (c *KeyorixCore) LogSecretReadWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) error { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	t := true
	event := &models.AuditEvent{
		EventType:    "secret.read",
		UserID:       &uid,
		SecretNodeID: &sid,
		ProjectID:    &pid,
		IPAddress:    ip,
		Description:  sanitizeAuditText(fmt.Sprintf("User %s read secret %s", username, secretName)),
		Success:      &t,
		EventTime:    time.Now(),
		ActorType:    actorTypeFromContext(ctx),
	}
	if adminID, ok := impersonatorFromContext(ctx); ok {
		a := adminID
		event.ImpersonatedBy = &a
		event.ActingAs = &uid
		event.Impersonation = true
	}
	accessLog := &models.SecretAccessLog{
		SecretNodeID: secretID,
		AccessedBy:   username,
		AccessTime:   time.Now(),
		Action:       "read",
		IPAddress:    ip,
		UserAgent:    ua,
	}
	return c.emitAuditWithAccessLog(ctx, event, accessLog)
}

// EventSecretVersionsListed is the audit event for listing a secret's version
// history (GET /secrets/{id}/versions, gRPC GetSecretVersions). The listing
// carries version numbers, timestamps and read counters, never a value
// (SecretVersion.EncryptedValue is json:"-"), so it is not a secret.read:
// secret.read, and every count keyed on it (read summaries, billing and usage
// reads, dashboard "accessed"), means a value disclosure only (AUDIT-UX-2, #2951).
const EventSecretVersionsListed = "secret.versions_listed"

// AccessActionVersionsList is the secret_access_logs action written with
// EventSecretVersionsListed. Not "read": read counts (total reads, most-accessed,
// rotation risk) filter on action "read". Anomaly detection reads every action,
// so who listed a secret's versions from where still feeds its baselines.
const AccessActionVersionsList = "versions_list"

// EventSecretMetadataRead is the audit event for a metadata-only secret lookup
// (GET /secrets/by-name): the response carries the secret's metadata, never its
// value, so it is not a secret.read (AUDIT-UX-3, same rule as
// EventSecretVersionsListed).
const EventSecretMetadataRead = "secret.metadata_read"

// AccessActionMetadataRead is the secret_access_logs action written with
// EventSecretMetadataRead. Not "read": read counts filter on action "read".
// Anomaly detection reads every action, so metadata lookups still feed its
// baselines.
const AccessActionMetadataRead = "metadata_read"

// LogSecretVersionsListed writes audit_events + secret_access_logs for a
// version-history listing, as ONE atomic unit, and blocks until both are
// durably committed: the same audit-before-response contract (and the same
// writer) as LogSecretReadWithProject, which this replaces for the listing.
// Returns an error if the write fails; the caller must not send the listing.
func (c *KeyorixCore) LogSecretVersionsListed(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) error { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	return c.logSecretMetadataAccess(ctx, EventSecretVersionsListed, AccessActionVersionsList,
		fmt.Sprintf("User %s listed the versions of secret %s", username, secretName),
		userID, secretID, projectID, username, ip, ua)
}

// LogSecretMetadataRead writes secret.metadata_read + an access-log row of
// action "metadata_read" (atomically, like LogSecretVersionsListed) for a
// metadata-only lookup by name.
func (c *KeyorixCore) LogSecretMetadataRead(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) error { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	return c.logSecretMetadataAccess(ctx, EventSecretMetadataRead, AccessActionMetadataRead,
		fmt.Sprintf("User %s looked up secret %s", username, secretName),
		userID, secretID, projectID, username, ip, ua)
}

// logSecretMetadataAccess is the shared atomic writer for metadata-only secret
// access events (no value disclosed). The description must end in
// " secret <name>" (the dashboard extracts the name from it).
func (c *KeyorixCore) logSecretMetadataAccess(ctx context.Context, eventType, accessAction, description string, userID, secretID, projectID uint, username, ip, ua string) error { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	t := true
	event := &models.AuditEvent{
		EventType:    eventType,
		UserID:       &uid,
		SecretNodeID: &sid,
		ProjectID:    &pid,
		IPAddress:    ip,
		Description:  sanitizeAuditText(description),
		Success:      &t,
		EventTime:    time.Now(),
		ActorType:    actorTypeFromContext(ctx),
	}
	if adminID, ok := impersonatorFromContext(ctx); ok {
		a := adminID
		event.ImpersonatedBy = &a
		event.ActingAs = &uid
		event.Impersonation = true
	}
	accessLog := &models.SecretAccessLog{
		SecretNodeID: secretID,
		AccessedBy:   username,
		AccessTime:   time.Now(),
		Action:       accessAction,
		IPAddress:    ip,
		UserAgent:    ua,
	}
	return c.emitAuditWithAccessLog(ctx, event, accessLog)
}

// LogSecretCreated writes audit_events + secret_access_logs for a secret creation.
func (c *KeyorixCore) LogSecretCreated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.created", &uid, &sid,
		fmt.Sprintf("User %s created secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "create", ip, ua)
}

// LogSecretCreatedWithProject writes audit_events + secret_access_logs including project context.
func (c *KeyorixCore) LogSecretCreatedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.created", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s created secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "create", ip, ua)
}

// LogSecretUpdated writes audit_events + secret_access_logs for a secret update.
func (c *KeyorixCore) LogSecretUpdated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, evtSecretUpdated, &uid, &sid,
		fmt.Sprintf("User %s updated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretUpdatedWithProject writes audit_events including project context.
func (c *KeyorixCore) LogSecretUpdatedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, evtSecretUpdated, &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s updated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretUpdatedWithDiff writes a secret.updated audit event carrying a
// structured before/after diff (see audit_diff.go — never includes plaintext
// values) plus the secret_access_logs row.
func (c *KeyorixCore) LogSecretUpdatedWithDiff(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua, diff string) { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventDiff(ctx, evtSecretUpdated, &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s updated secret %s", username, secretName), diff)
	c.writeAccessLog(ctx, secretID, username, "update", ip, ua)
}

// LogSecretRotated writes audit_events + secret_access_logs for a secret rotation.
func (c *KeyorixCore) LogSecretRotated(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.rotated", &uid, &sid,
		fmt.Sprintf("User %s rotated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "rotate", ip, ua)
}

// LogSecretRotatedWithProject writes audit_events + secret_access_logs including project context.
func (c *KeyorixCore) LogSecretRotatedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.rotated", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s rotated secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "rotate", ip, ua)
}

// LogSecretDeleted writes audit_events + secret_access_logs for a secret deletion.
func (c *KeyorixCore) LogSecretDeleted(ctx context.Context, userID uint, secretID uint, username, secretName, ip, ua string) {
	uid, sid := userID, secretID
	c.writeAuditEvent(ctx, "secret.deleted", &uid, &sid,
		fmt.Sprintf("User %s deleted secret %s", username, secretName))
	c.writeAccessLog(ctx, secretID, username, "delete", ip, ua)
}

// LogSecretDeletedWithProject writes audit_events including project context.
func (c *KeyorixCore) LogSecretDeletedWithProject(ctx context.Context, userID uint, secretID uint, projectID uint, username, secretName, ip, ua string) { // NOSONAR -- domain-driven parameter count; each field is a distinct audit attribute
	uid, sid, pid := userID, secretID, projectID
	c.writeAuditEventFull(ctx, "secret.deleted", &uid, &sid, &pid, ip,
		fmt.Sprintf("User %s deleted secret %s", username, secretName)+c.softDeleteNote(ctx, secretID, projectID))
	c.writeAccessLog(ctx, secretID, username, "delete", ip, ua)
}

// softDeleteNoteMarker starts the note appended to a secret.deleted description.
// extractSecretName cuts the description at it, so the secret's name is still
// recoverable from "User <u> deleted secret <name> (soft delete: ...)".
const softDeleteNoteMarker = " (soft delete:"

// softDeleteNote says what the delete actually did, for the audit entry (#2951):
// a secret delete is a soft delete (restorable until purge, its versions are kept,
// not destroyed), and secrets that depended on it lose that dependency until it is
// restored. Best-effort and display only: a failed lookup just yields a shorter
// note, never a missing or altered audit event.
func (c *KeyorixCore) softDeleteNote(ctx context.Context, secretID, projectID uint) string {
	versions := -1
	var dependents []string
	besteffort.Run(ctx, "audit.softDeleteNote", func() error {
		if vs, err := c.storage.GetSecretVersions(ctx, secretID); err == nil {
			versions = len(vs)
		}
		edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
		if err != nil {
			return err
		}
		for _, e := range edges {
			if e.DependsOnSecretID != secretID {
				continue
			}
			if dep, derr := c.storage.GetSecret(ctx, e.DependentSecretID); derr == nil && dep != nil {
				dependents = append(dependents, dep.Name)
			}
		}
		return nil
	})
	note := softDeleteNoteMarker + " restorable with 'secret restore' until purged"
	if versions >= 0 {
		note += fmt.Sprintf("; %d version(s) kept", versions)
	}
	if n := len(dependents); n > 0 {
		shown := dependents
		if n > 5 {
			shown = dependents[:5]
		}
		note += fmt.Sprintf("; %d dependent secret(s) lose this dependency until restored: %s", n, strings.Join(shown, ", "))
		if n > 5 {
			note += fmt.Sprintf(" and %d more", n-5)
		}
	}
	return note + ")"
}

// LogAuthLogin writes an auth.login audit event.
func (c *KeyorixCore) LogAuthLogin(ctx context.Context, userID uint, username, ip, ua string) {
	uid := userID
	c.writeAuditEventFull(ctx, "auth.login", &uid, nil, nil, ip,
		fmt.Sprintf("User %s logged in", username))
}

// LogAuthFailure writes an auth.login_failed audit event (Success=false).
func (c *KeyorixCore) LogAuthFailure(ctx context.Context, username, ip string) {
	c.writeAuditEventFailed(ctx, "auth.login_failed", nil, nil, ip,
		fmt.Sprintf("Failed login attempt for username: %s", username))
}

// LogAuthLogout writes an auth.logout audit event.
func (c *KeyorixCore) LogAuthLogout(ctx context.Context, userID uint, username, ip, ua string) {
	uid := userID
	c.writeAuditEventFull(ctx, "auth.logout", &uid, nil, nil, ip,
		fmt.Sprintf("User %s logged out", username))
}

// LookupSessionUser returns the userID and username for a session token.
func (c *KeyorixCore) LookupSessionUser(ctx context.Context, token string) (userID uint, username string) {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return 0, ""
	}
	user, err := c.storage.GetUser(ctx, session.UserID)
	if err != nil {
		return session.UserID, ""
	}
	return user.ID, user.Username
}
