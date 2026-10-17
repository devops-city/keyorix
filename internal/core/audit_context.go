// audit_context.go — propagation of impersonation and machine-actor
// attribution through context.
//
// When an admin acts inside an impersonation session, every audit event written
// during that session must record who really acted. The auth middleware tags the
// request context with the initiating admin's ID; writeAuditEventFull reads it
// and stamps ImpersonatedBy/ActingAs/Impersonation on the row. Because audit
// writes happen in detached goroutines (context.Background()), handlers use
// DetachedAuditContext to carry the tag past request cancellation.
//
// G80 #1530: the same mechanism, mirrored, closes a sibling gap. ActorType
// already distinguished a machine caller from a human one, but nothing carried
// WHICH machine identity — audit.UserID is nil for actorID==0 (every machine
// caller, by construction: middleware/auth.go's UserContext.UserID is 0 for
// any machine token), so a machine-attributable mutation produced a row
// correctly tagged ActorType="machine_identity" but with no identity to go
// with it. WithMachineActor/machineActorFromContext follow WithImpersonation's
// exact shape (not a new pattern) because that one is the working case of this
// same problem, already threaded through context and already stamped
// centrally in the writers -- copying a mechanism that demonstrably works is
// not the same claim as "matches existing precedent" when the precedent is
// itself the defect.
package core

import (
	"context"
	"strings"
	"sync"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/logging"
)

// Actor types stamped on every audit event (ADR-023). They distinguish a human
// user from a non-human machine identity so the audit view can segment and
// filter the two.
const (
	ActorTypeUser    = "user"
	ActorTypeMachine = "machine_identity"
	ActorTypeSystem  = "system"
)

type impersonationKey struct{}

type actorTypeKey struct{}

type machineActorKey struct{}

type auditActorKey struct{}

// WithActorType tags ctx with the principal kind for the current request
// (ActorTypeUser/ActorTypeMachine/ActorTypeSystem). The auth middleware sets it
// per request; writeAuditEvent* reads it and stamps ActorType on the row. An
// empty actorType is treated as "no tag" (the writer defaults to user).
func WithActorType(ctx context.Context, actorType string) context.Context {
	if actorType == "" {
		return ctx
	}
	return context.WithValue(ctx, actorTypeKey{}, actorType)
}

// actorTypeFromContext returns the tagged actor type, defaulting to
// ActorTypeUser when the context carries no tag.
func actorTypeFromContext(ctx context.Context) string {
	if t, ok := ctx.Value(actorTypeKey{}).(string); ok && t != "" {
		return t
	}
	return ActorTypeUser
}

// WithMachineActor tags ctx with the machine identity ID authenticated for
// the current request (ADR-030). A zero machineID is treated as "no machine
// actor" -- same shape as WithImpersonation. The auth middleware sets this
// alongside WithActorType(ctx, ActorTypeMachine); writeAuditEvent* reads it
// and stamps MachineIdentityID on the row, so a machine-attributable mutation
// records WHICH machine, not just that a machine did it.
func WithMachineActor(ctx context.Context, machineID uint) context.Context {
	if machineID == 0 {
		return ctx
	}
	return context.WithValue(ctx, machineActorKey{}, machineID)
}

// machineActorFromContext returns the tagged machine identity ID and whether
// the current context carries one.
func machineActorFromContext(ctx context.Context) (uint, bool) {
	machineID, ok := ctx.Value(machineActorKey{}).(uint)
	return machineID, ok && machineID != 0
}

// WithAuditActor tags ctx with the human caller ID that explicitly triggered
// the current operation (PR #2249 coordinator review: the /admin/jobs
// on-demand triggers -- anomaly-alerts, rotation/expiry/token-expiry
// reminders, role-expiry-check, check-read-quotas, run-alert-escalation,
// record-hygiene-snapshot, suspend-inactive-users -- share their core
// function with a background scheduler that has no caller at all, so those
// functions can't take an actor as a hard parameter; a zero-value default
// would make every manual trigger indistinguishable from the scheduler in
// the audit trail). The admin-jobs HTTP handlers tag ctx with the
// authenticated caller before invoking the shared core function; the
// scheduler invokes it with a plain, untagged context, so its own runs
// legitimately report no actor. A zero userID is treated as "no actor",
// same shape as WithMachineActor/WithImpersonation.
func WithAuditActor(ctx context.Context, userID uint) context.Context {
	if userID == 0 {
		return ctx
	}
	return context.WithValue(ctx, auditActorKey{}, userID)
}

// auditActorFromContext returns the tagged caller ID and whether ctx carries
// one -- see WithAuditActor.
func auditActorFromContext(ctx context.Context) (uint, bool) {
	userID, ok := ctx.Value(auditActorKey{}).(uint)
	return userID, ok && userID != 0
}

// adminJobAuditContext returns the (ctx, userID) pair an /admin/jobs "ran"
// summary event should audit with: if WithAuditActor tagged ctx with a real
// caller (an admin's on-demand trigger), returns that caller's ID unmodified;
// otherwise (the background scheduler's own untagged runs) tags ctx
// ActorTypeSystem and returns nil -- the same distinction SendComplianceDigest
// (compliance_digest.go) already makes for its own no-channel-configured
// event, extended to every other /admin/jobs summary event (coordinator
// review, PR #2249) so a scheduled run is never left defaulting to the
// generic "user" ActorType merely because no caller happened to tag it.
func adminJobAuditContext(ctx context.Context) (context.Context, *uint) {
	if userID, ok := auditActorFromContext(ctx); ok {
		return ctx, &userID
	}
	return WithActorType(ctx, ActorTypeSystem), nil
}

// WithImpersonation tags ctx with the admin user ID that initiated the current
// impersonation session. A zero adminID is treated as "no impersonation".
func WithImpersonation(ctx context.Context, adminID uint) context.Context {
	if adminID == 0 {
		return ctx
	}
	return context.WithValue(ctx, impersonationKey{}, adminID)
}

// impersonatorFromContext returns the initiating admin ID and whether the
// current context is an impersonation context.
func impersonatorFromContext(ctx context.Context) (uint, bool) {
	adminID, ok := ctx.Value(impersonationKey{}).(uint)
	return adminID, ok && adminID != 0
}

// DetachedAuditContext returns a background-rooted context that preserves any
// impersonation, actor-type, and machine-actor tag from parent. Audit writes
// run in goroutines that must outlive the request, but still need to record
// the impersonating admin / acting machine identity -- a detached write that
// dropped the machine-actor tag would silently reintroduce #1530's gap for
// every fire-and-forget audit call.
func DetachedAuditContext(parent context.Context) context.Context {
	ctx := context.Background() // NOSONAR
	if adminID, ok := impersonatorFromContext(parent); ok {
		ctx = WithImpersonation(ctx, adminID)
	}
	if t, ok := parent.Value(actorTypeKey{}).(string); ok && t != "" {
		ctx = WithActorType(ctx, t)
	}
	if machineID, ok := machineActorFromContext(parent); ok {
		ctx = WithMachineActor(ctx, machineID)
	}
	if origin, ok := clientOriginFromContext(parent); ok {
		ctx = WithClientOrigin(ctx, origin)
	}
	// Keep the request's log fields (request id, principal type, route) so a log line
	// written by a detached audit write still correlates with the request that caused it.
	if h := logging.HolderFrom(parent); h != nil {
		ctx = logging.WithExistingHolder(ctx, h)
	}
	return ctx
}

// ClientOriginHeader is the request header a client may set to say which tool, and which
// source item, a write came from — e.g. keyorix-migrate sends
// "keyorix-migrate/<version> source=vault:secret/team-a/db#password" (#2545). The value is
// CLIENT-ASSERTED: any caller can send any text, so it is recorded only as a labelled note in
// the audit event's description. It is never used to decide ActorType, attribution, or any
// authorization — those still come solely from the authenticated principal.
const ClientOriginHeader = "X-Keyorix-Client-Origin"

// maxClientOriginRunes caps the recorded origin so a client cannot bloat audit rows.
const maxClientOriginRunes = 256

type clientOriginKey struct{}

// WithClientOrigin tags ctx with a client-asserted origin (see ClientOriginHeader). The value
// is sanitized (control characters dropped, same as every audit description) and capped at
// maxClientOriginRunes; an empty result leaves ctx untouched.
func WithClientOrigin(ctx context.Context, origin string) context.Context {
	origin = strings.TrimSpace(sanitizeAuditText(origin))
	if r := []rune(origin); len(r) > maxClientOriginRunes {
		origin = string(r[:maxClientOriginRunes]) + "…"
	}
	if origin == "" {
		return ctx
	}
	return context.WithValue(ctx, clientOriginKey{}, origin)
}

func clientOriginFromContext(ctx context.Context) (string, bool) {
	origin, ok := ctx.Value(clientOriginKey{}).(string)
	return origin, ok && origin != ""
}

// withClientOriginNote appends the client-asserted origin, if ctx carries one, to an audit
// description — labelled as client-asserted so no reader mistakes it for verified attribution.
func withClientOriginNote(ctx context.Context, description string) string {
	origin, ok := clientOriginFromContext(ctx)
	if !ok {
		return description
	}
	return description + " [client-asserted origin: " + origin + "]"
}

// goSafe runs fn in a detached goroutine with panic recovery. Several core
// methods spawn "fire and forget" goroutines for post-response side effects
// (audit logging of secret reads/writes, password-reset link provisioning)
// so the caller isn't blocked on that I/O — but those goroutines run on the
// hottest request paths (every secret read/write, and — for
// RequestPasswordReset — even an unauthenticated one) and are NOT covered by
// the HTTP server's per-request recovery middleware, which only guards the
// goroutine actually serving the request. A panic in a bare `go
// c.LogSecret...(...)` here (a future nil-deref, malformed diff content,
// etc.) would crash the entire process for every connected tenant (backlog
// #481, an unrecovered-coverage gap in the #243 fix). goSafe closes that gap:
// any panic in fn is recovered and logged instead of taking the server down.
// This mirrors server/http/handlers' goSafe, duplicated here because that
// package cannot be imported from internal/core -- both delegate their
// actual recover/log/metric logic to besteffort.RunRecover (package
// besteffort) so that logic itself has one home instead of three.
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
		defer besteffort.RunRecover("core.goSafe")()
		fn()
	})
}
