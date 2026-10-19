// break_glass.go — self-service emergency access ("break-glass"). When enabled, a
// user can immediately self-grant a configured emergency role, time-bound (it
// auto-expires via the JIT mechanism), with a mandatory written justification. The
// activation is loudly audited (break_glass.activated) and fans out an alert to the
// project's admins, and is recorded as a queryable BreakGlassActivation for
// post-hoc review (NIS2/DORA incident response). Deliberately un-gated by RBAC —
// the whole point is access the user does NOT already have — so the controls are:
// it must be enabled, the activator must be a member of the project (a project-scoped
// role, not merely the global baseline), the emergency role must be contained (it may
// not carry roles.assign, so an auto-expiring grant cannot mint permanent access),
// every use is justified + audited + alerted, and it expires.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Break-glass review sentinel errors (#2461 round 2): ReviewBreakGlass wraps
// these into its returned error alongside the i18n-translated, human-facing
// message, so a caller can classify the refusal via errors.Is regardless of
// the server's configured locale. Matching the English TEXT of an
// i18n.T(...)-produced message (the previous approach) silently stops working
// the moment the deployment's locale isn't English.
var (
	ErrBreakGlassSelfReview             = errors.New("break-glass: self-review refused")
	ErrBreakGlassUnattributableReviewer = errors.New("break-glass: unattributable reviewer refused")
	ErrBreakGlassStillActive            = errors.New("break-glass: activation still active")
	// ErrBreakGlassInvalidNote covers both review-note length bounds (too
	// short and too long).
	ErrBreakGlassInvalidNote = errors.New("break-glass: invalid review note")
)

// Sentinels for ActivateBreakGlass / RevokeBreakGlass refusals (#2905). Their
// handlers (HTTP and gRPC) used to classify core's error by matching
// strings.Contains over err.Error(), which embeds i18n.T(...) output; under a
// locale that translates those prefixes a deliberate 403/404 silently fell
// through to 500. Callers now use errors.Is.
//
// Revoke's not-found and not-active refusals are storage.ErrBreakGlassNotFound
// and storage.ErrBreakGlassNotActive (already the sentinels the review path
// uses); only the refusals with no storage-level equivalent are defined here.
var (
	// ErrBreakGlassDisabled: self-service emergency access is not enabled.
	ErrBreakGlassDisabled = errors.New("break-glass: not enabled")
	// ErrBreakGlassNotProjectMember: the activator is not a member of the project.
	ErrBreakGlassNotProjectMember = errors.New("break-glass: caller is not a project member")
	// ErrBreakGlassInvalidRequest: the request itself is malformed (missing
	// project/user, short justification, bad TTL) or names no usable emergency role.
	ErrBreakGlassInvalidRequest = errors.New("break-glass: invalid request")
)

// breakGlassRefusal is an error whose user-visible text is fixed (the
// i18n-translated, human-facing message) and whose classification is carried
// separately as sentinels reachable through errors.Is/As. Wrapping a sentinel
// with fmt.Errorf("%w") instead would append the sentinel's own text to the
// message, changing what users see.
type breakGlassRefusal struct {
	msg   string
	kinds []error
}

func (e *breakGlassRefusal) Error() string   { return e.msg }
func (e *breakGlassRefusal) Unwrap() []error { return e.kinds }

// refuseBreakGlass returns an error reading exactly msg that matches every
// non-nil kind under errors.Is.
func refuseBreakGlass(msg string, kinds ...error) error {
	live := make([]error, 0, len(kinds))
	for _, k := range kinds {
		if k != nil {
			live = append(live, k)
		}
	}
	return &breakGlassRefusal{msg: msg, kinds: live}
}

// minBreakGlassJustificationLen is the minimum length, after trimming
// surrounding whitespace, a break-glass justification must have. This becomes
// a PERMANENT audit-trail record of why a real security incident required
// emergency access, so a bare non-empty check (a single space would pass)
// isn't enough — require something that at least resembles a genuine reason.
const minBreakGlassJustificationLen = 10

// Break-glass states and audit events.
const (
	BreakGlassActive  = "active"
	BreakGlassExpired = "expired"
	BreakGlassRevoked = "revoked"

	EventBreakGlassActivated      = "break_glass.activated"       // #nosec G101 -- audit event type, not a credential
	EventBreakGlassRevoked        = "break_glass.revoked"         // #nosec G101 -- audit event type, not a credential
	EventBreakGlassNotifyPanicked = "break_glass.notify_panicked" // #nosec G101 -- audit event type, not a credential
	EventBreakGlassReviewed       = "break_glass.reviewed"        // #nosec G101 -- audit event type, not a credential
	// EventBreakGlassReviewOverdue is emitted once per RunBreakGlassReviewReminder
	// pass that finds at least one activation unreviewed past the review window
	// (#2461) -- the permanent, auditable half of ADR-112's posture deviation,
	// alongside the posture report's own count.
	EventBreakGlassReviewOverdue = "break_glass.review_overdue" // #nosec G101 -- audit event type, not a credential
)

// errBreakGlassDisabled is the reason ActivateBreakGlass gives while
// break_glass.enabled is false (the default).
const errBreakGlassDisabled = "break-glass is not enabled on this server; set break_glass.enabled: true in keyorix.yaml and restart"

// minBreakGlassReviewNoteLen mirrors minBreakGlassJustificationLen's reasoning
// (above) for the review note (ADR-112 §3, break-glass review item 5): this
// becomes the PERMANENT audit-trail record of what the reviewer actually
// checked, so a bare non-empty string isn't enough.
const minBreakGlassReviewNoteLen = 10

// maxBreakGlassReviewNoteLen caps the review note (#2461 round 2): it is a
// free-text field that lands permanently in the audit trail, so an unbounded
// length would let a reviewer -- or anyone able to reach this path -- pack an
// arbitrarily large payload into storage and into every audit-log reader/export.
const maxBreakGlassReviewNoteLen = 2000

// BreakGlassPolicy is the deployment configuration for emergency access, wired from
// config at startup via SetBreakGlassPolicy.
type BreakGlassPolicy struct {
	Enabled       bool
	EmergencyRole string
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
	// ReviewWindow is how long an activation may go unreviewed before the
	// compliance posture report lists it as a deviation (ADR-112 §3, item 4)
	// and the periodic reminder logs it. Wired from
	// config.BreakGlassConfig.GetReviewWindow() at startup; zero falls back to
	// defaultBreakGlassReviewWindow, so a core built without SetBreakGlassPolicy
	// (every unit test, and any embedder) still reports deviations rather than
	// treating a zero window as "everything is overdue".
	ReviewWindow time.Duration
}

// defaultBreakGlassReviewWindow mirrors config.BreakGlassConfig's own 72h
// default. Duplicated rather than imported because internal/core must not
// depend on internal/config (ADR-109); kept honest by
// TestBreakGlassReviewWindowDefaultMatchesConfig.
const defaultBreakGlassReviewWindow = 72 * time.Hour

// breakGlassReviewWindow is the effective review window: the configured value,
// or the 72h default when unset. Never returns zero -- a zero window would
// make c.now().Add(-0) the cutoff and report every activation ever as overdue.
func (c *KeyorixCore) breakGlassReviewWindow() time.Duration {
	if c.breakGlassPolicy.ReviewWindow > 0 {
		return c.breakGlassPolicy.ReviewWindow
	}
	return defaultBreakGlassReviewWindow
}

// SetBreakGlassPolicy configures self-service emergency access (default: disabled).
func (c *KeyorixCore) SetBreakGlassPolicy(p BreakGlassPolicy) {
	c.breakGlassPolicy = p
}

// BreakGlassDisabledCode is the machine-readable code of the refusal ActivateBreakGlass
// gives while break_glass.enabled is false: the REST error field and the gRPC
// ErrorInfo reason. Clients switch on it instead of on the (localised) message.
const BreakGlassDisabledCode = "BreakGlassDisabled"

// defaultBreakGlassTTL is the grant lifetime when the policy sets none.
const defaultBreakGlassTTL = 4 * time.Hour

// breakGlassTTLs returns the effective default grant lifetime and the ceiling a requested
// lifetime is capped at. Always bound: when MaxTTL is unconfigured the ceiling falls back
// to the default TTL, so an override can only ever SHORTEN the grant, never exceed the
// default. The core enforces "break-glass is time-bound" itself rather than trusting the
// config layer to have supplied a ceiling; a policy built with MaxTTL=0 (e.g. by a future
// or non-startup caller) can't yield an unbounded emergency grant.
func (c *KeyorixCore) breakGlassTTLs() (defaultTTL, ceiling time.Duration) {
	defaultTTL = c.breakGlassPolicy.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultBreakGlassTTL
	}
	ceiling = c.breakGlassPolicy.MaxTTL
	if ceiling <= 0 {
		ceiling = defaultTTL
	}
	return defaultTTL, ceiling
}

// BreakGlassSettings is what a project member may learn about the server's break-glass
// limits so a client can offer only lifetimes the server will honour. Deployment limits
// only: no credential, no admin-only data (the emergency role's name is also on every
// activation the member gets back).
type BreakGlassSettings struct {
	Enabled       bool
	EmergencyRole string
	DefaultTTL    time.Duration
	// MaxTTL is the effective ceiling: a longer requested lifetime is capped to it.
	MaxTTL time.Duration
}

// BreakGlassSettings reports the effective policy. It does no authorization: callers
// return it only alongside a list answer ListBreakGlassActivationsForCaller allowed.
func (c *KeyorixCore) BreakGlassSettings() BreakGlassSettings {
	def, ceiling := c.breakGlassTTLs()
	if def > ceiling {
		// A default above the ceiling is capped at activation; report what is granted.
		def = ceiling
	}
	return BreakGlassSettings{
		Enabled:       c.breakGlassPolicy.Enabled,
		EmergencyRole: c.breakGlassPolicy.EmergencyRole,
		DefaultTTL:    def,
		MaxTTL:        ceiling,
	}
}

// ActivateBreakGlass immediately grants the requesting user the configured emergency
// role at the project scope, time-bound (default or a capped requested TTL), records
// the justified activation, audits it loudly, and alerts the project's admins.
// userID is the activating (self) user; ttlOverride is an optional Go duration.
func (c *KeyorixCore) ActivateBreakGlass(ctx context.Context, projectID, userID uint, justification, ttlOverride string) (*models.BreakGlassActivation, error) { // NOSONAR -- cognitive complexity 28, suppress go:S3776
	// PAT-GUARD-2: a restricted PAT may not escalate its owner. Checked before
	// anything else so the refusal does not depend on configuration or membership.
	if patRestrictionFromContext(ctx) != nil {
		return nil, ErrRestrictedPATCannotBreakGlass
	}
	if !c.breakGlassPolicy.Enabled {
		// Disabled is the secure default, but "permission denied" alone looks like
		// a role problem. Say it is off and which key turns it on (#2943). The
		// "permission denied" prefix keeps the HTTP mapping (403) in
		// server/http/handlers/break_glass.go.
		// refuseBreakGlass keeps the typed ErrBreakGlassDisabled kind that the
		// HTTP and gRPC mappings match with errors.Is.
		return nil, refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorPermissionDenied", nil), errBreakGlassDisabled), ErrBreakGlassDisabled)
	}
	if projectID == 0 || userID == 0 {
		return nil, refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and user are required"), ErrBreakGlassInvalidRequest)
	}
	justification = strings.TrimSpace(justification)
	if len(justification) < minBreakGlassJustificationLen {
		return nil, refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil),
			fmt.Sprintf("a justification of at least %d characters is required for emergency access", minBreakGlassJustificationLen)),
			ErrBreakGlassInvalidRequest)
	}
	// Only a user already affiliated with the project may break-glass it. Eligibility
	// must require a role scoped to THIS project (project_id = P), directly or via a
	// group — NOT merely a global/install-wide role. The previous check used
	// GetUserRoleIDsAt, which matches project_id = 0 OR P, so the install baseline
	// (system_viewer, granted globally to every SSO/JIT user) counted as membership and
	// let any authenticated user self-grant the emergency role on ANY project. IsProjectMember
	// excludes global roles, so a user scoped only globally (or to a different project) is refused.
	affiliated, merr := c.IsProjectMember(ctx, userID, projectID)
	if merr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), merr)
	}
	if !affiliated {
		return nil, refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "break-glass is available only to members of the project"), ErrBreakGlassNotProjectMember)
	}
	// Note: IsProjectMember has no minimum-tenure requirement — a user added
	// to the project seconds ago can immediately self-activate break-glass.
	// A configurable join-date cooldown would close this gap.
	// Refuse a new activation while the user already holds an active, unexpired one on
	// this project — otherwise the time-bound grant becomes indefinitely renewable.
	bgNow := c.now()
	existing, lerr := c.storage.ListBreakGlassActivations(ctx, projectID)
	if lerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), lerr)
	}
	for _, a := range existing {
		if a.UserID == userID && a.State == BreakGlassActive && a.ExpiresAt != nil && a.ExpiresAt.After(bgNow) {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you already have an active break-glass grant on this project; revoke it before activating again")
		}
	}
	if c.breakGlassPolicy.EmergencyRole == "" {
		return nil, refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "no emergency role is configured"), ErrBreakGlassInvalidRequest)
	}
	role, err := c.storage.GetRoleByName(ctx, c.breakGlassPolicy.EmergencyRole)
	if err != nil {
		// Only a genuine "no such role" is a client-side misconfiguration. Any other
		// error (DB failure) is internal: no sentinel, no driver text, no role name.
		if !errors.Is(err, storage.ErrRoleNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		return nil, refuseBreakGlass(fmt.Sprintf("emergency role %q not found: %v", c.breakGlassPolicy.EmergencyRole, err), ErrBreakGlassInvalidRequest, err)
	}
	// Refuse an install-wide admin role as the emergency role: break-glass grants at a
	// project scope and must not be a vehicle for install-wide super-user.
	// #2496: resolved from the structural admin-bypass flag, so a flag-carrying
	// role named outside the retired fixed list (project_admin included — which
	// the roles.assign check below names explicitly as unacceptable here) is
	// refused too. Fails closed on a resolution error.
	adminIDs, aerr := c.adminBypassRoleIDSet(ctx)
	if aerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), aerr)
	}
	if adminIDs[role.ID] {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the configured emergency role grants install-wide administration and cannot be used for break-glass")
	}
	// Refuse an emergency role that can ASSIGN ROLES or issue credentials. The whole
	// security model of break-glass is "it auto-expires", but a time-bound role carrying
	// roles.assign lets the holder mint a PERMANENT grant (or a long-lived machine token)
	// during the window that outlives it — defeating expiry entirely. The emergency role
	// must be powerful-but-contained (e.g. project_developer: read/write/delete secrets,
	// no role administration), NOT project_admin. roles.assign also gates machine-token
	// issuance, so this one check closes both persistence vectors.
	if hasAssign, perr := c.storage.RoleSetHasPermission(ctx, []uint{role.ID}, "roles.assign"); perr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), perr)
	} else if hasAssign {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the configured emergency role can assign roles or issue credentials and cannot be used for break-glass (it would let an emergency grant create permanent access); configure a contained role such as project_developer")
	}

	defaultTTL, ceiling := c.breakGlassTTLs()
	ttl := defaultTTL
	if ttlOverride != "" {
		d, perr := time.ParseDuration(ttlOverride)
		if perr != nil || d <= 0 {
			return nil, refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "ttl must be a positive Go duration (e.g. 2h)"), ErrBreakGlassInvalidRequest)
		}
		ttl = d
	}
	// ceiling (breakGlassTTLs) always bounds the grant: an override can only be capped.
	if ttl > ceiling {
		ttl = ceiling // cap a requested TTL at the effective ceiling
	}

	now := c.now()
	expiresAt := now.Add(ttl)
	scope := storage.Scope{ProjectID: projectID}

	// #1653 reopened: reconcile the user's own TTL-lapsed 'active' row in this
	// project (if one exists) BEFORE creating a new one, so a genuinely-expired
	// grant nobody has revisited since doesn't hold the partial unique index's
	// one-active-slot forever — the "backward drift blocks a NEW activation"
	// mirror of the "forward drift blocks revoke" bug that same finding
	// produced. Best-effort is wrong here: if this fails, don't silently
	// proceed to an INSERT that may spuriously reject a genuinely-eligible
	// reactivation with a misleading "already active" error.
	if err := c.storage.ReconcileExpiredBreakGlassActivation(ctx, projectID, userID); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// #2722: the record insert and the role grant are serialized against a
	// concurrent revoke by the SAME named lock RevokeBreakGlassActivationAtomic
	// takes, projectAdminGuardLockKey(projectID). They are two separate storage
	// operations with no shared transaction, and the revoke tolerates
	// ErrRoleNotAssigned ("already gone — proceed to reconcile the record"), so a
	// revoke landing between them removed nothing, transitioned the record to
	// `revoked`, audited success, and then the activation granted the emergency
	// role anyway. End state: a self-granted, SoD-bypassing role live for its full
	// TTL while the record every reviewer and the UI reads says revoked — and
	// because the admin's revoke reported success, nobody revisits it.
	// ReconcileExpired only touches `active` rows, so it never cleans it up, and
	// the freed unique-index slot lets the user activate a second time.
	//
	// Why the lock and NOT lockLiveParent, which is how every other fix in this
	// class is built: lockLiveParent requires the delete side to row-lock the
	// PARENT before it touches the children (its own doc comment says so
	// explicitly, and names this exact exclusion). The revoke does the opposite —
	// tx.RemoveRole runs BEFORE tx.RevokeBreakGlassActivation — so a FOR SHARE on
	// the activation row would be read AFTER the revoke had already looked for and
	// not found the grant, and the race would survive the fix. #2722's own
	// suggested "lockLiveParent-style" direction is unsound for that reason;
	// serializing on the lock the revoke already holds is not.
	//
	// Lock-order safety: this is a single acquisition of family rank 3
	// (project-admin-guard) with nothing nested inside it —
	// assignUserRoleWithExpirySkipSoD calls storage.AssignRoleWithExpiry directly
	// and takes no named lock, deliberately (see its doc comment on skipping the
	// SoD gate). No inversion against storage.NamedLockOrder.
	var activation *models.BreakGlassActivation
	if lockErr := c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(projectID), func(ctx context.Context) error {
		var err error
		activation, err = c.activateBreakGlassLocked(ctx, userID, projectID, role, justification, now, expiresAt, scope)
		return err
	}); lockErr != nil {
		return nil, lockErr
	}

	// The grant committed together with its role.assigned and
	// break_glass.activated rows (activateBreakGlassLocked), so a notification failure here
	// is a DETECTION-LATENCY gap, not a control failure — don't fail the activation on
	// it. But silently swallowing it would defeat break-glass's "loud by design" intent
	// if the notification pipeline itself is down, so surface it loudly (#166): a
	// SECURITY-prefixed log line, matching the convention emitAudit already uses for a
	// failed audit write, so an operational alerting pipeline watching logs still pages.
	if nerr := c.notifyBreakGlassAdmins(ctx, userID, projectID, role.Name, expiresAt); nerr != nil {
		log.Printf("SECURITY: break-glass activation %d (project %d, user %d): admin notification failed: %v",
			activation.ID, projectID, userID, nerr)
	}
	return activation, nil
}

// activateBreakGlassLocked is ActivateBreakGlass's insert-then-grant pair, split
// out so the whole pair runs under one projectAdminGuardLockKey acquisition
// (#2722). The audit and the admin notification deliberately stay OUTSIDE the
// lock in the caller: both happen after the grant is committed, and holding a
// cross-replica advisory lock across a notification fan-out would widen the
// window every other project-admin operation waits on, for no safety gain.
func (c *KeyorixCore) activateBreakGlassLocked(
	ctx context.Context,
	userID, projectID uint,
	role *models.Role,
	justification string,
	now, expiresAt time.Time,
	scope storage.Scope,
) (*models.BreakGlassActivation, error) {
	// Create the activation record FIRST, before granting anything. This is the
	// actual race gate: a partial unique index on (project_id, user_id) WHERE
	// state='active' (ensureBreakGlassActiveIndex) makes the insert itself the source
	// of truth for "at most one active activation", closing the gap in the
	// list-and-scan check above — under a race, two concurrent callers could both pass
	// that check before either inserted. Creating the record before the role grant
	// (rather than after, as before) also means a losing racer here never grants
	// itself the emergency role at all.
	//
	// #3109: the record insert and the role grant run in ONE transaction (the
	// same shape RevokeBreakGlassActivationAtomic uses for its two writes), so a
	// failed grant rolls the record back with it. The previous compensation (flip
	// the already-committed record to revoked afterwards) left a visible
	// 'active' row with no role for the window between the two commits, left a
	// 'revoked' row behind an error, and relied on a second write that could
	// itself fail ("MANUAL CLEANUP REQUIRED", user locked out of retrying by the
	// partial unique index). Nothing here is visible or notified until the
	// transaction commits. AUDIT-TX-2: the role.assigned and
	// break_glass.activated rows are the last statements of that same
	// transaction, so an emergency elevation never commits unaudited (an
	// activation is a grant, not a revocation: it fails closed on audit).
	//
	// Self-granted: actor == the activating user. Time-bound so it auto-expires.
	// Deliberately calls tx.AssignRoleWithExpiry directly (as
	// assignUserRoleWithExpirySkipSoD does), not AssignUserRoleWithExpiry:
	// break-glass is un-gated by design (the whole point is access the user does NOT
	// already have), so it must not be refused by the #419 separation-of-duties
	// preventive gate during a genuine incident — see that function's doc comment
	// (jit_access.go).
	var activation *models.BreakGlassActivation
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		a, err := tx.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
			ProjectID:     projectID,
			UserID:        userID,
			RoleID:        role.ID,
			RoleName:      role.Name,
			Justification: justification,
			State:         BreakGlassActive,
			ExpiresAt:     &expiresAt,
			CreatedAt:     now,
		})
		if err != nil {
			if errors.Is(err, storage.ErrBreakGlassAlreadyActive) {
				return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you already have an active break-glass grant on this project; revoke it before activating again")
			}
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if err := tx.AssignRoleWithExpiry(ctx, userID, role.ID, scope, expiresAt); err != nil {
			return fmt.Errorf("failed to grant emergency role: %s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.LogRoleAssignedOn(ctx, tgt, userID, userID, role.ID, scope)
		c.auditProjectScopedOn(ctx, tgt, EventBreakGlassActivated, userID, projectID,
			fmt.Sprintf("break-glass: user %d self-granted %q until %s — %s",
				userID, role.Name, expiresAt.UTC().Format(time.RFC3339), justification))
		activation = a
		return nil
	}); err != nil {
		return nil, err
	}
	return activation, nil
}

// ListBreakGlassActivations returns the project's activations, newest first. An
// active record whose expiry has passed is reported as expired — a pure,
// watermark-clamped (#1651) read-time projection the storage layer computes
// (LocalStorage.ListBreakGlassActivations), never persisted from here.
//
// #1653 reopened (2026-09-02): this function used to ALSO persist that
// transition on every call — a read path writing access-control-adjacent
// state. #1653's original deferral rested entirely on the premise that State
// is "a reporting label... not an independent access-control decision point";
// nothing asserted that, and it was false: RevokeBreakGlass's own guard (and
// its remote-storage-proxy mirror) read State to decide whether to even
// attempt the real de-authorization action, so a wall-clock hiccup in THIS
// function's old write could silently block a legitimate emergency revoke —
// and, the mirror direction, could leave a genuinely-expired row occupying
// the one-active-slot-per-(project,user) index forever, blocking a legitimate
// new activation. The fix moved the one place a TTL-lapse transition is ever
// persisted into ActivateBreakGlass itself (a mutating operation, immediately
// before its own INSERT) via ReconcileExpiredBreakGlassActivation, and made
// RevokeBreakGlass's guard depend only on whether the row has already been
// explicitly revoked — never on a clock-derived projection. See
// docs/security-review-2026-09.md's "Update" section for the full account.
func (c *KeyorixCore) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	rows, err := c.storage.ListBreakGlassActivations(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// What ListBreakGlassActivationsForCaller returned (BREAKGLASS-OWN-1): the whole
// project's activations, or only the caller's own.
const (
	BreakGlassListScopeProject = "project"
	BreakGlassListScopeOwn     = "own"
)

// ErrBreakGlassListForbidden: the caller may list neither the project's
// activations nor its own. Both transports answer it with the same refusal the
// old roles.read route gate gave (HTTP 403 "Insufficient permissions", gRPC
// PermissionDenied "insufficient permissions").
var ErrBreakGlassListForbidden = errors.New("break-glass: listing not permitted")

// ListBreakGlassActivationsForCaller is the one authorization decision behind
// GET /projects/{id}/break-glass and BreakGlassService.ListBreakGlassActivations
// (BREAKGLASS-OWN-1, Andrei 2026-10-13: a member lists their OWN activations):
//
//   - roles.read at the project (AuthorizePrincipal, so PAT restriction, admin
//     bypass and machine roles apply exactly as at the old route gate): every
//     activation of the project, scope "project". Unchanged.
//   - otherwise a USER (never a machine identity, which keeps today's refusal)
//     who is a member of the project NOW (IsProjectMember, the definition
//     activation uses) and whose PAT restriction, if any, allows roles.read at the
//     project: only the rows whose UserID is the caller, scope "own", with the same
//     fields. Nothing about anyone else's rows (not even how many) reaches the answer.
//   - anything else, including a failed authorization or membership lookup (fail
//     closed, never a silent downgrade to the own view): ErrBreakGlassListForbidden.
//
// Membership keeps a non-member's answer exactly what it was before: the same 403
// for every project id, existing or not. Without it a non-member would reach the
// transport's MFA check, whose ProjectMFARequired answer (only for a project that
// exists and requires MFA) would tell them which projects exist and how they are
// configured.
//
// userID is the authenticated user's id. The own view requires principalID ==
// userID so a context whose actor kind and principal disagree can never filter by
// someone else's id. The per-project MFA policy (ADR-037) is a transport check
// and stays with the caller, applied to both views.
//
// No audit event, for either view: listing was never audited, and this keeps it so.
func (c *KeyorixCore) ListBreakGlassActivationsForCaller(ctx context.Context, actorType string, principalID, userID, projectID uint) ([]*models.BreakGlassActivation, string, error) {
	if projectID == 0 {
		return nil, "", refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required"), ErrBreakGlassInvalidRequest)
	}
	scope := Scope{ProjectID: projectID}
	allowed, err := c.AuthorizePrincipal(ctx, actorType, principalID, permRolesRead, scope)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBreakGlassListForbidden, err)
	}
	if allowed {
		rows, lerr := c.ListBreakGlassActivations(ctx, projectID)
		if lerr != nil {
			return nil, "", lerr
		}
		return rows, BreakGlassListScopeProject, nil
	}
	if actorType != ActorTypeUser || userID == 0 || principalID != userID {
		return nil, "", ErrBreakGlassListForbidden
	}
	// A restricted PAT sees its owner's rows only where it could have been granted
	// the project view: the same check AuthorizePrincipal made above, minus the role.
	if !patRestrictionFromContext(ctx).Allows(permRolesRead, scope) {
		return nil, "", ErrBreakGlassListForbidden
	}
	member, err := c.IsProjectMember(ctx, userID, projectID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBreakGlassListForbidden, err)
	}
	if !member {
		return nil, "", ErrBreakGlassListForbidden
	}
	rows, err := c.ListBreakGlassActivations(ctx, projectID)
	if err != nil {
		return nil, "", err
	}
	own := make([]*models.BreakGlassActivation, 0, len(rows))
	for _, a := range rows {
		if a != nil && a.UserID == userID && a.ProjectID == projectID {
			own = append(own, redactBreakGlassForOwnView(a))
		}
	}
	return own, BreakGlassListScopeOwn, nil
}

// redactBreakGlassForOwnView is the single place the own view (scope "own", a
// caller without roles.read) loses the admin-side fields (FIX-3184, Andrei
// 2026-10-13): the reviewer's note and identity, and who revoked it (user or
// machine identity). Both transports render the rows this function returns, so
// neither can leak what it removed; the scope that triggers it comes from
// ListBreakGlassActivationsForCaller's own authorization, never from the client.
//
// State, CreatedAt, ExpiresAt, Justification, RevokedAt and ReviewedAt stay:
// State == "revoked" / RevokedAt != nil say "revoked", ReviewedAt != nil says
// "reviewed". The fields are zeroed (json omitempty / unset proto optional), not
// replaced with placeholders. It returns a copy, never mutating the storage row.
// Any new reviewer/revoker identity or note field on BreakGlassActivation must be
// cleared here (TestBreakGlassOwnView_RedactsEveryAdminField fails otherwise).
func redactBreakGlassForOwnView(a *models.BreakGlassActivation) *models.BreakGlassActivation {
	cp := *a
	cp.ReviewNote = ""
	cp.ReviewedBy = 0
	cp.RevokedBy = 0
	cp.RevokedByMachineIdentityID = 0
	return &cp
}

// RevokeBreakGlass ends an active emergency grant early: removes the role assignment
// (best-effort — it may already have auto-expired) and marks the record revoked.
// actorID is the admin performing the revoke.
func (c *KeyorixCore) RevokeBreakGlass(ctx context.Context, actorID, actorMachineID, projectID, activationID uint) error {
	if projectID == 0 {
		return refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required"), ErrBreakGlassInvalidRequest)
	}
	activation, err := c.storage.GetBreakGlassActivation(ctx, activationID)
	if err != nil {
		// GetBreakGlassActivation wraps storage.ErrBreakGlassNotFound for a
		// missing row and nothing of the kind for a genuine failure, so %w
		// keeps that distinction: only the former is a 404.
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if activation.ProjectID != projectID {
		return refuseBreakGlass(i18n.T("ErrorNotFound", nil), storage.ErrBreakGlassNotFound)
	}
	// #1653 reopened: only an ALREADY-revoked activation refuses a revoke. A
	// TTL-lapsed (State == BreakGlassExpired, a read-time projection —
	// GetBreakGlassActivation's doc) row is still revocable: revoking it is
	// always harmless (the role grant it represents is independently governed
	// by #1651's watermark regardless of what this projection says), and a
	// caller must never be refused a legitimate revoke because of what a
	// clock-derived value happens to read at this instant. Fast-path guard
	// BEFORE touching the role grant; the conditional UPDATE below (accepting
	// active-OR-expired, RevokeBreakGlassActivation's own doc) is what protects
	// the STATE TRANSITION from a concurrent double-revoke race, not this check.
	if activation.State == BreakGlassRevoked {
		return refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "activation is not active"), storage.ErrBreakGlassNotActive)
	}
	if err := c.RevokeBreakGlassActivationAtomic(ctx, actorID, actorMachineID, activation, c.now()); err != nil {
		if errors.Is(err, storage.ErrBreakGlassNotActive) {
			return refuseBreakGlass(fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), "activation is not active"), storage.ErrBreakGlassNotActive)
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RevokeBreakGlassActivationAtomic performs the two storage mutations a
// break-glass revoke requires — removing the emergency role grant and marking
// the activation record revoked — inside ONE storage.WithTransaction, so a
// fault landing between them (including an "effect-then-error" storage fault,
// where RemoveRole's own DELETE lands but the call still reports failure)
// rolls back the whole thing instead of leaving a mix: role gone, activation
// still "active", nothing audited
// (docs/findings/2026-09-23-FINDING-breakglass-revoke-half-commit.md).
// Exported so both RevokeBreakGlass (this file, backing the human-facing REST
// and gRPC routes) and RevokeBreakGlassActivationProxy
// (server/http/handlers/break_glass_proxy.go — the /system raw-storage-
// primitive proxy, scheduled for deletion under ADR-108 Phase 6 but reachable
// today) share the identical fix instead of drifting the way the pre-fix
// versions of those two already had. Callers are responsible for their own
// authorization and state-guard (activation.State == BreakGlassRevoked)
// checks first — this function performs neither.
//
// RevokeBreakGlassActivationProxy always runs against LocalStorage, so it is
// fully covered by this fix.
//
// TOCTOU-1 sibling fix (rbac_management.go's RemoveUserRole had the identical
// bug): the last-project-admin guard's read+decide and the role removal must
// happen under the SAME WithNamedLock acquisition, or two concurrent revokes
// targeting two different project admins' emergency grants can each pass the
// guard before either write commits and both succeed, stripping the project
// of every roles.assign holder — exactly RemoveUserRole's bug, reproduced
// here independently because this function bypasses RemoveUserRole entirely
// (it calls tx.RemoveRole directly, to share ONE transaction with the
// activation-state update below). The transaction therefore runs INSIDE the
// WithNamedLock closure, not after it. This does not reintroduce the
// documented lock-ordering hazard (namedLockConnCtxKey's doc comment,
// local_named_lock.go): that hazard is specifically about a NESTED
// WithNamedLock call needing a SECOND connection from the pool while the
// outer call still holds the first, for every additional distinct lock key
// — unbounded with nesting depth. WithTransaction is never itself a
// WithNamedLock call and takes no named lock inside; it needs at most one
// additional connection, the same single extra connection any ordinary
// storage call already needs when run inside a WithNamedLock closure (see
// the guard's own GetUserRoleIDsExact call two lines below, or
// RemoveUserRole/SetProjectMemberRole/RemoveProjectMember's identical
// shape) — a constraint already implicit in every existing WithNamedLock
// caller in this package, not a new one. It requires the pool to have at
// least 2 connections available, which is already required for this server
// to function at all under ordinary concurrent load.
func (c *KeyorixCore) RevokeBreakGlassActivationAtomic(ctx context.Context, actorID, actorMachineID uint, activation *models.BreakGlassActivation, now time.Time) error {
	scope := storage.Scope{ProjectID: activation.ProjectID}
	var roleRemoved bool
	err := c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(scope.ProjectID), func(ctx context.Context) error {
		// A break-glass emergency role can never itself carry roles.assign at
		// ACTIVATION time (ActivateBreakGlass's own policy check), but a role's
		// permission set can be edited afterward, so this still runs a real
		// check rather than assuming it can never fire.
		existing, err := c.storage.GetUserRoleIDsExact(ctx, activation.UserID, scope)
		if err != nil {
			return err
		}
		after := make([]uint, 0, len(existing))
		for _, id := range existing {
			if id != activation.RoleID {
				after = append(after, id)
			}
		}
		if err := c.guardLastProjectAdmin(ctx, scope.ProjectID, activation.UserID, existing, after); err != nil {
			return err
		}
		return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if err := tx.RemoveRole(ctx, activation.UserID, activation.RoleID, scope); err != nil {
				if !errors.Is(err, storage.ErrRoleNotAssigned) {
					return err
				}
				// Already gone (auto-expired, or a racing revoke's own removal
				// already ran) — not an error, proceed to reconcile the record.
			} else {
				roleRemoved = true
			}
			// Conditional UPDATE (WHERE state = active OR expired), not a
			// read-modify-write: two concurrent revokes of the same activation can
			// both reach here, but only the first's conditional update actually
			// transitions state — the second gets ErrBreakGlassNotActive instead of
			// silently overwriting RevokedBy/RevokedAt. Rolling this back together
			// with the role removal above (rather than committing the removal
			// unconditionally) is exactly what closes the half-commit: either both
			// land, or neither does.
			return tx.RevokeBreakGlassActivation(ctx, activation.ID, actorID, actorMachineID, now)
		})
	})
	if err != nil {
		return err
	}

	// Audit and cache-eviction happen AFTER commit, never before — same
	// convention CreateRole/UpdateRole use (#1969/#1996): an event recorded
	// before the transaction resolves could survive a later rollback and
	// assert an effect that never actually landed.
	if roleRemoved {
		c.LogRoleRemoved(ctx, actorID, activation.UserID, activation.RoleID, scope)
		c.evictUserSessionCache(ctx, activation.UserID)
	}
	c.LogBreakGlassRevoked(ctx, actorID, activation.ProjectID, activation.ID, activation.UserID, activation.RoleID, activation.RoleName)
	return nil
}

// LogBreakGlassRevoked records an EventBreakGlassRevoked audit event for an early
// (pre-TTL) break-glass revocation. Exported so a raw storage-primitive proxy
// (RevokeBreakGlassActivationProxy, server/http/handlers/break_glass_proxy.go) that
// deliberately does not call RevokeBreakGlass itself — the proxy must not rerun
// this server's own project-affiliation validation against a caller relaying
// another server's already-decided revoke — can still record the same audit
// event RevokeBreakGlass does, instead of silently skipping it.
func (c *KeyorixCore) LogBreakGlassRevoked(ctx context.Context, actorID, projectID, activationID, userID, roleID uint, roleName string) {
	c.auditProjectScoped(ctx, EventBreakGlassRevoked, actorID, projectID,
		fmt.Sprintf("break-glass: revoked activation %d (user %d, role %q) early", activationID, userID, roleName))
}

// ReviewBreakGlass records a post-activation review (ADR-112 §3, break-glass
// review item 5): who reviewed it, when, and why. Activation itself stays
// single-person (decided) -- this is a SEPARATE, after-the-fact check, not a
// second approver gating the grant. actorID is the reviewer; projectID scopes
// and double-checks the activation the same way RevokeBreakGlass does.
//
// Three refusals, all added in #2461's coordinator review, each of which the
// control is worthless without:
//
//   - An UNATTRIBUTABLE reviewer (actorID==0: a machine identity, which
//     authenticates with UserID==0 and authorizes via PrincipalID, or an
//     unauthenticated local-CLI invocation) is refused via the same
//     requireHumanReviewer access-review decisions already use. A review whose
//     reviewer is nobody records accountability to nobody.
//   - SELF-review is refused. This is the load-bearing one: ADR-112 keeps
//     activation single-person *because* an independent after-the-fact review
//     follows it ("Break-glass remains single-person, with mandatory alert,
//     audit event and post-activation review"). Letting the activator close
//     out their own activation collapses the two-person property the whole
//     design rests on into one person. There is no co-approver to also
//     exclude: BreakGlassActivation carries no approver field and ADR-112
//     explicitly rejects two-person break-glass ("an emergency path that needs
//     a second person fails exactly when it's needed"), so the actor and the
//     activating user are the only two identities an activation has.
//     TestBreakGlassActivation_HasNoApproverField guards that premise rather
//     than this conclusion, so adding co-approval later forces this exclusion
//     to be revisited instead of silently leaving a second self-review path.
//   - A STILL-ACTIVE activation is refused; it must be revoked or expired
//     first. A reviewer cannot assess what was done with access that is still
//     in use, and a recorded review of an unfinished event reads, to an
//     auditor and to the posture report alike, as a closed item. Note State is
//     a read-time projection (GetBreakGlassActivation), so a TTL-lapsed
//     activation reads "expired" here without needing a write first.
//
// Refusing a review while active does NOT weaken the posture deviation: an
// unreviewed activation past the review window is reported either way (see
// accumulateBreakGlassPosture), which is exactly ADR-112's "an open activation
// without a recorded review shows as a posture deviation."
func (c *KeyorixCore) ReviewBreakGlass(ctx context.Context, actorID, projectID, activationID uint, note string) error {
	if projectID == 0 {
		return fmt.Errorf("%w: %s: %s", ErrInvalidInput, i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if err := requireHumanReviewer(actorID); err != nil {
		return fmt.Errorf("%w: %s: %s", ErrBreakGlassUnattributableReviewer, i18n.T("ErrorPermissionDenied", nil), err)
	}
	note = strings.TrimSpace(note)
	if len(note) < minBreakGlassReviewNoteLen {
		return fmt.Errorf("%w: %s: %s", ErrBreakGlassInvalidNote, i18n.T("ErrorValidation", nil),
			fmt.Sprintf("review note must be at least %d characters", minBreakGlassReviewNoteLen))
	}
	// #2461 round 2: this becomes a PERMANENT audit-trail record (same reasoning
	// as minBreakGlassReviewNoteLen above); cap it so a reviewer cannot pack an
	// arbitrarily large payload into the audit log via a review note.
	if len(note) > maxBreakGlassReviewNoteLen {
		return fmt.Errorf("%w: %s: %s", ErrBreakGlassInvalidNote, i18n.T("ErrorValidation", nil),
			fmt.Sprintf("review note must be at most %d characters", maxBreakGlassReviewNoteLen))
	}
	activation, err := c.storage.GetBreakGlassActivation(ctx, activationID)
	if err != nil {
		// GetBreakGlassActivation already distinguishes a definitive "no such
		// row" (storage.ErrBreakGlassNotFound) from a transient retrieval
		// failure. Keep them apart here so the handler maps the first to 404
		// and the second to 500, instead of reporting a DB fault as a 404 (the
		// bug local_break_glass.go's own comment records for the proxy path).
		// The not-found message is rebuilt rather than wrapped so it is
		// byte-identical to the project-mismatch refusal below.
		if storage.IsBreakGlassNotFound(err) {
			return fmt.Errorf("%w: %s", storage.ErrBreakGlassNotFound, i18n.T("ErrorNotFound", nil))
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if activation.ProjectID != projectID {
		// Deliberately the SAME sentinel, and so the same 404, as "no such
		// activation": a project-ID mismatch must not disclose that the
		// activation ID exists under some project the caller cannot see.
		return fmt.Errorf("%w: %s", storage.ErrBreakGlassNotFound, i18n.T("ErrorNotFound", nil))
	}
	if actorID == activation.UserID {
		return fmt.Errorf("%w: %s: %s", ErrBreakGlassSelfReview, i18n.T("ErrorPermissionDenied", nil),
			"you cannot review your own break-glass activation; an independent reviewer is required")
	}
	if activation.State == BreakGlassActive {
		return fmt.Errorf("%w: %s: %s", ErrBreakGlassStillActive, i18n.T("ErrorValidation", nil),
			"activation is still active; revoke it or wait for it to expire before reviewing")
	}
	now := c.now()
	if err := c.storage.ReviewBreakGlassActivation(ctx, activationID, actorID, note, now); err != nil {
		if errors.Is(err, storage.ErrBreakGlassAlreadyReviewed) {
			return fmt.Errorf("%w: %s: %s", storage.ErrBreakGlassAlreadyReviewed, i18n.T("ErrorValidation", nil), "activation has already been reviewed")
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.auditProjectScoped(ctx, EventBreakGlassReviewed, actorID, projectID,
		fmt.Sprintf("break-glass: activation %d (user %d, role %q) reviewed", activationID, activation.UserID, activation.RoleName))
	return nil
}

// ListUnreviewedBreakGlassActivations returns every activation (across all
// projects) that has gone unreviewed for at least window -- the posture
// report's (item 4) source for "open break-glass activations without
// review." window is typically BreakGlassConfig.GetReviewWindow().
func (c *KeyorixCore) ListUnreviewedBreakGlassActivations(ctx context.Context, window time.Duration) ([]*models.BreakGlassActivation, error) {
	cutoff := c.now().Add(-window)
	rows, err := c.storage.ListUnreviewedBreakGlassActivationsBefore(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// RunBreakGlassReviewReminder is the periodic half of ADR-112's
// post-activation-review requirement (#2461): it finds every activation that
// has gone unreviewed past the configured review window and makes that
// visible, returning how many it found.
//
// What "enforced" means here is exactly what ADR-112 says and nothing more --
// see ReviewBreakGlass's doc comment above for why activation stays
// single-person and a self-review is refused; that reasoning is not repeated
// here. A pending review never blocks break-glass ACTIVATION itself
// (INV-CORE-break-glass-unreviewed-reported-never-blocks-activation, narrowed
// #2461 round 2 -- Andrei's decision): nothing here
// blocks an activation, blocks a user, or expires a grant early, and no such
// lockout should be added without a fresh, explicit product decision. What IS
// enforced, and made hard to ignore (round 2): the "emergency-access"
// compliance control going to Gap (EvaluateControls, not merely
// informational), this recurring SECURITY: log line, a repeating
// notification to each affected project's admins (below), and a permanent
// audit event.
//
// Emits ONE audit event per pass when the count is non-zero, not one per
// activation: the per-activation detail is already in the posture report and
// in each activation's own break_glass.activated event, and a per-row event
// would make a long-ignored review spam the audit log it is supposed to make
// legible. A pass that finds nothing writes nothing.
func (c *KeyorixCore) RunBreakGlassReviewReminder(ctx context.Context) (int, error) {
	window := c.breakGlassReviewWindow()
	rows, err := c.ListUnreviewedBreakGlassActivations(ctx, window)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	// Oldest first (ListUnreviewedBreakGlassActivationsBefore orders by
	// created_at ASC), so the age reported is the worst one outstanding.
	oldest := c.now().Sub(rows[0].CreatedAt)
	log.Printf("SECURITY: %d break-glass activation(s) have gone unreviewed for longer than %s (oldest: activation %d, project %d, user %d, %s ago) -- ADR-112 requires a post-activation review of every activation; this is a compliance posture deviation until each is reviewed",
		len(rows), window, rows[0].ID, rows[0].ProjectID, rows[0].UserID, oldest.Round(time.Hour))
	auditCtx, userID := adminJobAuditContext(ctx)
	c.writeAuditEvent(auditCtx, EventBreakGlassReviewOverdue, userID, nil,
		fmt.Sprintf("break-glass: %d activation(s) unreviewed past the %s review window (oldest: activation %d, %s ago)",
			len(rows), window, rows[0].ID, oldest.Round(time.Hour)))
	c.notifyOverdueBreakGlassReviewers(ctx, rows, window)
	return len(rows), nil
}

// notifyOverdueBreakGlassReviewers fans out a repeating reminder to each
// affected project's approver-role members (#2461 round 2, Andrei's decision
// item (b)): "repeating overdue reminders to all admins" -- a log line and an
// audit event are visible to whoever goes looking, but neither actively
// surfaces to anyone the way notifyBreakGlassAdmins' activation alert does, so
// before this an overdue review could go unnoticed indefinitely by anyone who
// doesn't happen to read logs or query the posture API. Grouped by project
// (rows span every project, same as ListUnreviewedBreakGlassActivations
// itself) so each notification names the activations that project's admins
// can actually act on, not a deployment-wide count unrelated to their access.
//
// Best-effort and panic-recovered for the same reason notifyBreakGlassAdmins
// is: this runs on every periodic pass, already after the audit event above
// is durably written, so a notification-delivery hiccup must never fail (or
// repeatedly retry) the reminder job itself.
func (c *KeyorixCore) notifyOverdueBreakGlassReviewers(ctx context.Context, rows []*models.BreakGlassActivation, window time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: notifyOverdueBreakGlassReviewers panicked: %v\n%s", r, debug.Stack())
		}
	}()
	byProject := map[uint][]*models.BreakGlassActivation{}
	for _, a := range rows {
		byProject[a.ProjectID] = append(byProject[a.ProjectID], a)
	}
	for pid, acts := range byProject {
		recipients, err := c.projectAdminRecipients(ctx, pid)
		if err != nil {
			log.Printf("SECURITY: notifyOverdueBreakGlassReviewers: failed to fully resolve project %d admins (%d resolved), some admins may not be notified for %d overdue activation(s): %v", pid, len(recipients), len(acts), err)
		}
		title := "Break-glass review overdue"
		msg := fmt.Sprintf("%d break-glass activation(s) in this project have gone unreviewed for longer than %s. ADR-112 requires an independent post-activation review of every activation.", len(acts), window)
		link := fmt.Sprintf("/projects/%d/access-review", pid)
		for _, uid := range recipients {
			c.notify(ctx, uid, EventBreakGlassReviewOverdue, title, msg, &pid, link)
		}
	}
}

// notifyBreakGlassAdmins alerts the project's approver-role members that emergency
// access was activated. Individual notify() delivery is still best-effort (an
// email/webhook sink hiccup for one admin shouldn't abort the fan-out to the
// others), but a failure to even LIST the project's members is a distinct, louder
// failure mode — it means NO admin was considered for the alert at all — so that
// case is returned as an error (#166) rather than swallowed silently.
//
// Called strictly after the break-glass grant is already committed and audited
// (ActivateBreakGlass, above) — a notification failure is a detection-latency
// gap, not a control failure. A panic here is recovered rather than left to
// propagate, for the same reason: it must not turn an already-succeeded
// activation into a failed response. Unlike a plain returned error (which
// ActivateBreakGlass's own caller just logs), a panic is additionally audited
// under EventBreakGlassNotifyPanicked, since a panic mid-fan-out can leave an
// unknown subset of admins un-notified with no other signal that happened.
func (c *KeyorixCore) notifyBreakGlassAdmins(ctx context.Context, actorID, projectID uint, roleName string, expiresAt time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.auditProjectScoped(ctx, EventBreakGlassNotifyPanicked, actorID, projectID,
				fmt.Sprintf("break-glass admin notification failed: panic notifying project %d admins: %v — emergency access is active but admins may not have been alerted, review manually", projectID, r))
			log.Printf("SECURITY: notifyBreakGlassAdmins panicked for project %d (break-glass grant already committed and audited): %v\n%s", projectID, r, debug.Stack())
			err = nil
		}
	}()
	recipients, rerr := c.projectAdminRecipients(ctx, projectID)
	pid := projectID
	title := "Break-glass emergency access activated"
	msg := fmt.Sprintf("User %d self-granted emergency role %q until %s. Review the audit trail.",
		actorID, roleName, expiresAt.UTC().Format(time.RFC3339))
	link := fmt.Sprintf("/projects/%d/access-review", projectID)
	// Notify whoever WAS resolved even when part of the resolution failed.
	for _, uid := range recipients {
		c.notify(ctx, uid, EventBreakGlassActivated, title, msg, &pid, link)
	}
	return rerr
}
