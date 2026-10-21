// risk_exceptions.go — the risk register / exceptions (ISO 27001 A.5.8 risk
// treatment / A.5.36 compliance with policies). An exception is a governed,
// time-bound acceptance of a known control gap: a named risk, accepted by an owner
// with a written justification, that sunsets at a fixed date. It turns a raw
// posture violation into a *governed* exception an auditor can see was accepted with
// a deadline, not silently ignored. Effective status (active/expired/revoked) is
// computed at read time from the revoked flag and the expiry.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Effective risk-exception status (computed from revoked + expiry).
const (
	ExceptionStatusActive  = "active"
	ExceptionStatusExpired = "expired"
	ExceptionStatusRevoked = "revoked"

	EventRiskExceptionCreated  = "risk.exception_created"
	EventRiskExceptionRevoked  = "risk.exception_revoked"
	EventRiskExceptionApproved = "risk.exception_approved"
)

// #1531: RevokeRiskException/ApproveRiskException return a plain error for
// every failure mode -- permission denial, validation, AND a lost CAS race
// or an already-decided precondition. The local human-facing handler
// (risk_exceptions.go) is fine with that (a human clicking revoke twice just
// wants an error message either way), but RevokeRiskExceptionProxy/
// ApproveRiskExceptionProxy back a wire contract where a lost race or an
// already-decided precondition is a normal outcome (matched=false), not a
// failure -- every sibling conditional-transition wire method in this
// package (TransitionMachineIdentityState, TransitionSecretStatus, ...)
// already makes that distinction. These sentinels let the proxy tell the
// two apart via errors.Is without string-matching the message (the existing
// local-handler precedent, kept working unchanged since these wrap the same
// text via %w) and without a signature change that would touch the local
// handler too.
//
// Scoped to exactly the preconditions RevokeRiskExceptionIfNotRevoked's
// ("revoked = false") and ApproveRiskExceptionIfPending's ("revoked = false
// AND approved = false") own WHERE clauses enforce -- the same invariant,
// checked once eagerly here and once atomically at the storage layer.
// ExceptionStatusExpired is deliberately NOT one of these: expiry is a
// deterministic function of wall-clock time, not a concurrently-decided
// precondition a CAS could lose a race on, so it stays a genuine error.
var (
	ErrRiskExceptionAlreadyRevoked       = errors.New("risk exception is already revoked")
	ErrRiskExceptionConcurrentlyRevoked  = errors.New("risk exception was concurrently revoked by another request")
	ErrRiskExceptionAlreadyApproved      = errors.New("risk exception is already approved")
	ErrRiskExceptionRevokedNotApprovable = errors.New("cannot approve a revoked risk exception")
	ErrRiskExceptionConcurrentlyDecided  = errors.New("risk exception was concurrently revoked or approved by another request")
)

// ErrRiskExceptionPermissionDenied and ErrRiskExceptionNotFound (re-exported
// from storage.ErrRiskExceptionNotFound for errors.Is convenience) classify
// RevokeRiskException failures for server/http/handlers/risk_exceptions.go to
// match via errors.Is, rather than the substring text match it used to do
// (strings.Contains(msg, "not found"), with no case at all for permission
// denial, which fell through to a generic 500). Same pattern as FIX-4/FIX-6.
//
// Part 2 regression audit (adversarial review run 2): RevokeRiskException's
// authority check ran AFTER the existence lookup (GetRiskException),
// returning that lookup's raw error on failure -- so a caller holding this
// route's own gate (system.write) but no creator/admin-tier standing could
// distinguish "exception id doesn't exist" from "exists but isn't mine" by
// the different status codes/bodies that produced, exactly the oracle
// PR #1695 fixed for the identically-shaped DeleteSoDPolicy but never swept
// to this sibling site.
var (
	ErrRiskExceptionPermissionDenied = errors.New("risk exception permission denied")
	ErrRiskExceptionNotFoundPublic   = errors.New("risk exception not found")
)

type riskExceptionClassifiedError struct {
	err    error
	target error
}

func (e *riskExceptionClassifiedError) Error() string        { return e.err.Error() }
func (e *riskExceptionClassifiedError) Unwrap() error        { return e.err }
func (e *riskExceptionClassifiedError) Is(target error) bool { return target == e.target }

func wrapRiskExceptionPermissionDenied(err error) error {
	return &riskExceptionClassifiedError{err: err, target: ErrRiskExceptionPermissionDenied}
}
func wrapRiskExceptionNotFoundPublic(err error) error {
	return &riskExceptionClassifiedError{err: err, target: ErrRiskExceptionNotFoundPublic}
}

// validExceptionCategories are the risk areas an exception may cover (aligned with
// the posture controls so an exception can annotate a specific gap).
var validExceptionCategories = map[string]struct{}{
	"sod": {}, "mfa": {}, "rotation": {}, "dormant_access": {}, "classification": {}, "other": {},
}

// RiskExceptionView is a stored exception plus its effective status at read time.
type RiskExceptionView struct {
	*models.RiskException
	Status string `json:"status"` // active | expired | revoked (computed)
}

// exceptionStatus computes the effective status from the revoked flag and expiry.
func exceptionStatus(e *models.RiskException, now time.Time) string {
	if e.Revoked {
		return ExceptionStatusRevoked
	}
	if !e.ExpiresAt.After(now) {
		return ExceptionStatusExpired
	}
	return ExceptionStatusActive
}

// maxRiskExceptionDuration caps how far out a risk exception may be set to expire — an
// exception must sunset and be re-reviewed, not become a permanent waiver.
const maxRiskExceptionDuration = 365 * 24 * time.Hour

// validateSoDReferenceIsLiveViolation enforces that a "sod"-category risk
// exception's reference actually names a CURRENTLY-DETECTED SoD violation
// (Wave 6 core-sod finding #3, ISO 27001 A.5.8/A.5.3): without this, two
// system.write holders could create-and-approve an exception for a
// (policy, principal) pair that has never violated anything yet — or no
// longer does — pre-emptively suppressing a violation before it's ever real
// (or rubber-stamping one that was resolved between creation and approval).
// That defeats dual control's whole point, which is governed acceptance of a
// KNOWN, currently-real gap, not a blanket bypass for a future one. Applies
// only to category "sod"; every other category's reference is free text (a
// user, a secret, ...) with no live report to check it against. Fails closed:
// a reference that doesn't appear in DetectSoDViolations' current output —
// including because the scan couldn't fully evaluate the referenced
// principal (report.Degraded) — is refused, not assumed valid.
func (c *KeyorixCore) validateSoDReferenceIsLiveViolation(ctx context.Context, category, reference string) error {
	if category != "sod" {
		return nil
	}
	report, err := c.DetectSoDViolations(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate SoD violation reference: %w", err)
	}
	for _, v := range report.Violations {
		if v.Reference == reference {
			return nil
		}
	}
	return fmt.Errorf("reference %q does not match any currently-detected SoD violation (see GET /sod/violations for a valid reference)", reference)
}

// CreateRiskException records a governed, time-bound acceptance of a control gap.
// actorID is the accepting owner; expiresAt must be in the future. The exception
// does NOT suppress anything yet: it must be separately approved by a DIFFERENT
// system.write holder (see ApproveRiskException) before it takes effect — dual
// control (#170), so the creator can't unilaterally suppress a violation of their
// own. For category "sod", reference should be the matching SoDViolation's
// Reference field (as returned by GET /sod/violations) so the exception, once
// approved, suppresses that one violation specifically.
//
// #1529: actorIsMachine mirrors ApproveRiskException's own reasoning exactly —
// "governed acceptance of a control gap" only means something if a HUMAN took
// responsibility for proposing it; a machine credential (including a bare node
// credential, zero RBAC permissions by design) creating the row with
// CreatedBy==0 would also silently weaken ApproveRiskException's own
// self-approval check (actorID != e.CreatedBy trivially passes for ANY real
// approver against CreatedBy==0). CreateRiskException itself was missing this
// check even though the sibling Approve function already had it — an
// asymmetry, not a deliberate design (dual control's whole premise is two
// humans, not "one human plus whatever created the row").
func (c *KeyorixCore) CreateRiskException(ctx context.Context, actorID uint, actorIsMachine bool, title, category, reference, justification string, expiresAt time.Time) (*models.RiskException, error) {
	if actorIsMachine {
		c.writeAuditEventFailed(ctx, EventRiskExceptionCreated, nil, nil, "",
			"risk exception create DENIED: a machine-authenticated actor cannot propose a governed risk acceptance")
		return nil, fmt.Errorf("only a human principal may create a risk exception")
	}
	if title == "" || justification == "" {
		return nil, fmt.Errorf("title and justification are required")
	}
	if _, ok := validExceptionCategories[category]; !ok {
		return nil, fmt.Errorf("category must be one of sod|mfa|rotation|dormant_access|classification|other")
	}
	if !expiresAt.After(c.now()) {
		return nil, fmt.Errorf("expires_at must be in the future (exceptions are time-bound)")
	}
	// A risk exception MUST sunset — bound the duration so it can't be set effectively
	// forever (e.g. year 9999), defeating the "accepted with a sunset" governance intent.
	if expiresAt.After(c.now().Add(maxRiskExceptionDuration)) {
		return nil, fmt.Errorf("expires_at must be within %d days (exceptions must sunset and be re-reviewed)", int(maxRiskExceptionDuration/(24*time.Hour)))
	}
	if err := c.validateSoDReferenceIsLiveViolation(ctx, category, reference); err != nil {
		return nil, err
	}
	// AUDIT-TX-3: accepting a control gap is governance-weakening, so the exception
	// and its audit row commit together (fail closed).
	var created *models.RiskException
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var cerr error
		created, cerr = tx.CreateRiskException(ctx, &models.RiskException{
			Title: title, Category: category, Reference: reference, Justification: justification,
			CreatedBy: actorID, CreatedAt: c.now(), ExpiresAt: expiresAt,
		})
		if cerr != nil {
			return cerr
		}
		c.writeAuditEventFullOn(ctx, tgt, EventRiskExceptionCreated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("risk exception %d accepted: %q (category=%s, ref=%q) until %s",
				created.ID, title, category, reference, expiresAt.UTC().Format(time.RFC3339)))
		return nil
	}); err != nil {
		return nil, err
	}
	return created, nil
}

// listRiskExceptionRows is the one storage read shared by ListRiskExceptions,
// CountExpiredRiskExceptions, and the compliance snapshot's own risk-register
// rollup: every row gets its effective status computed here, so a caller needing a
// different slice of that status (active only, expired only, or every non-revoked
// row) never has to re-query storage to get it (#256, #395).
func (c *KeyorixCore) listRiskExceptionRows(ctx context.Context, activeOnly bool) ([]*RiskExceptionView, error) {
	rows, err := c.storage.ListRiskExceptions(ctx, activeOnly) // activeOnly excludes revoked at storage
	if err != nil {
		return nil, err
	}
	now := c.now()
	out := make([]*RiskExceptionView, 0, len(rows))
	for _, e := range rows {
		out = append(out, &RiskExceptionView{RiskException: e, Status: exceptionStatus(e, now)})
	}
	return out, nil
}

// ListRiskExceptions returns exceptions with their effective status. When activeOnly
// is set, only currently-active (not revoked, not expired) exceptions are returned;
// otherwise every non-revoked exception is returned (expired included, for history).
func (c *KeyorixCore) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*RiskExceptionView, error) {
	views, err := c.listRiskExceptionRows(ctx, activeOnly)
	if err != nil {
		return nil, err
	}
	if !activeOnly {
		return views, nil
	}
	out := make([]*RiskExceptionView, 0, len(views))
	for _, v := range views {
		if v.Status == ExceptionStatusActive {
			out = append(out, v) // storage dropped revoked; drop expired here too
		}
	}
	return out, nil
}

// CountExpiredRiskExceptions returns how many stored risk exceptions have passed
// their expiry but are still marked non-revoked — i.e. a governed acceptance whose
// sunset came and went with no renewal or explicit revocation (#395). The risk it
// was excepting is unmitigated again the moment expiry passes, but without this
// count the compliance matrix has no visibility into that: the exception simply
// drops out of the "active" tally (see ListRiskExceptions/CountActiveRiskExceptions)
// as if it had never existed, rather than surfacing as a stale acceptance an
// auditor needs to see.
func (c *KeyorixCore) CountExpiredRiskExceptions(ctx context.Context) (int, error) {
	views, err := c.listRiskExceptionRows(ctx, true) // excludes revoked; expiry computed here
	if err != nil {
		return 0, err
	}
	expired := 0
	for _, v := range views {
		if v.Status == ExceptionStatusExpired {
			expired++
		}
	}
	return expired, nil
}

// RevokeRiskException withdraws an exception before its expiry. actorID is the admin.
//
// #1529: actorID used to be threaded through ONLY for attribution (RevokedBy),
// with no authority check at all -- unlike ApproveRiskException's own careful
// dual-control gate, revocation got no equivalent thought. Mirrors
// LiftLegalHold's creator-or-admin precedent exactly: only the principal who
// created the exception, or a global-admin-tier principal, may revoke it. A
// denied attempt is itself audited.
//
// Part 2 regression audit fix (adversarial review run 2): the authority check
// used to run AFTER the existence lookup, returning that lookup's error
// verbatim on failure -- the same #1645 403-for-both oracle PR #1695 fixed
// for DeleteSoDPolicy, present here too since this function shares the exact
// same shape and was never swept. A real 404 is now safe ONLY for a caller
// already authorized at global admin-tier (the same standing that would
// grant access to ANY exception); every other caller gets the identical
// ErrRiskExceptionPermissionDenied response whether the id is missing or
// just not theirs.
func (c *KeyorixCore) RevokeRiskException(ctx context.Context, actorID, id uint) error {
	adminRole, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	isAdminTier := adminRole != ""

	e, err := c.storage.GetRiskException(ctx, id)
	if err != nil {
		if isAdminTier && errors.Is(err, storage.ErrRiskExceptionNotFound) {
			return wrapRiskExceptionNotFoundPublic(err)
		}
		if errors.Is(err, storage.ErrRiskExceptionNotFound) {
			c.writeAuditEventFailed(ctx, EventRiskExceptionRevoked, actorPtr(actorID), nil, "",
				fmt.Sprintf("risk exception %d revoke DENIED: actor %d is not an admin-tier principal (exception lookup found no match)", id, actorID))
			return wrapRiskExceptionPermissionDenied(fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
				"only the creating admin or an admin-tier principal may revoke this risk exception"))
		}
		return err
	}

	if actorID != e.CreatedBy && !isAdminTier {
		c.writeAuditEventFailed(ctx, EventRiskExceptionRevoked, actorPtr(actorID), nil, "",
			fmt.Sprintf("risk exception %d revoke DENIED: actor %d is neither the creator (%d) nor an admin-tier principal", id, actorID, e.CreatedBy))
		return wrapRiskExceptionPermissionDenied(fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
			"only the creating admin or an admin-tier principal may revoke this risk exception"))
	}
	if e.Revoked {
		return fmt.Errorf("risk exception %d is already revoked: %w", id, ErrRiskExceptionAlreadyRevoked)
	}
	now := c.now()
	e.Revoked = true
	e.RevokedBy = actorID
	e.RevokedAt = &now
	// AUDIT-TX-3: revoking an exception puts a violation back on the record: a
	// revocation, so never blocked by the audit log; its row is owed from this
	// transaction.
	return c.withOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		matched, rerr := tx.RevokeRiskExceptionIfNotRevoked(ctx, e)
		if rerr != nil {
			return rerr
		}
		if !matched {
			// Lost the race: the row's persisted revoked flag moved to true between
			// the GetRiskException read above and this write (a concurrent
			// RevokeRiskException or ApproveRiskException call) — treat exactly like
			// the already-revoked precondition failure above rather than silently
			// overwriting the winner (StateTransitionMissingCAS.ql).
			return fmt.Errorf("risk exception %d was concurrently revoked by another request: %w", id, ErrRiskExceptionConcurrentlyRevoked)
		}
		c.writeAuditEventFullOn(ctx, tgt, EventRiskExceptionRevoked, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("risk exception %d revoked: %q", id, e.Title))
		return nil
	})
}

// ApproveRiskException dual-controls an exception (#170): actorID must be a
// DIFFERENT principal than the one who created it. Only an approved, still-active
// exception suppresses its matched violation from the compliance posture — before
// approval the raw violation keeps counting, so a self-dealt exception has no
// effect. A denied self-approval attempt is itself audited distinctly from a grant.
//
// actorIsMachine: dual control's entire premise is "a different HUMAN reviewed
// this" — a machine credential can never BE that different human, by definition,
// regardless of any other detail (#1524 finding (c)). This is not a narrower
// version of the self-approval check (actorID == e.CreatedBy): a node relaying a
// HUMAN-created exception (CreatedBy != 0) doesn't collide with that comparison
// at all and would otherwise approve with no authority check whatsoever. Deny
// unconditionally rather than trying to make the comparison "work" for a
// principal type it was never written to represent.
func (c *KeyorixCore) ApproveRiskException(ctx context.Context, actorID uint, actorIsMachine bool, id uint) error {
	e, err := c.storage.GetRiskException(ctx, id)
	if err != nil {
		return err
	}
	if e.Revoked {
		return fmt.Errorf("cannot approve a revoked risk exception: %w", ErrRiskExceptionRevokedNotApprovable)
	}
	if exceptionStatus(e, c.now()) == ExceptionStatusExpired {
		return fmt.Errorf("cannot approve an expired risk exception")
	}
	if e.Approved {
		return fmt.Errorf("risk exception %d is already approved: %w", id, ErrRiskExceptionAlreadyApproved)
	}
	if actorIsMachine {
		c.writeAuditEventFailed(ctx, EventRiskExceptionApproved, actorPtr(actorID), nil, "",
			fmt.Sprintf("risk exception %d approval DENIED: a machine credential cannot satisfy dual control", id))
		return fmt.Errorf("dual control requires a human approver; a machine credential cannot approve a risk exception")
	}
	if actorID == e.CreatedBy {
		c.writeAuditEventFailed(ctx, EventRiskExceptionApproved, actorPtr(actorID), nil, "",
			fmt.Sprintf("risk exception %d approval DENIED: creator %d cannot self-approve", id, actorID))
		return fmt.Errorf("the exception's creator cannot approve it (dual control); a different system.write holder must approve")
	}
	// Re-validate against a FRESH DetectSoDViolations scan, not just at creation
	// time: the referenced violation may have been resolved (or, if creation-time
	// validation were ever bypassed, may never have existed) by the time a
	// different approver reviews it — a stale or bogus reference must not be
	// rubber-stamped either.
	if err := c.validateSoDReferenceIsLiveViolation(ctx, e.Category, e.Reference); err != nil {
		c.writeAuditEventFailed(ctx, EventRiskExceptionApproved, actorPtr(actorID), nil, "",
			fmt.Sprintf("risk exception %d approval DENIED: %v", id, err))
		return err
	}
	now := c.now()
	e.Approved = true
	e.ApprovedBy = actorID
	e.ApprovedAt = &now
	// AUDIT-TX-3: an approval suppresses a violation from the posture, so it is
	// grant-shaped: the approval and its audit row commit together (fail closed).
	return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		matched, aerr := tx.ApproveRiskExceptionIfPending(ctx, e)
		if aerr != nil {
			return aerr
		}
		if !matched {
			// Lost the race: the row's persisted revoked/approved flags moved between
			// the GetRiskException read above and this write (a concurrent
			// RevokeRiskException or ApproveRiskException call) — treat exactly like
			// the already-revoked/already-approved precondition failures above rather
			// than silently overwriting the winner (StateTransitionMissingCAS.ql).
			return fmt.Errorf("risk exception %d was concurrently revoked or approved by another request: %w", id, ErrRiskExceptionConcurrentlyDecided)
		}
		c.writeAuditEventFullOn(ctx, tgt, EventRiskExceptionApproved, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("risk exception %d approved by %d (created by %d): %q", id, actorID, e.CreatedBy, e.Title))
		return nil
	})
}

// CountActiveRiskExceptions returns how many exceptions are currently active and how
// many of those expire within the `soon` window — for the compliance posture.
func (c *KeyorixCore) CountActiveRiskExceptions(ctx context.Context, soon time.Duration) (active, expiringSoon int, err error) {
	rows, err := c.storage.ListRiskExceptions(ctx, true)
	if err != nil {
		return 0, 0, err
	}
	now := c.now()
	cutoff := now.Add(soon)
	for _, e := range rows {
		if exceptionStatus(e, now) != ExceptionStatusActive {
			continue
		}
		active++
		if e.ExpiresAt.Before(cutoff) {
			expiringSoon++
		}
	}
	return active, expiringSoon, nil
}
