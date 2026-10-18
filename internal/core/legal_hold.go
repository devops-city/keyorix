// legal_hold.go — deployment-wide legal hold (ISO 27001 A.5.34 / eDiscovery / DORA
// record-keeping). While a hold is active the background purge/retention jobs are
// blocked from hard-deleting records (the schedulers call IsLegalHoldActive each
// tick), so data subject to litigation or investigation is preserved. Placing and
// lifting a hold are audited; the row history is the evidence of when holds applied.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Legal-hold audit event types.
const (
	EventLegalHoldPlaced = "data.legal_hold_placed"
	EventLegalHoldLifted = "data.legal_hold_lifted"
)

// GetActiveLegalHold returns the current active hold, or (nil, nil) when none.
func (c *KeyorixCore) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	return c.storage.GetActiveLegalHold(ctx)
}

// IsLegalHoldActive reports whether a legal hold is currently in effect. The purge
// schedulers call this each tick and skip when it returns true; on error they must
// fail SAFE (skip the purge), so a transient lookup failure never risks destroying
// data that may be under hold.
func (c *KeyorixCore) IsLegalHoldActive(ctx context.Context) (bool, error) {
	hold, err := c.storage.GetActiveLegalHold(ctx)
	if err != nil {
		return false, err
	}
	return hold != nil, nil
}

// legalHoldGuard returns a non-nil error when a deployment-wide legal hold is active OR
// its status cannot be confirmed — fail SAFE. The hard-delete purges call this at their
// top (inside the scheduler lock, immediately before the deletes) so a hold placed after
// the scheduler's pre-lock check still aborts the in-flight purge, never destroying
// records that may be under hold.
func (c *KeyorixCore) legalHoldGuard(ctx context.Context) error {
	held, err := c.IsLegalHoldActive(ctx)
	if err != nil {
		return fmt.Errorf("refusing to purge: could not confirm legal-hold status: %w", err)
	}
	if held {
		return fmt.Errorf("refusing to purge: a deployment-wide legal hold is active")
	}
	return nil
}

// PlaceLegalHold activates a deployment-wide legal hold with a reason. Refuses if a
// hold is already active. actorID is the placing admin.
//
// The active check below and the insert in CreateLegalHold are not atomic: two
// concurrent calls can both observe "no active hold" before either commits (#305).
// That TOCTOU window fails SAFE, not open — a partial unique index on legal_holds
// (released) WHERE released = false means only one of the two inserts can succeed,
// and the loser's CreateLegalHold returns storage.ErrLegalHoldAlreadyActive, which
// is mapped to the same "already active" client error as the pre-check below rather
// than a 500.
//
// #377: placement used to be gated on only the plain system.write permission — the
// same tier LiftLegalHold used before #157 tightened it — letting any system.write
// holder place a bogus/decoy hold that halts all four purge/prune schedulers
// deployment-wide until someone lifts it (reversible griefing, not data loss, but
// still an under-authorized compliance control). Placement has no prior actor to
// compare against the way lift compares against the placer, so the direct mirror of
// #157's "placer-or-admin-tier" rule is: only an admin-tier (permission-bypass)
// principal may place a hold. A denied placement attempt is itself audited.
func (c *KeyorixCore) PlaceLegalHold(ctx context.Context, actorID uint, reason string) (*models.LegalHold, error) {
	if reason == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a reason is required to place a legal hold")
	}
	adminRole, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if adminRole == "" {
		c.writeAuditEventFailed(ctx, EventLegalHoldPlaced, actorPtr(actorID), nil, "",
			fmt.Sprintf("legal hold placement DENIED: actor %d is not an admin-tier principal", actorID))
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
			"only an admin-tier principal may place a legal hold")
	}
	if active, err := c.storage.GetActiveLegalHold(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	} else if active != nil {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a legal hold is already active")
	}
	// AUDIT-TX-3: placing a hold halts every purge scheduler, so the hold and its
	// audit row commit together (fail closed).
	var hold *models.LegalHold
	err = c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var cerr error
		hold, cerr = tx.CreateLegalHold(ctx, &models.LegalHold{
			Reason: reason, PlacedBy: actorID, PlacedAt: c.now(), Released: false,
		})
		if cerr != nil {
			return cerr
		}
		c.writeAuditEventFullOn(ctx, tgt, EventLegalHoldPlaced, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("legal hold %d placed: %s", hold.ID, reason))
		return nil
	})
	if errors.Is(err, storage.ErrLegalHoldAlreadyActive) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a legal hold is already active")
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return hold, nil
}

// LiftLegalHold releases the active hold so the purge jobs resume. Refuses if no
// hold is active. actorID is the lifting admin.
//
// #380: placement always records a Reason, but lift previously recorded none — the
// audit trail showed WHO/WHEN a hold was lifted but never WHY. reason is required,
// mirroring placement's own required-reason precedent, and is persisted on the row
// (ReleaseReason) and in the audit description.
//
// Separation of duties (#157): both place and lift are gated on the same
// system.write permission, so without an additional check whoever placed a hold
// specifically to preserve evidence could have it lifted by any other system.write
// holder — including, worst case, an insider under investigation lifting a hold a
// colleague placed over that insider's own conduct. Rather than a full dual-control
// workflow (which would need a new approval step this compliance control doesn't
// otherwise have), the practical restriction is: only the placer OR a principal who
// holds an admin-tier (permission-bypass) role may lift — mirroring the "different,
// higher-tier principal" framing without inventing a new permission tier, and
// without deadlocking release if the original placer is unavailable. A denied
// attempt is itself audited (distinctly from a successful lift) so the asymmetry
// between placer and lifter is visible either way.
func (c *KeyorixCore) LiftLegalHold(ctx context.Context, actorID uint, reason string) error {
	if reason == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a reason is required to lift a legal hold")
	}
	hold, err := c.storage.GetActiveLegalHold(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if hold == nil {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "no legal hold is active")
	}
	if actorID != hold.PlacedBy {
		adminRole, err := c.isGlobalAdminRoleName(ctx, actorID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		if adminRole == "" {
			c.writeAuditEventFailed(ctx, EventLegalHoldLifted, actorPtr(actorID), nil, "",
				fmt.Sprintf("legal hold %d lift DENIED: actor %d is neither the placer (%d) nor an admin-tier principal", hold.ID, actorID, hold.PlacedBy))
			return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
				"only the placing admin or an admin-tier principal may lift this legal hold")
		}
	}
	now := c.now()
	hold.Released = true
	hold.ReleasedBy = actorID
	hold.ReleasedAt = &now
	hold.ReleaseReason = reason
	// AUDIT-TX-3: lifting a hold lets the purge jobs destroy data again, so the
	// release and its audit row commit together (fail closed).
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.UpdateLegalHold(ctx, hold); err != nil {
			return err
		}
		c.writeAuditEventFullOn(ctx, tgt, EventLegalHoldLifted, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("legal hold %d lifted by %d (originally placed by %d): %s", hold.ID, actorID, hold.PlacedBy, reason))
		return nil
	}); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}
