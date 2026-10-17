// secret_suspend.go — suspend/resume a secret. Suspending blocks value reads (an
// incident-response control: a suspected-compromised secret can be frozen without
// deleting it, preserving its versions, shares, and audit trail) and is reversible.
// Metadata, listing, and management operations stay available so the secret can be
// inspected, rotated, or resumed while suspended.
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

// Secret lifecycle statuses.
const (
	SecretStatusActive    = "active"
	SecretStatusSuspended = "suspended"
)

// Audit event types for suspend/resume.
const (
	EventSecretSuspended = "secret.suspended"
	EventSecretResumed   = "secret.resumed"
)

// SuspendSecret freezes value reads of a secret (idempotent). The caller (transport)
// must have enforced scoped secrets.write. The synced Kubernetes copies follow each
// resource's own onSuspend setting; use SuspendSecretWithOptions to also clear them.
func (c *KeyorixCore) SuspendSecret(ctx context.Context, secretID, actorID uint, reason string) (*models.SecretNode, error) {
	return c.SuspendSecretWithOptions(ctx, secretID, actorID, reason, SuspendOptions{})
}

// SuspendOptions are the per-suspension choices a suspend request can carry.
type SuspendOptions struct {
	// ClearSyncedCopies asks the operator and k8s-sync to empty the copies of this
	// secret synced to Kubernetes clusters for the duration of THIS suspension, as if
	// the resource said onSuspend: Clear (a compromise response). The marker lives with
	// the suspension: resume removes it and the next sync restores the copies.
	ClearSyncedCopies bool
}

// SuspendSecretWithOptions is SuspendSecret with per-suspension options.
//
// With opts.ClearSyncedCopies the status change (and marker) and the secret.suspended audit
// row commit in ONE transaction; a failure to record the audit rolls everything back and
// returns ErrSuspendAuditUnavailable. A plain suspend keeps its historical best-effort
// audit after the write.
//
// Already suspended: without opts.ClearSyncedCopies it is a no-op (no duplicate audit,
// and an existing marker is never downgraded; only resume removes it). With it, a
// suspension that lacks the marker is upgraded in place, because "I suspended it, and
// now I know it leaked" is the commonest way to reach this choice. That upgrade is
// audited like any suspend, before it takes effect for a reader.
func (c *KeyorixCore) SuspendSecretWithOptions(ctx context.Context, secretID, actorID uint, reason string, opts SuspendOptions) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	alreadySuspended := secret.Status == SecretStatusSuspended
	if alreadySuspended && (!opts.ClearSyncedCopies || secret.SuspendClearSyncedCopies) {
		return secret, nil // already suspended (and nothing to add) — no-op, no duplicate audit
	}
	fromStatus := secret.Status
	secret.Status = SecretStatusSuspended
	secret.SuspendClearSyncedCopies = opts.ClearSyncedCopies
	secret.UpdatedAt = c.now()
	uid, sid := actorID, secretID
	desc := fmt.Sprintf("suspended secret %q", secret.Name)
	if reason != "" {
		desc += ": " + reason
	}
	if !opts.ClearSyncedCopies {
		// A plain freeze keeps its long-standing best-effort audit: an audit outage
		// must not stop a responder from blocking reads.
		if err := transitionSuspend(ctx, c.storage, secret, fromStatus); err != nil {
			return nil, err
		}
		c.writeAuditEvent(ctx, EventSecretSuspended, &uid, &sid, desc)
		return secret, nil
	}
	// Clearing the synced copies destroys data in clusters, so it never takes effect
	// without its record: the marker and the secret.suspended row commit in ONE
	// transaction, and a failed audit write rolls the marker back (fail closed, retry).
	desc += " (clear_synced_copies=true)"
	sink := &auditForwardSink{}
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := transitionSuspend(ctx, tx, secret, fromStatus); err != nil {
			return err
		}
		if !c.writeAuditEventFullOn(ctx, auditInto(tx, sink), EventSecretSuspended, &uid, &sid, nil, "", desc) {
			return ErrSuspendAuditUnavailable
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sink.Flush(c)
	return secret, nil
}

// ErrSuspendAuditUnavailable: a suspend asking to clear the synced copies could not
// record its audit event, so nothing was changed. Retry once the audit store is back.
var ErrSuspendAuditUnavailable = errors.New("could not record the suspension in the audit log; nothing was changed, retry")

// SuspendWithoutClearingHint is the next step every transport gives with a refused
// clear-synced-copies suspend (ErrSuspendAuditUnavailable, ErrBulkSuspendAuditUnavailable):
// a plain suspend is never blocked by the audit log, so it cuts access now; the copies can
// be cleared with a second suspend once the audit log is back.
const SuspendWithoutClearingHint = "suspend without clearing to cut access now"

// transitionSuspend is the conditional status write shared by both suspend paths.
func transitionSuspend(ctx context.Context, st storage.Storage, secret *models.SecretNode, fromStatus string) error {
	matched, err := st.TransitionSecretStatus(ctx, secret, fromStatus)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		// Lost the race: the row's persisted status moved away from fromStatus
		// between the GetSecret read above and this write (a concurrent
		// suspend/resume, or any other concurrent writer of this row) — treat
		// as a failed write rather than silently overwriting the winner.
		return fmt.Errorf("secret %d's status changed concurrently; retry", secret.ID)
	}
	return nil
}

const projectSuspendPageSize = 500

// SuspendProjectSecrets freezes value reads of every active secret in a project (a
// breach-response "freeze the project" action) and returns how many it suspended.
// Already-suspended secrets are left untouched; a per-secret failure (including a
// per-secret authorization denial — see the EnforceSecretWritePermission re-check
// below) is skipped so one bad secret doesn't abort the freeze. The caller must have
// enforced scoped secrets.write on the project.
func (c *KeyorixCore) SuspendProjectSecrets(ctx context.Context, projectID, actorID uint, reason string) (int, error) {
	return c.SuspendProjectSecretsWithOptions(ctx, projectID, actorID, reason, SuspendOptions{})
}

// ErrBulkSuspendAuditUnavailable is returned, with no secret touched, when a project-wide
// suspension that asks to clear synced copies could not record that decision first.
var ErrBulkSuspendAuditUnavailable = errors.New("bulk suspend audit event could not be recorded; nothing was suspended")

// SuspendProjectSecretsWithOptions is SuspendProjectSecrets with the same per-suspension
// options as SuspendSecretWithOptions, applied to every secret it affects: each gets the
// per-suspension marker exactly as a single-secret suspend would (an already-suspended
// secret without the marker is upgraded, one that has it is left alone), and a later
// ResumeProjectSecrets / ResumeSecret clears it.
//
// The project-level audit event (secret.bulk_suspend_attempted) is written BEFORE any
// secret is touched and records the choice and how many secrets this request will try to
// affect (the ones the actor may write, that are not already in the requested state).
// When opts.ClearSyncedCopies is set, a failure to record it aborts the request with
// ErrBulkSuspendAuditUnavailable and nothing is suspended: a decision to empty copies in
// other clusters is never taken without a trail. A plain suspend keeps its historical
// best-effort audit. The per-secret events (secret.suspended) are unchanged.
func (c *KeyorixCore) SuspendProjectSecretsWithOptions(ctx context.Context, projectID, actorID uint, reason string, opts SuspendOptions) (int, error) {
	if projectID == 0 || actorID == 0 {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and actor ID are required")
	}
	secrets, err := c.listProjectSecrets(ctx, projectID)
	if err != nil {
		return 0, err
	}
	var targets []*models.SecretNode
	recheckFailed := 0
	for _, s := range secrets {
		if s.Status == SecretStatusSuspended && (!opts.ClearSyncedCopies || s.SuspendClearSyncedCopies) {
			continue // already suspended, nothing to add
		}
		// Re-check per-secret write authorization (owner/share). The project-wide
		// secrets.write route gate is not sufficient on its own — the single-secret PUT
		// path enforces this too, so a caller who can't update a secret individually must
		// not be able to via the bulk op (mirrors ExtendExpiringSecrets). Skip (don't
		// abort) on denial.
		if _, err := c.EnforceSecretWritePermission(ctx, s.ID, actorID); err != nil {
			// A denial (or a secret deleted since the list) is a skip. Any other error
			// is a failed re-check, not a denial: a plain suspend still skips it, but a
			// clear-synced-copies suspend counts it as a secret it could not suspend.
			if opts.ClearSyncedCopies && !isSuspendSkip(err) {
				recheckFailed++
			}
			continue
		}
		targets = append(targets, s)
	}
	// Written unconditionally and before any effect: a project with nothing to suspend
	// (all already suspended, or none writable by actorID) would otherwise leave no trail
	// that this bulk operation was attempted (F5, audit-completeness campaign), and the
	// clear-copies choice must be on record before it can empty anything.
	pid := projectID
	desc := fmt.Sprintf("project %d bulk-suspend attempted: %d secret(s) targeted", projectID, len(targets))
	if reason != "" {
		desc += ": " + reason
	}
	if opts.ClearSyncedCopies {
		desc += " (clear_synced_copies=true)"
	}
	persisted := c.writeAuditEventFull(ctx, "secret.bulk_suspend_attempted", actorPtr(actorID), nil, &pid, "", desc)
	if !persisted && opts.ClearSyncedCopies {
		return 0, ErrBulkSuspendAuditUnavailable
	}
	n, failed := 0, recheckFailed
	for _, s := range targets {
		_, err := c.SuspendSecretWithOptions(ctx, s.ID, actorID, reason, opts)
		if err == nil {
			n++
			continue
		}
		if !opts.ClearSyncedCopies {
			continue // a plain suspend is best-effort per secret, as it always was
		}
		// A clear-synced-copies suspend is fail-closed on audit: stop at the first secret
		// whose own audit row was refused and tell the caller. Secrets already suspended
		// stay suspended (each committed with its own audit row).
		if errors.Is(err, ErrSuspendAuditUnavailable) {
			return n, &BulkSuspendPartialError{Suspended: n, Failed: len(targets) - n + recheckFailed, AuditRefused: true}
		}
		// Any other per-secret failure (storage error, commit failure, concurrent status
		// change) leaves that secret readable: count it so the caller is never told the
		// whole project was suspended. A secret deleted since the list is not a failure.
		if !isSuspendSkip(err) {
			failed++
		}
	}
	if failed > 0 {
		return n, &BulkSuspendPartialError{Suspended: n, Failed: failed}
	}
	return n, nil
}

// isSuspendSkip reports whether a per-secret error during a bulk suspend is a skip
// (permission denied, or the secret no longer exists) rather than a failure.
func isSuspendSkip(err error) bool {
	return storage.IsSecretNotFound(err) || strings.Contains(err.Error(), i18n.T("ErrorPermissionDenied", nil))
}

// BulkSuspendPartialError is returned by SuspendProjectSecretsWithOptions when a
// clear-synced-copies suspend did not suspend every secret it should have. Suspended
// secrets stay suspended; Failed counts those that are not and remain readable.
//
// AuditRefused: the run stopped because a secret's own audit row could not be
// recorded; Failed then includes that secret and every target never attempted, and
// the error unwraps to ErrSuspendAuditUnavailable. Otherwise the run finished and
// Failed counts the secrets whose permission re-check or suspend failed for another
// reason (storage error, commit failure, concurrent status change).
type BulkSuspendPartialError struct {
	Suspended    int
	Failed       int
	AuditRefused bool
}

func (e *BulkSuspendPartialError) Error() string {
	if e.AuditRefused {
		return fmt.Sprintf("%v: %d suspended, %d not suspended", ErrSuspendAuditUnavailable, e.Suspended, e.Failed)
	}
	return fmt.Sprintf("bulk suspend incomplete: %d suspended, %d could not be suspended and are still readable, retry", e.Suspended, e.Failed)
}

// Unwrap returns ErrSuspendAuditUnavailable when the run stopped on an audit refusal.
func (e *BulkSuspendPartialError) Unwrap() error {
	if e.AuditRefused {
		return ErrSuspendAuditUnavailable
	}
	return nil
}

// ResumeProjectSecrets restores value reads of every suspended secret in a project and
// returns how many it resumed. See SuspendProjectSecrets for semantics.
func (c *KeyorixCore) ResumeProjectSecrets(ctx context.Context, projectID, actorID uint) (int, error) {
	if projectID == 0 || actorID == 0 {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and actor ID are required")
	}
	secrets, err := c.listProjectSecrets(ctx, projectID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range secrets {
		if s.Status != SecretStatusSuspended {
			continue
		}
		// Re-check per-secret write authorization — see the matching check in
		// SuspendProjectSecrets above.
		if _, err := c.EnforceSecretWritePermission(ctx, s.ID, actorID); err != nil {
			continue
		}
		if _, err := c.ResumeSecret(ctx, s.ID, actorID); err == nil {
			n++
		}
	}
	// Written unconditionally, same reasoning as SuspendProjectSecrets' own
	// summary event immediately above (F5, audit-completeness campaign).
	pid := projectID
	c.writeAuditEventFull(ctx, "secret.bulk_resume_attempted", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("project %d bulk-resume attempted: %d secret(s) resumed", projectID, n))
	return n, nil
}

// listProjectSecrets pages through every secret in a project.
func (c *KeyorixCore) listProjectSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	pid := projectID
	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			ProjectID: &pid, Page: page, PageSize: projectSuspendPageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		all = append(all, secrets...)
		if len(secrets) < projectSuspendPageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
}

// ResumeSecret restores value reads of a suspended secret (idempotent).
func (c *KeyorixCore) ResumeSecret(ctx context.Context, secretID, actorID uint) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Status != SecretStatusSuspended {
		return secret, nil // not suspended — no-op
	}
	fromStatus := secret.Status
	secret.Status = SecretStatusActive
	secret.SuspendClearSyncedCopies = false // the marker lives only as long as the suspension
	secret.UpdatedAt = c.now()
	matched, err := c.storage.TransitionSecretStatus(ctx, secret, fromStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		// Lost the race: the row's persisted status moved away from fromStatus
		// between the GetSecret read above and this write (a concurrent
		// suspend/resume, or any other concurrent writer of this row) — treat
		// as a failed write rather than silently overwriting the winner.
		return nil, fmt.Errorf("secret %d's status changed concurrently; retry", secretID)
	}
	uid, sid := actorID, secretID
	c.writeAuditEvent(ctx, EventSecretResumed, &uid, &sid, fmt.Sprintf("resumed secret %q", secret.Name))
	return secret, nil
}
