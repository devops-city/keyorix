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
	if projectID == 0 || actorID == 0 {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and actor ID are required")
	}
	secrets, err := c.listProjectSecrets(ctx, projectID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range secrets {
		if s.Status == SecretStatusSuspended {
			continue
		}
		// Re-check per-secret write authorization (owner/share). The project-wide
		// secrets.write route gate is not sufficient on its own — the single-secret PUT
		// path enforces this too, so a caller who can't update a secret individually must
		// not be able to via the bulk op (mirrors ExtendExpiringSecrets). Skip (don't
		// abort) on denial.
		if _, err := c.EnforceSecretWritePermission(ctx, s.ID, actorID); err != nil {
			continue
		}
		if _, err := c.SuspendSecret(ctx, s.ID, actorID, reason); err == nil {
			n++
		}
	}
	// Written unconditionally: SuspendSecret audits each individual
	// suspension, but a project with nothing left to suspend (all already
	// suspended, or none owned/writable by actorID) would otherwise leave no
	// trail that this bulk operation was attempted (F5, audit-completeness
	// campaign).
	pid := projectID
	c.writeAuditEventFull(ctx, "secret.bulk_suspend_attempted", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("project %d bulk-suspend attempted: %d secret(s) suspended", projectID, n))
	return n, nil
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
