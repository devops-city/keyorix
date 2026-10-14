// classification.go — data classification of secrets (ISO 27001 A.5.12 classification
// of information / A.5.13 labelling). Each secret carries an optional sensitivity
// label; the label drives the classification posture and lets a reviewer find the
// high-sensitivity secrets. "" means unclassified.
//
// UPDATE (#128's residual, resolved by product decision): classification was
// historically a label with zero enforcement anywhere. It now gates ONE thing, and
// only when explicitly opted into: config classification.restricted_requires_approval
// (default false — every deployment's behaviour is unchanged unless an operator turns
// this on) requires an approved, secret-scoped access request before a direct read of
// a "restricted"-classified secret's VALUE succeeds (see classification_gate.go). A
// secret's metadata (this classification label included), RBAC, rate limiting, and
// every other classification tier remain exactly as informational as before — this is
// a narrow, additive control on the single highest tier's value-read path, not the
// general "policy engine" this comment used to describe as unbuilt. MFA step-up and
// narrower RBAC for "restricted" remain undecided/unimplemented, same as before.
package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Classification levels, lowest → highest sensitivity. "" (unclassified) is also
// a valid stored state (not yet labelled).
const (
	ClassificationPublic       = "public"
	ClassificationInternal     = "internal"
	ClassificationConfidential = "confidential"
	ClassificationRestricted   = "restricted"
)

// ClassificationLevels is the ordered set of valid (non-empty) labels.
var ClassificationLevels = []string{
	ClassificationPublic, ClassificationInternal, ClassificationConfidential, ClassificationRestricted,
}

// IsValidClassification reports whether level is "" (unclassified) or a known label.
func IsValidClassification(level string) bool {
	if level == "" {
		return true
	}
	return slices.Contains(ClassificationLevels, level)
}

// ClassifySecret sets (or clears, with "") a secret's data-classification label and
// audits the change as a secret.updated event with a before/after diff. actorID is
// the acting user; username is for the audit description.
func (c *KeyorixCore) ClassifySecret(ctx context.Context, actorID uint, username string, secretID uint, level string) (*models.SecretNode, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil),
			"classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Classification == level {
		return secret, nil // no-op
	}
	// #G09: stripping/downgrading the "restricted" label is at least as
	// sensitive as a single value read of the secret — it removes the
	// classification-restricted read-gate (step-up/approval/permission) from
	// every FUTURE read, not just this one. Require the actor to pass that
	// same gate before allowing the downgrade, closing an otherwise-trivial
	// way for any secrets.write holder to unprotect a restricted secret
	// without ever needing the authority to read it.
	if secret.Classification == ClassificationRestricted {
		if err := c.checkRestrictedSecretReadApproval(ctx, secret, actorID); err != nil {
			return nil, err
		}
	}
	old := secret.Classification
	// #2695: write `classification` alone, onto a row that is still live. The
	// previous full-row Save carried this function's whole unlocked read back —
	// so it resurrected a concurrently deleted secret (shares and ACLs already
	// revoked, no restore audit) and reverted a concurrent suspend, read-count
	// increment or ownership clear.
	matched, err := c.storage.UpdateSecretFields(ctx, secret.ID, storage.SecretFieldUpdate{Classification: &level})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	secret.Classification = level
	updated := secret
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.LogSecretUpdatedWithDiff(ctx, actorID, secretID, secret.ProjectID, username, secret.Name, "", "", diff)
	return updated, nil
}
