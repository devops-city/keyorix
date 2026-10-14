// secret_move.go — move a secret or folder to a different parent folder.
//
// MoveSecret re-parents a SecretNode under a new parent (folder) or to the
// root (parentID == nil). The caller (transport) must have enforced scoped
// secrets.write; this function re-checks write access and validates that the
// target parent, when set, is a folder (IsSecret == false).
package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventSecretMoved is emitted when a secret or folder is moved to a new parent.
const EventSecretMoved = "secret.moved"

// MoveSecret changes the parent of secretID to newParentID.
//
//   - actorID must have secrets.write on the secret (via EnforceSecretWritePermission).
//   - newParentID == nil moves the node to the root (no parent).
//   - newParentID != nil validates that the target is a folder (IsSecret == false).
func (c *KeyorixCore) MoveSecret(ctx context.Context, actorID, secretID uint, newParentID *uint) (*models.SecretNode, error) {
	if secretID == 0 || actorID == 0 {
		return nil, fmt.Errorf("%s: secret ID and actor ID are required", i18n.T("ErrorValidation", nil))
	}

	// Authorization: the actor must be able to write the secret.
	if _, err := c.EnforceSecretWritePermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}

	// Load the target secret / folder.
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Validate the new parent when specified.
	if newParentID != nil && *newParentID != 0 {
		// Prevent moving a node into itself before the storage lookup.
		if *newParentID == secretID {
			return nil, fmt.Errorf("%s: cannot move a node into itself", i18n.T("ErrorValidation", nil))
		}
		parent, err := c.storage.GetSecret(ctx, *newParentID)
		if err != nil {
			return nil, fmt.Errorf("%s: parent %d not found", i18n.T("ErrorValidation", nil), *newParentID)
		}
		if parent.IsSecret {
			return nil, fmt.Errorf("%s: target parent %d is a secret, not a folder", i18n.T("ErrorValidation", nil), *newParentID)
		}
		// The destination parent was never authorized or scope-checked: actorID's
		// secrets.write on secretID says nothing about the target folder, which
		// this function loaded with a bare, unauthorized GetSecret. Mirroring
		// CreateSecret's own parent-folder validation (secrets.go), require the
		// destination to live in the SAME project/environment as the secret being
		// moved — otherwise an actor who can write one project's secret could
		// re-parent it into a folder in an entirely different project they have
		// no access to, and folder-inheriting ACL/sharing resolution would then
		// apply that other project's grants to it.
		if parent.ProjectID != secret.ProjectID || parent.EnvironmentID != secret.EnvironmentID {
			return nil, fmt.Errorf("%s: target parent %d does not belong to the same project/environment", i18n.T("ErrorValidation", nil), *newParentID)
		}
		// Reject moves that would introduce a cycle: the direct self-parent
		// check above only catches *newParentID == secretID, but a folder can
		// also be moved underneath one of its OWN descendants (e.g. A -> B ->
		// C, then move A under C), which corrupts the tree just as badly and
		// would send any parent-chain walk (breadcrumbs, ACL inheritance in
		// HasSecretACL) into an infinite loop. Walk the proposed new parent's
		// ancestor chain — reusing the same bounded, cycle-safe walk
		// GetSecretAncestors already provides for ACL folder inheritance — and
		// refuse the move if secretID appears in it, meaning newParentID is a
		// descendant of the node being moved.
		ancestors, err := c.storage.GetSecretAncestors(ctx, *newParentID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if slices.Contains(ancestors, secretID) {
			return nil, fmt.Errorf("%s: cannot move a node into its own descendant", i18n.T("ErrorValidation", nil))
		}
		secret.ParentID = newParentID
	} else {
		// Move to root (no parent).
		secret.ParentID = nil
	}

	// #2695: parent_id + updated_at only — see ClassifySecret's comment.
	// SetParentID is explicit so a move to root (nil) really writes NULL
	// rather than reading as "leave the parent alone".
	now := c.now()
	matched, err := c.storage.UpdateSecretFields(ctx, secret.ID, storage.SecretFieldUpdate{
		SetParentID: true, ParentID: secret.ParentID, UpdatedAt: &now,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	secret.UpdatedAt = now
	updated := secret

	uid, sid := actorID, secretID
	parentDesc := "root"
	if secret.ParentID != nil {
		parentDesc = fmt.Sprintf("folder %d", *secret.ParentID)
	}
	c.writeAuditEvent(ctx, EventSecretMoved, &uid, &sid,
		fmt.Sprintf("moved secret/folder %q to %s", updated.Name, parentDesc))
	return updated, nil
}
