// secret_ownership.go — transfer a secret's ownership to another user. A secret's
// owner is the only principal that can manage/share it (CheckSecretPermission grants
// PermissionOwner only to the owner), so when an owner leaves the org their secrets
// are effectively orphaned. Transfer hands ownership to another user — either by the
// current owner, or (for recovery, gated on roles.assign) when the current owner is
// gone (ownerless or a deleted account). The new owner must already hold write-tier
// access. See transferOwnership's doc comment for the full authorization model.
package core

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventSecretOwnerTransferred is audited when a secret's ownership changes hands.
const EventSecretOwnerTransferred = "secret.owner_transferred"

// ownershipTransferDetail is the structured payload stored in a
// secret.owner_transferred event's Diff field, carrying the from/to user IDs
// out-of-band from the free-text Description. The Description also embeds the
// secret's NAME (e.g. `transferred ownership of secret "NAME" from user X to
// user Y`), and the name is attacker-controllable via rename — a secret named
// something like `evil" from user 1 to user 999 fake` would let a regex over the
// Description forge the reported from/to owners. GetSecretOwnershipHistory reads
// FromUserID/ToUserID from this structured field instead, so the untrusted name
// can never be mistaken for the security-relevant IDs.
type ownershipTransferDetail struct {
	FromUserID uint `json:"from_user_id"`
	ToUserID   uint `json:"to_user_id"`
	// SharesReassigned counts the ShareRecord rows (live, expired and revoked) the
	// transfer re-stamped to the new owner in the same transaction (#3102).
	SharesReassigned int64 `json:"shares_reassigned"`
}

// TransferSecretOwnership sets secretID's owner to newOwnerID. The caller (transport)
// must have enforced scoped secrets.write. Authorization here: the actor must be the
// current owner, OR (with roles.assign at this scope) the current owner may be gone
// (ownerless, or an account that no longer exists) — so an active owner's secret can't
// be taken from under them, while a departed owner's secrets can still be recovered,
// but only by someone with authority to grant authority. The new owner must already
// hold write-tier access. See transferOwnership's doc comment for why (G-secret-
// ownership-ceiling). newOwnerID must be an existing user.
func (c *KeyorixCore) TransferSecretOwnership(ctx context.Context, secretID, newOwnerID, actorID uint, actorKind string) (*models.SecretNode, error) {
	updated, err := c.transferOwnership(ctx, secretID, newOwnerID, actorID, actorKind)
	if err != nil {
		return nil, err
	}
	// Tell the new owner they now own it (single transfer). Bulk reassignment uses
	// transferOwnership directly and sends one summary instead. Best-effort.
	c.notifySecretOwnershipTransferred(ctx, updated, newOwnerID, actorID)
	return updated, nil
}

// transferOwnership performs the validated, audited ownership change without the
// new-owner notification — the ONE shared, authorization-checked primitive for both
// the single-secret path (TransferSecretOwnership) and the bulk path
// (ReassignOwnedSecrets, secret_reassign_owner.go). Every caller of either of those
// two routes through this function; do not add a third function that mutates
// SecretNode.OwnerID directly — secret_ownership_guard_test.go's AST sweep fails the
// build if one appears.
//
// Ownership is an AUTHORITY GRANT, not a data write: CheckSecretPermission's owner
// branch (permissions.go) gives the owner every permission on the secret, and
// permissionLevelToRBACPerm documents PermissionOwner as secrets.delete-equivalent —
// "the most restrictive mutation the RBAC model expresses." Two checks follow from
// that, matching how this codebase gates every other authority grant (roles.assign,
// e.g. router.go's RestoreProject comment: "same blast radius as a role grant... gate
// on roles.assign, not secrets.write") and stacked router+core double-gating
// elsewhere:
//
//  1. New-owner ceiling: the new owner must already hold secrets.write (or
//     secrets.manage) at the secret's scope, not merely secrets.read. Without this, a
//     secrets.write-tier actor could hand full owner/delete/re-share authority to any
//     project_viewer/project_auditor (seeded with secrets.read alone) — bypassing the
//     roles.assign gate every other privilege grant in this codebase goes through.
//  2. Actor ceiling on the RECOVERY path: when the current owner is gone (ownerless —
//     the ROUTINE state for machine-created secrets per ADR-023/030, not a rare edge
//     case — or a deleted account), re-homing the secret on their behalf is an
//     administrative action, not a routine self-service handoff, so the actor must
//     hold roles.assign at this scope. Without this, ANY secrets.write-tier actor
//     could claim (or hand off) ownership of every orphaned secret in a project with
//     no admin-tier check at all — the concrete exploit this closes. A LIVE owner
//     handing off their own secret does not need roles.assign: they already hold
//     owner-tier authority over this one secret, so handing it to another
//     already-write-tier principal (check 1) is not an escalation of what they could
//     already do with it.
func (c *KeyorixCore) transferOwnership(ctx context.Context, secretID, newOwnerID, actorID uint, actorKind string) (*models.SecretNode, error) {
	if secretID == 0 || newOwnerID == 0 || actorID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID, new owner ID and actor ID are required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.OwnerID == newOwnerID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret is already owned by that user")
	}
	if _, err := c.storage.GetUser(ctx, newOwnerID); err != nil {
		return nil, fmt.Errorf("%s: new owner %d not found", i18n.T("ErrorValidation", nil), newOwnerID)
	}

	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}

	// Authorize the ACTOR. The live current owner may hand it off; otherwise this is
	// the recovery path, gated on roles.assign (see doc comment above).
	if !secretOwnedBy(secret.OwnerID, actorID) {
		if !c.currentOwnerGone(ctx, secret.OwnerID) {
			return nil, fmt.Errorf("%s: only the current owner can transfer this secret", i18n.T("ErrorPermissionDenied", nil))
		}
		if ok, aerr := c.AuthorizePrincipal(ctx, actorKind, actorID, permRolesAssign, scope); aerr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), aerr)
		} else if !ok {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
				"recovering an orphaned or departed-owner secret requires roles.assign at this scope")
		}
	}

	// The NEW owner must already hold write-tier (or manage-tier) access to the
	// secret's scope — see doc comment above (new-owner ceiling). Evaluate the new
	// owner's OWN roles, not gated by the actor's PAT restriction.
	hasWrite, werr := c.principalHasScopedPermission(ctx, newOwnerID, permSecretsWrite, scope)
	if werr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), werr)
	}
	if !hasWrite {
		hasManage, merr := c.principalHasScopedPermission(ctx, newOwnerID, permSecretsManage, scope)
		if merr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), merr)
		}
		hasWrite = hasManage
	}
	if !hasWrite {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil),
			"the new owner must already hold secrets.write (or secrets.manage) access to this secret's project/environment")
	}

	oldOwner := secret.OwnerID
	// The secret's owner_id and its shares' owner_id move in ONE transaction (#3102).
	// ShareRecord.OwnerID keys the owner-scoped share lists (ListSharesByOwner) while
	// revoke/update are gated on owning the SECRET (requireShareAuthority); moved
	// separately, a crash or a concurrent reader between the two writes would leave the
	// previous owner listing shares they cannot revoke (or the new owner revoking shares
	// they cannot list), which is the bug. Every share row of the secret is re-stamped,
	// revoked and expired ones included (ReassignSecretShareOwner says why). No
	// recipient, permission or expiry is touched, so nobody's access changes.
	//
	// #2695: owner_id only — see ClassifySecret's comment. Notably this is the
	// column ClearProjectSecretOwnership (offboarding) also writes, so a
	// full-row write from ANY other caller could hand the owner short-circuit
	// back to a departed user.
	var sharesReassigned int64
	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		matched, uerr := tx.UpdateSecretFields(ctx, secret.ID, storage.SecretFieldUpdate{OwnerID: &newOwnerID})
		if uerr != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
		}
		if !matched {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		n, rerr := tx.ReassignSecretShareOwner(ctx, secret.ID, newOwnerID)
		if rerr != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), rerr)
		}
		sharesReassigned = n
		return nil
	})
	if err != nil {
		return nil, err
	}
	secret.OwnerID = newOwnerID
	updated := secret

	uid := actorID
	sid := secretID
	detail, _ := json.Marshal(ownershipTransferDetail{FromUserID: oldOwner, ToUserID: newOwnerID, SharesReassigned: sharesReassigned})
	c.writeAuditEventDiff(ctx, EventSecretOwnerTransferred, &uid, &sid, nil, "",
		fmt.Sprintf("transferred ownership of secret %q from user %d to user %d (%d share record(s) re-owned)", updated.Name, oldOwner, newOwnerID, sharesReassigned),
		string(detail))
	return updated, nil
}

// currentOwnerGone reports whether a secret's owner is positively absent: ownerless
// (0) or an account confirmed not to exist. It FAILS CLOSED — a transient GetUser
// error returns false (owner assumed present), so a non-owner cannot ride a momentary
// lookup failure into seizing an actively-owned secret. Only a confirmed "not found"
// (storage.IsUserNotFound, which unwraps the typed ErrUserNotFound sentinel) counts
// as "gone".
func (c *KeyorixCore) currentOwnerGone(ctx context.Context, ownerID uint) bool {
	if ownerID == 0 {
		return true
	}
	_, err := c.storage.GetUser(ctx, ownerID)
	return storage.IsUserNotFound(err)
}
