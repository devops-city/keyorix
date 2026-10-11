// secret_acl.go — per-secret fine-grained access control (RBAC Phase 3).
//
// A SecretACL row grants a specific user one or more permissions on a single secret,
// independently of any project-level role they hold (or don't hold). This implements
// the Vault-path-style least-privilege model: a CI token can be granted secrets.read
// on exactly one secret without needing a project role at all.
//
// ACL grants are ADDITIVE: the user is allowed if EITHER a SecretACL entry covers the
// requested permission OR the project-scope RBAC check passes (see AuthorizeSecret in
// authz.go). ACL management itself (grant/revoke/list) requires secrets.manage at
// project scope, so only project admins can hand out per-secret grants.
//
// Folder inheritance: HasSecretACL also walks the ancestor folder chain via
// GetSecretAncestors so that a grant on a parent folder node is inherited by all
// child secret nodes automatically — no extra grant per secret needed. GrantSecretACL
// accordingly accepts either a leaf secret's ID or a folder's ID as the grant target
// (see requireSecretOrFolderNode) — every ancestor GetSecretAncestors can ever return
// is structurally a folder node (CreateSecret/CreateFolder both reject a parent whose
// IsSecret is true), so a folder-only creation path is required for the inheritance
// walk in HasSecretACL to ever find a match.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Valid permission values for a SecretACL entry.
var validACLPermissions = []string{"secrets.read", "secrets.write"}

// Secret-ACL audit event types.
const (
	EventSecretACLGranted = "secret.acl_granted" // #nosec G101 -- audit event type, not a credential
	EventSecretACLRevoked = "secret.acl_revoked" // #nosec G101 -- audit event type, not a credential
)

// EncodeSecretACLPerms JSON-encodes a permission list for storage.
func EncodeSecretACLPerms(perms []string) (string, error) {
	if len(perms) == 0 {
		return "", fmt.Errorf("%s: at least one permission is required", i18n.T("ErrorValidation", nil))
	}
	b, err := json.Marshal(perms)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GrantSecretACL creates or updates a SecretACL grant for (secretID, userID).
// secretID may name either a leaf secret or a folder node — a folder-targeted
// grant is inherited by every descendant secret via HasSecretACL's ancestor walk
// (see requireSecretOrFolderNode). actorID is the admin performing the grant.
// perms must be a non-empty subset of validACLPermissions. Requires
// secrets.manage at the target's project scope (enforced at the HTTP layer).
// Emits a secret.acl_granted audit event.
func (c *KeyorixCore) GrantSecretACL(ctx context.Context, actorID, secretID, userID uint, perms []string) error {
	if actorID == 0 {
		return fmt.Errorf("%s: actor ID is required", i18n.T("ErrorValidation", nil))
	}
	if secretID == 0 {
		return fmt.Errorf("%s: secret ID is required", i18n.T("ErrorValidation", nil))
	}
	if userID == 0 {
		return fmt.Errorf("%s: user ID is required", i18n.T("ErrorValidation", nil))
	}
	if len(perms) == 0 {
		return fmt.Errorf("%s: at least one permission is required", i18n.T("ErrorValidation", nil))
	}
	for _, p := range perms {
		if !slices.Contains(validACLPermissions, p) {
			return fmt.Errorf("%s: invalid ACL permission %q — must be one of %v", i18n.T("ErrorValidation", nil), p, validACLPermissions)
		}
	}

	// Verify the target node exists (this is defence-in-depth; the HTTP layer also
	// resolves it). Unlike requireSecret, this accepts a folder node too — see
	// requireSecretOrFolderNode.
	secret, err := c.requireSecretOrFolderNode(ctx, secretID)
	if err != nil {
		return err
	}

	// Check that the grant target is a project member — granting access to a
	// non-member is confusing and potentially unintended.
	if isMember, merr := c.IsProjectMember(ctx, userID, secret.ProjectID); merr != nil {
		return fmt.Errorf("failed to verify project membership: %w", merr)
	} else if !isMember {
		return fmt.Errorf("%s: user %d is not a member of this secret's project", i18n.T("ErrorValidation", nil), userID)
	}

	permsJSON, err := EncodeSecretACLPerms(perms)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	acl := &models.SecretACL{
		SecretID:    secretID,
		UserID:      userID,
		Permissions: permsJSON,
		GrantedBy:   actorID,
	}
	if err := c.storage.CreateOrUpdateSecretACL(ctx, acl); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	projectID := secret.ProjectID
	c.writeAuditEventFull(ctx, EventSecretACLGranted, actorPtr(actorID), &secretID, &projectID, "",
		fmt.Sprintf("granted %s ACL %v on %s", c.auditRef(ctx, c.storage, auditKindUser, userID), perms, c.auditRef(ctx, c.storage, auditKindSecret, secretID)))
	return nil
}

// RevokeSecretACL removes the ACL row with the given aclID, verifying it belongs
// to secretID. actorID is the admin performing the revocation. Emits a
// secret.acl_revoked audit event.
func (c *KeyorixCore) RevokeSecretACL(ctx context.Context, actorID, secretID, aclID uint) error {
	if aclID == 0 {
		return fmt.Errorf("%s: ACL ID is required", i18n.T("ErrorValidation", nil))
	}

	// Look up all ACLs for this secret to verify the aclID belongs here.
	acls, err := c.storage.ListSecretACLs(ctx, secretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	var found *models.SecretACL
	for _, a := range acls {
		if a.ID == aclID {
			found = a
			break
		}
	}
	if found == nil {
		return fmt.Errorf("%s: ACL %d does not belong to secret %d", i18n.T("ErrorNotFound", nil), aclID, secretID)
	}

	if err := c.storage.DeleteSecretACL(ctx, aclID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	c.writeAuditEvent(ctx, EventSecretACLRevoked, actorPtr(actorID), &secretID,
		fmt.Sprintf("revoked ACL %d (%s) on %s", aclID, c.auditRef(ctx, c.storage, auditKindUser, found.UserID), c.auditRef(ctx, c.storage, auditKindSecret, secretID)))
	return nil
}

// ListSecretACLs returns all ACL grants for the given secret.
func (c *KeyorixCore) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	return c.storage.ListSecretACLs(ctx, secretID)
}

// HasSecretACL reports whether userID holds an explicit SecretACL grant on secretID
// (or on any ancestor folder node) that covers perm. The check first examines
// the specific secret, then walks the ancestor folder chain via GetSecretAncestors
// so that a grant on a parent folder is inherited by all child secrets.
//
// Returns (false, nil) when no matching grant exists or the grant doesn't cover
// perm; only returns an error on storage failure.
func (c *KeyorixCore) HasSecretACL(ctx context.Context, userID, secretID uint, perm string) (bool, error) {
	// Check the specific secret first.
	found, err := c.aclGrantsPermission(ctx, secretID, userID, perm)
	if err != nil || found {
		return found, err
	}
	// Walk ancestor folders for inheritance.
	ancestors, err := c.storage.GetSecretAncestors(ctx, secretID)
	if err != nil {
		return false, err
	}
	for _, ancestorID := range ancestors {
		found, err := c.aclGrantsPermission(ctx, ancestorID, userID, perm)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// aclGrantsPermission checks if userID has an ACL grant on nodeID covering
// perm, AND that userID is still a live member of the grant's project.
func (c *KeyorixCore) aclGrantsPermission(ctx context.Context, nodeID, userID uint, perm string) (bool, error) {
	acl, err := c.storage.GetSecretACL(ctx, nodeID, userID)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	perms := DecodeSecretACLPerms(acl.Permissions)
	if !slices.Contains(perms, perm) {
		return false, nil
	}
	// #G13: an ACL grant only remains valid while its grantee is still a member
	// of the secret's project. Without this, a user removed from the project
	// (offboarded) retains per-secret access indefinitely via this row alone —
	// AuthorizeSecret checks ACL grants before the project-scope RBAC fallback
	// and short-circuits on the first match, so the project-level removal
	// provides no protection by itself. RemoveProjectMember's
	// DeleteSecretACLsByUserAndProject call proactively deletes these rows on
	// removal, but that's cleanup-on-write; this is the corresponding
	// authorization-time guard, so a gap in that cleanup path (a backend that
	// doesn't support it, a code path that bypasses RemoveProjectMember, a
	// TOCTOU window) can't leave a stale grant silently exploitable in the
	// meantime. Fails closed: a lookup error denies the grant.
	node, err := c.storage.GetSecret(ctx, nodeID)
	if err != nil {
		return false, err
	}
	isMember, err := c.IsProjectMember(ctx, userID, node.ProjectID)
	if err != nil {
		return false, err
	}
	return isMember, nil
}

// requireSecretOrFolderNode resolves id to any live SecretNode — a leaf secret OR
// a folder container — unlike requireSecret (secret_dependencies.go), which
// rejects folder nodes and is used by callers (dependency edges, blast-radius,
// impact preview) that inherently need a concrete secret. GrantSecretACL uses
// this wider gate deliberately: a folder-targeted grant is how per-folder ACL
// inheritance (HasSecretACL's ancestor walk over GetSecretAncestors) gets
// populated in the first place. Every ancestor ID that walk ever visits is
// structurally a folder node — CreateSecret and CreateFolder both reject a
// parent whose IsSecret is true — so restricting grant targets to leaf secrets
// (as requireSecret would) makes the inheritance walk permanently unable to find
// a match: no SecretACL row could ever exist for an ID the walk visits.
func (c *KeyorixCore) requireSecretOrFolderNode(ctx context.Context, id uint) (*models.SecretNode, error) {
	node, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: node %d not found", i18n.T("ErrorNotFound", nil), id)
	}
	return node, nil
}

// isNotFound reports whether err looks like a "not found" storage error.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "record not found")
}
